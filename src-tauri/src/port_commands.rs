use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct PortHolder {
    pub pid: u32,
    pub name: String,
    pub command: String,
    pub addr: String,
}

#[derive(Debug, Serialize)]
pub struct PortStatus {
    pub port: u16,
    pub in_use: bool,
    pub holders: Vec<PortHolder>,
}

fn quick_bind_check(port: u16) -> bool {
    std::net::TcpListener::bind(("127.0.0.1", port)).is_err()
}

#[cfg(target_os = "windows")]
fn collect_holders(port: u16) -> Vec<PortHolder> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let netstat =
        match Command::new("netstat").args(["-ano", "-p", "tcp"]).creation_flags(CREATE_NO_WINDOW).output() {
            Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
            Err(_) => return Vec::new(),
        };

    let needle = format!(":{}", port);
    let mut by_pid: std::collections::BTreeMap<u32, String> = std::collections::BTreeMap::new();
    for line in netstat.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }
        let local = cols[1];
        let foreign = cols[2];

        if !local.ends_with(&needle) {
            continue;
        }

        let is_listening = foreign == "0.0.0.0:0"
            || foreign == "[::]:0"
            || foreign == "*:*"
            || foreign.ends_with(":0");
        if !is_listening {
            continue;
        }

        let pid_col = cols.last().copied().unwrap_or("");
        if let Ok(pid) = pid_col.parse::<u32>() {
            by_pid.entry(pid).or_insert_with(|| local.to_string());
        }
    }

    if by_pid.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    let tasklist = Command::new("tasklist")
        .args(["/FO", "CSV", "/NH"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    for (pid, addr) in by_pid {
        let mut name = String::new();
        for line in tasklist.lines() {
            let cells: Vec<&str> = line.split("\",\"").map(|s| s.trim_matches('"')).collect();
            if cells.len() < 2 {
                continue;
            }
            if cells.get(1).and_then(|s| s.parse::<u32>().ok()) == Some(pid) {
                name = cells[0].to_string();
                break;
            }
        }
        out.push(PortHolder { pid, name: name.clone(), command: name, addr });
    }
    out
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn collect_holders(port: u16) -> Vec<PortHolder> {
    use std::process::Command;
    let out = match Command::new("lsof")
        .args(["-nP", "-iTCP", &format!(":{}", port), "-sTCP:LISTEN", "-F", "pcnL"])
        .output()
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => return Vec::new(),
    };
    let mut holders = Vec::new();
    let mut cur_pid: Option<u32> = None;
    let mut cur_name = String::new();
    let mut cur_user = String::new();
    for line in out.lines() {
        let (tag, rest) = line.split_at(line.chars().next().map(|c| c.len_utf8()).unwrap_or(0));
        match tag {
            "p" => {
                if let Some(pid) = cur_pid {
                    holders.push(PortHolder {
                        pid,
                        name: cur_name.clone(),
                        command: cur_user.clone(),
                        addr: format!("127.0.0.1:{}", port),
                    });
                }
                cur_pid = rest.parse().ok();
                cur_name.clear();
                cur_user.clear();
            }
            "c" => cur_name = rest.to_string(),
            "L" => cur_user = rest.to_string(),
            _ => {}
        }
    }
    if let Some(pid) = cur_pid {
        holders.push(PortHolder {
            pid,
            name: cur_name,
            command: cur_user,
            addr: format!("127.0.0.1:{}", port),
        });
    }
    holders
}

#[tauri::command]
pub fn port_status(port: u16) -> PortStatus {
    let in_use = quick_bind_check(port);
    let holders = if in_use { collect_holders(port) } else { Vec::new() };
    PortStatus { port, in_use, holders }
}

#[tauri::command]
pub fn kill_process(pid: u32) -> Result<bool, String> {
    if pid == 0 || pid == std::process::id() {
        return Err("refusing to kill PID 0 or self".into());
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        use std::process::Command;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let out = Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("taskkill spawn: {}", e))?;
        if out.status.success() {
            Ok(true)
        } else {
            Err(String::from_utf8_lossy(&out.stderr).to_string())
        }
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::process::Command;
        let out = Command::new("kill")
            .args(["-9", &pid.to_string()])
            .output()
            .map_err(|e| format!("kill spawn: {}", e))?;
        if out.status.success() {
            Ok(true)
        } else {
            Err(String::from_utf8_lossy(&out.stderr).to_string())
        }
    }
}
