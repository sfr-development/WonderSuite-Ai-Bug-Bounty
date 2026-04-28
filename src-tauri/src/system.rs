use serde::Serialize;
use std::env;
use std::path::PathBuf;

/// System architecture and platform information.
#[derive(Debug, Clone, Serialize)]
pub struct SystemInfo {
    pub arch: String,
    pub arch_display: String,
    pub os: String,
    pub os_version: String,
    pub is_arm: bool,
    pub is_x64: bool,
    pub cpu_cores: usize,
    pub home_dir: String,
    pub wondersuite_dir: String,
}

impl SystemInfo {
    pub fn detect() -> Self {
        let arch = env::consts::ARCH.to_string();
        let is_arm = arch.contains("aarch64") || arch.contains("arm");
        let is_x64 = arch.contains("x86_64") || arch.contains("x86");

        let arch_display = if is_arm {
            "ARM64 (AArch64)".to_string()
        } else if arch == "x86_64" {
            "x86_64 (AMD64)".to_string()
        } else if arch == "x86" {
            "x86 (32-bit)".to_string()
        } else {
            format!("{} (Unknown)", arch)
        };

        let os_version = Self::get_windows_version();

        let home = env::var("USERPROFILE")
            .or_else(|_| env::var("HOME"))
            .unwrap_or_else(|_| ".".to_string());

        let wondersuite_dir = PathBuf::from(&home)
            .join(".wondersuite")
            .to_string_lossy()
            .to_string();

        println!("[System] Architecture: {} | OS: {} {} | Cores: {}",
            arch_display, env::consts::OS, os_version, num_cpus());

        Self {
            arch,
            arch_display,
            os: env::consts::OS.to_string(),
            os_version,
            is_arm,
            is_x64,
            cpu_cores: num_cpus(),
            home_dir: home,
            wondersuite_dir,
        }
    }

    fn get_windows_version() -> String {
        #[cfg(target_os = "windows")]
        {
            use std::process::Command;
            #[cfg(target_os = "windows")]
            use std::os::windows::process::CommandExt;

            let mut cmd = Command::new("cmd");
            #[cfg(target_os = "windows")]
            cmd.creation_flags(0x08000000);

            if let Ok(out) = cmd.args(["/c", "ver"]).output()
            {
                let ver = String::from_utf8_lossy(&out.stdout);
                // Extract version number from "Microsoft Windows [Version 10.0.22631.4890]"
                if let Some(start) = ver.find("Version ") {
                    let rest = &ver[start + 8..];
                    if let Some(end) = rest.find(']') {
                        return rest[..end].trim().to_string();
                    }
                }
                return ver.trim().to_string();
            }
        }
        "Unknown".to_string()
    }
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

#[tauri::command]
pub async fn get_system_info() -> Result<SystemInfo, String> {
    Ok(SystemInfo::detect())
}
