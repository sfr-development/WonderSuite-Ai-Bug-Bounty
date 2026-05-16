// Output writers for scan results.
// All synchronous + return String — caller writes to disk via Tauri save dialog.

use crate::portscan::types::{PortState, ScanResult};

pub fn to_jsonl(results: &[ScanResult]) -> String {
    let mut out = String::new();
    for r in results {
        if let Ok(s) = serde_json::to_string(r) {
            out.push_str(&s);
            out.push('\n');
        }
    }
    out
}

pub fn to_csv(results: &[ScanResult]) -> String {
    let mut out = String::from("ip,port,proto,state,service,product,version,banner\n");
    for r in results {
        let svc = r.service.as_ref();
        let name = svc.map(|s| s.name.as_str()).unwrap_or("");
        let product = svc.and_then(|s| s.product.as_deref()).unwrap_or("");
        let version = svc.and_then(|s| s.version.as_deref()).unwrap_or("");
        let banner = svc.and_then(|s| s.banner.as_deref()).unwrap_or("").replace(',', " ");
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            r.ip,
            r.port,
            r.proto,
            state_str(r.state),
            name,
            product,
            version,
            banner.lines().next().unwrap_or("")
        ));
    }
    out
}

pub fn to_plain(results: &[ScanResult]) -> String {
    let mut out = String::new();
    for r in results {
        if matches!(r.state, PortState::Open) {
            out.push_str(&format!("{}:{}\n", r.ip, r.port));
        }
    }
    out
}

pub fn to_nmap_xml(results: &[ScanResult], started_unix: i64) -> String {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(&format!(
        "<nmaprun scanner=\"wondersuite\" version=\"0.3.7\" start=\"{}\">\n",
        started_unix
    ));
    let mut by_ip: std::collections::BTreeMap<std::net::IpAddr, Vec<&ScanResult>> =
        std::collections::BTreeMap::new();
    for r in results {
        by_ip.entry(r.ip).or_default().push(r);
    }
    for (ip, rs) in &by_ip {
        out.push_str(&format!("  <host>\n    <status state=\"up\" reason=\"connect\"/>\n    <address addr=\"{}\" addrtype=\"{}\"/>\n",
            ip,
            if ip.is_ipv4() { "ipv4" } else { "ipv6" },
        ));
        out.push_str("    <ports>\n");
        for r in rs {
            let st = state_str(r.state);
            out.push_str(&format!(
                "      <port protocol=\"{}\" portid=\"{}\">\n        <state state=\"{}\" reason=\"{}\"/>\n",
                r.proto,
                r.port,
                st,
                if st == "open" { "syn-ack" } else { st }
            ));
            if let Some(svc) = &r.service {
                let extras = [
                    svc.product.as_ref().map(|p| format!(" product=\"{}\"", xml_escape(p))),
                    svc.version.as_ref().map(|v| format!(" version=\"{}\"", xml_escape(v))),
                ]
                .into_iter()
                .flatten()
                .collect::<String>();
                out.push_str(&format!("        <service name=\"{}\"{}/>\n", xml_escape(&svc.name), extras));
            }
            out.push_str("      </port>\n");
        }
        out.push_str("    </ports>\n  </host>\n");
    }
    out.push_str("</nmaprun>\n");
    out
}

pub fn to_gnmap(results: &[ScanResult]) -> String {
    let mut by_ip: std::collections::BTreeMap<std::net::IpAddr, Vec<&ScanResult>> =
        std::collections::BTreeMap::new();
    for r in results {
        by_ip.entry(r.ip).or_default().push(r);
    }
    let mut out = String::new();
    for (ip, rs) in &by_ip {
        out.push_str(&format!("Host: {} ()    Status: Up\n", ip));
        let port_parts: Vec<String> = rs
            .iter()
            .map(|r| {
                let st = state_str(r.state);
                let svc_name = r.service.as_ref().map(|s| s.name.as_str()).unwrap_or("");
                let version = r
                    .service
                    .as_ref()
                    .map(|s| {
                        format!(
                            "{} {}",
                            s.product.as_deref().unwrap_or(""),
                            s.version.as_deref().unwrap_or("")
                        )
                        .trim()
                        .to_string()
                    })
                    .unwrap_or_default();
                format!("{}/{}/{}//{}//{}/", r.port, st, r.proto, svc_name, version)
            })
            .collect();
        out.push_str(&format!("Host: {} ()    Ports: {}\n", ip, port_parts.join(", ")));
    }
    out
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn state_str(s: PortState) -> &'static str {
    match s {
        PortState::Open => "open",
        PortState::Closed => "closed",
        PortState::Filtered => "filtered",
        PortState::OpenFiltered => "open|filtered",
    }
}
