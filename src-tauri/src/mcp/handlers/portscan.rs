// MCP handlers for the port scanner — 4 user-facing tools + paginated drill-down.
//
// All five rely on `portscan::orchestrator` and the global state Tauri owns;
// since MCP handlers are called from the JSON-RPC dispatcher without a Tauri
// `State` accessor, we keep a separate process-global Arc that the run()
// entrypoint in lib.rs hands over via init_state(). This mirrors the pattern
// used by proxy_commands::GLOBAL_PROXY_APP_STATE.

use crate::mcp::types::HandlerResult;
use crate::portscan::orchestrator::{self, PortScanState};
use crate::portscan::types::{ScanMode, ScanRequest, TimingTemplate};
use std::sync::OnceLock;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

static GLOBAL_PORTSCAN_STATE: OnceLock<PortScanState> = OnceLock::new();

pub fn init_state(state: PortScanState) {
    let _ = GLOBAL_PORTSCAN_STATE.set(state);
}

fn state() -> Result<PortScanState, String> {
    GLOBAL_PORTSCAN_STATE.get().cloned().ok_or_else(|| "Port scanner not initialized".into())
}

fn parse_timing(s: Option<&str>) -> TimingTemplate {
    match s.unwrap_or("T3").to_ascii_uppercase().as_str() {
        "T0" => TimingTemplate::T0,
        "T1" => TimingTemplate::T1,
        "T2" => TimingTemplate::T2,
        "T3" => TimingTemplate::T3,
        "T4" => TimingTemplate::T4,
        "T5" => TimingTemplate::T5,
        "T6" => TimingTemplate::T6,
        _ => TimingTemplate::T3,
    }
}

fn parse_mode(s: Option<&str>) -> ScanMode {
    match s.unwrap_or("connect").to_ascii_lowercase().as_str() {
        "syn" => ScanMode::Syn,
        "udp" => ScanMode::Udp,
        _ => ScanMode::Connect,
    }
}

/// Wait for a scan to finish or until `max_wait_ms` elapses. Returns the
/// final summary either way.
async fn wait_for_summary(
    st: PortScanState,
    scan_id: &str,
    max_wait_ms: u64,
) -> Result<serde_json::Value, String> {
    let waited_until = std::time::Instant::now() + Duration::from_millis(max_wait_ms);
    loop {
        let summary = orchestrator::summarize(st.clone(), scan_id.to_string()).await?;
        if summary.status != "running" {
            return Ok(serde_json::to_value(summary).unwrap_or(serde_json::Value::Null));
        }
        if std::time::Instant::now() >= waited_until {
            return Ok(serde_json::to_value(summary).unwrap_or(serde_json::Value::Null));
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

/// port_scan — single host, returns summary + scan_id.
pub async fn handle_port_scan(params: &serde_json::Value) -> HandlerResult {
    let target = params["target"].as_str().ok_or("Missing 'target'")?;
    let ports = params["ports"].as_str().unwrap_or("top-100").to_string();
    let mode = parse_mode(params["mode"].as_str());
    let timing = parse_timing(params["timing"].as_str());
    let service_detect = params["service_detect"].as_bool().unwrap_or(true);
    let intensity = params["intensity"].as_u64().unwrap_or(5) as u8;
    let max_wait_ms = params["max_wait_ms"].as_u64().unwrap_or(20_000);

    let st = state()?;
    let req = ScanRequest {
        targets: vec![target.into()],
        ports,
        mode,
        timing,
        service_detect,
        probe_intensity: intensity,
        exclude_cdn: false,
        adaptive: true,
        idle_mode: false,
        max_hosts: None,
        // MCP callers historically saw all states — keep that contract.
        emit_closed_filtered: true,
    };
    // Build a dummy AppHandle? We need one for emit. Workaround: pass via
    // the state's emitter. For MCP we can skip emitter — the orchestrator
    // tolerates the AppHandle being a no-op? It doesn't — it requires real.
    // Solution: route through Tauri command rather than calling orchestrator
    // directly. We use crate::mcp::handlers::dispatch_via_tauri (defined in
    // mod.rs) when possible. For now we expose a separate non-emitting
    // orchestrator path.
    let reply = orchestrator::start_scan_no_emit(st.clone(), req).await?;
    let summary = wait_for_summary(st, &reply.scan_id, max_wait_ms).await?;
    Ok(serde_json::json!({
        "scan_id": reply.scan_id,
        "total_probes": reply.total_probes,
        "targets_resolved": reply.targets_resolved,
        "ports_count": reply.ports_count,
        "summary": summary,
    }))
}

/// port_scan_range — CIDR or list of hosts. Same as port_scan but takes a
/// `targets` array.
pub async fn handle_port_scan_range(params: &serde_json::Value) -> HandlerResult {
    let targets: Vec<String> = params["targets"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .ok_or("Missing 'targets' array")?;
    if targets.is_empty() {
        return Err("targets must be a non-empty array".into());
    }
    let ports = params["ports"].as_str().unwrap_or("top-100").to_string();
    let mode = parse_mode(params["mode"].as_str());
    let timing = parse_timing(params["timing"].as_str());
    let service_detect = params["service_detect"].as_bool().unwrap_or(true);
    let intensity = params["intensity"].as_u64().unwrap_or(5) as u8;
    let exclude_cdn = params["exclude_cdn"].as_bool().unwrap_or(false);
    let max_hosts = params["max_hosts"].as_u64().map(|v| v as usize);
    let max_wait_ms = params["max_wait_ms"].as_u64().unwrap_or(60_000);

    let st = state()?;
    let req = ScanRequest {
        targets,
        ports,
        mode,
        timing,
        service_detect,
        probe_intensity: intensity,
        exclude_cdn,
        adaptive: true,
        idle_mode: false,
        max_hosts,
        // MCP callers historically saw all states — keep that contract.
        emit_closed_filtered: true,
    };
    let reply = orchestrator::start_scan_no_emit(st.clone(), req).await?;
    let summary = wait_for_summary(st, &reply.scan_id, max_wait_ms).await?;
    Ok(serde_json::json!({
        "scan_id": reply.scan_id,
        "total_probes": reply.total_probes,
        "targets_resolved": reply.targets_resolved,
        "ports_count": reply.ports_count,
        "summary": summary,
    }))
}

/// service_detect — assumes port open, runs the probe pipeline.
pub async fn handle_service_detect(params: &serde_json::Value) -> HandlerResult {
    let host = params["host"].as_str().ok_or("Missing 'host'")?;
    let port = params["port"].as_u64().ok_or("Missing 'port'")? as u16;
    let intensity = params["intensity"].as_u64().unwrap_or(7) as u8;
    let timeout_ms = params["timeout_ms"].as_u64().unwrap_or(2000);

    // Try plain TCP first
    let target = format!("{}:{}", host, port);
    let stream = match timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&target)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Ok(serde_json::json!({
                "host": host, "port": port,
                "state": "closed",
                "error": e.to_string(),
            }))
        }
        Err(_) => {
            return Ok(serde_json::json!({
                "host": host, "port": port,
                "state": "filtered",
                "error": "connect timeout",
            }))
        }
    };
    let service = crate::portscan::probes::detect_service(stream, port, intensity).await;
    // Always also try TLS probe for HTTPS-ish ports.
    let service = if service.is_none() && matches!(port, 443 | 8443 | 9443 | 465 | 993 | 995 | 636 | 5671) {
        crate::portscan::probes::probe_tls(host, port, None).await
    } else {
        service
    };
    Ok(serde_json::json!({
        "host": host,
        "port": port,
        "state": "open",
        "service": service,
    }))
}

/// banner_grab — raw bytes only, no probe synthesis.
pub async fn handle_banner_grab(params: &serde_json::Value) -> HandlerResult {
    let host = params["host"].as_str().ok_or("Missing 'host'")?;
    let port = params["port"].as_u64().ok_or("Missing 'port'")? as u16;
    let max_bytes = params["max_bytes"].as_u64().unwrap_or(256).min(4096) as usize;
    let timeout_ms = params["timeout_ms"].as_u64().unwrap_or(800);
    let prefer_send = params["prefer_send"].as_str();

    let target = format!("{}:{}", host, port);
    let mut stream = match timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&target)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(format!("connect: {}", e)),
        Err(_) => return Err("connect timeout".into()),
    };
    if let Some(send_str) = prefer_send {
        let _ = stream.write_all(send_str.as_bytes()).await;
    }
    let mut buf = vec![0u8; max_bytes];
    let n = match timeout(Duration::from_millis(timeout_ms), stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => 0,
    };
    let head = &buf[..n];
    let is_text = head.iter().all(|&b| b == 0 || b == 9 || b == 10 || b == 13 || (32..=126).contains(&b));
    let banner_str = if is_text { Some(String::from_utf8_lossy(head).to_string()) } else { None };
    Ok(serde_json::json!({
        "host": host,
        "port": port,
        "banner": banner_str,
        "is_text": is_text,
        "bytes": n,
        "hex": hex_encode(head),
    }))
}

/// port_scan_results — paginated drill-down for a scan_id.
pub async fn handle_port_scan_results(params: &serde_json::Value) -> HandlerResult {
    let scan_id = params["scan_id"].as_str().ok_or("Missing 'scan_id'")?.to_string();
    let offset = params["offset"].as_u64().unwrap_or(0) as usize;
    let limit = params["limit"].as_u64().unwrap_or(50).min(500) as usize;
    let open_only = params["open_only"].as_bool().unwrap_or(true);

    let st = state()?;
    let results = orchestrator::get_results(st.clone(), scan_id.clone(), offset, limit, open_only).await?;
    Ok(serde_json::json!({
        "scan_id": scan_id,
        "offset": offset,
        "limit": limit,
        "count": results.len(),
        "results": results,
    }))
}

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for &byte in b {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}
