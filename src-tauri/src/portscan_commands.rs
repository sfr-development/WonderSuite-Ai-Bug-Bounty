use serde::Serialize;
use tauri::AppHandle;

use crate::portscan::orchestrator::{self, ScanStartReply};
use crate::portscan::types::{ScanProgress, ScanRequest, ScanResult, ScanSummary};
use crate::portscan::windriver::{self, DriverStatus};
use crate::portscan::PortScanState;

#[derive(Debug, Serialize)]
pub struct CapabilityCheck {
    pub mode: String,
    pub available: bool,
    pub missing: Vec<String>,
    pub note: Option<String>,
}

#[tauri::command]
pub async fn portscan_start(
    app: AppHandle,
    state: tauri::State<'_, PortScanState>,
    req: ScanRequest,
) -> Result<ScanStartReply, String> {
    orchestrator::start_scan(app, state.inner().clone(), req).await
}

#[tauri::command]
pub async fn portscan_stop(state: tauri::State<'_, PortScanState>, scan_id: String) -> Result<(), String> {
    orchestrator::stop_scan(state.inner().clone(), scan_id).await
}

#[tauri::command]
pub async fn portscan_status(
    state: tauri::State<'_, PortScanState>,
    scan_id: String,
) -> Result<ScanProgress, String> {
    orchestrator::status_scan(state.inner().clone(), scan_id).await
}

#[tauri::command]
pub async fn portscan_list(state: tauri::State<'_, PortScanState>) -> Result<Vec<ScanProgress>, String> {
    orchestrator::list_scans(state.inner().clone()).await
}

#[tauri::command]
pub async fn portscan_results(
    state: tauri::State<'_, PortScanState>,
    scan_id: String,
    offset: Option<usize>,
    limit: Option<usize>,
    open_only: Option<bool>,
) -> Result<Vec<ScanResult>, String> {
    orchestrator::get_results(
        state.inner().clone(),
        scan_id,
        offset.unwrap_or(0),
        limit.unwrap_or(500),
        open_only.unwrap_or(false),
    )
    .await
}

#[tauri::command]
pub async fn portscan_summary(
    state: tauri::State<'_, PortScanState>,
    scan_id: String,
) -> Result<ScanSummary, String> {
    orchestrator::summarize(state.inner().clone(), scan_id).await
}

#[tauri::command]
pub async fn portscan_export(
    state: tauri::State<'_, PortScanState>,
    scan_id: String,
    format: String,
) -> Result<String, String> {
    let scan = {
        let scans = state.scans.read().await;
        scans.get(&scan_id).cloned().ok_or_else(|| format!("Unknown scan_id '{}'", scan_id))?
    };
    let results = scan.results.read().await.clone();
    let started_unix = chrono::Utc::now().timestamp() - scan.started.elapsed().as_secs() as i64;
    Ok(match format.as_str() {
        "jsonl" => crate::portscan::output::to_jsonl(&results),
        "csv" => crate::portscan::output::to_csv(&results),
        "xml" | "nmap" | "nmap-xml" => crate::portscan::output::to_nmap_xml(&results, started_unix),
        "gnmap" => crate::portscan::output::to_gnmap(&results),
        "plain" | "txt" => crate::portscan::output::to_plain(&results),
        other => return Err(format!("Unknown format '{}'", other)),
    })
}

#[tauri::command]
pub async fn portscan_driver_status() -> Result<DriverStatus, String> {
    Ok(windriver::detect_status())
}

#[tauri::command]
pub async fn portscan_driver_install(app: tauri::AppHandle) -> Result<DriverStatus, String> {
    windriver::install(app).await
}

#[tauri::command]
pub async fn portscan_capability_check(mode: String) -> Result<CapabilityCheck, String> {
    let m = mode.as_str();
    Ok(match m {
        "connect" => CapabilityCheck {
            mode: "connect".into(),
            available: true,
            missing: vec![],
            note: None,
        },
        "syn" => match crate::portscan::engine::syn::check_capability() {
            Ok(_) => CapabilityCheck {
                mode: "syn".into(),
                available: true,
                missing: vec![],
                note: Some(
                    "Raw SYN packet engine ready. Stateless SipHash sequence-cookie matching, IPv4 only in v0.3.7."
                        .into(),
                ),
            },
            Err(msg) => CapabilityCheck {
                mode: "syn".into(),
                available: false,
                missing: vec![
                    #[cfg(target_os = "linux")]
                    "cap-net-raw".to_string(),
                    #[cfg(target_os = "macos")]
                    "root".to_string(),
                    #[cfg(target_os = "windows")]
                    "npcap".to_string(),
                ],
                note: Some(format!("{}. Falling back to TCP connect if you proceed.", msg)),
            },
        },
        "udp" => CapabilityCheck {
            mode: "udp".into(),
            available: true,
            missing: vec![],
            note: Some(
                "UDP scan runs without elevation but cannot distinguish closed from open|filtered without raw ICMP (v0.3.8). Open ports detected by protocol-specific replies (DNS, NTP, SNMP, SSDP, mDNS, IPMI, IKE, RIP, NetBIOS, OpenVPN, SIP, TFTP, QUIC)."
                    .into(),
            ),
        },
        other => {
            return Err(format!("Unknown scan mode '{}'", other));
        }
    })
}
