use crate::reporting::{self, ReportConfig, ReportFinding};
use crate::scanner::{self, ScanConfig, ScanLive, ScanResult};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

pub type ScannerState = Arc<Mutex<ScannerManager>>;

// v0.3.16: global accessor mirroring intruder.rs so non-State callers
// (e.g. get_memory_stats) can read the live scan count without plumbing
// Tauri State<'_, ScannerState> through every consumer.
static GLOBAL_SCANNER_STATE: std::sync::OnceLock<ScannerState> = std::sync::OnceLock::new();

pub fn create_scanner_state() -> ScannerState {
    let s: ScannerState = Arc::new(Mutex::new(ScannerManager::new()));
    let _ = GLOBAL_SCANNER_STATE.set(s.clone());
    s
}

pub fn scanner_state() -> Option<ScannerState> {
    GLOBAL_SCANNER_STATE.get().cloned()
}

pub struct ScannerManager {
    pub scans: HashMap<String, ScanLive>,
}

impl ScannerManager {
    pub fn new() -> Self {
        Self { scans: HashMap::new() }
    }
}

#[derive(Debug, Serialize)]
pub struct ScanProgress {
    pub scan_id: String,
    pub status: String,
    pub progress: f64,
    pub total_requests: u32,
    pub finding_count: usize,
    pub elapsed_ms: u64,
}

// Add https:// if missing so reqwest doesn't choke on bare hostnames.
fn normalize_target(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Target URL is empty".into());
    }
    let with_scheme = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("https://{}", trimmed)
    };
    url::Url::parse(&with_scheme).map_err(|e| format!("Invalid target URL '{}': {}", raw, e))?;
    Ok(with_scheme)
}

#[tauri::command]
pub async fn scanner_start_active(
    app: tauri::AppHandle,
    state: tauri::State<'_, ScannerState>,
    proxy_app_state: tauri::State<'_, crate::proxy_commands::ProxyAppState>,
    target: String,
    config: Option<ScanConfig>,
) -> Result<String, String> {
    let target = normalize_target(&target)?;
    let mut cfg = config.unwrap_or_default();
    cfg.apply_preset();
    let scan_id = uuid::Uuid::new_v4().to_string();
    let started_at = iso_now();
    let proxy_state_for_task = Some(proxy_app_state.proxy_state.clone());

    let initial = ScanResult {
        scan_id: scan_id.clone(),
        target: target.clone(),
        scan_type: "active".into(),
        status: "starting".into(),
        progress: 0.0,
        total_requests: 0,
        findings: vec![],
        started_at: started_at.clone(),
        completed_at: None,
        duration_ms: 0,
        crawled_urls: vec![],
        injection_points: vec![],
        request_log: vec![],
        technologies: vec![],
    };

    let live = ScanLive {
        result: Arc::new(std::sync::Mutex::new(initial)),
        cancel: Arc::new(AtomicBool::new(false)),
    };

    {
        let mut mgr = state.lock().await;
        mgr.scans.insert(scan_id.clone(), live.clone());
    }

    let live_for_task = live.clone();
    let target_for_task = target.clone();
    tokio::spawn(async move {
        let start = std::time::Instant::now();
        let outcome =
            scanner::run_active_scan(&target_for_task, &cfg, live_for_task.clone(), proxy_state_for_task)
                .await;

        if let Ok(mut s) = live_for_task.result.lock() {
            s.duration_ms = start.elapsed().as_millis() as u64;
            s.completed_at = Some(iso_now());
            s.progress = 100.0;
            s.status = match outcome {
                Ok(()) => {
                    if live_for_task.cancel.load(Ordering::SeqCst) {
                        "cancelled".into()
                    } else {
                        "completed".into()
                    }
                }
                Err(e) => format!("error: {}", e),
            };
        }
    });

    // v0.3.10: real-time finding emitter. Findings.tsx has been listening
    // for `scanner-finding` since v0.3.0 but the Rust side never emitted —
    // the panel only refreshed via polling. This task watches the scan's
    // findings vector and emits each new finding as it appears. Sidecar
    // model: zero overhead in the hot loop, ~250ms latency from push to
    // UI receipt.
    let app_emit = app.clone();
    let live_emit = live.clone();
    let scan_id_emit = scan_id.clone();
    tokio::spawn(async move {
        use tauri::Emitter;
        let mut last_emitted = 0usize;
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            let (status, new_findings) = {
                let Ok(snap) = live_emit.result.lock() else { break };
                let new_findings: Vec<scanner::ScanFinding> =
                    snap.findings.iter().skip(last_emitted).cloned().collect();
                (snap.status.clone(), new_findings)
            };
            for finding in new_findings {
                last_emitted += 1;
                let _ = app_emit.emit(
                    "scanner-finding",
                    serde_json::json!({
                        "scan_id": scan_id_emit,
                        "finding": finding,
                    }),
                );
            }
            // Stop the watcher when the scan is no longer running. We do
            // one more pass first (above) so the final batch lands.
            if status == "completed" || status == "cancelled" || status.starts_with("error:") {
                break;
            }
        }
    });

    Ok(scan_id)
}

#[tauri::command]
pub async fn scanner_stop(state: tauri::State<'_, ScannerState>, scan_id: String) -> Result<bool, String> {
    let mgr = state.lock().await;
    let live = mgr.scans.get(&scan_id).ok_or("Scan not found")?;
    live.cancel.store(true, Ordering::SeqCst);
    Ok(true)
}

#[tauri::command]
pub async fn scanner_status(
    state: tauri::State<'_, ScannerState>,
    scan_id: String,
) -> Result<ScanProgress, String> {
    let mgr = state.lock().await;
    let live = mgr.scans.get(&scan_id).ok_or("Scan not found")?;
    let snap = live.result.lock().map_err(|_| "scan state poisoned".to_string())?.clone();
    let elapsed_ms = if snap.duration_ms > 0 {
        snap.duration_ms
    } else {
        chrono::Utc::now()
            .signed_duration_since(
                chrono::DateTime::parse_from_rfc3339(&snap.started_at)
                    .map(|d| d.with_timezone(&chrono::Utc))
                    .unwrap_or_else(|_| chrono::Utc::now()),
            )
            .num_milliseconds()
            .max(0) as u64
    };
    Ok(ScanProgress {
        scan_id,
        status: snap.status,
        progress: snap.progress,
        total_requests: snap.total_requests,
        finding_count: snap.findings.len(),
        elapsed_ms,
    })
}

#[tauri::command]
pub async fn scanner_get_findings(
    state: tauri::State<'_, ScannerState>,
    scan_id: String,
    severity_filter: Option<String>,
) -> Result<serde_json::Value, String> {
    let mgr = state.lock().await;
    let live = mgr.scans.get(&scan_id).ok_or("Scan not found")?;
    let snap = live.result.lock().map_err(|_| "scan state poisoned".to_string())?.clone();

    let findings: Vec<&scanner::ScanFinding> = snap
        .findings
        .iter()
        .filter(|f| if let Some(ref sev) = severity_filter { f.severity == *sev } else { true })
        .collect();

    Ok(serde_json::json!({
        "scan_id": scan_id,
        "target": snap.target,
        "status": snap.status,
        "total_requests": snap.total_requests,
        "duration_ms": snap.duration_ms,
        "technologies": snap.technologies,
        "crawled_urls": snap.crawled_urls.len(),
        "injection_points": snap.injection_points.len(),
        "findings": findings,
    }))
}

#[tauri::command]
pub async fn scanner_get_result(
    state: tauri::State<'_, ScannerState>,
    scan_id: String,
) -> Result<ScanResult, String> {
    let mgr = state.lock().await;
    let live = mgr.scans.get(&scan_id).ok_or("Scan not found")?;
    let snap = live.result.lock().map_err(|_| "scan state poisoned".to_string())?.clone();
    Ok(snap)
}

#[tauri::command]
pub async fn scanner_list_scans(
    state: tauri::State<'_, ScannerState>,
) -> Result<Vec<serde_json::Value>, String> {
    let mgr = state.lock().await;
    let mut scans: Vec<serde_json::Value> = mgr
        .scans
        .iter()
        .filter_map(|(id, live)| {
            let s = live.result.lock().ok()?.clone();
            Some(serde_json::json!({
                "scan_id": id,
                "target": s.target,
                "status": s.status,
                "progress": s.progress,
                "total_requests": s.total_requests,
                "finding_count": s.findings.len(),
                "duration_ms": s.duration_ms,
                "started_at": s.started_at,
                "completed_at": s.completed_at,
                "technologies": s.technologies,
            }))
        })
        .collect();
    scans.sort_by(|a, b| b["started_at"].as_str().cmp(&a["started_at"].as_str()));
    Ok(scans)
}

#[tauri::command]
pub async fn scanner_delete_scan(
    state: tauri::State<'_, ScannerState>,
    scan_id: String,
) -> Result<String, String> {
    let mut mgr = state.lock().await;
    if let Some(live) = mgr.scans.remove(&scan_id) {
        // make sure any still-running task notices it's been removed
        live.cancel.store(true, Ordering::SeqCst);
    }
    Ok("Scan deleted".into())
}

#[tauri::command]
pub async fn scanner_generate_report(
    state: tauri::State<'_, ScannerState>,
    scan_id: String,
    format: Option<String>,
    title: Option<String>,
) -> Result<String, String> {
    let mgr = state.lock().await;
    let live = mgr.scans.get(&scan_id).ok_or("Scan not found")?;
    let result = live.result.lock().map_err(|_| "scan state poisoned".to_string())?.clone();

    let report_findings: Vec<ReportFinding> = result
        .findings
        .iter()
        .map(|f| ReportFinding {
            name: f.name.clone(),
            severity: f.severity.clone(),
            confidence: f.confidence.clone(),
            url: f.url.clone(),
            parameter: f.parameter.clone(),
            detail: f.detail.clone(),
            evidence: f.evidence.clone(),
            remediation: Some(f.remediation.clone()),
        })
        .collect();

    let report_title = title.unwrap_or_else(|| format!("Security Assessment — {}", result.target));
    let fmt = format.unwrap_or_else(|| "html".into());

    let config = ReportConfig {
        format: fmt.clone(),
        title: report_title.clone(),
        include_evidence: true,
        include_remediation: true,
        severity_filter: None,
        confidence_filter: None,
    };

    match fmt.as_str() {
        "json" => Ok(reporting::generate_json_report(&report_title, &report_findings)),
        _ => Ok(reporting::generate_html_report(&report_title, &report_findings, &config)),
    }
}

pub fn iso_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
