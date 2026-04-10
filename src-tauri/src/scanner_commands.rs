use crate::scanner::{self, ScanConfig, ScanResult};
use crate::reporting::{self, ReportConfig, ReportFinding};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

// ── Scanner App State ───────────────────────────────────────────────────────

pub type ScannerState = Arc<Mutex<ScannerManager>>;

pub fn create_scanner_state() -> ScannerState {
    Arc::new(Mutex::new(ScannerManager::new()))
}

pub struct ScannerManager {
    pub scans: HashMap<String, ScanResult>,
    pub running: HashMap<String, bool>,  // scan_id → is_running
}

impl ScannerManager {
    pub fn new() -> Self {
        Self {
            scans: HashMap::new(),
            running: HashMap::new(),
        }
    }
}

// ── Tauri Commands ──────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ScanProgress {
    pub scan_id: String,
    pub status: String,
    pub progress: f64,
    pub total_requests: u32,
    pub finding_count: usize,
    pub elapsed_ms: u64,
}

#[tauri::command]
pub async fn scanner_start_active(
    state: tauri::State<'_, ScannerState>,
    target: String,
    config: Option<ScanConfig>,
) -> Result<String, String> {
    let cfg = config.unwrap_or_default();
    let scan_id = uuid::Uuid::new_v4().to_string();
    let sid = scan_id.clone();

    // Mark as running
    {
        let mut mgr = state.lock().await;
        mgr.running.insert(sid.clone(), true);
    }

    let state_clone = state.inner().clone();

    // Spawn scan in background
    tokio::spawn(async move {
        match scanner::run_active_scan(&target, &cfg).await {
            Ok(result) => {
                let mut mgr = state_clone.lock().await;
                mgr.running.insert(sid.clone(), false);
                mgr.scans.insert(sid, result);
            }
            Err(e) => {
                let mut mgr = state_clone.lock().await;
                mgr.running.insert(sid.clone(), false);
                // Store a failed result
                mgr.scans.insert(sid.clone(), ScanResult {
                    scan_id: sid,
                    target,
                    scan_type: "failed".into(),
                    status: format!("error: {}", e),
                    progress: 100.0,
                    total_requests: 0,
                    findings: vec![],
                    started_at: chrono_now(),
                    completed_at: Some(chrono_now()),
                    duration_ms: 0,
                    crawled_urls: vec![],
                    injection_points: vec![],
                    request_log: vec![],
                    technologies: vec![],
                });
            }
        }
    });

    Ok(scan_id)
}

#[tauri::command]
pub async fn scanner_status(
    state: tauri::State<'_, ScannerState>,
    scan_id: String,
) -> Result<ScanProgress, String> {
    let mgr = state.lock().await;
    let is_running = mgr.running.get(&scan_id).copied().unwrap_or(false);

    if let Some(result) = mgr.scans.get(&scan_id) {
        Ok(ScanProgress {
            scan_id: scan_id.clone(),
            status: if is_running { "running".into() } else { result.status.clone() },
            progress: result.progress,
            total_requests: result.total_requests,
            finding_count: result.findings.len(),
            elapsed_ms: result.duration_ms,
        })
    } else if is_running {
        Ok(ScanProgress {
            scan_id,
            status: "running".into(),
            progress: 0.0,
            total_requests: 0,
            finding_count: 0,
            elapsed_ms: 0,
        })
    } else {
        Err("Scan not found".into())
    }
}

#[tauri::command]
pub async fn scanner_get_findings(
    state: tauri::State<'_, ScannerState>,
    scan_id: String,
    severity_filter: Option<String>,
) -> Result<serde_json::Value, String> {
    let mgr = state.lock().await;
    let result = mgr.scans.get(&scan_id).ok_or("Scan not found")?;

    let findings: Vec<&scanner::ScanFinding> = result.findings.iter()
        .filter(|f| {
            if let Some(ref sev) = severity_filter {
                f.severity == *sev
            } else {
                true
            }
        })
        .collect();

    Ok(serde_json::json!({
        "scan_id": scan_id,
        "target": result.target,
        "status": result.status,
        "total_requests": result.total_requests,
        "duration_ms": result.duration_ms,
        "technologies": result.technologies,
        "crawled_urls": result.crawled_urls.len(),
        "injection_points": result.injection_points.len(),
        "findings": findings,
    }))
}

#[tauri::command]
pub async fn scanner_get_result(
    state: tauri::State<'_, ScannerState>,
    scan_id: String,
) -> Result<ScanResult, String> {
    let mgr = state.lock().await;
    mgr.scans.get(&scan_id).cloned().ok_or("Scan not found".into())
}

#[tauri::command]
pub async fn scanner_list_scans(
    state: tauri::State<'_, ScannerState>,
) -> Result<Vec<serde_json::Value>, String> {
    let mgr = state.lock().await;
    let mut scans: Vec<serde_json::Value> = mgr.scans.iter().map(|(id, r)| {
        let is_running = mgr.running.get(id).copied().unwrap_or(false);
        serde_json::json!({
            "scan_id": id,
            "target": r.target,
            "status": if is_running { "running" } else { &r.status },
            "progress": r.progress,
            "total_requests": r.total_requests,
            "finding_count": r.findings.len(),
            "duration_ms": r.duration_ms,
            "started_at": r.started_at,
            "completed_at": r.completed_at,
            "technologies": r.technologies,
        })
    }).collect();
    scans.sort_by(|a, b| b["started_at"].as_str().cmp(&a["started_at"].as_str()));
    Ok(scans)
}

#[tauri::command]
pub async fn scanner_delete_scan(
    state: tauri::State<'_, ScannerState>,
    scan_id: String,
) -> Result<String, String> {
    let mut mgr = state.lock().await;
    mgr.scans.remove(&scan_id);
    mgr.running.remove(&scan_id);
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
    let result = mgr.scans.get(&scan_id).ok_or("Scan not found")?;

    let report_findings: Vec<ReportFinding> = result.findings.iter().map(|f| {
        ReportFinding {
            name: f.name.clone(),
            severity: f.severity.clone(),
            confidence: f.confidence.clone(),
            url: f.url.clone(),
            parameter: f.parameter.clone(),
            detail: f.detail.clone(),
            evidence: f.evidence.clone(),
            remediation: Some(f.remediation.clone()),
        }
    }).collect();

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

fn chrono_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}Z", now.as_secs())
}
