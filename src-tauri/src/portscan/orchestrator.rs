use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use serde::Serialize;
use tauri::{AppHandle, Emitter};
use tokio::sync::{mpsc, Notify, RwLock};

use super::engine::connect::run_connect_scan;
use super::engine::syn::{check_capability as syn_check_capability, run_syn_scan};
use super::engine::udp::run_udp_scan;
use super::probes::probe_tls;
use super::targets::{expand_all, parse_ports};
use super::timing::AdaptiveTiming;
use super::types::{ScanMode, ScanProgress, ScanRequest, ScanResult, ScanSummary};

pub type PortScanState = Arc<PortScanManager>;

pub struct ActiveScan {
    pub id: String,
    pub cancel: Arc<Notify>,
    pub started: Instant,
    pub total_probes: usize,
    pub completed: Arc<AtomicUsize>,
    pub results: Arc<RwLock<Vec<ScanResult>>>,
    pub status: Arc<RwLock<String>>,
    pub timing: Arc<AdaptiveTiming>,
}

pub struct PortScanManager {
    pub scans: RwLock<HashMap<String, Arc<ActiveScan>>>,
}

pub fn create_state() -> PortScanState {
    Arc::new(PortScanManager { scans: RwLock::new(HashMap::new()) })
}

#[derive(Debug, Serialize)]
pub struct ScanStartReply {
    pub scan_id: String,
    pub total_probes: usize,
    pub targets_resolved: usize,
    pub ports_count: usize,
}

pub async fn start_scan_no_emit(state: PortScanState, req: ScanRequest) -> Result<ScanStartReply, String> {
    start_scan_inner(None, state, req).await
}

pub async fn start_scan(
    app: AppHandle,
    state: PortScanState,
    req: ScanRequest,
) -> Result<ScanStartReply, String> {
    start_scan_inner(Some(app), state, req).await
}

async fn start_scan_inner(
    app: Option<AppHandle>,
    state: PortScanState,
    req: ScanRequest,
) -> Result<ScanStartReply, String> {
    let targets = expand_all(&req.targets, req.max_hosts).await?;
    if targets.is_empty() {
        return Err("No targets resolved".into());
    }
    let ports = parse_ports(&req.ports)?;
    if ports.is_empty() {
        return Err("No ports parsed".into());
    }

    let total_probes = targets.len() * ports.len();
    let scan_id = format!("scan-{:x}", rand::random::<u64>());
    let cancel = Arc::new(Notify::new());
    let completed = Arc::new(AtomicUsize::new(0));
    let results = Arc::new(RwLock::new(Vec::<ScanResult>::new()));
    let status = Arc::new(RwLock::new("running".to_string()));
    let timing = Arc::new(AdaptiveTiming::new(req.timing, req.adaptive, req.idle_mode));
    timing.clone().spawn_controller(cancel.clone());

    let active = Arc::new(ActiveScan {
        id: scan_id.clone(),
        cancel: cancel.clone(),
        started: Instant::now(),
        total_probes,
        completed: completed.clone(),
        results: results.clone(),
        status: status.clone(),
        timing: timing.clone(),
    });
    state.scans.write().await.insert(scan_id.clone(), active.clone());

    // Channel for engine → orchestrator results
    let (tx, mut rx) = mpsc::channel::<ScanResult>(1024);

    let progress_tick: Arc<dyn Fn() + Send + Sync> = {
        let counter = completed.clone();
        Arc::new(move || {
            counter.fetch_add(1, Ordering::Relaxed);
        })
    };

    // Engine task
    let engine_targets = targets.clone();
    let engine_ports = ports.clone();
    let engine_timing = timing.clone();
    let engine_cancel = cancel.clone();
    let engine_intensity = req.probe_intensity;
    let engine_service_detect = req.service_detect;
    let engine_mode = req.mode;
    let app_for_engine = app.clone();
    let scan_id_for_engine = scan_id.clone();
    tokio::spawn(async move {
        match engine_mode {
            ScanMode::Udp => {
                run_udp_scan(
                    engine_targets,
                    engine_ports,
                    engine_timing,
                    engine_service_detect,
                    engine_cancel,
                    tx,
                    progress_tick,
                )
                .await;
            }
            ScanMode::Syn => {
                match syn_check_capability() {
                    Ok(_) => {
                        run_syn_scan(
                            engine_targets,
                            engine_ports,
                            engine_timing,
                            engine_cancel,
                            tx,
                            progress_tick,
                        )
                        .await;
                    }
                    Err(msg) => {
                        // Capability missing. Emit a clear event to the UI
                        // before we silently exit — otherwise the progress
                        // task ticks 0/total and the user sees a confusing
                        // "100% / 0 open" result with no explanation.
                        if let Some(app) = &app_for_engine {
                            let _ = app.emit(
                                "portscan:error",
                                (scan_id_for_engine.clone(), msg.clone()),
                            );
                        }
                        eprintln!("[syn] capability missing: {}", msg);
                        // Drop tx so the fan-out task sees end-of-stream and
                        // emits the final done event.
                        drop(tx);
                    }
                }
            }
            ScanMode::Connect => {
                run_connect_scan(
                    engine_targets,
                    engine_ports,
                    engine_timing,
                    engine_service_detect,
                    engine_intensity,
                    engine_cancel,
                    tx,
                    progress_tick,
                )
                .await;
            }
        }
    });

    // Result fan-out task: collects from engine, stores in scan state, emits to UI (if AppHandle).
    let scan_id_inner = scan_id.clone();
    let app_inner = app.clone();
    let results_inner = results.clone();
    let active_for_followup = active.clone();
    tokio::spawn(async move {
        while let Some(mut r) = rx.recv().await {
            // For 443/8443, run a TLS probe if we don't already have one
            if matches!(r.port, 443 | 8443 | 9443 | 465 | 993 | 995 | 636 | 5671)
                && r.service.as_ref().map(|s| !s.tls).unwrap_or(true)
            {
                if let Some(tls_svc) = probe_tls(&r.host, r.port, None).await {
                    r.service = Some(tls_svc);
                }
            }
            results_inner.write().await.push(r.clone());
            if let Some(app) = &app_inner {
                let _ = app.emit("portscan:result", (scan_id_inner.clone(), r));
            }
        }
        // Engine drained → finalize
        *active_for_followup.status.write().await = "done".to_string();
        let elapsed = active_for_followup.started.elapsed().as_millis() as u64;
        if let Some(app) = &app_inner {
            let _ = app.emit("portscan:done", (scan_id_inner.clone(), elapsed));
        }
    });

    // Progress emitter (every 500ms while running) — only spawned if we have an AppHandle.
    if let Some(app) = app.clone() {
        let active_for_progress = active.clone();
        let scan_id_progress = scan_id.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                let st = active_for_progress.status.read().await.clone();
                if st != "running" {
                    break;
                }
                let prog = build_progress(&active_for_progress).await;
                let _ = app.emit("portscan:progress", (scan_id_progress.clone(), prog));
            }
        });
    }

    Ok(ScanStartReply { scan_id, total_probes, targets_resolved: targets.len(), ports_count: ports.len() })
}

pub async fn build_progress(scan: &ActiveScan) -> ScanProgress {
    let completed = scan.completed.load(Ordering::Relaxed);
    let elapsed = scan.started.elapsed().as_millis() as u64;
    let elapsed_s = (elapsed as f64 / 1000.0).max(0.001);
    let pps = completed as f64 / elapsed_s;
    let results = scan.results.read().await;
    let open = results.iter().filter(|r| matches!(r.state, super::types::PortState::Open)).count();
    let filtered = results.iter().filter(|r| matches!(r.state, super::types::PortState::Filtered)).count();
    ScanProgress {
        scan_id: scan.id.clone(),
        status: scan.status.read().await.clone(),
        total_probes: scan.total_probes,
        completed,
        open_count: open,
        filtered_count: filtered,
        pps,
        rtt_p50_ms: scan.timing.rtt.p50_ms(),
        permits: scan.timing.current_permits.load(Ordering::Relaxed),
        elapsed_ms: elapsed,
    }
}

pub async fn stop_scan(state: PortScanState, scan_id: String) -> Result<(), String> {
    if let Some(scan) = state.scans.read().await.get(&scan_id).cloned() {
        // notify_waiters needs ≥1 task listening; we ALSO close the semaphore
        // so any in-flight acquire_owned() returns Err immediately and the
        // engine drains rather than blocking on permits. This is the trick
        // that makes Stop feel instant even at high concurrency.
        scan.cancel.notify_waiters();
        scan.timing.permits.close();
        *scan.status.write().await = "stopped".to_string();
        Ok(())
    } else {
        Err(format!("Unknown scan_id '{}'", scan_id))
    }
}

pub async fn status_scan(state: PortScanState, scan_id: String) -> Result<ScanProgress, String> {
    let scan = {
        let scans = state.scans.read().await;
        scans.get(&scan_id).cloned().ok_or_else(|| format!("Unknown scan_id '{}'", scan_id))?
    };
    Ok(build_progress(&scan).await)
}

pub async fn list_scans(state: PortScanState) -> Result<Vec<ScanProgress>, String> {
    let scans = state.scans.read().await;
    let mut out = Vec::new();
    for scan in scans.values() {
        out.push(build_progress(scan).await);
    }
    Ok(out)
}

pub async fn get_results(
    state: PortScanState,
    scan_id: String,
    offset: usize,
    limit: usize,
    open_only: bool,
) -> Result<Vec<ScanResult>, String> {
    let scan = {
        let scans = state.scans.read().await;
        scans.get(&scan_id).cloned().ok_or_else(|| format!("Unknown scan_id '{}'", scan_id))?
    };
    let results = scan.results.read().await;
    let filtered: Vec<ScanResult> = results
        .iter()
        .filter(|r| !open_only || matches!(r.state, super::types::PortState::Open))
        .skip(offset)
        .take(limit)
        .cloned()
        .collect();
    Ok(filtered)
}

pub async fn summarize(state: PortScanState, scan_id: String) -> Result<ScanSummary, String> {
    let scan = {
        let scans = state.scans.read().await;
        scans.get(&scan_id).cloned().ok_or_else(|| format!("Unknown scan_id '{}'", scan_id))?
    };
    let results_snapshot = scan.results.read().await.clone();
    let status = scan.status.read().await.clone();
    let total_open =
        results_snapshot.iter().filter(|r| matches!(r.state, super::types::PortState::Open)).count();
    let total_filtered =
        results_snapshot.iter().filter(|r| matches!(r.state, super::types::PortState::Filtered)).count();
    let mut by_service = HashMap::<String, usize>::new();
    for r in results_snapshot.iter() {
        if !matches!(r.state, super::types::PortState::Open) {
            continue;
        }
        let name = r.service.as_ref().map(|s| s.name.clone()).unwrap_or_else(|| "tcp-open".into());
        *by_service.entry(name).or_default() += 1;
    }
    let sample: Vec<ScanResult> = results_snapshot
        .iter()
        .filter(|r| matches!(r.state, super::types::PortState::Open))
        .take(50)
        .cloned()
        .collect();
    Ok(ScanSummary {
        scan_id: scan.id.clone(),
        status,
        total_open,
        total_filtered,
        total_probed: scan.completed.load(Ordering::Relaxed),
        elapsed_ms: scan.started.elapsed().as_millis() as u64,
        by_service,
        sample,
    })
}
