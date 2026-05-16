// TCP connect engine — Tokio-based, semaphore-bounded, adaptive.
// Streams results back via tokio::mpsc so the orchestrator can fan out to
// the UI live and to output writers.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Notify};
use tokio::time::timeout;

use crate::portscan::probes::detect_service;
use crate::portscan::timing::AdaptiveTiming;
use crate::portscan::types::{PortState, ScanResult};

/// Iterate the (host, ip, port) product column-major (all hosts × port 1,
/// then port 2, …). Reduces obvious linear-port scan signatures and spreads
/// load across hosts during the early phase.
pub fn iterate_sockets<'a>(
    targets: &'a [(String, IpAddr)],
    ports: &'a [u16],
) -> impl Iterator<Item = (String, IpAddr, u16)> + 'a {
    ports.iter().flat_map(move |&p| targets.iter().map(move |(host, ip)| (host.clone(), *ip, p)))
}

#[allow(clippy::too_many_arguments)]
pub async fn run_connect_scan(
    targets: Vec<(String, IpAddr)>,
    ports: Vec<u16>,
    timing: Arc<AdaptiveTiming>,
    service_detect: bool,
    probe_intensity: u8,
    cancel: Arc<Notify>,
    result_tx: mpsc::Sender<ScanResult>,
    progress_tick: Arc<dyn Fn() + Send + Sync>,
) {
    let total = targets.len() * ports.len();
    let mut handles = Vec::with_capacity(total.min(65536));

    // Cancel flag observed by the iteration loop; flipped by a small task that
    // waits on the Notify. Avoids polling Notified<'_> which isn't Unpin.
    let cancelled = Arc::new(AtomicBool::new(false));
    {
        let flag = cancelled.clone();
        let notify = cancel.clone();
        tokio::spawn(async move {
            notify.notified().await;
            flag.store(true, Ordering::Relaxed);
        });
    }

    'outer: for (host, ip, port) in iterate_sockets(&targets, &ports) {
        if cancelled.load(Ordering::Relaxed) {
            break 'outer;
        }
        // Acquire permit (controller may shrink/grow the pool live).
        let permit = match timing.permits.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break,
        };

        let tx = result_tx.clone();
        let to = timing.timeout();
        let rtt = timing.rtt.clone();
        let tick = progress_tick.clone();
        let host = host.clone();

        let h = tokio::spawn(async move {
            let _p = permit; // dropped on completion → frees a slot
            let addr = SocketAddr::new(ip, port);
            let started = Instant::now();
            let outcome = match timeout(to, TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => {
                    let rtt_ms = started.elapsed().as_millis() as u32;
                    rtt.observe(rtt_ms);
                    let service = if service_detect {
                        detect_service(stream, port, probe_intensity).await
                    } else {
                        None
                    };
                    Some(ScanResult {
                        host: host.clone(),
                        ip,
                        port,
                        proto: "tcp".into(),
                        state: PortState::Open,
                        service,
                        rtt_ms,
                        ts: now_ts(),
                    })
                }
                Ok(Err(e)) => {
                    // Distinguish ConnectionRefused (closed) vs everything else (filtered).
                    let kind = e.kind();
                    let state = match kind {
                        std::io::ErrorKind::ConnectionRefused => PortState::Closed,
                        _ => PortState::Filtered,
                    };
                    // Only emit closed/filtered if intensity > 0; keeps payload sane.
                    if state == PortState::Closed && probe_intensity == 0 {
                        None
                    } else {
                        Some(ScanResult {
                            host: host.clone(),
                            ip,
                            port,
                            proto: "tcp".into(),
                            state,
                            service: None,
                            rtt_ms: started.elapsed().as_millis() as u32,
                            ts: now_ts(),
                        })
                    }
                }
                Err(_) => {
                    // Timeout → filtered
                    Some(ScanResult {
                        host: host.clone(),
                        ip,
                        port,
                        proto: "tcp".into(),
                        state: PortState::Filtered,
                        service: None,
                        rtt_ms: started.elapsed().as_millis() as u32,
                        ts: now_ts(),
                    })
                }
            };
            // We always tick progress, regardless of whether we emit a result.
            tick();
            if let Some(r) = outcome {
                // Send only OPEN by default; closed/filtered get filtered out at the
                // orchestrator level based on user prefs. Right now we forward all
                // non-None results and let the orchestrator decide.
                let _ = tx.send(r).await;
            }
        });
        handles.push(h);
    }

    for h in handles {
        let _ = h.await;
    }
}

fn now_ts() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}
