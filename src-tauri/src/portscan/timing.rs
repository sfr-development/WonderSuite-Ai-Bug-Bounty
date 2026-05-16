// Adaptive concurrency controller based on Little's Law:
//   in_flight = throughput × latency
// We measure RTT (EWMA p50) and target a per-target throughput. Permit count
// floats with the observation. Floor 64, ceiling 65535.

use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;

use super::types::TimingTemplate;

pub struct RttStats {
    sum_ns: AtomicU32,
    count: AtomicU32,
    p50_ms: AtomicU32,
    sample: Mutex<Vec<u32>>,
}

impl Default for RttStats {
    fn default() -> Self {
        Self {
            sum_ns: AtomicU32::new(0),
            count: AtomicU32::new(0),
            p50_ms: AtomicU32::new(100),
            sample: Mutex::new(Vec::with_capacity(256)),
        }
    }
}

impl RttStats {
    pub fn observe(&self, ms: u32) {
        self.sum_ns.fetch_add(ms.saturating_mul(1_000_000), Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        let mut buf = match self.sample.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if buf.len() < 256 {
            buf.push(ms);
        } else {
            let i = (self.count.load(Ordering::Relaxed) as usize) % 256;
            buf[i] = ms;
        }
        // Cheap p50 estimate: median of the rolling 256 sample.
        if buf.len() >= 8 {
            let mut s = buf.clone();
            s.sort_unstable();
            self.p50_ms.store(s[s.len() / 2], Ordering::Relaxed);
        }
    }

    pub fn p50_ms(&self) -> u32 {
        self.p50_ms.load(Ordering::Relaxed)
    }
}

pub struct AdaptiveTiming {
    pub template: TimingTemplate,
    pub adaptive: bool,
    pub idle: bool,
    pub timeout_ms: u64,
    pub max_retries: u8,
    pub target_pps: u32,
    pub rtt: Arc<RttStats>,
    pub permits: Arc<Semaphore>,
    pub current_permits: AtomicUsize,
}

impl AdaptiveTiming {
    pub fn new(template: TimingTemplate, adaptive: bool, idle: bool) -> Self {
        let (initial, timeout_ms, max_retries, pps) = template.defaults();
        let permits = Arc::new(Semaphore::new(initial));
        Self {
            template,
            adaptive,
            idle,
            timeout_ms,
            max_retries,
            target_pps: pps,
            rtt: Arc::new(RttStats::default()),
            permits,
            current_permits: AtomicUsize::new(initial),
        }
    }

    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }

    /// Spawn the permit controller. Adjusts permits every 2 seconds based on
    /// observed RTT × target_pps (Little's Law). Idle-mode caps at 100 pps.
    pub fn spawn_controller(self: Arc<Self>, cancel: Arc<tokio::sync::Notify>) {
        if !self.adaptive {
            return;
        }
        let me = self.clone();
        tokio::spawn(async move {
            let target_pps = if me.idle { 100 } else { me.target_pps } as f64;
            loop {
                tokio::select! {
                    _ = cancel.notified() => break,
                    _ = tokio::time::sleep(Duration::from_secs(2)) => {}
                }
                let rtt_s = (me.rtt.p50_ms() as f64 / 1000.0).max(0.001);
                let want = (target_pps * rtt_s).round() as i64;
                let want = want.clamp(64, 65535) as usize;
                let cur = me.current_permits.load(Ordering::Relaxed) as i64;
                let delta = want as i64 - cur;
                // Dead-band: ignore tiny adjustments
                if delta.abs() < (cur / 5).max(8) {
                    continue;
                }
                if delta > 0 {
                    me.permits.add_permits(delta as usize);
                    me.current_permits.store(want, Ordering::Relaxed);
                } else if delta < 0 {
                    // Shrinking: take permits without releasing
                    let take = (-delta) as usize;
                    for _ in 0..take {
                        if let Ok(p) = me.permits.clone().try_acquire_owned() {
                            p.forget();
                        } else {
                            break;
                        }
                    }
                    me.current_permits.store(want, Ordering::Relaxed);
                }
            }
        });
    }
}
