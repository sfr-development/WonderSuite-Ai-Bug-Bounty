//! Shared adaptive-throttling / rate-limit handling (v0.3.35).
//!
//! Used by the Intruder dispatch loop (and available to the scanner) to slow
//! down automatically when a target starts answering `429 Too Many Requests`
//! or `503 Service Unavailable`, then recover once it calms down.
//!
//! The state machine is intentionally additive (it tracks the current delay in
//! milliseconds directly) rather than multiplier-based: the Intruder's default
//! `throttle_ms` is `0`, and a multiplier model would divide by the base delay.
//! Tracking `current_ms` keeps the math correct even when the base delay is 0 —
//! the first rate-limit bootstraps from a small seed and grows from there.

/// Small seed used to bootstrap the backoff when there is no base throttle and
/// no current delay yet (i.e. the user did not configure a throttle but the
/// target just rate-limited us).
const BOOTSTRAP_MS: u64 = 250;

/// Parse a `Retry-After` header value (RFC 7231 §7.1.3).
///
/// Two accepted forms:
///   * delay-seconds — a non-negative integer, e.g. `"120"`
///   * HTTP-date (IMF-fixdate) — e.g. `"Wed, 21 Oct 2025 07:28:00 GMT"`
///
/// Returns the number of seconds to wait, or `None` if the value cannot be
/// parsed. An HTTP-date in the past yields `Some(0)`.
pub fn parse_retry_after(header_value: &str) -> Option<u64> {
    let trimmed = header_value.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Form 1: delay-seconds.
    if let Ok(secs) = trimmed.parse::<u64>() {
        return Some(secs);
    }

    // Form 2: HTTP-date, e.g. "Wed, 21 Oct 2025 07:28:00 GMT". chrono is already
    // a dependency (no extra crate). We strip the leading weekday before parsing:
    // chrono otherwise rejects dates whose weekday name is inconsistent, and we'd
    // rather honor a slightly-malformed Retry-After than ignore it.
    let date_part = trimmed.split_once(", ").map(|(_, rest)| rest).unwrap_or(trimmed);
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(date_part, "%d %b %Y %H:%M:%S GMT") {
        let target = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(naive, chrono::Utc);
        let now = chrono::Utc::now();
        if target > now {
            return Some((target - now).num_seconds().max(1) as u64);
        }
        return Some(0);
    }

    None
}

/// Adaptive backoff state machine.
///
/// Call [`on_rate_limit`](BackoffState::on_rate_limit) when a response is
/// `429`/`503` and [`on_success`](BackoffState::on_success) otherwise; read the
/// delay to apply with [`current_delay_ms`](BackoffState::current_delay_ms).
#[derive(Debug, Clone)]
pub struct BackoffState {
    /// Floor delay in ms — the current delay never drops below this.
    base_delay_ms: u64,
    /// Hard cap in ms — the current delay never rises above this.
    max_backoff_ms: u64,
    /// The current inter-dispatch delay in ms.
    current_ms: u64,
    /// Consecutive successes since the last rate-limit / decay step.
    success_count: u32,
    /// Successes required before decaying one step toward the base delay.
    decay_threshold: u32,
}

impl BackoffState {
    /// Create a new state. `max_backoff_ms` is clamped up to at least
    /// `base_delay_ms` so the cap can never sit below the floor.
    pub fn new(base_delay_ms: u64, max_backoff_ms: u64) -> Self {
        Self {
            base_delay_ms,
            max_backoff_ms: max_backoff_ms.max(base_delay_ms),
            current_ms: base_delay_ms,
            success_count: 0,
            decay_threshold: 5,
        }
    }

    /// The delay to apply right now, clamped to `[base, max]`.
    pub fn current_delay_ms(&self) -> u64 {
        self.current_ms.clamp(self.base_delay_ms, self.max_backoff_ms)
    }

    /// Record a non-rate-limited response. After `decay_threshold` consecutive
    /// successes the delay decays ~20 % toward the base.
    pub fn on_success(&mut self) {
        self.success_count = self.success_count.saturating_add(1);
        if self.success_count >= self.decay_threshold && self.current_ms > self.base_delay_ms {
            let decayed = (self.current_ms as f64 * 0.8) as u64;
            self.current_ms = decayed.max(self.base_delay_ms);
            self.success_count = 0;
        }
    }

    /// Record a `429`/`503`. Doubles the current delay (bootstrapping from a
    /// seed when there is none), raises it to at least the server-supplied
    /// `Retry-After`, and clamps to the configured cap.
    pub fn on_rate_limit(&mut self, retry_after_secs: Option<u64>) {
        self.success_count = 0;
        let doubled = if self.current_ms == 0 {
            self.base_delay_ms.max(BOOTSTRAP_MS)
        } else {
            self.current_ms.saturating_mul(2)
        };
        let floor = retry_after_secs.map(|s| s.saturating_mul(1000)).unwrap_or(0);
        let cap = self.max_backoff_ms.max(self.base_delay_ms);
        self.current_ms = doubled.max(floor).min(cap);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_retry_after_numeric() {
        assert_eq!(parse_retry_after("120"), Some(120));
        assert_eq!(parse_retry_after("  60 "), Some(60));
        assert_eq!(parse_retry_after("0"), Some(0));
    }

    #[test]
    fn parse_retry_after_invalid() {
        assert_eq!(parse_retry_after("not-a-number"), None);
        assert_eq!(parse_retry_after(""), None);
        assert_eq!(parse_retry_after("   "), None);
    }

    #[test]
    fn parse_retry_after_http_date_future() {
        // A date far in the future must yield a large positive wait.
        let secs = parse_retry_after("Wed, 21 Oct 2099 07:28:00 GMT");
        assert!(secs.is_some());
        assert!(secs.unwrap() > 1_000_000);
    }

    #[test]
    fn parse_retry_after_http_date_past() {
        // A date in the past yields 0 (don't wait), not None.
        assert_eq!(parse_retry_after("Wed, 21 Oct 1999 07:28:00 GMT"), Some(0));
    }

    #[test]
    fn initial_delay_is_base() {
        let s = BackoffState::new(100, 5000);
        assert_eq!(s.current_delay_ms(), 100);
    }

    #[test]
    fn exponential_growth() {
        let mut s = BackoffState::new(100, 5000);
        s.on_rate_limit(None);
        assert_eq!(s.current_delay_ms(), 200);
        s.on_rate_limit(None);
        assert_eq!(s.current_delay_ms(), 400);
        s.on_rate_limit(None);
        assert_eq!(s.current_delay_ms(), 800);
    }

    #[test]
    fn growth_is_capped() {
        let mut s = BackoffState::new(100, 1000);
        for _ in 0..10 {
            s.on_rate_limit(None);
        }
        assert_eq!(s.current_delay_ms(), 1000);
    }

    #[test]
    fn zero_base_bootstraps_on_rate_limit() {
        // The real-world default: throttle_ms = 0, max_backoff_ms = 30000.
        let mut s = BackoffState::new(0, 30000);
        assert_eq!(s.current_delay_ms(), 0); // no delay under normal conditions
        s.on_rate_limit(None);
        assert_eq!(s.current_delay_ms(), BOOTSTRAP_MS); // bootstraps, no div-by-zero
        s.on_rate_limit(None);
        assert_eq!(s.current_delay_ms(), BOOTSTRAP_MS * 2);
    }

    #[test]
    fn retry_after_is_a_floor() {
        let mut s = BackoffState::new(100, 10000);
        s.on_rate_limit(Some(5)); // 5s = 5000ms, well above the 200ms double
        assert!(s.current_delay_ms() >= 5000);
    }

    #[test]
    fn decays_after_successes() {
        let mut s = BackoffState::new(100, 5000);
        s.on_rate_limit(None);
        s.on_rate_limit(None);
        assert_eq!(s.current_delay_ms(), 400);
        for _ in 0..5 {
            s.on_success();
        }
        let after = s.current_delay_ms();
        assert!(after < 400 && after >= 100, "expected decay below 400, got {after}");
    }
}
