//! Exponential backoff with full jitter.
//!
//! Why jitter is mandatory here: when an exit node restarts, every entry node's
//! whole tunnel pool fails at the same instant. Without jitter all of them
//! retry in lockstep and hammer the exit the moment it comes back, which looks
//! exactly like a SYN flood and delays recovery. Full jitter spreads the
//! retries across the window.

use std::time::Duration;

use rand::Rng;

#[derive(Debug, Clone)]
pub struct Backoff {
    initial: Duration,
    max: Duration,
    factor: f64,
    /// Fraction of the computed delay that is randomised. 1.0 = full jitter.
    jitter: f64,
    attempt: u32,
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new(Duration::from_millis(500), Duration::from_secs(30))
    }
}

impl Backoff {
    pub fn new(initial: Duration, max: Duration) -> Self {
        Self {
            initial,
            max,
            factor: 2.0,
            jitter: 1.0,
            attempt: 0,
        }
    }

    pub fn with_factor(mut self, factor: f64) -> Self {
        self.factor = factor.max(1.0);
        self
    }

    pub fn with_jitter(mut self, jitter: f64) -> Self {
        self.jitter = jitter.clamp(0.0, 1.0);
        self
    }

    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    /// Advance and return the next delay.
    pub fn next_delay(&mut self) -> Duration {
        let base = self.base_for(self.attempt);
        self.attempt = self.attempt.saturating_add(1);

        if self.jitter <= f64::EPSILON {
            return base;
        }

        let base_ms = base.as_millis() as f64;
        let fixed = base_ms * (1.0 - self.jitter);
        let random = rand::thread_rng().gen_range(0.0..=base_ms * self.jitter);
        Duration::from_millis((fixed + random).round() as u64)
    }

    /// Delay for a given attempt without mutating state. Exposed for tests and
    /// for UI estimates ("next retry in ~Ns").
    pub fn base_for(&self, attempt: u32) -> Duration {
        // Cap the exponent before the multiply so we never overflow f64 into inf.
        let exp = attempt.min(32) as f64;
        let ms = self.initial.as_millis() as f64 * self.factor.powf(exp);
        let capped = ms.min(self.max.as_millis() as f64);
        Duration::from_millis(capped.round() as u64)
    }

    /// Call after a successful connect so the next failure starts from scratch.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grows_then_saturates_at_max() {
        let b = Backoff::new(Duration::from_millis(100), Duration::from_secs(5));
        assert_eq!(b.base_for(0), Duration::from_millis(100));
        assert_eq!(b.base_for(1), Duration::from_millis(200));
        assert_eq!(b.base_for(2), Duration::from_millis(400));
        assert_eq!(b.base_for(10), Duration::from_secs(5));
        // Huge attempt counts must not overflow into a nonsense duration.
        assert_eq!(b.base_for(u32::MAX), Duration::from_secs(5));
    }

    #[test]
    fn jitter_stays_within_the_base_window() {
        let mut b = Backoff::new(Duration::from_millis(1000), Duration::from_secs(60));
        for _ in 0..200 {
            let prev_attempt = b.attempt();
            let base = b.base_for(prev_attempt);
            let d = b.next_delay();
            assert!(d <= base, "{d:?} exceeded base {base:?}");
        }
    }

    #[test]
    fn full_jitter_actually_varies() {
        let mut b = Backoff::new(Duration::from_secs(10), Duration::from_secs(10));
        let mut seen = std::collections::HashSet::new();
        for _ in 0..50 {
            seen.insert(b.next_delay().as_millis());
        }
        assert!(seen.len() > 10, "expected spread, got {} values", seen.len());
    }

    #[test]
    fn zero_jitter_is_deterministic() {
        let mut b = Backoff::new(Duration::from_millis(100), Duration::from_secs(5)).with_jitter(0.0);
        assert_eq!(b.next_delay(), Duration::from_millis(100));
        assert_eq!(b.next_delay(), Duration::from_millis(200));
    }

    #[test]
    fn reset_restarts_the_sequence() {
        let mut b = Backoff::new(Duration::from_millis(100), Duration::from_secs(5)).with_jitter(0.0);
        b.next_delay();
        b.next_delay();
        b.reset();
        assert_eq!(b.next_delay(), Duration::from_millis(100));
    }
}
