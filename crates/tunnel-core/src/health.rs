//! Endpoint health tracking and failover decisions.
//!
//! # The problem this solves
//!
//! Naive failover makes things worse. An IEPL link that drops 5% of packets
//! produces intermittent connect failures; a system that switches to the public
//! path on the first failure and back on the first success will flap between the
//! two every few seconds. Every flap rebuilds a tunnel pool, and rebuilding a
//! pool drops the live streams on it. The cure ends up worse than the disease.
//!
//! So failover here is deliberately reluctant:
//!
//! * **Failure threshold** — N consecutive failures before demoting. A single
//!   refused connect during a routine exit restart must not move traffic off
//!   IEPL.
//! * **Recovery threshold** — M consecutive successes before promoting back.
//!   Higher than the failure threshold on purpose: returning to a path means
//!   abandoning one that is currently working, so it needs more evidence.
//! * **Cooldown** — minimum dwell time between switches. Thresholds alone still
//!   oscillate under a link that fails in bursts; the cooldown is what actually
//!   stops flapping.
//!
//! Only *consecutive* events count — a success resets the failure streak and
//! vice versa — so an endpoint that alternates never reaches either threshold
//! and stays where it is.
//!
//! The cooldown does not apply to the first transition. A fresh agent whose
//! primary endpoint is genuinely down must be able to fail over immediately
//! rather than waiting out a dwell timer against a dead link.

use std::time::{Duration, Instant};

use tunnel_common::model::{Endpoint, EndpointKind, EndpointPriority};
use tunnel_common::Result;

#[derive(Debug, Clone)]
pub struct HealthPolicy {
    /// Consecutive failures before an endpoint is considered down.
    pub failure_threshold: u32,
    /// Consecutive successes before a down endpoint is considered up again.
    pub recovery_threshold: u32,
    /// Minimum time between state changes, after the first one.
    pub cooldown: Duration,
}

impl Default for HealthPolicy {
    fn default() -> Self {
        Self {
            failure_threshold: 3,
            recovery_threshold: 5,
            cooldown: Duration::from_secs(60),
        }
    }
}

impl HealthPolicy {
    pub fn validate(&self) -> Result<()> {
        if self.failure_threshold == 0 {
            return Err(tunnel_common::Error::config(
                "health.failure_threshold must be >= 1",
            ));
        }
        if self.recovery_threshold == 0 {
            return Err(tunnel_common::Error::config(
                "health.recovery_threshold must be >= 1",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthVerdict {
    Up,
    Down,
}

impl HealthVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            HealthVerdict::Up => "up",
            HealthVerdict::Down => "down",
        }
    }
}

/// Health state for one endpoint.
#[derive(Debug, Clone)]
pub struct EndpointHealth {
    pub endpoint_id: String,
    pub endpoint_name: String,
    pub kind: EndpointKind,
    pub priority: EndpointPriority,
    verdict: HealthVerdict,
    consecutive_failures: u32,
    consecutive_successes: u32,
    /// `None` until the first transition, which is how the cooldown is skipped
    /// for that first switch.
    last_change: Option<Instant>,
    last_error: Option<String>,
    total_failures: u64,
    total_successes: u64,
}

impl EndpointHealth {
    pub fn new(endpoint: &Endpoint) -> Self {
        Self {
            endpoint_id: endpoint.id.clone(),
            endpoint_name: endpoint.name.clone(),
            kind: endpoint.kind,
            priority: endpoint.priority,
            // Optimistic: a fresh agent must not start out on its backup path.
            verdict: HealthVerdict::Up,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_change: None,
            last_error: None,
            total_failures: 0,
            total_successes: 0,
        }
    }

    pub fn verdict(&self) -> HealthVerdict {
        self.verdict
    }

    pub fn is_up(&self) -> bool {
        self.verdict == HealthVerdict::Up
    }

    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    pub fn totals(&self) -> (u64, u64) {
        (self.total_successes, self.total_failures)
    }

    /// Seconds remaining before a switch is permitted, 0 if allowed now.
    pub fn cooldown_remaining(&self, policy: &HealthPolicy) -> u64 {
        match self.last_change {
            None => 0,
            Some(t) => policy
                .cooldown
                .saturating_sub(t.elapsed())
                .as_secs(),
        }
    }

    fn cooldown_elapsed(&self, policy: &HealthPolicy) -> bool {
        match self.last_change {
            // First transition is never gated.
            None => true,
            Some(t) => t.elapsed() >= policy.cooldown,
        }
    }

    /// Record a successful connect. Returns `true` if the endpoint was promoted.
    pub fn record_success(&mut self, policy: &HealthPolicy) -> bool {
        self.total_successes += 1;
        self.consecutive_failures = 0;
        self.consecutive_successes = self.consecutive_successes.saturating_add(1);
        self.last_error = None;

        if self.verdict == HealthVerdict::Down
            && self.consecutive_successes >= policy.recovery_threshold
            && self.cooldown_elapsed(policy)
        {
            self.verdict = HealthVerdict::Up;
            self.last_change = Some(Instant::now());
            self.consecutive_successes = 0;
            return true;
        }
        false
    }

    /// Record a failed connect. Returns `true` if the endpoint was demoted.
    pub fn record_failure(&mut self, error: &str, policy: &HealthPolicy) -> bool {
        self.total_failures += 1;
        self.consecutive_successes = 0;
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        // Bound the stored string: it comes from network-adjacent error paths
        // and is surfaced in the UI.
        self.last_error = Some(error.chars().take(200).collect());

        if self.verdict == HealthVerdict::Up
            && self.consecutive_failures >= policy.failure_threshold
            && self.cooldown_elapsed(policy)
        {
            self.verdict = HealthVerdict::Down;
            self.last_change = Some(Instant::now());
            self.consecutive_failures = 0;
            return true;
        }
        false
    }
}

/// Health for a route's endpoint set, plus endpoint selection.
///
/// Endpoints are held in configured order, primary before backup. Selection
/// walks that order and returns the first one that is `Up`.
#[derive(Debug)]
pub struct EndpointSelector {
    endpoints: Vec<Endpoint>,
    health: Vec<EndpointHealth>,
    policy: HealthPolicy,
}

impl EndpointSelector {
    /// Build a selector. Endpoints are sorted primary-first, preserving the
    /// configured order within a priority so an operator's ordering is honoured.
    pub fn new(mut endpoints: Vec<Endpoint>, policy: HealthPolicy) -> Result<Self> {
        policy.validate()?;
        endpoints.retain(|e| e.enabled);
        if endpoints.is_empty() {
            return Err(tunnel_common::Error::config(
                "route has no enabled endpoints",
            ));
        }
        endpoints.sort_by_key(|e| e.priority);
        let health = endpoints.iter().map(EndpointHealth::new).collect();
        Ok(Self {
            endpoints,
            health,
            policy,
        })
    }

    pub fn policy(&self) -> &HealthPolicy {
        &self.policy
    }

    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    /// The endpoint to dial: highest-priority healthy one.
    ///
    /// If every endpoint is down we still return the highest-priority one rather
    /// than nothing. Refusing to dial when all paths look bad would guarantee an
    /// outage; retrying the primary at least recovers on its own once the link
    /// returns, and the backoff in the caller keeps the retry rate sane.
    pub fn select(&self) -> &Endpoint {
        for (i, h) in self.health.iter().enumerate() {
            if h.is_up() {
                return &self.endpoints[i];
            }
        }
        &self.endpoints[0]
    }

    /// `true` when every endpoint is currently marked down.
    pub fn all_down(&self) -> bool {
        self.health.iter().all(|h| !h.is_up())
    }

    fn index_of(&self, endpoint_id: &str) -> Option<usize> {
        self.health.iter().position(|h| h.endpoint_id == endpoint_id)
    }

    /// Report a successful connect. Returns `true` if this changed the selection.
    pub fn record_success(&mut self, endpoint_id: &str) -> bool {
        let before = self.select().id.clone();
        if let Some(i) = self.index_of(endpoint_id) {
            let policy = self.policy.clone();
            if self.health[i].record_success(&policy) {
                tracing::info!(
                    endpoint = %self.health[i].endpoint_name,
                    kind = %self.health[i].kind,
                    "endpoint recovered"
                );
            }
        }
        self.select().id != before
    }

    /// Report a failed connect. Returns `true` if this changed the selection.
    pub fn record_failure(&mut self, endpoint_id: &str, error: &str) -> bool {
        let before = self.select().id.clone();
        if let Some(i) = self.index_of(endpoint_id) {
            let policy = self.policy.clone();
            if self.health[i].record_failure(error, &policy) {
                tracing::warn!(
                    endpoint = %self.health[i].endpoint_name,
                    kind = %self.health[i].kind,
                    error = %error,
                    "endpoint marked down"
                );
            }
        }
        let after = self.select().id.clone();
        if after != before {
            tracing::warn!(from = %before, to = %after, "failing over to a different endpoint");
            true
        } else {
            false
        }
    }

    pub fn health(&self) -> &[EndpointHealth] {
        &self.health
    }

    pub fn endpoints(&self) -> &[Endpoint] {
        &self.endpoints
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> HealthPolicy {
        HealthPolicy {
            failure_threshold: 3,
            recovery_threshold: 5,
            // Zero cooldown keeps the threshold tests focused; cooldown has its
            // own tests below.
            cooldown: Duration::ZERO,
        }
    }

    fn endpoint(id: &str, priority: EndpointPriority, kind: EndpointKind) -> Endpoint {
        Endpoint {
            id: id.into(),
            node_id: "hk-01".into(),
            name: format!("ep-{id}"),
            address: "10.20.0.2".into(),
            port: 5000,
            kind,
            priority,
            interface: None,
            source_ip: None,
            tls_server_name: None,
            enabled: true,
        }
    }

    fn iepl_then_public() -> Vec<Endpoint> {
        vec![
            endpoint("iepl", EndpointPriority::Primary, EndpointKind::Iepl),
            endpoint("public", EndpointPriority::Backup, EndpointKind::Public),
        ]
    }

    #[test]
    fn starts_up_and_prefers_primary() {
        let s = EndpointSelector::new(iepl_then_public(), policy()).unwrap();
        assert_eq!(s.select().id, "iepl");
        assert!(!s.all_down());
    }

    #[test]
    fn backup_is_ordered_after_primary_regardless_of_input_order() {
        let mut eps = iepl_then_public();
        eps.reverse();
        let s = EndpointSelector::new(eps, policy()).unwrap();
        assert_eq!(s.select().id, "iepl", "primary must be selected first");
    }

    #[test]
    fn single_failure_does_not_trigger_failover() {
        // The whole point of the failure threshold.
        let mut s = EndpointSelector::new(iepl_then_public(), policy()).unwrap();
        assert!(!s.record_failure("iepl", "connection refused"));
        assert_eq!(s.select().id, "iepl");
        assert!(!s.record_failure("iepl", "connection refused"));
        assert_eq!(s.select().id, "iepl");
    }

    #[test]
    fn threshold_failures_trigger_failover_to_backup() {
        let mut s = EndpointSelector::new(iepl_then_public(), policy()).unwrap();
        s.record_failure("iepl", "timeout");
        s.record_failure("iepl", "timeout");
        assert!(s.record_failure("iepl", "timeout"), "third failure should switch");
        assert_eq!(s.select().id, "public");
    }

    #[test]
    fn intermittent_failures_never_trigger_failover() {
        // A link that fails every other attempt must not flap the route. This is
        // the case that breaks naive implementations.
        let mut s = EndpointSelector::new(iepl_then_public(), policy()).unwrap();
        for _ in 0..50 {
            s.record_failure("iepl", "transient");
            s.record_failure("iepl", "transient");
            s.record_success("iepl");
        }
        assert_eq!(
            s.select().id,
            "iepl",
            "alternating results should never reach the consecutive threshold"
        );
    }

    #[test]
    fn recovery_needs_more_evidence_than_failure() {
        let mut s = EndpointSelector::new(iepl_then_public(), policy()).unwrap();
        for _ in 0..3 {
            s.record_failure("iepl", "down");
        }
        assert_eq!(s.select().id, "public");

        // Four successes are not enough (recovery_threshold is 5).
        for _ in 0..4 {
            s.record_success("iepl");
        }
        assert_eq!(s.select().id, "public", "promoted too eagerly");

        assert!(s.record_success("iepl"), "fifth success should promote");
        assert_eq!(s.select().id, "iepl");
    }

    #[test]
    fn cooldown_blocks_a_rapid_second_switch() {
        let p = HealthPolicy {
            failure_threshold: 2,
            recovery_threshold: 2,
            cooldown: Duration::from_secs(300),
        };
        let mut s = EndpointSelector::new(iepl_then_public(), p).unwrap();

        // First transition is allowed immediately even with a long cooldown.
        s.record_failure("iepl", "down");
        assert!(s.record_failure("iepl", "down"));
        assert_eq!(s.select().id, "public");

        // Now the dwell timer applies: recovery must wait.
        for _ in 0..10 {
            s.record_success("iepl");
        }
        assert_eq!(
            s.select().id,
            "public",
            "cooldown should hold the route on the backup"
        );
        assert!(s.health()[0].cooldown_remaining(s.policy()) > 0);
    }

    #[test]
    fn first_transition_is_not_gated_by_cooldown() {
        // A fresh agent whose primary is genuinely dead must fail over now, not
        // after the dwell timer.
        let p = HealthPolicy {
            failure_threshold: 1,
            recovery_threshold: 1,
            cooldown: Duration::from_secs(3600),
        };
        let mut s = EndpointSelector::new(iepl_then_public(), p).unwrap();
        assert!(s.record_failure("iepl", "no route to host"));
        assert_eq!(s.select().id, "public");
    }

    #[test]
    fn all_endpoints_down_still_returns_the_primary() {
        // Returning nothing would guarantee an outage; retrying the primary
        // recovers on its own once the link returns.
        let mut s = EndpointSelector::new(iepl_then_public(), policy()).unwrap();
        for _ in 0..3 {
            s.record_failure("iepl", "down");
        }
        for _ in 0..3 {
            s.record_failure("public", "down");
        }
        assert!(s.all_down());
        assert_eq!(s.select().id, "iepl");
    }

    #[test]
    fn success_resets_the_failure_streak() {
        let mut s = EndpointSelector::new(iepl_then_public(), policy()).unwrap();
        s.record_failure("iepl", "x");
        s.record_failure("iepl", "x");
        s.record_success("iepl");
        assert_eq!(s.health()[0].consecutive_failures(), 0);
        // Streak restarted, so two more failures still must not switch.
        s.record_failure("iepl", "x");
        assert!(!s.record_failure("iepl", "x"));
        assert_eq!(s.select().id, "iepl");
    }

    #[test]
    fn error_text_is_recorded_and_bounded() {
        let mut s = EndpointSelector::new(iepl_then_public(), policy()).unwrap();
        s.record_failure("iepl", &"x".repeat(5000));
        let err = s.health()[0].last_error().unwrap();
        assert!(err.len() <= 200, "error text not bounded: {}", err.len());
    }

    #[test]
    fn totals_are_tracked() {
        let mut s = EndpointSelector::new(iepl_then_public(), policy()).unwrap();
        s.record_success("iepl");
        s.record_success("iepl");
        s.record_failure("iepl", "e");
        let (ok, fail) = s.health()[0].totals();
        assert_eq!((ok, fail), (2, 1));
    }

    #[test]
    fn unknown_endpoint_id_is_ignored() {
        let mut s = EndpointSelector::new(iepl_then_public(), policy()).unwrap();
        assert!(!s.record_failure("does-not-exist", "e"));
        assert_eq!(s.select().id, "iepl");
    }

    #[test]
    fn disabled_endpoints_are_excluded() {
        let mut eps = iepl_then_public();
        eps[0].enabled = false;
        let s = EndpointSelector::new(eps, policy()).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s.select().id, "public");
    }

    #[test]
    fn no_enabled_endpoints_is_a_config_error() {
        let mut eps = iepl_then_public();
        for e in &mut eps {
            e.enabled = false;
        }
        assert!(EndpointSelector::new(eps, policy()).is_err());
    }

    #[test]
    fn invalid_policy_is_rejected() {
        let p = HealthPolicy {
            failure_threshold: 0,
            ..Default::default()
        };
        assert!(EndpointSelector::new(iepl_then_public(), p).is_err());
    }

    #[test]
    fn single_endpoint_route_never_fails_over() {
        let eps = vec![endpoint("only", EndpointPriority::Primary, EndpointKind::Public)];
        let mut s = EndpointSelector::new(eps, policy()).unwrap();
        for _ in 0..20 {
            s.record_failure("only", "down");
        }
        assert_eq!(s.select().id, "only");
        assert!(s.all_down());
    }
}
