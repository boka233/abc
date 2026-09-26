//! Counters and rate tracking.
//!
//! Hard rule: nothing here touches a database, a lock, or an allocation on the
//! per-byte path. A relay copy loop does `fetch_add` on an `AtomicU64` and
//! nothing else. Aggregation, rate computation and persistence all happen in a
//! separate low-frequency task.
//!
//! `Relaxed` ordering throughout: these are statistics, not synchronisation.
//! Paying for `SeqCst` on every 16 KiB chunk would be measurable and buys
//! nothing — an operator does not care whether the byte counter is 4 KiB stale.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use tunnel_common::model::{ConnectionSnapshot, TunnelState};

const REL: Ordering = Ordering::Relaxed;

/// Byte and connection counters, shared by clone-of-Arc.
#[derive(Debug, Default)]
pub struct Counters {
    /// Bytes received by this component. On an entry relay: client → target.
    pub rx_bytes: AtomicU64,
    /// Bytes sent by this component. On an entry relay: target → client.
    pub tx_bytes: AtomicU64,
    /// Currently established connections/streams.
    pub active: AtomicU32,
    /// Lifetime accepted count.
    pub accepted_total: AtomicU64,
    /// Refused by a limit (max connections, pool unavailable).
    pub rejected_total: AtomicU64,
    /// Failed after acceptance (target unreachable, tunnel died mid-stream).
    pub failed_total: AtomicU64,
}

impl Counters {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    #[inline]
    pub fn add_rx(&self, n: u64) {
        self.rx_bytes.fetch_add(n, REL);
    }

    #[inline]
    pub fn add_tx(&self, n: u64) {
        self.tx_bytes.fetch_add(n, REL);
    }

    #[inline]
    pub fn rx(&self) -> u64 {
        self.rx_bytes.load(REL)
    }

    #[inline]
    pub fn tx(&self) -> u64 {
        self.tx_bytes.load(REL)
    }

    #[inline]
    pub fn active(&self) -> u32 {
        self.active.load(REL)
    }

    pub fn accepted(&self) -> u64 {
        self.accepted_total.load(REL)
    }

    pub fn rejected(&self) -> u64 {
        self.rejected_total.load(REL)
    }

    pub fn failed(&self) -> u64 {
        self.failed_total.load(REL)
    }

    pub fn on_accept(&self) {
        self.accepted_total.fetch_add(1, REL);
        self.active.fetch_add(1, REL);
    }

    pub fn on_reject(&self) {
        self.rejected_total.fetch_add(1, REL);
    }

    pub fn on_fail(&self) {
        self.failed_total.fetch_add(1, REL);
    }

    /// Decrement the live gauge. Saturating: a double-close from an error path
    /// must not wrap the counter to 4 billion.
    pub fn on_close(&self) {
        let _ = self
            .active
            .fetch_update(REL, REL, |v| Some(v.saturating_sub(1)));
    }
}

/// Converts cumulative byte counters into a bits-per-second rate.
///
/// Sampled by the reporting loop, not by the data path.
#[derive(Debug)]
pub struct RateTracker {
    last_rx: AtomicU64,
    last_tx: AtomicU64,
    last_at: std::sync::Mutex<Instant>,
    rx_bps: AtomicU64,
    tx_bps: AtomicU64,
}

impl Default for RateTracker {
    fn default() -> Self {
        Self {
            last_rx: AtomicU64::new(0),
            last_tx: AtomicU64::new(0),
            last_at: std::sync::Mutex::new(Instant::now()),
            rx_bps: AtomicU64::new(0),
            tx_bps: AtomicU64::new(0),
        }
    }
}

impl RateTracker {
    /// Feed current cumulative totals; returns `(rx_bps, tx_bps)`.
    ///
    /// The mutex here is contended once per sampling interval by one task. It is
    /// not on the data path.
    pub fn sample(&self, rx_total: u64, tx_total: u64) -> (u64, u64) {
        let now = Instant::now();
        let elapsed = {
            let mut guard = match self.last_at.lock() {
                Ok(g) => g,
                // A poisoned lock here is a statistics glitch, not a reason to
                // take down a process that is moving traffic fine.
                Err(poisoned) => poisoned.into_inner(),
            };
            let elapsed = now.duration_since(*guard).as_secs_f64();
            *guard = now;
            elapsed
        };

        let prev_rx = self.last_rx.swap(rx_total, REL);
        let prev_tx = self.last_tx.swap(tx_total, REL);

        // Guard against a division blow-up on a fast double-sample, and against
        // counters that went backwards (they shouldn't, but a reset would).
        if elapsed < 0.001 {
            return (self.rx_bps.load(REL), self.tx_bps.load(REL));
        }
        let rx_delta = rx_total.saturating_sub(prev_rx);
        let tx_delta = tx_total.saturating_sub(prev_tx);
        let rx_bps = ((rx_delta as f64 * 8.0) / elapsed) as u64;
        let tx_bps = ((tx_delta as f64 * 8.0) / elapsed) as u64;
        self.rx_bps.store(rx_bps, REL);
        self.tx_bps.store(tx_bps, REL);
        (rx_bps, tx_bps)
    }

    pub fn current(&self) -> (u64, u64) {
        (self.rx_bps.load(REL), self.tx_bps.load(REL))
    }
}

/// Per-route aggregate.
#[derive(Debug)]
pub struct RouteMetrics {
    pub route_id: String,
    pub counters: Arc<Counters>,
    pub rates: RateTracker,
}

impl RouteMetrics {
    pub fn new(route_id: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            route_id: route_id.into(),
            counters: Counters::new(),
            rates: RateTracker::default(),
        })
    }

    pub fn sample(&self) -> (u64, u64) {
        self.rates
            .sample(self.counters.rx(), self.counters.tx())
    }
}

/// Per-tunnel-connection state.
#[derive(Debug)]
pub struct TunnelMetrics {
    pub tunnel_id: u64,
    pub counters: Arc<Counters>,
    state: AtomicU32,
    /// Last measured round-trip time in ms; `u32::MAX` means "not yet known".
    rtt_ms: AtomicU32,
    reconnects: AtomicU32,
    established_at: std::sync::Mutex<Option<Instant>>,
}

const RTT_UNKNOWN: u32 = u32::MAX;

fn state_to_u32(s: TunnelState) -> u32 {
    match s {
        TunnelState::Connecting => 0,
        TunnelState::Online => 1,
        TunnelState::Degraded => 2,
        TunnelState::Offline => 3,
    }
}

fn u32_to_state(v: u32) -> TunnelState {
    match v {
        0 => TunnelState::Connecting,
        1 => TunnelState::Online,
        2 => TunnelState::Degraded,
        _ => TunnelState::Offline,
    }
}

impl TunnelMetrics {
    pub fn new(tunnel_id: u64) -> Arc<Self> {
        Arc::new(Self {
            tunnel_id,
            counters: Counters::new(),
            state: AtomicU32::new(state_to_u32(TunnelState::Connecting)),
            rtt_ms: AtomicU32::new(RTT_UNKNOWN),
            reconnects: AtomicU32::new(0),
            established_at: std::sync::Mutex::new(None),
        })
    }

    pub fn state(&self) -> TunnelState {
        u32_to_state(self.state.load(REL))
    }

    pub fn set_state(&self, s: TunnelState) {
        self.state.store(state_to_u32(s), REL);
        if s == TunnelState::Online {
            if let Ok(mut g) = self.established_at.lock() {
                if g.is_none() {
                    *g = Some(Instant::now());
                }
            }
        } else if s == TunnelState::Offline {
            if let Ok(mut g) = self.established_at.lock() {
                *g = None;
            }
        }
    }

    pub fn set_rtt(&self, ms: u32) {
        self.rtt_ms.store(ms, REL);
    }

    pub fn rtt(&self) -> Option<u32> {
        let v = self.rtt_ms.load(REL);
        (v != RTT_UNKNOWN).then_some(v)
    }

    pub fn on_reconnect(&self) {
        self.reconnects.fetch_add(1, REL);
        self.rtt_ms.store(RTT_UNKNOWN, REL);
    }

    pub fn reconnects(&self) -> u32 {
        self.reconnects.load(REL)
    }

    pub fn established_secs(&self) -> u64 {
        self.established_at
            .lock()
            .ok()
            .and_then(|g| g.map(|t| t.elapsed().as_secs()))
            .unwrap_or(0)
    }
}

/// Live connection table, for the Connections page.
///
/// A `DashMap` rather than a `Mutex<HashMap>`: inserts and removes happen on
/// connection setup/teardown from many tasks at once, and sharding keeps those
/// off a single lock. Per-connection *byte* counters are atomics inside the
/// entry, so the hot path never touches the map at all.
#[derive(Debug, Default)]
pub struct ConnectionRegistry {
    entries: DashMap<u64, ConnectionEntry>,
    next_id: AtomicU64,
    capacity: usize,
}

#[derive(Debug)]
struct ConnectionEntry {
    route_id: String,
    route_name: String,
    tunnel_id: u64,
    stream_id: u32,
    client_addr: String,
    target: String,
    rx: Arc<AtomicU64>,
    tx: Arc<AtomicU64>,
    started: Instant,
    last_activity: Arc<AtomicU64>,
}

/// Handle held by a live connection; updates are lock-free.
#[derive(Debug, Clone)]
pub struct ConnectionHandle {
    pub id: u64,
    rx: Arc<AtomicU64>,
    tx: Arc<AtomicU64>,
    last_activity: Arc<AtomicU64>,
    start: Instant,
}

impl ConnectionHandle {
    #[inline]
    pub fn add_rx(&self, n: u64) {
        self.rx.fetch_add(n, REL);
        self.touch();
    }

    #[inline]
    pub fn add_tx(&self, n: u64) {
        self.tx.fetch_add(n, REL);
        self.touch();
    }

    #[inline]
    fn touch(&self) {
        self.last_activity
            .store(self.start.elapsed().as_secs(), REL);
    }
}

impl ConnectionRegistry {
    /// `capacity` bounds how many connections are *tracked* for display. The
    /// data plane keeps working past it; we just stop growing the table, because
    /// a 10k-row registry is both a memory cost and useless in a UI.
    pub fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            entries: DashMap::new(),
            next_id: AtomicU64::new(1),
            capacity,
        })
    }

    pub fn register(
        &self,
        route_id: &str,
        route_name: &str,
        tunnel_id: u64,
        stream_id: u32,
        client_addr: String,
        target: String,
    ) -> ConnectionHandle {
        let id = self.next_id.fetch_add(1, REL);
        let rx = Arc::new(AtomicU64::new(0));
        let tx = Arc::new(AtomicU64::new(0));
        let last_activity = Arc::new(AtomicU64::new(0));
        let start = Instant::now();

        if self.entries.len() < self.capacity {
            self.entries.insert(
                id,
                ConnectionEntry {
                    route_id: route_id.to_string(),
                    route_name: route_name.to_string(),
                    tunnel_id,
                    stream_id,
                    client_addr,
                    target,
                    rx: rx.clone(),
                    tx: tx.clone(),
                    started: start,
                    last_activity: last_activity.clone(),
                },
            );
        }

        ConnectionHandle {
            id,
            rx,
            tx,
            last_activity,
            start,
        }
    }

    pub fn unregister(&self, id: u64) {
        self.entries.remove(&id);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Snapshot for the API. Allocates, so call it on the reporting cadence.
    pub fn snapshot(&self, limit: usize) -> Vec<ConnectionSnapshot> {
        let mut out = Vec::with_capacity(limit.min(self.entries.len()));
        for entry in self.entries.iter().take(limit) {
            let e = entry.value();
            let age = e.started.elapsed().as_secs();
            let last = e.last_activity.load(REL);
            out.push(ConnectionSnapshot {
                id: *entry.key(),
                route_id: e.route_id.clone(),
                route_name: e.route_name.clone(),
                tunnel_id: e.tunnel_id,
                stream_id: e.stream_id,
                client_addr: e.client_addr.clone(),
                target: e.target.clone(),
                rx_bytes: e.rx.load(REL),
                tx_bytes: e.tx.load(REL),
                age_secs: age,
                idle_secs: age.saturating_sub(last),
            });
        }
        // 按存活时长倒序：最老的连接在最前面，排查「卡住不走」的连接时最常看它们。
        out.sort_by_key(|c| std::cmp::Reverse(c.age_secs));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_counters_accumulate() {
        let c = Counters::new();
        c.add_rx(100);
        c.add_rx(50);
        c.add_tx(7);
        assert_eq!(c.rx(), 150);
        assert_eq!(c.tx(), 7);
    }

    #[test]
    fn active_gauge_tracks_lifecycle() {
        let c = Counters::new();
        c.on_accept();
        c.on_accept();
        assert_eq!(c.active(), 2);
        assert_eq!(c.accepted(), 2);
        c.on_close();
        assert_eq!(c.active(), 1);
    }

    #[test]
    fn close_underflow_saturates_instead_of_wrapping() {
        // Error paths can call on_close twice; wrapping to u32::MAX would make
        // the dashboard claim 4 billion live connections.
        let c = Counters::new();
        c.on_close();
        c.on_close();
        assert_eq!(c.active(), 0);
    }

    #[test]
    fn rate_tracker_computes_bits_per_second() {
        let t = RateTracker::default();
        t.sample(0, 0);
        std::thread::sleep(std::time::Duration::from_millis(120));
        let (rx, tx) = t.sample(12_000, 6_000);
        // ~12 kB in ~0.12 s ≈ 800 kbit/s. Wide bounds to stay robust on CI.
        assert!(rx > 200_000 && rx < 4_000_000, "rx_bps = {rx}");
        assert!(tx > 100_000 && tx < 2_000_000, "tx_bps = {tx}");
        assert_eq!(t.current(), (rx, tx));
    }

    #[test]
    fn rate_tracker_survives_a_zero_interval() {
        let t = RateTracker::default();
        t.sample(1000, 1000);
        // Immediate re-sample: must not divide by ~0 and produce inf/NaN.
        let (rx, tx) = t.sample(2000, 2000);
        assert!(rx < u64::MAX && tx < u64::MAX);
    }

    #[test]
    fn rate_tracker_handles_counter_reset() {
        let t = RateTracker::default();
        t.sample(10_000, 10_000);
        std::thread::sleep(std::time::Duration::from_millis(20));
        let (rx, _) = t.sample(0, 0);
        assert_eq!(rx, 0, "a reset must not produce a giant negative-wrap rate");
    }

    #[test]
    fn tunnel_state_transitions() {
        let m = TunnelMetrics::new(1);
        assert_eq!(m.state(), TunnelState::Connecting);
        assert!(m.rtt().is_none());

        m.set_state(TunnelState::Online);
        assert_eq!(m.state(), TunnelState::Online);
        m.set_rtt(42);
        assert_eq!(m.rtt(), Some(42));

        m.set_state(TunnelState::Offline);
        m.on_reconnect();
        assert_eq!(m.reconnects(), 1);
        assert!(m.rtt().is_none(), "rtt must be cleared on reconnect");
        assert_eq!(m.established_secs(), 0);
    }

    #[test]
    fn all_tunnel_states_roundtrip() {
        for s in [
            TunnelState::Connecting,
            TunnelState::Online,
            TunnelState::Degraded,
            TunnelState::Offline,
        ] {
            assert_eq!(u32_to_state(state_to_u32(s)), s);
        }
    }

    #[test]
    fn registry_tracks_and_releases() {
        let reg = ConnectionRegistry::new(10);
        let h = reg.register("r1", "route one", 7, 3, "1.2.3.4:5".into(), "127.0.0.1:80".into());
        h.add_rx(500);
        h.add_tx(250);

        let snap = reg.snapshot(10);
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].rx_bytes, 500);
        assert_eq!(snap[0].tx_bytes, 250);
        assert_eq!(snap[0].tunnel_id, 7);
        assert_eq!(snap[0].stream_id, 3);

        reg.unregister(h.id);
        assert!(reg.is_empty());
    }

    #[test]
    fn registry_stops_growing_past_capacity_but_still_hands_out_handles() {
        let reg = ConnectionRegistry::new(2);
        let handles: Vec<_> = (0..5)
            .map(|i| reg.register("r", "r", 1, i, "c".into(), "t".into()))
            .collect();
        assert_eq!(reg.len(), 2, "table must stay bounded");
        // Every connection still gets a working handle — traffic is never
        // blocked by the display limit.
        assert_eq!(handles.len(), 5);
        for h in &handles {
            h.add_rx(1);
        }
    }

    #[test]
    fn registry_ids_are_unique() {
        let reg = ConnectionRegistry::new(100);
        let ids: std::collections::HashSet<u64> = (0..50)
            .map(|_| reg.register("r", "r", 1, 1, "c".into(), "t".into()).id)
            .collect();
        assert_eq!(ids.len(), 50);
    }

    #[test]
    fn concurrent_counter_updates_do_not_lose_bytes() {
        let c = Counters::new();
        let mut handles = Vec::new();
        for _ in 0..8 {
            let c = c.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..1000 {
                    c.add_rx(10);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(c.rx(), 8 * 1000 * 10);
    }
}
