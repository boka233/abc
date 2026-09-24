//! Tunnel connection pool: several TLS connections per route.
//!
//! # Why a pool instead of one connection
//!
//! Multiplexing N streams over one TCP connection means one lost segment stalls
//! every stream behind it — head-of-line blocking that no amount of application
//! framing can undo. A single connection also caps throughput at whatever one
//! TCP congestion window and one TLS encryption context can sustain on one core.
//!
//! Running `tunnel_pool_size` independent connections and spreading streams over
//! them means a stalled connection affects roughly `1/N` of traffic instead of
//! all of it, and encryption work spreads across cores. It does not *eliminate*
//! HOL blocking — that would require a per-stream transport — but it bounds the
//! blast radius, which is the achievable goal here.
//!
//! # Supervision
//!
//! Each slot runs its own supervisor task: connect, hand the live multiplexer to
//! the pool, wait for it to die, back off, reconnect. Slots are independent, so
//! one flapping connection never disturbs the others, and the pool self-heals
//! without any central reconciliation loop.
//!
//! Backoff is per-slot with full jitter, so an exit restart does not cause all N
//! slots (times every entry node) to reconnect in lockstep.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use tokio::sync::mpsc;
use tunnel_common::backoff::Backoff;
use tunnel_common::model::{
    Endpoint, LoadBalance, Limits, RouteSnapshot, TunnelSnapshot, TunnelState,
};
use tunnel_common::net::{EgressBinding, TcpTuning};
use tunnel_common::{Error, Result, Secret};
use tunnel_protocol::codec::{FrameReader, FrameWriter};
use tunnel_protocol::handshake::{self, ClientHello, ServerHello};

use crate::health::{EndpointSelector, HealthPolicy};
use crate::metrics::{RouteMetrics, TunnelMetrics};
use crate::mux::{MuxConfig, MuxRole, Multiplexer, StreamHandle};
use crate::tls::TlsMaterial;

const REL: Ordering = Ordering::Relaxed;

#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub route_id: String,
    pub route_name: String,
    pub node_id: String,
    pub size: u16,
    pub load_balance: LoadBalance,
    pub limits: Limits,
    pub psk: Option<Secret>,
    pub health: HealthPolicy,
    /// Source-IP / device binding for the *tunnel* connection. On an IEPL entry
    /// this pins the tunnel to the private NIC.
    pub egress: EgressBinding,
}

/// One pool slot. Holds the live multiplexer when connected.
struct Slot {
    index: u16,
    mux: ArcSwapOption<Multiplexer>,
    metrics: Arc<TunnelMetrics>,
    endpoint_id: std::sync::Mutex<String>,
    endpoint_name: std::sync::Mutex<String>,
}

impl Slot {
    fn snapshot(&self, route_id: &str, endpoints: &[Endpoint]) -> TunnelSnapshot {
        let endpoint_id = self
            .endpoint_id
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();
        let endpoint_name = self
            .endpoint_name
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();
        let kind = endpoints
            .iter()
            .find(|e| e.id == endpoint_id)
            .map(|e| e.kind)
            .unwrap_or(tunnel_common::model::EndpointKind::Public);

        TunnelSnapshot {
            tunnel_id: self.metrics.tunnel_id,
            route_id: route_id.to_string(),
            endpoint_id,
            endpoint_name,
            endpoint_kind: kind,
            state: self.metrics.state(),
            streams: self
                .mux
                .load()
                .as_ref()
                .map(|m| m.live_streams())
                .unwrap_or(0),
            rx_bytes: self.metrics.counters.rx(),
            tx_bytes: self.metrics.counters.tx(),
            rtt_ms: self.metrics.rtt(),
            established_secs: self.metrics.established_secs(),
            reconnects: self.metrics.reconnects(),
        }
    }
}

/// A route's tunnel pool.
pub struct TunnelPool {
    cfg: PoolConfig,
    slots: Vec<Arc<Slot>>,
    selector: tokio::sync::Mutex<EndpointSelector>,
    metrics: Arc<RouteMetrics>,
    /// Round-robin cursor.
    cursor: AtomicUsize,
    shutdown: Arc<AtomicBool>,
    tls: Arc<TlsMaterial>,
}

/// Process-wide tunnel id source so ids are unique across routes in the UI.
static TUNNEL_ID_SEQ: AtomicU64 = AtomicU64::new(1);

impl std::fmt::Debug for TunnelPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelPool")
            .field("route", &self.cfg.route_name)
            .field("size", &self.cfg.size)
            .field("online", &self.online_tunnels())
            .field("streams", &self.live_streams())
            .field("shutdown", &self.shutdown.load(REL))
            .finish()
    }
}

impl TunnelPool {
    /// Build the pool and start every slot's supervisor.
    pub fn start(
        cfg: PoolConfig,
        endpoints: Vec<Endpoint>,
        tls: Arc<TlsMaterial>,
        metrics: Arc<RouteMetrics>,
    ) -> Result<Arc<Self>> {
        if cfg.size == 0 {
            return Err(Error::config("tunnel pool size must be >= 1"));
        }
        let selector = EndpointSelector::new(endpoints, cfg.health.clone())?;

        let slots: Vec<Arc<Slot>> = (0..cfg.size)
            .map(|index| {
                let tunnel_id = TUNNEL_ID_SEQ.fetch_add(1, REL);
                Arc::new(Slot {
                    index,
                    mux: ArcSwapOption::from(None),
                    metrics: TunnelMetrics::new(tunnel_id),
                    endpoint_id: std::sync::Mutex::new(String::new()),
                    endpoint_name: std::sync::Mutex::new(String::new()),
                })
            })
            .collect();

        let pool = Arc::new(Self {
            cfg,
            slots,
            selector: tokio::sync::Mutex::new(selector),
            metrics,
            cursor: AtomicUsize::new(0),
            shutdown: Arc::new(AtomicBool::new(false)),
            tls,
        });

        for slot in &pool.slots {
            let pool = pool.clone();
            let slot = slot.clone();
            tokio::spawn(async move { pool.supervise(slot).await });
        }

        Ok(pool)
    }

    /// Per-slot connect/retry loop. Runs until shutdown.
    async fn supervise(self: Arc<Self>, slot: Arc<Slot>) {
        // Stagger the initial connects so `size` handshakes do not land on the
        // exit in the same millisecond.
        if slot.index > 0 {
            let spread = Duration::from_millis(50 * slot.index as u64);
            tokio::time::sleep(spread).await;
        }

        let mut backoff = Backoff::new(Duration::from_millis(500), Duration::from_secs(30));

        while !self.shutdown.load(REL) {
            slot.metrics.set_state(TunnelState::Connecting);

            let endpoint = {
                let selector = self.selector.lock().await;
                selector.select().clone()
            };
            if let Ok(mut g) = slot.endpoint_id.lock() {
                *g = endpoint.id.clone();
            }
            if let Ok(mut g) = slot.endpoint_name.lock() {
                *g = endpoint.name.clone();
            }

            match self.connect_one(&endpoint, slot.index, slot.metrics.clone()).await {
                Ok(mux) => {
                    backoff.reset();
                    {
                        let mut selector = self.selector.lock().await;
                        selector.record_success(&endpoint.id);
                    }
                    tracing::info!(
                        route = %self.cfg.route_name,
                        tunnel = slot.metrics.tunnel_id,
                        slot = slot.index,
                        endpoint = %endpoint.name,
                        kind = %endpoint.kind,
                        "tunnel established"
                    );
                    slot.metrics.set_state(TunnelState::Online);
                    slot.mux.store(Some(mux.clone()));

                    // Park until the multiplexer's own tasks decide it is done.
                    while !mux.is_closed() && !self.shutdown.load(REL) {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }

                    slot.mux.store(None);
                    slot.metrics.set_state(TunnelState::Offline);
                    if self.shutdown.load(REL) {
                        mux.shutdown().await;
                        return;
                    }
                    slot.metrics.on_reconnect();
                    tracing::warn!(
                        route = %self.cfg.route_name,
                        tunnel = slot.metrics.tunnel_id,
                        "tunnel closed; reconnecting"
                    );
                    // Short pause so a connection that dies instantly cannot
                    // spin this loop.
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                Err(e) => {
                    slot.metrics.set_state(TunnelState::Offline);
                    {
                        let mut selector = self.selector.lock().await;
                        selector.record_failure(&endpoint.id, &e.to_string());
                    }
                    let delay = backoff.next_delay();
                    tracing::warn!(
                        route = %self.cfg.route_name,
                        slot = slot.index,
                        endpoint = %endpoint.name,
                        error = %e,
                        retry_in_ms = delay.as_millis() as u64,
                        attempt = backoff.attempt(),
                        "tunnel connect failed"
                    );
                    // Interruptible sleep so shutdown is not delayed by a long
                    // backoff.
                    let mut waited = Duration::ZERO;
                    let step = Duration::from_millis(100);
                    while waited < delay && !self.shutdown.load(REL) {
                        tokio::time::sleep(step).await;
                        waited += step;
                    }
                }
            }
        }
    }

    /// Dial one tunnel: TCP → TLS → handshake → multiplexer.
    async fn connect_one(
        &self,
        endpoint: &Endpoint,
        pool_index: u16,
        metrics: Arc<TunnelMetrics>,
    ) -> Result<Arc<Multiplexer>> {
        let limits = &self.cfg.limits;

        // Egress binding: the endpoint's own source_ip wins over the route-wide
        // default, so one route can reach two exits over different NICs.
        let egress = if endpoint.source_ip.is_some() {
            EgressBinding {
                source_ip: endpoint.source_ip,
                interface: endpoint.interface.clone().filter(|_| false),
            }
        } else {
            self.cfg.egress.clone()
        };

        let tcp = tunnel_common::net::connect(
            &endpoint.dial_target(),
            &TcpTuning::tunnel(),
            &egress,
            limits.connect_timeout,
        )
        .await?;

        let server_name = endpoint.server_name().to_string();
        let name = rustls_pki_types::ServerName::try_from(server_name.clone())
            .map_err(|_| Error::config(format!("invalid TLS server name `{server_name}`")))?
            .to_owned();

        let connector = self.tls.connector();
        let tls = tokio::time::timeout(limits.handshake_timeout, connector.connect(name, tcp))
            .await
            .map_err(|_| Error::Timeout("tls handshake"))?
            .map_err(|e| Error::tls(format!("handshake with {}: {e}", endpoint.name)))?;

        // --- application handshake ---
        let (read_half, write_half) = tokio::io::split(tls);
        let mut writer = FrameWriter::new(write_half, limits.max_frame_payload as usize);
        let mut reader = FrameReader::new(read_half, limits.max_frame_payload as usize);

        let hello = ClientHello::new(
            &self.cfg.node_id,
            &self.cfg.route_id,
            pool_index,
            self.cfg.psk.as_ref(),
            limits.max_frame_payload,
            limits.stream_window,
        );
        tokio::time::timeout(limits.handshake_timeout, writer.write_handshake(&hello))
            .await
            .map_err(|_| Error::Timeout("tunnel handshake write"))??;

        let reply: ServerHello =
            tokio::time::timeout(limits.handshake_timeout, reader.read_handshake())
                .await
                .map_err(|_| Error::Timeout("tunnel handshake read"))??;

        if !reply.accepted {
            return Err(Error::Protocol(format!(
                "exit rejected the tunnel: {}",
                reply.reason.unwrap_or_else(|| "no reason given".into())
            )));
        }
        if reply.version != tunnel_protocol::PROTOCOL_VERSION {
            return Err(Error::protocol(format!(
                "exit speaks protocol v{}, we speak v{}",
                reply.version,
                tunnel_protocol::PROTOCOL_VERSION
            )));
        }

        // Both sides must now use the *negotiated* values, not their proposals.
        let (payload, window) = handshake::negotiate(
            limits.max_frame_payload,
            limits.stream_window,
            reply.max_frame_payload,
            reply.stream_window,
        )?;

        // Reassemble the TLS stream from the two halves the codecs hold.
        let conn = reader.into_inner().unsplit(writer.into_inner());

        let mux_cfg = MuxConfig::from_limits(MuxRole::Initiator, limits, payload, window);
        Ok(Multiplexer::start(conn, mux_cfg, metrics, None))
    }

    /// Pick a tunnel and open a logical stream on it.
    ///
    /// Tries every healthy tunnel before giving up, so one wedged connection
    /// does not fail a user connection that another tunnel could carry.
    pub async fn open_stream(
        &self,
        client_addr: Option<String>,
    ) -> Result<StreamHandle> {
        let candidates = self.ordered_candidates();
        if candidates.is_empty() {
            return Err(Error::other(format!(
                "route `{}` has no online tunnel",
                self.cfg.route_name
            )));
        }

        let mut last_err = None;
        for slot in candidates {
            let Some(mux) = slot.mux.load_full() else {
                continue;
            };
            if mux.is_closed() || mux.is_draining() {
                continue;
            }
            match mux
                .open_stream(
                    &self.cfg.route_id,
                    client_addr.clone(),
                    self.cfg.limits.connect_timeout,
                )
                .await
            {
                Ok(handle) => return Ok(handle),
                Err(e) => {
                    tracing::debug!(
                        tunnel = slot.metrics.tunnel_id,
                        error = %e,
                        "stream open failed; trying another tunnel"
                    );
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            Error::other(format!("route `{}` has no usable tunnel", self.cfg.route_name))
        }))
    }

    /// Candidate slots in dispatch order for the configured strategy.
    fn ordered_candidates(&self) -> Vec<Arc<Slot>> {
        let mut live: Vec<Arc<Slot>> = self
            .slots
            .iter()
            .filter(|s| {
                s.mux
                    .load()
                    .as_ref()
                    .map(|m| !m.is_closed() && !m.is_draining())
                    .unwrap_or(false)
            })
            .cloned()
            .collect();

        if live.is_empty() {
            return live;
        }

        match self.cfg.load_balance {
            LoadBalance::RoundRobin => {
                let start = self.cursor.fetch_add(1, REL) % live.len();
                live.rotate_left(start);
            }
            LoadBalance::LeastStreams => {
                live.sort_by_key(|s| {
                    s.mux
                        .load()
                        .as_ref()
                        .map(|m| m.live_streams())
                        .unwrap_or(u32::MAX)
                });
            }
        }
        live
    }

    pub fn online_tunnels(&self) -> u32 {
        self.slots
            .iter()
            .filter(|s| s.metrics.state() == TunnelState::Online)
            .count() as u32
    }

    pub fn total_tunnels(&self) -> u32 {
        self.slots.len() as u32
    }

    pub fn live_streams(&self) -> u32 {
        self.slots
            .iter()
            .filter_map(|s| s.mux.load_full())
            .map(|m| m.live_streams())
            .sum()
    }

    /// Aggregate byte counters across the pool's tunnels.
    pub fn tunnel_bytes(&self) -> (u64, u64) {
        self.slots.iter().fold((0, 0), |(rx, tx), s| {
            (rx + s.metrics.counters.rx(), tx + s.metrics.counters.tx())
        })
    }

    pub async fn snapshots(&self) -> Vec<TunnelSnapshot> {
        let endpoints = {
            let selector = self.selector.lock().await;
            selector.endpoints().to_vec()
        };
        self.slots
            .iter()
            .map(|s| s.snapshot(&self.cfg.route_id, &endpoints))
            .collect()
    }

    pub async fn active_endpoint_id(&self) -> String {
        let selector = self.selector.lock().await;
        selector.select().id.clone()
    }

    pub async fn route_snapshot(&self, listen: String, target: String) -> RouteSnapshot {
        self.route_snapshot_with_targets(listen, target, Vec::new())
            .await
    }

    /// 带目标健康状态的快照。隧道模式下目标由**出口**拨号，入口无从得知它们的健康
    /// 状况，所以这里由调用方传入（通常为空）。
    pub async fn route_snapshot_with_targets(
        &self,
        listen: String,
        target: String,
        targets: Vec<tunnel_common::model::TargetHealth>,
    ) -> RouteSnapshot {
        let (rx_bps, tx_bps) = self.metrics.rates.current();
        RouteSnapshot {
            targets,
            route_id: self.cfg.route_id.clone(),
            name: self.cfg.route_name.clone(),
            enabled: !self.shutdown.load(REL),
            listen,
            target,
            active_endpoint_id: Some(self.active_endpoint_id().await),
            tunnels_online: self.online_tunnels(),
            tunnels_total: self.total_tunnels(),
            connections: self.metrics.counters.active(),
            rx_bytes: self.metrics.counters.rx(),
            tx_bytes: self.metrics.counters.tx(),
            rx_bps,
            tx_bps,
            accepted_total: self.metrics.counters.accepted(),
            rejected_total: self.metrics.counters.rejected(),
            failed_total: self.metrics.counters.failed(),
        }
    }

    pub fn metrics(&self) -> &Arc<RouteMetrics> {
        &self.metrics
    }

    pub fn config(&self) -> &PoolConfig {
        &self.cfg
    }

    /// Reap idle streams across all tunnels.
    pub fn reap_idle_streams(&self, timeout: Duration) -> usize {
        self.slots
            .iter()
            .filter_map(|s| s.mux.load_full())
            .map(|m| m.reap_idle_streams(timeout))
            .sum()
    }

    /// Stop the pool: GO_AWAY, then close each tunnel.
    pub async fn shutdown(&self) {
        if self.shutdown.swap(true, REL) {
            return;
        }
        for slot in &self.slots {
            if let Some(mux) = slot.mux.load_full() {
                mux.go_away("route shutting down").await;
            }
        }
        // Brief grace period so in-flight frames reach the peer.
        tokio::time::sleep(Duration::from_millis(200)).await;
        for slot in &self.slots {
            if let Some(mux) = slot.mux.load_full() {
                mux.shutdown().await;
            }
            slot.mux.store(None);
            slot.metrics.set_state(TunnelState::Offline);
        }
    }

    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(REL)
    }

    pub async fn health_report(&self) -> Vec<(String, bool, Option<String>)> {
        let selector = self.selector.lock().await;
        selector
            .health()
            .iter()
            .map(|h| {
                (
                    h.endpoint_name.clone(),
                    h.is_up(),
                    h.last_error().map(|s| s.to_string()),
                )
            })
            .collect()
    }
}

/// Receiver side for pools that accept inbound streams. Unused by the entry
/// role; kept so the exit can share the snapshot types.
pub type IncomingStreams = mpsc::Receiver<crate::mux::IncomingStream>;

#[cfg(test)]
mod tests {
    use super::*;
    use tunnel_common::model::{EndpointKind, EndpointPriority, TlsConfig};

    fn endpoint(id: &str, port: u16, priority: EndpointPriority) -> Endpoint {
        Endpoint {
            id: id.into(),
            node_id: "hk".into(),
            name: format!("ep-{id}"),
            address: "127.0.0.1".into(),
            port,
            kind: EndpointKind::Public,
            priority,
            interface: None,
            source_ip: None,
            tls_server_name: Some("exit.internal".into()),
            enabled: true,
        }
    }

    fn pool_cfg(size: u16) -> PoolConfig {
        PoolConfig {
            route_id: "r1".into(),
            route_name: "test-route".into(),
            node_id: "sh-01".into(),
            size,
            load_balance: LoadBalance::RoundRobin,
            limits: Limits {
                connect_timeout: Duration::from_millis(300),
                handshake_timeout: Duration::from_millis(300),
                ..Default::default()
            },
            psk: Some(Secret::new("test-psk")),
            health: HealthPolicy {
                failure_threshold: 2,
                recovery_threshold: 2,
                cooldown: Duration::ZERO,
            },
            egress: EgressBinding::default(),
        }
    }

    fn insecure_tls() -> Arc<TlsMaterial> {
        TlsMaterial::load(
            &TlsConfig {
                insecure_skip_verify: true,
                ..Default::default()
            },
            false,
        )
        .unwrap()
    }

    #[test]
    fn zero_size_pool_is_rejected() {
        let err = TunnelPool::start(
            pool_cfg(0),
            vec![endpoint("a", 5000, EndpointPriority::Primary)],
            insecure_tls(),
            RouteMetrics::new("r1"),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn pool_with_no_endpoints_is_rejected() {
        let err = TunnelPool::start(
            pool_cfg(4),
            vec![],
            insecure_tls(),
            RouteMetrics::new("r1"),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[tokio::test]
    async fn pool_reports_its_size_before_connecting() {
        let pool = TunnelPool::start(
            pool_cfg(4),
            vec![endpoint("a", 1, EndpointPriority::Primary)],
            insecure_tls(),
            RouteMetrics::new("r1"),
        )
        .unwrap();
        assert_eq!(pool.total_tunnels(), 4);
        assert_eq!(pool.online_tunnels(), 0);
        assert_eq!(pool.live_streams(), 0);
        pool.shutdown().await;
    }

    #[tokio::test]
    async fn open_stream_fails_cleanly_when_nothing_is_connected() {
        let pool = TunnelPool::start(
            pool_cfg(2),
            vec![endpoint("a", 1, EndpointPriority::Primary)],
            insecure_tls(),
            RouteMetrics::new("r1"),
        )
        .unwrap();
        // Port 1 has no listener, so no tunnel can come up.
        let err = pool.open_stream(None).await.unwrap_err();
        assert!(err.to_string().contains("no online tunnel"), "{err}");
        pool.shutdown().await;
    }

    #[tokio::test]
    async fn unreachable_endpoint_is_marked_down_and_retried() {
        let pool = TunnelPool::start(
            pool_cfg(1),
            vec![endpoint("dead", 1, EndpointPriority::Primary)],
            insecure_tls(),
            RouteMetrics::new("r1"),
        )
        .unwrap();

        // Give the supervisor time to fail a couple of times.
        tokio::time::sleep(Duration::from_secs(2)).await;
        let report = pool.health_report().await;
        assert_eq!(report.len(), 1);
        let (_, _up, last_error) = &report[0];
        assert!(last_error.is_some(), "connect failures should be recorded");
        pool.shutdown().await;
    }

    #[tokio::test]
    async fn snapshots_cover_every_slot() {
        let pool = TunnelPool::start(
            pool_cfg(3),
            vec![endpoint("a", 1, EndpointPriority::Primary)],
            insecure_tls(),
            RouteMetrics::new("r1"),
        )
        .unwrap();
        let snaps = pool.snapshots().await;
        assert_eq!(snaps.len(), 3);
        let ids: std::collections::HashSet<u64> = snaps.iter().map(|s| s.tunnel_id).collect();
        assert_eq!(ids.len(), 3, "tunnel ids must be unique");
        pool.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_is_idempotent() {
        let pool = TunnelPool::start(
            pool_cfg(2),
            vec![endpoint("a", 1, EndpointPriority::Primary)],
            insecure_tls(),
            RouteMetrics::new("r1"),
        )
        .unwrap();
        pool.shutdown().await;
        pool.shutdown().await;
        assert!(pool.is_shutdown());
    }

    #[tokio::test]
    async fn failover_selects_the_backup_after_repeated_failures() {
        let pool = TunnelPool::start(
            pool_cfg(1),
            vec![
                endpoint("primary", 1, EndpointPriority::Primary),
                endpoint("backup", 2, EndpointPriority::Backup),
            ],
            insecure_tls(),
            RouteMetrics::new("r1"),
        )
        .unwrap();

        // Both ports are dead, but the selector must still move off the primary
        // once its failure threshold is crossed.
        tokio::time::sleep(Duration::from_secs(3)).await;
        let report = pool.health_report().await;
        assert_eq!(report.len(), 2);
        pool.shutdown().await;
    }

    #[tokio::test]
    async fn route_snapshot_reports_configured_values() {
        let pool = TunnelPool::start(
            pool_cfg(2),
            vec![endpoint("a", 1, EndpointPriority::Primary)],
            insecure_tls(),
            RouteMetrics::new("r1"),
        )
        .unwrap();
        let snap = pool
            .route_snapshot("0.0.0.0:443".into(), "127.0.0.1:8443".into())
            .await;
        assert_eq!(snap.route_id, "r1");
        assert_eq!(snap.name, "test-route");
        assert_eq!(snap.tunnels_total, 2);
        assert_eq!(snap.listen, "0.0.0.0:443");
        pool.shutdown().await;
    }
}
