//! Shared application state and the live telemetry hub.
//!
//! # Why telemetry is held in memory
//!
//! Agent reports arrive every few seconds and are read by the dashboard on every
//! refresh. Persisting each one and querying it back would put a write and a read
//! on SQLite's single writer for data that is stale within seconds. Instead the
//! latest report per node lives in a [`DashMap`], and only rolled-up counters are
//! written to `traffic_stats` on the aggregation interval.
//!
//! This means live telemetry does not survive a control-plane restart. That is
//! correct: after a restart the agents' next heartbeat repopulates it within
//! seconds, and historical data is what the database is for.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde::Serialize;
use tokio::sync::broadcast;
use tunnel_common::model::{AgentReport, ConnectionSnapshot};
use tunnel_storage::Database;

use crate::auth::{LoginThrottle, TokenIssuer};
use crate::config::ControlConfig;

const REL: Ordering = Ordering::Relaxed;

/// Capacity of the WebSocket broadcast channel.
///
/// A slow browser tab must not be able to stall the reporting loop, so this is
/// bounded and lagging receivers are dropped rather than waited for.
const BROADCAST_CAPACITY: usize = 256;

/// Latest report from one node, plus arrival time.
#[derive(Debug, Clone)]
pub struct LiveReport {
    pub report: AgentReport,
    pub received_at: Instant,
}

impl LiveReport {
    pub fn age(&self) -> Duration {
        self.received_at.elapsed()
    }
}

/// Events pushed to connected browsers.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// Incremental telemetry for one node.
    NodeReport {
        node_id: String,
        node_name: String,
        report: Box<AgentReport>,
    },
    /// A node crossed the staleness threshold.
    NodeOffline { node_id: String, node_name: String },
    /// Configuration changed; the panel should refetch the affected collection.
    ConfigChanged { entity: String },
    /// Periodic fleet summary for the dashboard header.
    Summary(Box<FleetSummary>),
}

/// Aggregate figures for the dashboard.
#[derive(Debug, Clone, Default, Serialize)]
pub struct FleetSummary {
    pub nodes_online: u32,
    pub nodes_offline: u32,
    pub nodes_degraded: u32,
    pub routes_total: u32,
    pub routes_enabled: u32,
    pub tunnels_online: u32,
    pub tunnels_total: u32,
    pub connections: u32,
    pub rx_bps: u64,
    pub tx_bps: u64,
    pub total_rx_bytes: u64,
    pub total_tx_bytes: u64,
}

pub struct AppState {
    pub db: Database,
    pub config: arc_swap::ArcSwap<ControlConfig>,
    pub tokens: TokenIssuer,
    pub throttle: LoginThrottle,
    /// Latest report per node id.
    reports: DashMap<String, LiveReport>,
    /// Event fan-out to WebSocket clients.
    events: broadcast::Sender<Event>,
    /// Count of reports received, for diagnostics.
    reports_received: AtomicU64,
    started_at: Instant,
}

impl AppState {
    pub fn new(db: Database, config: ControlConfig) -> Arc<Self> {
        let tokens = TokenIssuer::new(&config.auth.jwt_secret, config.auth.token_ttl);
        let throttle = LoginThrottle::new(
            config.auth.login_attempt_limit,
            config.auth.login_lockout,
        );
        let (events, _) = broadcast::channel(BROADCAST_CAPACITY);

        Arc::new(Self {
            db,
            config: arc_swap::ArcSwap::from_pointee(config),
            tokens,
            throttle,
            reports: DashMap::new(),
            events,
            reports_received: AtomicU64::new(0),
            started_at: Instant::now(),
        })
    }

    pub fn config(&self) -> Arc<ControlConfig> {
        self.config.load_full()
    }

    pub fn uptime(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// agent 应当连接的面板地址。
    ///
    /// 优先用配置里的 `public_url`：`listen` 往常是 `127.0.0.1:8080`（反代后面），
    /// 把它写进安装命令会让远程机器连不上。回落到 `listen` 时调用方会给出警告。
    pub fn panel_url(&self) -> String {
        let cfg = self.config();
        match &cfg.public_url {
            Some(url) => url.trim_end_matches('/').to_string(),
            None => format!("http://{}", cfg.listen),
        }
    }

    pub fn reports_received(&self) -> u64 {
        self.reports_received.load(REL)
    }

    /// Store a report and broadcast it.
    pub fn ingest_report(&self, node_name: &str, report: AgentReport) {
        let node_id = report.node_id.clone();
        self.reports_received.fetch_add(1, REL);
        self.reports.insert(
            node_id.clone(),
            LiveReport {
                report: report.clone(),
                received_at: Instant::now(),
            },
        );
        self.broadcast(Event::NodeReport {
            node_id,
            node_name: node_name.to_string(),
            report: Box::new(report),
        });
    }

    /// Send an event to every connected client.
    ///
    /// Failure means nobody is listening, which is normal and not an error.
    pub fn broadcast(&self, event: Event) {
        let _ = self.events.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    pub fn subscriber_count(&self) -> usize {
        self.events.receiver_count()
    }

    pub fn report_for(&self, node_id: &str) -> Option<LiveReport> {
        self.reports.get(node_id).map(|r| r.clone())
    }

    pub fn all_reports(&self) -> Vec<LiveReport> {
        self.reports.iter().map(|r| r.value().clone()).collect()
    }

    /// Node ids whose last report is older than `stale_after`.
    pub fn stale_nodes(&self, stale_after: Duration) -> Vec<String> {
        self.reports
            .iter()
            .filter(|r| r.value().age() > stale_after)
            .map(|r| r.key().clone())
            .collect()
    }

    /// Forget a node's telemetry, e.g. after deletion.
    pub fn drop_report(&self, node_id: &str) {
        self.reports.remove(node_id);
    }

    /// Live connections across the fleet, longest-running first, bounded.
    ///
    /// Assembled from the bounded samples each agent reports, so this cannot
    /// balloon regardless of how much traffic the fleet is carrying.
    pub fn connections(&self, limit: usize, stale_after: Duration) -> Vec<ConnectionSnapshot> {
        let mut all: Vec<ConnectionSnapshot> = Vec::new();
        for entry in self.reports.iter() {
            let live = entry.value();
            if live.age() > stale_after {
                continue;
            }
            all.extend(live.report.connection_samples.iter().cloned());
        }
        // 最老的连接排在前面：截断后保留的是存活最久的那些，排查卡住的连接时
        // 最有用。
        all.sort_by_key(|c| std::cmp::Reverse(c.age_secs));
        all.truncate(limit);
        all
    }

    /// Compute the fleet summary from live reports.
    ///
    /// Counts only nodes whose report is fresh, so a departed node stops
    /// contributing bandwidth to the dashboard instead of freezing its last
    /// value there forever.
    pub fn summary(&self, stale_after: Duration) -> FleetSummary {
        let mut s = FleetSummary::default();
        for entry in self.reports.iter() {
            let live = entry.value();
            if live.age() > stale_after {
                s.nodes_offline += 1;
                continue;
            }
            let report = &live.report;
            s.nodes_online += 1;
            s.connections += report.connections;
            s.rx_bps += report.rx_bps;
            s.tx_bps += report.tx_bps;
            s.total_rx_bytes += report.rx_bytes;
            s.total_tx_bytes += report.tx_bytes;
            s.tunnels_total += report.tunnels.len() as u32;
            s.tunnels_online += report
                .tunnels
                .iter()
                .filter(|t| t.state == tunnel_common::model::TunnelState::Online)
                .count() as u32;
            // A node reporting some tunnels down is degraded, not offline.
            if report
                .tunnels
                .iter()
                .any(|t| t.state != tunnel_common::model::TunnelState::Online)
            {
                s.nodes_degraded += 1;
            }
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnel_common::model::{
        EndpointKind, HostStats, NodeRole, RouteSnapshot, TunnelSnapshot, TunnelState,
    };

    async fn state() -> Arc<AppState> {
        let db = Database::connect_in_memory().await.unwrap();
        let mut cfg = ControlConfig::default();
        cfg.ensure_jwt_secret();
        AppState::new(db, cfg)
    }

    fn tunnel(state: TunnelState) -> TunnelSnapshot {
        TunnelSnapshot {
            tunnel_id: 1,
            route_id: "r1".into(),
            endpoint_id: "e1".into(),
            endpoint_name: "hk-iepl".into(),
            endpoint_kind: EndpointKind::Iepl,
            state,
            streams: 3,
            rx_bytes: 100,
            tx_bytes: 200,
            rtt_ms: Some(12),
            established_secs: 60,
            reconnects: 0,
        }
    }

    fn report(node_id: &str, rx_bps: u64, tunnels: Vec<TunnelSnapshot>) -> AgentReport {
        AgentReport {
            node_id: node_id.into(),
            agent_version: "0.1.0".into(),
            config_revision: 1,
            role: NodeRole::Both,
            host: HostStats::default(),
            interfaces: vec![],
            routes: vec![RouteSnapshot {
                route_id: "r1".into(),
                name: "sh-hk".into(),
                enabled: true,
                listen: "0.0.0.0:443".into(),
                target: "127.0.0.1:8443".into(),
                active_endpoint_id: Some("e1".into()),
                tunnels_online: 1,
                tunnels_total: 1,
                connections: 5,
                rx_bytes: 1000,
                tx_bytes: 2000,
                rx_bps,
                tx_bps: rx_bps / 2,
                accepted_total: 10,
                rejected_total: 0,
                failed_total: 0,
                targets: vec![],
            }],
            tunnels,
            connection_samples: vec![ConnectionSnapshot {
                id: 1,
                route_id: "r1".into(),
                route_name: "sh-hk".into(),
                tunnel_id: 1,
                stream_id: 7,
                client_addr: "198.51.100.9:54321".into(),
                target: "127.0.0.1:8443".into(),
                rx_bytes: 500,
                tx_bytes: 600,
                age_secs: 30,
                idle_secs: 1,
            }],
            connections: 5,
            rx_bytes: 1000,
            tx_bytes: 2000,
            rx_bps,
            tx_bps: rx_bps / 2,
            reported_at: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn ingest_then_read_back() {
        let state = state().await;
        state.ingest_report("sh-01", report("n1", 1000, vec![tunnel(TunnelState::Online)]));

        assert_eq!(state.reports_received(), 1);
        let live = state.report_for("n1").expect("report stored");
        assert_eq!(live.report.node_id, "n1");
        assert!(live.age() < Duration::from_secs(1));
        assert_eq!(state.all_reports().len(), 1);
    }

    #[tokio::test]
    async fn newer_report_replaces_the_previous_one() {
        let state = state().await;
        state.ingest_report("sh-01", report("n1", 1000, vec![]));
        state.ingest_report("sh-01", report("n1", 5000, vec![]));

        assert_eq!(state.all_reports().len(), 1, "reports must not accumulate");
        assert_eq!(state.report_for("n1").unwrap().report.rx_bps, 5000);
        assert_eq!(state.reports_received(), 2);
    }

    #[tokio::test]
    async fn summary_aggregates_across_nodes() {
        let state = state().await;
        state.ingest_report("sh-01", report("n1", 1000, vec![tunnel(TunnelState::Online)]));
        state.ingest_report("hk-01", report("n2", 2000, vec![tunnel(TunnelState::Online)]));

        let s = state.summary(Duration::from_secs(60));
        assert_eq!(s.nodes_online, 2);
        assert_eq!(s.nodes_offline, 0);
        assert_eq!(s.rx_bps, 3000);
        assert_eq!(s.connections, 10);
        assert_eq!(s.tunnels_online, 2);
        assert_eq!(s.tunnels_total, 2);
        assert_eq!(s.nodes_degraded, 0);
    }

    #[tokio::test]
    async fn stale_nodes_stop_contributing_bandwidth() {
        // Otherwise a departed node's last reading is frozen into the dashboard
        // and the graph never returns to zero.
        let state = state().await;
        state.ingest_report("sh-01", report("n1", 9999, vec![tunnel(TunnelState::Online)]));

        let s = state.summary(Duration::ZERO);
        assert_eq!(s.nodes_online, 0);
        assert_eq!(s.nodes_offline, 1);
        assert_eq!(s.rx_bps, 0, "stale node still counted toward bandwidth");
        assert_eq!(s.connections, 0);
    }

    #[tokio::test]
    async fn a_node_with_a_down_tunnel_is_degraded() {
        let state = state().await;
        state.ingest_report(
            "sh-01",
            report(
                "n1",
                1000,
                vec![tunnel(TunnelState::Online), tunnel(TunnelState::Offline)],
            ),
        );
        let s = state.summary(Duration::from_secs(60));
        assert_eq!(s.nodes_online, 1);
        assert_eq!(s.nodes_degraded, 1);
        assert_eq!(s.tunnels_online, 1);
        assert_eq!(s.tunnels_total, 2);
    }

    #[tokio::test]
    async fn stale_node_detection() {
        let state = state().await;
        state.ingest_report("sh-01", report("n1", 1000, vec![]));

        assert!(state.stale_nodes(Duration::from_secs(60)).is_empty());
        assert_eq!(state.stale_nodes(Duration::ZERO), vec!["n1".to_string()]);
    }

    #[tokio::test]
    async fn dropping_a_report_removes_it_from_the_summary() {
        let state = state().await;
        state.ingest_report("sh-01", report("n1", 1000, vec![]));
        state.drop_report("n1");
        assert!(state.report_for("n1").is_none());
        assert_eq!(state.summary(Duration::from_secs(60)).nodes_online, 0);
    }

    #[tokio::test]
    async fn connections_are_collected_and_bounded() {
        let state = state().await;
        state.ingest_report("sh-01", report("n1", 1000, vec![]));
        state.ingest_report("hk-01", report("n2", 1000, vec![]));

        let conns = state.connections(10, Duration::from_secs(60));
        assert_eq!(conns.len(), 2, "one sample per reporting node");
        assert_eq!(conns[0].route_name, "sh-hk");

        // The limit is honoured so the API response stays bounded.
        assert_eq!(state.connections(1, Duration::from_secs(60)).len(), 1);
        // Stale nodes drop out, as with the summary.
        assert!(state.connections(10, Duration::ZERO).is_empty());
    }

    #[tokio::test]
    async fn events_reach_subscribers() {
        let state = state().await;
        let mut rx = state.subscribe();
        assert_eq!(state.subscriber_count(), 1);

        state.ingest_report("sh-01", report("n1", 1000, vec![]));
        let event = rx.try_recv().expect("event should be queued");
        match event {
            Event::NodeReport { node_id, node_name, .. } => {
                assert_eq!(node_id, "n1");
                assert_eq!(node_name, "sh-01");
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn broadcast_with_no_subscribers_is_not_an_error() {
        // The reporting loop runs whether or not a browser is open.
        let state = state().await;
        assert_eq!(state.subscriber_count(), 0);
        state.broadcast(Event::ConfigChanged {
            entity: "routes".into(),
        });
        state.ingest_report("sh-01", report("n1", 1, vec![]));
    }

    #[tokio::test]
    async fn a_slow_subscriber_cannot_stall_the_producer() {
        // The channel is bounded; a tab that stops reading must be dropped from
        // the stream rather than blocking telemetry for everyone.
        let state = state().await;
        let mut rx = state.subscribe();
        for i in 0..(BROADCAST_CAPACITY * 2) {
            state.ingest_report("sh-01", report(&format!("n{i}"), 1, vec![]));
        }
        // The receiver is now behind and must report lag, not deadlock.
        match rx.try_recv() {
            Err(broadcast::error::TryRecvError::Lagged(_)) => {}
            Ok(_) => {}
            Err(e) => panic!("unexpected receiver state: {e:?}"),
        }
        assert!(state.reports_received() >= BROADCAST_CAPACITY as u64 * 2);
    }

    #[tokio::test]
    async fn event_serialisation_is_tagged_for_the_client() {
        let event = Event::ConfigChanged {
            entity: "routes".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"config_changed\""), "{json}");

        let summary = Event::Summary(Box::default());
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"type\":\"summary\""), "{json}");
    }
}
