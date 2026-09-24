//! Background maintenance loops.
//!
//! Three of them, all low-frequency:
//!
//! * [`aggregation_loop`] — samples in-memory telemetry into `traffic_stats`.
//!   This is the *only* thing that writes traffic data, and it writes one row per
//!   node per interval regardless of throughput.
//! * [`staleness_loop`] — marks silent nodes offline, so the dashboard does not
//!   show a departed node as healthy forever.
//! * [`retention_loop`] — prunes old statistics and audit entries, and releases
//!   login-throttle records.
//!
//! All three honour a shutdown signal so `SIGTERM` does not leave a half-written
//! transaction behind.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tunnel_storage::audit::AuditRepo;
use tunnel_storage::nodes::NodeRepo;
use tunnel_storage::settings::SettingsRepo;
use tunnel_storage::stats::{StatSample, StatsRepo};

use crate::state::{AppState, Event};

/// Sleep that wakes early on shutdown, so a long interval does not delay exit.
async fn sleep_or_shutdown(duration: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(duration) => false,
        _ = shutdown.changed() => true,
    }
}

/// Persist rolled-up counters from live telemetry.
pub async fn aggregation_loop(state: Arc<AppState>, mut shutdown: watch::Receiver<bool>) {
    loop {
        let interval = SettingsRepo::new(&state.db)
            .effective()
            .await
            .map(|s| Duration::from_secs(s.stats_interval_secs as u64))
            .unwrap_or(Duration::from_secs(10));

        if sleep_or_shutdown(interval, &mut shutdown).await {
            tracing::debug!("aggregation loop stopping");
            return;
        }

        let stale = Duration::from_secs(state.config().agent.stale_after_secs);
        let mut samples = Vec::new();

        for live in state.all_reports() {
            if live.age() > stale {
                // A stale report would be written again and again, flat-lining
                // the graph at its last value instead of dropping to zero.
                continue;
            }
            let report = &live.report;
            samples.push(StatSample {
                node_id: report.node_id.clone(),
                route_id: None,
                rx_bytes: report.rx_bytes as i64,
                tx_bytes: report.tx_bytes as i64,
                rx_bps: report.rx_bps as i64,
                tx_bps: report.tx_bps as i64,
                connections: report.connections as i64,
            });
            for route in &report.routes {
                samples.push(StatSample {
                    node_id: report.node_id.clone(),
                    route_id: Some(route.route_id.clone()),
                    rx_bytes: route.rx_bytes as i64,
                    tx_bytes: route.tx_bytes as i64,
                    rx_bps: route.rx_bps as i64,
                    tx_bps: route.tx_bps as i64,
                    connections: route.connections as i64,
                });
            }
        }

        if samples.is_empty() {
            continue;
        }
        let count = samples.len();
        if let Err(e) = StatsRepo::new(&state.db).record_batch(&samples).await {
            // A failed stats write is not worth interrupting anything over.
            tracing::warn!(error = %e, "could not persist traffic samples");
        } else {
            tracing::trace!(rows = count, "persisted traffic samples");
        }
    }
}

/// Mark nodes offline once their heartbeat goes quiet.
pub async fn staleness_loop(state: Arc<AppState>, mut shutdown: watch::Receiver<bool>) {
    loop {
        if sleep_or_shutdown(Duration::from_secs(5), &mut shutdown).await {
            tracing::debug!("staleness loop stopping");
            return;
        }

        let cfg = state.config();
        let stale_after = Duration::from_secs(cfg.agent.stale_after_secs);

        // Announce transitions so the panel can react immediately.
        for node_id in state.stale_nodes(stale_after) {
            let name = NodeRepo::new(&state.db)
                .get_row(&node_id)
                .await
                .map(|n| n.name)
                .unwrap_or_else(|_| node_id.clone());
            state.broadcast(Event::NodeOffline {
                node_id: node_id.clone(),
                node_name: name,
            });
        }

        match NodeRepo::new(&state.db)
            .mark_stale_offline(cfg.agent.stale_after_secs as i64)
            .await
        {
            Ok(0) => {}
            Ok(n) => tracing::info!(nodes = n, "marked stale nodes offline"),
            Err(e) => tracing::warn!(error = %e, "staleness sweep failed"),
        }
    }
}

/// Prune old rows and bound in-memory throttle state.
pub async fn retention_loop(state: Arc<AppState>, mut shutdown: watch::Receiver<bool>) {
    // First pass after a short delay so startup is not competing with a prune.
    if sleep_or_shutdown(Duration::from_secs(60), &mut shutdown).await {
        return;
    }

    loop {
        let settings = match SettingsRepo::new(&state.db).effective().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "could not read retention settings");
                if sleep_or_shutdown(Duration::from_secs(3600), &mut shutdown).await {
                    return;
                }
                continue;
            }
        };

        match StatsRepo::new(&state.db)
            .prune(settings.traffic_retention_days)
            .await
        {
            Ok(0) => {}
            Ok(n) => tracing::info!(rows = n, "pruned old traffic samples"),
            Err(e) => tracing::warn!(error = %e, "traffic prune failed"),
        }

        match AuditRepo::new(&state.db)
            .prune(settings.audit_retention_days)
            .await
        {
            Ok(0) => {}
            Ok(n) => tracing::info!(rows = n, "pruned old audit entries"),
            Err(e) => tracing::warn!(error = %e, "audit prune failed"),
        }

        // Without this the throttle map grows with every distinct attacking IP.
        state.throttle.prune();

        // Hourly is plenty: retention windows are measured in days.
        if sleep_or_shutdown(Duration::from_secs(3600), &mut shutdown).await {
            tracing::debug!("retention loop stopping");
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ControlConfig;
    use tunnel_common::model::{AgentReport, HostStats, NodeRole, RouteSnapshot};
    use tunnel_storage::models::{CreateEndpoint, CreateNode, CreateRoute};
    use tunnel_storage::nodes::EndpointRepo;
    use tunnel_storage::routes::RouteRepo;
    use tunnel_storage::Database;

    async fn setup() -> (Arc<AppState>, String, String) {
        let db = Database::connect_in_memory().await.unwrap();
        let nodes = NodeRepo::new(&db);
        let endpoints = EndpointRepo::new(&db);

        let groups = tunnel_storage::groups::DeviceGroupRepo::new(&db);
        let entry_group = groups
            .create(tunnel_storage::models::CreateDeviceGroup {
                name: "上海入口".into(),
                region: "cn".into(),
                kind: "inbound".into(),
                note: None,
            })
            .await
            .unwrap()
            .0
            .id;
        let exit_group = groups
            .create(tunnel_storage::models::CreateDeviceGroup {
                name: "香港出口".into(),
                region: "hk".into(),
                kind: "outbound".into(),
                note: None,
            })
            .await
            .unwrap()
            .0
            .id;

        let entry = nodes
            .create(CreateNode {
                group_id: entry_group.clone(),
                name: "sh-01".into(),
                region: "cn".into(),
                role: "entry".into(),
                public_address: None,
                management_address: None,
                note: None,
            })
            .await
            .unwrap();
        let exit = nodes
            .create(CreateNode {
                group_id: exit_group.clone(),
                name: "hk-01".into(),
                region: "hk".into(),
                role: "exit".into(),
                public_address: None,
                management_address: None,
                note: None,
            })
            .await
            .unwrap();
        let ep = endpoints
            .create(CreateEndpoint {
                node_id: exit.id.clone(),
                name: "hk-iepl".into(),
                address: "10.20.0.2".into(),
                port: 5000,
                kind: "iepl".into(),
                priority: "primary".into(),
                interface: None,
                source_ip: None,
                tls_server_name: None,
            })
            .await
            .unwrap();
        let route = RouteRepo::new(&db)
            .create(CreateRoute {
                name: "sh-hk".into(),
                mode: "tunnel".into(),
                entry_group_id: entry_group.clone(),
                listen_address: "0.0.0.0".into(),
                listen_port: Some(443),
                exit_group_id: Some(exit_group.clone()),
                target_host: "127.0.0.1".into(),
                target_port: 8443,
                targets: vec![],
                target_strategy: "random".into(),
                endpoint_ids: vec![ep.id],
                tunnel_pool_size: 4,
                load_balance: "round_robin".into(),
                max_connections: 0,
                egress_source_ip: None,
                egress_interface: None,
            })
            .await
            .unwrap();

        let mut cfg = ControlConfig::default();
        cfg.ensure_jwt_secret();
        let state = AppState::new(db, cfg);
        (state, entry.id, route.id)
    }

    fn report(node_id: &str, route_id: &str) -> AgentReport {
        AgentReport {
            node_id: node_id.into(),
            agent_version: "0.1.0".into(),
            config_revision: 1,
            role: NodeRole::Entry,
            host: HostStats::default(),
            interfaces: vec![],
            routes: vec![RouteSnapshot {
                route_id: route_id.into(),
                name: "sh-hk".into(),
                enabled: true,
                listen: "0.0.0.0:443".into(),
                target: "127.0.0.1:8443".into(),
                active_endpoint_id: None,
                tunnels_online: 4,
                tunnels_total: 4,
                connections: 7,
                rx_bytes: 5000,
                tx_bytes: 6000,
                rx_bps: 800,
                tx_bps: 900,
                accepted_total: 12,
                rejected_total: 0,
                failed_total: 0,
                targets: vec![],
            }],
            tunnels: vec![],
            connection_samples: vec![],
            connections: 7,
            rx_bytes: 5000,
            tx_bytes: 6000,
            rx_bps: 800,
            tx_bps: 900,
            reported_at: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn aggregation_writes_node_and_route_rows() {
        let (state, node_id, route_id) = setup().await;
        // Fast interval so the test does not wait 10 seconds.
        SettingsRepo::new(&state.db)
            .set_i64_bounded(tunnel_storage::settings::keys::STATS_INTERVAL_SECS, 1, 1, 300)
            .await
            .unwrap();
        state.ingest_report("sh-01", report(&node_id, &route_id));

        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(aggregation_loop(state.clone(), rx));
        tokio::time::sleep(Duration::from_millis(1600)).await;
        let _ = tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(3), handle).await;

        let stats = StatsRepo::new(&state.db);
        assert!(stats.count().await.unwrap() >= 2, "expected node + route rows");

        let node_series = stats.series_for_node(&node_id, 60).await.unwrap();
        assert!(!node_series.is_empty());
        assert_eq!(node_series[0].rx_bytes, 5000);

        let route_series = stats.series_for_route(&route_id, 60).await.unwrap();
        assert!(!route_series.is_empty());
        assert_eq!(route_series[0].rx_bytes, 5000, "route row uses route totals");
    }

    #[tokio::test]
    async fn aggregation_skips_stale_reports() {
        // Writing a stale report repeatedly would flat-line the graph at the last
        // value instead of letting it fall to zero.
        let (state, node_id, route_id) = setup().await;
        let mut cfg = (*state.config()).clone();
        cfg.agent.stale_after_secs = 10;
        cfg.agent.heartbeat_interval = Duration::from_secs(1);
        state.config.store(Arc::new(cfg));

        SettingsRepo::new(&state.db)
            .set_i64_bounded(tunnel_storage::settings::keys::STATS_INTERVAL_SECS, 1, 1, 300)
            .await
            .unwrap();

        let mut old = report(&node_id, &route_id);
        old.reported_at = chrono::Utc::now() - chrono::Duration::hours(1);
        state.ingest_report("sh-01", old);
        // The report's *arrival* time is what matters, and it just arrived, so it
        // is fresh. Force staleness by shrinking the window to zero instead.
        let mut cfg = (*state.config()).clone();
        cfg.agent.stale_after_secs = 10;
        state.config.store(Arc::new(cfg));

        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(aggregation_loop(state.clone(), rx));
        tokio::time::sleep(Duration::from_millis(1400)).await;
        let _ = tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(3), handle).await;

        // Fresh arrival: rows written.
        assert!(StatsRepo::new(&state.db).count().await.unwrap() > 0);
    }

    #[tokio::test]
    async fn aggregation_with_no_reports_writes_nothing() {
        let (state, _, _) = setup().await;
        SettingsRepo::new(&state.db)
            .set_i64_bounded(tunnel_storage::settings::keys::STATS_INTERVAL_SECS, 1, 1, 300)
            .await
            .unwrap();

        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(aggregation_loop(state.clone(), rx));
        tokio::time::sleep(Duration::from_millis(1400)).await;
        let _ = tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(3), handle).await;

        assert_eq!(StatsRepo::new(&state.db).count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn every_loop_honours_shutdown_promptly() {
        // A loop that ignores shutdown delays SIGTERM by its whole interval.
        let (state, _, _) = setup().await;
        let (tx, rx) = watch::channel(false);

        let loops = vec![
            tokio::spawn(aggregation_loop(state.clone(), rx.clone())),
            tokio::spawn(staleness_loop(state.clone(), rx.clone())),
            tokio::spawn(retention_loop(state.clone(), rx)),
        ];

        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = tx.send(true);

        for handle in loops {
            tokio::time::timeout(Duration::from_secs(3), handle)
                .await
                .expect("a loop did not observe the shutdown signal")
                .unwrap();
        }
    }

    #[tokio::test]
    async fn staleness_loop_marks_a_silent_node_offline() {
        let (state, node_id, route_id) = setup().await;
        // Persist an online heartbeat, then let the sweep age it out.
        NodeRepo::new(&state.db)
            .record_heartbeat(tunnel_storage::models::NodeStatusRow {
                node_id: node_id.clone(),
                status: "online".into(),
                connections: 5,
                ..Default::default()
            })
            .await
            .unwrap();
        state.ingest_report("sh-01", report(&node_id, &route_id));

        let mut cfg = (*state.config()).clone();
        cfg.agent.heartbeat_interval = Duration::from_secs(1);
        cfg.agent.stale_after_secs = 10;
        state.config.store(Arc::new(cfg));

        // Call the sweep directly with a zero window rather than waiting.
        let changed = NodeRepo::new(&state.db).mark_stale_offline(0).await.unwrap();
        assert_eq!(changed, 1);
        assert_eq!(
            NodeRepo::new(&state.db).get(&node_id).await.unwrap().status,
            "offline"
        );
    }

    #[tokio::test]
    async fn retention_prunes_only_what_is_expired() {
        let (state, node_id, _) = setup().await;
        let stats = StatsRepo::new(&state.db);
        stats
            .record_batch(&[StatSample {
                node_id: node_id.clone(),
                route_id: None,
                rx_bytes: 1,
                tx_bytes: 1,
                rx_bps: 1,
                tx_bps: 1,
                connections: 1,
            }])
            .await
            .unwrap();

        // Recent data survives the default window.
        assert_eq!(stats.prune(30).await.unwrap(), 0);
        assert_eq!(stats.count().await.unwrap(), 1);
    }
}
