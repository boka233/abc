//! Traffic statistics repository.
//!
//! # Write discipline
//!
//! Nothing here is called from a relay path. The data plane keeps `AtomicU64`
//! counters in memory; the control plane's aggregation loop samples them on a
//! bucket interval and writes **one row per node (plus one per route)** per
//! bucket. At a 10-second bucket and 20 nodes that is ~2 inserts/second
//! regardless of whether the system is moving 1 Mbps or 10 Gbps.
//!
//! Writing per connection — let alone per packet — would put SQLite's write lock
//! in the path of user traffic. That is the mistake this design exists to avoid.
//!
//! # Retention
//!
//! Rows accumulate forever without a sweep. [`StatsRepo::prune`] drops buckets
//! older than a cutoff and is expected to run on a timer.

use crate::db::{now_string, Database, Result};
use crate::models::TrafficPoint;
use serde::Serialize;
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct DailyRouteTraffic {
    pub route_id: String,
    pub route_name: String,
    pub rx_bytes: i64,
    pub tx_bytes: i64,
}

/// One node's counters at a point in time.
#[derive(Debug, Clone)]
pub struct StatSample {
    pub node_id: String,
    /// `None` for the node-level roll-up.
    pub route_id: Option<String>,
    pub rx_bytes: i64,
    pub tx_bytes: i64,
    pub rx_bps: i64,
    pub tx_bps: i64,
    pub connections: i64,
}

pub struct StatsRepo<'a> {
    db: &'a Database,
}

impl<'a> StatsRepo<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Persist a batch of samples in one transaction.
    ///
    /// Batched because SQLite commits are the expensive part: 40 separate
    /// inserts cost 40 fsyncs, one transaction costs one.
    pub async fn record_batch(&self, samples: &[StatSample]) -> Result<()> {
        if samples.is_empty() {
            return Ok(());
        }
        let bucket = now_string();
        let mut tx = self.db.pool().begin().await?;
        for s in samples {
            sqlx::query(
                "INSERT INTO traffic_stats
                 (bucket_at, node_id, route_id, rx_bytes, tx_bytes, rx_bps, tx_bps, connections)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&bucket)
            .bind(&s.node_id)
            .bind(&s.route_id)
            .bind(s.rx_bytes)
            .bind(s.tx_bytes)
            .bind(s.rx_bps)
            .bind(s.tx_bps)
            .bind(s.connections)
            .execute(&mut *tx)
            .await?;
            if s.route_id.is_none() {
                sqlx::query(
                    "INSERT INTO node_traffic_totals
                     (node_id, total_rx_bytes, total_tx_bytes, last_rx_bytes, last_tx_bytes)
                     VALUES (?, ?, ?, ?, ?)
                     ON CONFLICT (node_id) DO UPDATE SET
                       total_rx_bytes = total_rx_bytes + CASE
                         WHEN excluded.last_rx_bytes >= last_rx_bytes
                         THEN excluded.last_rx_bytes - last_rx_bytes
                         ELSE excluded.last_rx_bytes END,
                       total_tx_bytes = total_tx_bytes + CASE
                         WHEN excluded.last_tx_bytes >= last_tx_bytes
                         THEN excluded.last_tx_bytes - last_tx_bytes
                         ELSE excluded.last_tx_bytes END,
                       last_rx_bytes = excluded.last_rx_bytes,
                       last_tx_bytes = excluded.last_tx_bytes",
                )
                .bind(&s.node_id)
                .bind(s.rx_bytes.max(0))
                .bind(s.tx_bytes.max(0))
                .bind(s.rx_bytes.max(0))
                .bind(s.tx_bytes.max(0))
                .execute(&mut *tx)
                .await?;
            }
        }
        tx.commit().await?;
        Ok(())
    }

    /// Node-level series for the last `minutes`.
    pub async fn series_for_node(&self, node_id: &str, minutes: i64) -> Result<Vec<TrafficPoint>> {
        let cutoff = (chrono::Utc::now() - chrono::Duration::minutes(minutes.max(1))).to_rfc3339();
        let rows: Vec<TrafficPoint> = sqlx::query_as(
            "SELECT bucket_at, rx_bytes, tx_bytes, rx_bps, tx_bps, connections
             FROM traffic_stats
             WHERE node_id = ? AND route_id IS NULL AND bucket_at >= ?
             ORDER BY bucket_at",
        )
        .bind(node_id)
        .bind(cutoff)
        .fetch_all(self.db.pool())
        .await?;
        Ok(rows)
    }

    pub async fn series_for_route(&self, route_id: &str, minutes: i64) -> Result<Vec<TrafficPoint>> {
        let cutoff = (chrono::Utc::now() - chrono::Duration::minutes(minutes.max(1))).to_rfc3339();
        let rows: Vec<TrafficPoint> = sqlx::query_as(
            "SELECT bucket_at, rx_bytes, tx_bytes, rx_bps, tx_bps, connections
             FROM traffic_stats
             WHERE route_id = ? AND bucket_at >= ?
             ORDER BY bucket_at",
        )
        .bind(route_id)
        .bind(cutoff)
        .fetch_all(self.db.pool())
        .await?;
        Ok(rows)
    }

    /// Fleet-wide series: node-level rows summed per bucket.
    ///
    /// `route_id IS NULL` filters to roll-up rows so per-route rows are not
    /// double-counted into the total.
    pub async fn series_total(&self, minutes: i64) -> Result<Vec<TrafficPoint>> {
        let cutoff = (chrono::Utc::now() - chrono::Duration::minutes(minutes.max(1))).to_rfc3339();
        let rows: Vec<TrafficPoint> = sqlx::query_as(
            "SELECT bucket_at,
                    SUM(rx_bytes) AS rx_bytes,
                    SUM(tx_bytes) AS tx_bytes,
                    SUM(rx_bps)   AS rx_bps,
                    SUM(tx_bps)   AS tx_bps,
                    SUM(connections) AS connections
             FROM traffic_stats
             WHERE route_id IS NULL AND bucket_at >= ?
             GROUP BY bucket_at
             ORDER BY bucket_at",
        )
        .bind(cutoff)
        .fetch_all(self.db.pool())
        .await?;
        Ok(rows)
    }

    /// Cumulative totals across the fleet.
    ///
    /// The ledger adds only counter deltas and survives agent restarts and pruning.
    pub async fn lifetime_totals(&self) -> Result<(i64, i64)> {
        let row: Option<(Option<i64>, Option<i64>)> = sqlx::query_as(
            "SELECT SUM(total_rx_bytes), SUM(total_tx_bytes) FROM node_traffic_totals",
        )
        .fetch_optional(self.db.pool())
        .await?;
        Ok(match row {
            Some((rx, tx)) => (rx.unwrap_or(0), tx.unwrap_or(0)),
            None => (0, 0),
        })
    }

    pub async fn node_lifetime_totals(&self, node_id: &str) -> Result<(i64, i64)> {
        let row: Option<(i64, i64)> = sqlx::query_as(
            "SELECT total_rx_bytes, total_tx_bytes FROM node_traffic_totals WHERE node_id = ?",
        )
        .bind(node_id)
        .fetch_optional(self.db.pool())
        .await?;
        Ok(row.unwrap_or((0, 0)))
    }

    /// One local calendar day's traffic per route, using UTC boundaries supplied
    /// by the caller. Route snapshots come from entry nodes, so the same tunneled
    /// bytes are not counted again on the exit node.
    ///
    /// Counters are cumulative. Each sample contributes its difference from the
    /// preceding sample of that node and route, including the sample before the
    /// day starts. A reset contributes the new counter value. Without a preceding
    /// sample, the first reading is a baseline rather than traffic for this day.
    pub async fn daily_routes(
        &self,
        start_utc: &str,
        end_utc: &str,
    ) -> Result<Vec<DailyRouteTraffic>> {
        let rows = sqlx::query_as::<_, DailyRouteTraffic>(
            "WITH daily AS (
                 SELECT node_id, route_id, rx_bytes, tx_bytes,
                        LAG(rx_bytes) OVER sequence AS previous_rx,
                        LAG(tx_bytes) OVER sequence AS previous_tx
                 FROM traffic_stats
                 WHERE route_id IS NOT NULL AND bucket_at >= ? AND bucket_at < ?
                 WINDOW sequence AS (
                     PARTITION BY node_id, route_id ORDER BY bucket_at, id
                 )
             ), with_baseline AS (
                 SELECT daily.*,
                        CASE WHEN previous_rx IS NULL THEN (
                            SELECT p.rx_bytes FROM traffic_stats p
                            WHERE p.node_id = daily.node_id AND p.route_id = daily.route_id
                              AND p.bucket_at < ?
                            ORDER BY p.bucket_at DESC, p.id DESC LIMIT 1
                        ) ELSE previous_rx END AS baseline_rx,
                        CASE WHEN previous_tx IS NULL THEN (
                            SELECT p.tx_bytes FROM traffic_stats p
                            WHERE p.node_id = daily.node_id AND p.route_id = daily.route_id
                              AND p.bucket_at < ?
                            ORDER BY p.bucket_at DESC, p.id DESC LIMIT 1
                        ) ELSE previous_tx END AS baseline_tx
                 FROM daily
             )
             SELECT r.id AS route_id, r.name AS route_name,
                    SUM(CASE WHEN d.baseline_rx IS NULL THEN 0
                             WHEN d.rx_bytes >= d.baseline_rx THEN d.rx_bytes - d.baseline_rx
                             ELSE d.rx_bytes END) AS rx_bytes,
                    SUM(CASE WHEN d.baseline_tx IS NULL THEN 0
                             WHEN d.tx_bytes >= d.baseline_tx THEN d.tx_bytes - d.baseline_tx
                             ELSE d.tx_bytes END) AS tx_bytes
             FROM with_baseline d JOIN routes r ON r.id = d.route_id
             GROUP BY r.id, r.name
             HAVING rx_bytes > 0 OR tx_bytes > 0
             ORDER BY rx_bytes + tx_bytes DESC, r.name",
        )
        .bind(start_utc)
        .bind(end_utc)
        .bind(start_utc)
        .bind(start_utc)
        .fetch_all(self.db.pool())
        .await?;
        Ok(rows)
    }

    /// Drop buckets older than `days`. Returns the number of rows removed.
    pub async fn prune(&self, days: i64) -> Result<u64> {
        let cutoff = (chrono::Utc::now() - chrono::Duration::days(days.max(1))).to_rfc3339();
        let result = sqlx::query("DELETE FROM traffic_stats WHERE bucket_at < ?")
            .bind(cutoff)
            .execute(self.db.pool())
            .await?;
        Ok(result.rows_affected())
    }

    pub async fn count(&self) -> Result<i64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM traffic_stats")
            .fetch_one(self.db.pool())
            .await?;
        Ok(row.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::CreateNode;
    use crate::nodes::NodeRepo;

    /// 建组 + 一台机器，返回机器 id。
    async fn fixture() -> (Database, String) {
        let db = Database::connect_in_memory().await.unwrap();
        let group = test_group(&db, "上海入口", "inbound").await;
        let node = NodeRepo::new(&db)
            .create(CreateNode {
                group_id: group,
                name: "sh-01".into(),
                region: "cn".into(),
                role: "entry".into(),
                public_address: None,
                management_address: None,
                note: None,
            })
            .await
            .unwrap();
        (db, node.id)
    }

    async fn test_group(db: &Database, name: &str, kind: &str) -> String {
        crate::groups::DeviceGroupRepo::new(db)
            .create(crate::models::CreateDeviceGroup {
                name: name.into(),
                region: "test".into(),
                kind: kind.into(),
                note: None,
            })
            .await
            .unwrap()
            .0
            .id
    }

    fn sample(node_id: &str, rx: i64, tx: i64) -> StatSample {
        StatSample {
            node_id: node_id.into(),
            route_id: None,
            rx_bytes: rx,
            tx_bytes: tx,
            rx_bps: rx * 8,
            tx_bps: tx * 8,
            connections: 5,
        }
    }

    #[tokio::test]
    async fn record_and_read_back_a_node_series() {
        let (db, node_id) = fixture().await;
        let repo = StatsRepo::new(&db);

        repo.record_batch(&[sample(&node_id, 1000, 2000)])
            .await
            .unwrap();
        let series = repo.series_for_node(&node_id, 60).await.unwrap();
        assert_eq!(series.len(), 1);
        assert_eq!(series[0].rx_bytes, 1000);
        assert_eq!(series[0].tx_bytes, 2000);
        assert_eq!(series[0].connections, 5);
    }

    #[tokio::test]
    async fn empty_batch_is_a_noop() {
        let (db, _) = fixture().await;
        let repo = StatsRepo::new(&db);
        repo.record_batch(&[]).await.unwrap();
        assert_eq!(repo.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn one_transaction_covers_the_whole_batch() {
        let (db, node_id) = fixture().await;
        let repo = StatsRepo::new(&db);
        let batch: Vec<StatSample> = (0..50).map(|i| sample(&node_id, i * 100, i * 200)).collect();
        repo.record_batch(&batch).await.unwrap();
        assert_eq!(repo.count().await.unwrap(), 50);
    }

    #[tokio::test]
    async fn route_rows_do_not_pollute_the_node_series() {
        let (db, node_id) = fixture().await;
        let repo = StatsRepo::new(&db);

        let mut route_sample = sample(&node_id, 999, 999);
        // A route id that does not exist would violate the FK, so use NULL-only
        // rows here and cover route series in the route test below.
        route_sample.route_id = None;
        repo.record_batch(&[sample(&node_id, 100, 100), route_sample])
            .await
            .unwrap();

        let series = repo.series_for_node(&node_id, 60).await.unwrap();
        assert_eq!(series.len(), 2, "both roll-up rows should be present");
    }

    #[tokio::test]
    async fn per_route_series_is_separate_from_the_node_series() {
        let db = Database::connect_in_memory().await.unwrap();
        let nodes = NodeRepo::new(&db);
        let endpoints = crate::nodes::EndpointRepo::new(&db);
        let entry_group = test_group(&db, "上海入口", "inbound").await;
        let exit_group = test_group(&db, "香港出口", "outbound").await;
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
            .create(crate::models::CreateEndpoint {
                node_id: exit.id.clone(),
                name: "hk".into(),
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
        let route = crate::routes::RouteRepo::new(&db)
            .create(crate::models::CreateRoute {
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
                tunnel_pool_size: 8,
                load_balance: "round_robin".into(),
                max_connections: 0,
                egress_source_ip: None,
                egress_interface: None,
            })
            .await
            .unwrap();

        let repo = StatsRepo::new(&db);
        repo.record_batch(&[
            sample(&entry.id, 500, 600),
            StatSample {
                route_id: Some(route.id.clone()),
                ..sample(&entry.id, 250, 300)
            },
        ])
        .await
        .unwrap();

        let node_series = repo.series_for_node(&entry.id, 60).await.unwrap();
        assert_eq!(node_series.len(), 1, "route row leaked into the node series");
        assert_eq!(node_series[0].rx_bytes, 500);

        let route_series = repo.series_for_route(&route.id, 60).await.unwrap();
        assert_eq!(route_series.len(), 1);
        assert_eq!(route_series[0].rx_bytes, 250);
    }

    #[tokio::test]
    async fn totals_sum_across_nodes_per_bucket() {
        let db = Database::connect_in_memory().await.unwrap();
        let nodes = NodeRepo::new(&db);
        // 两台机器放在同一个组里：聚合是按机器求和，与分组无关。
        let g = test_group(&db, "g", "both").await;
        let a = nodes
            .create(CreateNode {
                group_id: g.clone(),
                name: "a".into(),
                region: "x".into(),
                role: "entry".into(),
                public_address: None,
                management_address: None,
                note: None,
            })
            .await
            .unwrap();
        let b = nodes
            .create(CreateNode {
                group_id: g.clone(),
                name: "b".into(),
                region: "x".into(),
                role: "exit".into(),
                public_address: None,
                management_address: None,
                note: None,
            })
            .await
            .unwrap();

        let repo = StatsRepo::new(&db);
        repo.record_batch(&[sample(&a.id, 100, 200), sample(&b.id, 300, 400)])
            .await
            .unwrap();

        let total = repo.series_total(60).await.unwrap();
        assert_eq!(total.len(), 1, "same batch shares one bucket timestamp");
        assert_eq!(total[0].rx_bytes, 400);
        assert_eq!(total[0].tx_bytes, 600);
    }

    #[tokio::test]
    async fn lifetime_totals_use_the_newest_bucket_not_a_sum_of_samples() {
        // rx_bytes is cumulative. Summing the series would report 6x the truth
        // after six samples, which is the classic version of this bug.
        let (db, node_id) = fixture().await;
        let repo = StatsRepo::new(&db);

        for total in [1000i64, 2000, 3000] {
            repo.record_batch(&[sample(&node_id, total, total * 2)])
                .await
                .unwrap();
            // Distinct bucket timestamps.
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        let (rx, tx) = repo.lifetime_totals().await.unwrap();
        assert_eq!(rx, 3000, "expected the latest cumulative value, got {rx}");
        assert_eq!(tx, 6000);
    }

    #[tokio::test]
    async fn lifetime_totals_on_an_empty_table_are_zero() {
        let (db, _) = fixture().await;
        assert_eq!(StatsRepo::new(&db).lifetime_totals().await.unwrap(), (0, 0));
    }

    #[tokio::test]
    async fn lifetime_totals_survive_resets_and_sample_pruning() {
        let (db, node_id) = fixture().await;
        let repo = StatsRepo::new(&db);
        for (rx, tx) in [(100, 200), (150, 250), (0, 0), (25, 35)] {
            repo.record_batch(&[sample(&node_id, rx, tx)]).await.unwrap();
        }
        assert_eq!(repo.node_lifetime_totals(&node_id).await.unwrap(), (175, 285));

        sqlx::query("UPDATE traffic_stats SET bucket_at = '2000-01-01T00:00:00+00:00'")
            .execute(db.pool())
            .await
            .unwrap();
        assert_eq!(repo.prune(1).await.unwrap(), 4);
        assert_eq!(repo.lifetime_totals().await.unwrap(), (175, 285));
    }

    #[tokio::test]
    async fn daily_routes_use_deltas_across_midnight_and_counter_resets() {
        let (db, node_id) = fixture().await;
        let (group_id,): (String,) = sqlx::query_as("SELECT group_id FROM nodes WHERE id = ?")
            .bind(&node_id)
            .fetch_one(db.pool())
            .await
            .unwrap();
        for (id, port) in [("route-one", 5001), ("route-two", 5002)] {
            sqlx::query(
                "INSERT INTO routes
                 (id, name, entry_group_id, exit_group_id, listen_address, listen_port,
                  target_host, target_port, mode, created_at, updated_at)
                 VALUES (?, ?, ?, ?, '0.0.0.0', ?, '127.0.0.1', 443, 'direct', ?, ?)",
            )
            .bind(id)
            .bind(id)
            .bind(&group_id)
            .bind(&group_id)
            .bind(port)
            .bind(now_string())
            .bind(now_string())
            .execute(db.pool())
            .await
            .unwrap();
        }

        let samples = [
            ("2026-09-25T15:59:50+00:00", Some("route-one"), 100, 200),
            ("2026-09-25T16:00:10+00:00", Some("route-one"), 130, 220),
            ("2026-09-25T16:00:20+00:00", Some("route-one"), 180, 250),
            ("2026-09-25T16:00:30+00:00", Some("route-one"), 5, 7),
            ("2026-09-26T16:00:10+00:00", Some("route-one"), 50, 70),
            ("2026-09-25T16:00:10+00:00", Some("route-two"), 10, 20),
            ("2026-09-25T16:00:20+00:00", Some("route-two"), 20, 40),
            ("2026-09-25T16:00:20+00:00", None, 9999, 9999),
        ];
        for (at, route_id, rx, tx) in samples {
            sqlx::query(
                "INSERT INTO traffic_stats
                 (bucket_at, node_id, route_id, rx_bytes, tx_bytes)
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind(at)
            .bind(&node_id)
            .bind(route_id)
            .bind(rx)
            .bind(tx)
            .execute(db.pool())
            .await
            .unwrap();
        }

        let second = NodeRepo::new(&db)
            .create(CreateNode {
                group_id,
                name: "sh-02".into(),
                region: "cn".into(),
                role: "entry".into(),
                public_address: None,
                management_address: None,
                note: None,
            })
            .await
            .unwrap();
        for (at, rx, tx) in [
            ("2026-09-25T15:59:50+00:00", 30, 40),
            ("2026-09-25T16:00:10+00:00", 50, 60),
        ] {
            sqlx::query(
                "INSERT INTO traffic_stats
                 (bucket_at, node_id, route_id, rx_bytes, tx_bytes)
                 VALUES (?, ?, 'route-one', ?, ?)",
            )
            .bind(at)
            .bind(&second.id)
            .bind(rx)
            .bind(tx)
            .execute(db.pool())
            .await
            .unwrap();
        }

        let routes = StatsRepo::new(&db)
            .daily_routes("2026-09-25T16:00:00+00:00", "2026-09-26T16:00:00+00:00")
            .await
            .unwrap();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].route_id, "route-one");
        assert_eq!((routes[0].rx_bytes, routes[0].tx_bytes), (105, 77));
        assert_eq!(routes[1].route_id, "route-two");
        assert_eq!((routes[1].rx_bytes, routes[1].tx_bytes), (10, 20));
    }

    #[tokio::test]
    async fn prune_drops_old_buckets_only() {
        let (db, node_id) = fixture().await;
        let repo = StatsRepo::new(&db);
        repo.record_batch(&[sample(&node_id, 1, 1)]).await.unwrap();

        // A 30-day window keeps a row written seconds ago.
        assert_eq!(repo.prune(30).await.unwrap(), 0);
        assert_eq!(repo.count().await.unwrap(), 1);

        // Backdate a row and prune again.
        sqlx::query("UPDATE traffic_stats SET bucket_at = '2000-01-01T00:00:00+00:00'")
            .execute(db.pool())
            .await
            .unwrap();
        assert_eq!(repo.prune(1).await.unwrap(), 1);
        assert_eq!(repo.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn stats_are_removed_with_their_node() {
        let (db, node_id) = fixture().await;
        let repo = StatsRepo::new(&db);
        repo.record_batch(&[sample(&node_id, 1, 1)]).await.unwrap();
        NodeRepo::new(&db).delete(&node_id).await.unwrap();
        assert_eq!(
            repo.count().await.unwrap(),
            0,
            "stats should cascade with the node"
        );
    }

    #[tokio::test]
    async fn window_is_clamped_to_at_least_one_minute() {
        let (db, node_id) = fixture().await;
        let repo = StatsRepo::new(&db);
        repo.record_batch(&[sample(&node_id, 1, 1)]).await.unwrap();
        // A zero or negative window must not produce a future cutoff that hides
        // everything.
        assert_eq!(repo.series_for_node(&node_id, 0).await.unwrap().len(), 1);
        assert_eq!(repo.series_for_node(&node_id, -5).await.unwrap().len(), 1);
    }
}
