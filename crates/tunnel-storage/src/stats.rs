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
    /// Takes the newest bucket per node rather than summing every bucket:
    /// `rx_bytes` is a cumulative counter, so summing the series would multiply
    /// the real total by the number of samples.
    pub async fn lifetime_totals(&self) -> Result<(i64, i64)> {
        let row: Option<(Option<i64>, Option<i64>)> = sqlx::query_as(
            "SELECT SUM(rx_bytes), SUM(tx_bytes) FROM (
                 SELECT node_id, rx_bytes, tx_bytes
                 FROM traffic_stats t
                 WHERE route_id IS NULL
                   AND bucket_at = (
                       SELECT MAX(bucket_at) FROM traffic_stats
                       WHERE node_id = t.node_id AND route_id IS NULL
                   )
                 GROUP BY node_id
             )",
        )
        .fetch_optional(self.db.pool())
        .await?;
        Ok(match row {
            Some((rx, tx)) => (rx.unwrap_or(0), tx.unwrap_or(0)),
            None => (0, 0),
        })
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
