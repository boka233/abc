//! Runtime settings key/value store.
//!
//! For values an operator can change in the panel without a restart (retention
//! windows, heartbeat thresholds). Deployment-level configuration — bind
//! addresses, database path, JWT secret — stays in the config file, because a
//! setting that can lock you out of the panel should not be editable *from* the
//! panel.

use crate::db::{now_string, Database, DbError, Result};

pub struct SettingsRepo<'a> {
    db: &'a Database,
}

/// Known keys, with their defaults.
pub mod keys {
    /// Seconds without a heartbeat before a node is marked offline.
    pub const NODE_STALE_SECS: &str = "node_stale_secs";
    /// Days of traffic samples to retain.
    pub const TRAFFIC_RETENTION_DAYS: &str = "traffic_retention_days";
    /// Days of audit entries to retain.
    pub const AUDIT_RETENTION_DAYS: &str = "audit_retention_days";
    /// Seconds between statistics aggregation passes.
    pub const STATS_INTERVAL_SECS: &str = "stats_interval_secs";
}

pub const DEFAULT_NODE_STALE_SECS: i64 = 45;
pub const DEFAULT_TRAFFIC_RETENTION_DAYS: i64 = 30;
pub const DEFAULT_AUDIT_RETENTION_DAYS: i64 = 180;
pub const DEFAULT_STATS_INTERVAL_SECS: i64 = 10;

impl<'a> SettingsRepo<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    pub async fn get(&self, key: &str) -> Result<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as("SELECT value FROM settings WHERE key = ?")
            .bind(key)
            .fetch_optional(self.db.pool())
            .await?;
        Ok(row.map(|r| r.0))
    }

    /// Integer setting with a fallback.
    ///
    /// A malformed stored value falls back to the default rather than erroring:
    /// a bad row in this table must not stop the control plane from starting.
    pub async fn get_i64(&self, key: &str, default: i64) -> Result<i64> {
        Ok(self
            .get(key)
            .await?
            .and_then(|v| v.trim().parse::<i64>().ok())
            .unwrap_or(default))
    }

    pub async fn set(&self, key: &str, value: &str) -> Result<()> {
        if key.trim().is_empty() {
            return Err(DbError::Invalid("setting key is required".into()));
        }
        if value.len() > 4096 {
            return Err(DbError::Invalid("setting value is too long".into()));
        }
        sqlx::query(
            "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        )
        .bind(key)
        .bind(value)
        .bind(now_string())
        .execute(self.db.pool())
        .await?;
        Ok(())
    }

    /// Set an integer, rejecting values outside `[min, max]`.
    ///
    /// Bounds exist because these feed live loops: a zero stats interval would
    /// spin a task at full tilt, and a zero retention would delete everything.
    pub async fn set_i64_bounded(
        &self,
        key: &str,
        value: i64,
        min: i64,
        max: i64,
    ) -> Result<()> {
        if value < min || value > max {
            return Err(DbError::Invalid(format!(
                "{key} must be between {min} and {max}"
            )));
        }
        self.set(key, &value.to_string()).await
    }

    pub async fn all(&self) -> Result<Vec<(String, String)>> {
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT key, value FROM settings ORDER BY key")
                .fetch_all(self.db.pool())
                .await?;
        Ok(rows)
    }

    pub async fn delete(&self, key: &str) -> Result<()> {
        sqlx::query("DELETE FROM settings WHERE key = ?")
            .bind(key)
            .execute(self.db.pool())
            .await?;
        Ok(())
    }

    /// Effective values, defaults applied.
    pub async fn effective(&self) -> Result<EffectiveSettings> {
        Ok(EffectiveSettings {
            node_stale_secs: self
                .get_i64(keys::NODE_STALE_SECS, DEFAULT_NODE_STALE_SECS)
                .await?
                .clamp(10, 3600),
            traffic_retention_days: self
                .get_i64(keys::TRAFFIC_RETENTION_DAYS, DEFAULT_TRAFFIC_RETENTION_DAYS)
                .await?
                .clamp(1, 3650),
            audit_retention_days: self
                .get_i64(keys::AUDIT_RETENTION_DAYS, DEFAULT_AUDIT_RETENTION_DAYS)
                .await?
                .clamp(1, 3650),
            stats_interval_secs: self
                .get_i64(keys::STATS_INTERVAL_SECS, DEFAULT_STATS_INTERVAL_SECS)
                .await?
                .clamp(1, 300),
        })
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct EffectiveSettings {
    pub node_stale_secs: i64,
    pub traffic_retention_days: i64,
    pub audit_retention_days: i64,
    pub stats_interval_secs: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn db() -> Database {
        Database::connect_in_memory().await.unwrap()
    }

    #[tokio::test]
    async fn set_then_get() {
        let db = db().await;
        let repo = SettingsRepo::new(&db);
        assert!(repo.get("missing").await.unwrap().is_none());

        repo.set("k", "v").await.unwrap();
        assert_eq!(repo.get("k").await.unwrap().as_deref(), Some("v"));
    }

    #[tokio::test]
    async fn set_is_an_upsert() {
        let db = db().await;
        let repo = SettingsRepo::new(&db);
        repo.set("k", "first").await.unwrap();
        repo.set("k", "second").await.unwrap();
        assert_eq!(repo.get("k").await.unwrap().as_deref(), Some("second"));
        assert_eq!(repo.all().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn integer_accessor_falls_back_on_garbage() {
        // A hand-edited or partially written row must not stop startup.
        let db = db().await;
        let repo = SettingsRepo::new(&db);
        repo.set("n", "not-a-number").await.unwrap();
        assert_eq!(repo.get_i64("n", 42).await.unwrap(), 42);

        repo.set("n", " 7 ").await.unwrap();
        assert_eq!(repo.get_i64("n", 42).await.unwrap(), 7);
    }

    #[tokio::test]
    async fn bounded_setter_rejects_out_of_range() {
        let db = db().await;
        let repo = SettingsRepo::new(&db);
        assert!(repo
            .set_i64_bounded(keys::STATS_INTERVAL_SECS, 0, 1, 300)
            .await
            .is_err());
        assert!(repo
            .set_i64_bounded(keys::STATS_INTERVAL_SECS, 99999, 1, 300)
            .await
            .is_err());
        repo.set_i64_bounded(keys::STATS_INTERVAL_SECS, 30, 1, 300)
            .await
            .unwrap();
        assert_eq!(
            repo.get_i64(keys::STATS_INTERVAL_SECS, 10).await.unwrap(),
            30
        );
    }

    #[tokio::test]
    async fn empty_key_and_huge_value_are_rejected() {
        let db = db().await;
        let repo = SettingsRepo::new(&db);
        assert!(repo.set("  ", "v").await.is_err());
        assert!(repo.set("k", &"x".repeat(5000)).await.is_err());
    }

    #[tokio::test]
    async fn effective_settings_use_defaults_when_unset() {
        let db = db().await;
        let repo = SettingsRepo::new(&db);
        let s = repo.effective().await.unwrap();
        assert_eq!(s.node_stale_secs, DEFAULT_NODE_STALE_SECS);
        assert_eq!(s.traffic_retention_days, DEFAULT_TRAFFIC_RETENTION_DAYS);
        assert_eq!(s.audit_retention_days, DEFAULT_AUDIT_RETENTION_DAYS);
        assert_eq!(s.stats_interval_secs, DEFAULT_STATS_INTERVAL_SECS);
    }

    #[tokio::test]
    async fn effective_settings_clamp_dangerous_values() {
        // Even if a value reached the table by another path, the live loops must
        // receive something survivable.
        let db = db().await;
        let repo = SettingsRepo::new(&db);
        repo.set(keys::STATS_INTERVAL_SECS, "0").await.unwrap();
        repo.set(keys::TRAFFIC_RETENTION_DAYS, "-5").await.unwrap();
        repo.set(keys::NODE_STALE_SECS, "1").await.unwrap();

        let s = repo.effective().await.unwrap();
        assert!(s.stats_interval_secs >= 1, "a 0s interval would spin a task");
        assert!(s.traffic_retention_days >= 1);
        assert!(s.node_stale_secs >= 10, "too low would flap node status");
    }

    #[tokio::test]
    async fn delete_removes_a_key() {
        let db = db().await;
        let repo = SettingsRepo::new(&db);
        repo.set("k", "v").await.unwrap();
        repo.delete("k").await.unwrap();
        assert!(repo.get("k").await.unwrap().is_none());
        // Deleting a missing key is not an error.
        repo.delete("k").await.unwrap();
    }
}
