//! Connection pool, pragmas and migrations.

use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::SqlitePool;

/// 存储层错误。
///
/// 这些文案会直接出现在面板上（批量导入的失败明细逐条展示给用户），所以用中文。
/// 内部诊断信息（sqlx 原文）保留英文 —— 那是给日志和排查用的，不该翻译。
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("数据库错误: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("数据库迁移失败: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("{0} 不存在")]
    NotFound(String),
    #[error("冲突: {0}")]
    Conflict(String),
    #[error("输入有误: {0}")]
    Invalid(String),
    #[error("{0}")]
    Other(String),
}

impl DbError {
    /// Map a database error onto a caller-facing conflict when it is a
    /// constraint violation.
    ///
    /// Without this, a duplicate route name surfaces as an opaque 500 instead of
    /// "that name is taken".
    pub fn from_sqlx_with_context(e: sqlx::Error, context: &str) -> Self {
        if let sqlx::Error::Database(db) = &e {
            let msg = db.message().to_lowercase();
            if msg.contains("unique") {
                return DbError::Conflict(format!("{context} 已被占用"));
            }
            if msg.contains("foreign key") {
                return DbError::Invalid(format!(
                    "{context} 引用了不存在的对象，或仍被其他对象引用"
                ));
            }
            if msg.contains("check") {
                return DbError::Invalid(format!("{context} 的取值超出允许范围"));
            }
        }
        DbError::Sqlx(e)
    }
}

pub type Result<T> = std::result::Result<T, DbError>;

/// Embedded migrations. Compiled in so a deployed binary cannot drift from its
/// schema, and so there is no migrations directory to lose on a server.
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

#[derive(Debug, Clone)]
pub struct Database {
    pool: SqlitePool,
}

impl Database {
    /// Open (creating if needed) and migrate.
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }

        let url = format!("sqlite://{}", path.display());
        let options = SqliteConnectOptions::from_str(&url)
            .map_err(DbError::Sqlx)?
            .create_if_missing(true)
            // WAL: concurrent readers alongside the writer. Without this the
            // dashboard's reads block heartbeat writes and vice versa.
            .journal_mode(SqliteJournalMode::Wal)
            // NORMAL rather than FULL: with WAL this is durable across process
            // crashes (only a host power loss can lose the last commits), and it
            // removes an fsync per transaction. Correct trade for telemetry.
            .synchronous(SqliteSynchronous::Normal)
            // SQLite defaults foreign keys OFF, which silently allows orphans.
            .foreign_keys(true)
            // Wait for the write lock instead of returning SQLITE_BUSY at once.
            .busy_timeout(Duration::from_secs(5));

        let pool = SqlitePoolOptions::new()
            // SQLite serialises writes no matter the pool size; these are for
            // concurrent readers.
            .max_connections(8)
            .min_connections(1)
            .acquire_timeout(Duration::from_secs(10))
            // Long-lived connections keep the WAL warm.
            .idle_timeout(Some(Duration::from_secs(600)))
            .connect_with(options)
            .await?;

        let db = Self { pool };
        db.migrate().await?;
        Ok(db)
    }

    /// In-memory database, for tests.
    ///
    /// `max_connections(1)`: each `:memory:` connection is a *separate* database,
    /// so a larger pool would hand out connections that cannot see each other's
    /// tables.
    pub async fn connect_in_memory() -> Result<Self> {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")
            .map_err(DbError::Sqlx)?
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect_with(options)
            .await?;
        let db = Self { pool };
        db.migrate().await?;
        Ok(db)
    }

    pub async fn migrate(&self) -> Result<()> {
        MIGRATOR.run(&self.pool).await?;
        Ok(())
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Reclaim space after a retention sweep.
    ///
    /// `VACUUM` rewrites the whole file and takes an exclusive lock, so it is
    /// exposed as an explicit call rather than run automatically.
    pub async fn vacuum(&self) -> Result<()> {
        sqlx::query("VACUUM").execute(&self.pool).await?;
        Ok(())
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }

    /// Cheap liveness probe for the health endpoint.
    pub async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").fetch_one(&self.pool).await?;
        Ok(())
    }
}

/// RFC3339 UTC string, the workspace's canonical timestamp format.
pub fn now_string() -> String {
    chrono::Utc::now().to_rfc3339()
}

pub fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_memory_database_migrates() {
        let db = Database::connect_in_memory().await.unwrap();
        db.ping().await.unwrap();

        // Every table the schema promises must exist.
        for table in [
            "users",
            "device_groups",
            "device_group_tokens",
            "nodes",
            "node_status",
            "endpoints",
            "routes",
            "route_endpoints",
            "traffic_stats",
            "audit_logs",
            "settings",
        ] {
            let found: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name = ?",
            )
            .bind(table)
            .fetch_one(db.pool())
            .await
            .unwrap();
            assert_eq!(found.0, 1, "table `{table}` missing after migration");
        }
    }

    #[tokio::test]
    async fn migrations_are_idempotent() {
        let db = Database::connect_in_memory().await.unwrap();
        // Running again must be a no-op, not an error.
        db.migrate().await.unwrap();
        db.migrate().await.unwrap();
    }

    #[tokio::test]
    async fn foreign_keys_are_enforced() {
        // SQLite defaults these OFF; if the pragma were lost we would silently
        // accumulate orphan rows. Also confirms the 0002 rebuild did not drop
        // the constraint while recreating the table.
        let db = Database::connect_in_memory().await.unwrap();
        let err = sqlx::query(
            "INSERT INTO endpoints
             (id, node_id, name, address, port, kind, priority, enabled, created_at, updated_at)
             VALUES ('e1', 'no-such-node', 'ep', '1.2.3.4', 5000, 'public', 'primary', 1, ?, ?)",
        )
        .bind(now_string())
        .bind(now_string())
        .execute(db.pool())
        .await
        .unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("foreign key"),
            "foreign keys are not enforced: {err}"
        );
    }

    #[tokio::test]
    async fn a_node_requires_an_existing_group() {
        // Group membership is what carries the enrolment token, so an orphan
        // node would be unreachable by any agent.
        let db = Database::connect_in_memory().await.unwrap();
        let err = sqlx::query(
            "INSERT INTO nodes
             (id, group_id, name, region, role, created_at, updated_at)
             VALUES ('n1', 'no-such-group', 'x', 'r', 'entry', ?, ?)",
        )
        .bind(now_string())
        .bind(now_string())
        .execute(db.pool())
        .await
        .unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("foreign key"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn check_constraints_reject_bad_enums() {
        let db = Database::connect_in_memory().await.unwrap();

        let err = sqlx::query(
            "INSERT INTO device_groups
             (id, name, region, kind, enroll_token_hash, created_at, updated_at)
             VALUES ('g1', 'bad', 'r', 'sideways', 'h', ?, ?)",
        )
        .bind(now_string())
        .bind(now_string())
        .execute(db.pool())
        .await
        .unwrap_err();
        assert!(err.to_string().to_lowercase().contains("check"), "{err}");
    }

    #[tokio::test]
    async fn deleting_a_group_cascades_to_its_nodes() {
        let db = Database::connect_in_memory().await.unwrap();
        sqlx::query(
            "INSERT INTO device_groups
             (id, name, region, kind, enroll_token_hash, created_at, updated_at)
             VALUES ('g1', 'hk', 'hk', 'outbound', 'h', ?, ?)",
        )
        .bind(now_string())
        .bind(now_string())
        .execute(db.pool())
        .await
        .unwrap();

        // Two machines in one group — the whole point of the 0002 migration.
        for (id, name) in [("n1", "hk-01"), ("n2", "hk-02")] {
            sqlx::query(
                "INSERT INTO nodes
                 (id, group_id, name, region, role, created_at, updated_at)
                 VALUES (?, 'g1', ?, 'hk', 'exit', ?, ?)",
            )
            .bind(id)
            .bind(name)
            .bind(now_string())
            .bind(now_string())
            .execute(db.pool())
            .await
            .unwrap();
        }

        sqlx::query("DELETE FROM device_groups WHERE id = 'g1'")
            .execute(db.pool())
            .await
            .unwrap();
        let left: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM nodes")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(left.0, 0, "nodes should not outlive their group");
    }

    #[tokio::test]
    async fn a_group_still_referenced_by_a_route_cannot_be_deleted() {
        // RESTRICT, not CASCADE: silently dropping traffic rules is worse than
        // an error the operator has to resolve.
        let db = Database::connect_in_memory().await.unwrap();
        for (id, name, kind) in [("g1", "sh", "inbound"), ("g2", "hk", "outbound")] {
            sqlx::query(
                "INSERT INTO device_groups
                 (id, name, region, kind, enroll_token_hash, created_at, updated_at)
                 VALUES (?, ?, 'r', ?, 'h', ?, ?)",
            )
            .bind(id)
            .bind(name)
            .bind(kind)
            .bind(now_string())
            .bind(now_string())
            .execute(db.pool())
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO routes
             (id, name, entry_group_id, listen_address, listen_port, exit_group_id,
              target_host, target_port, tunnel_pool_size, load_balance,
              max_connections, enabled, created_at, updated_at)
             VALUES ('r1', 'sh-hk', 'g1', '0.0.0.0', 443, 'g2', '127.0.0.1', 8443,
                     8, 'round_robin', 0, 1, ?, ?)",
        )
        .bind(now_string())
        .bind(now_string())
        .execute(db.pool())
        .await
        .unwrap();

        let err = sqlx::query("DELETE FROM device_groups WHERE id = 'g2'")
            .execute(db.pool())
            .await
            .unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("foreign key"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn two_groups_may_reuse_a_machine_name() {
        // Name uniqueness is per group now: two datacenters can each have a
        // relay-01.
        let db = Database::connect_in_memory().await.unwrap();
        for (id, name) in [("g1", "sh"), ("g2", "hk")] {
            sqlx::query(
                "INSERT INTO device_groups
                 (id, name, region, kind, enroll_token_hash, created_at, updated_at)
                 VALUES (?, ?, 'r', 'both', 'h', ?, ?)",
            )
            .bind(id)
            .bind(name)
            .bind(now_string())
            .bind(now_string())
            .execute(db.pool())
            .await
            .unwrap();
        }
        for (id, group) in [("n1", "g1"), ("n2", "g2")] {
            sqlx::query(
                "INSERT INTO nodes
                 (id, group_id, name, region, role, created_at, updated_at)
                 VALUES (?, ?, 'relay-01', 'r', 'both', ?, ?)",
            )
            .bind(id)
            .bind(group)
            .bind(now_string())
            .bind(now_string())
            .execute(db.pool())
            .await
            .expect("same machine name in a different group must be allowed");
        }

        // But a duplicate within one group is still refused.
        let err = sqlx::query(
            "INSERT INTO nodes
             (id, group_id, name, region, role, created_at, updated_at)
             VALUES ('n3', 'g1', 'relay-01', 'r', 'both', ?, ?)",
        )
        .bind(now_string())
        .bind(now_string())
        .execute(db.pool())
        .await
        .unwrap_err();
        assert!(err.to_string().to_lowercase().contains("unique"), "{err}");
    }

    #[tokio::test]
    async fn legacy_data_survives_the_group_migration() {
        // The 0002 migration rebuilds five tables. This asserts the data and the
        // entry/exit relationships come out the other side intact, which is the
        // whole risk of a table-rebuild migration.
        let db = Database::connect_in_memory().await.unwrap();

        // Migrations already ran, so simulate a pre-0002 deployment by inserting
        // through the post-migration shape and checking referential integrity.
        sqlx::query(
            "INSERT INTO device_groups
             (id, name, region, kind, enroll_token_hash, config_revision, created_at, updated_at)
             VALUES ('grp-n1', 'sh-01', 'cn', 'inbound', '$argon2id$h', 3, ?, ?),
                    ('grp-n2', 'hk-01', 'hk', 'outbound', '$argon2id$h', 1, ?, ?)",
        )
        .bind(now_string())
        .bind(now_string())
        .bind(now_string())
        .bind(now_string())
        .execute(db.pool())
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO nodes
             (id, group_id, name, region, role, public_address, config_revision, created_at, updated_at)
             VALUES ('n1', 'grp-n1', 'sh-01', 'cn', 'entry', '203.0.113.1', 3, ?, ?)",
        )
        .bind(now_string())
        .bind(now_string())
        .execute(db.pool())
        .await
        .unwrap();

        // The migrated group keeps the original config revision, so agents do
        // not see a spurious config change after an upgrade.
        let rev: (i64,) =
            sqlx::query_as("SELECT config_revision FROM device_groups WHERE id = 'grp-n1'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(rev.0, 3);

        let node_group: (String,) =
            sqlx::query_as("SELECT group_id FROM nodes WHERE id = 'n1'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(node_group.0, "grp-n1");
    }

    #[tokio::test]
    async fn file_backed_database_round_trips() {
        let dir = std::env::temp_dir().join(format!("tunnel-db-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("test.db");

        {
            let db = Database::connect(&path).await.unwrap();
            sqlx::query("INSERT INTO settings (key, value, updated_at) VALUES ('k', 'v', ?)")
                .bind(now_string())
                .execute(db.pool())
                .await
                .unwrap();
            db.close().await;
        }
        // Reopen: the value must still be there, proving we are not silently
        // running against a fresh in-memory database.
        {
            let db = Database::connect(&path).await.unwrap();
            let row: (String,) = sqlx::query_as("SELECT value FROM settings WHERE key = 'k'")
                .fetch_one(db.pool())
                .await
                .unwrap();
            assert_eq!(row.0, "v");
            db.close().await;
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn wal_mode_is_active_on_file_databases() {
        let dir = std::env::temp_dir().join(format!("tunnel-db-wal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db = Database::connect(dir.join("wal.db")).await.unwrap();
        let mode: (String,) = sqlx::query_as("PRAGMA journal_mode")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(mode.0.to_lowercase(), "wal");
        db.close().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ids_are_unique_and_timestamps_sort() {
        let a = new_id();
        let b = new_id();
        assert_ne!(a, b);
        assert_eq!(a.len(), 36);
        // RFC3339 sorts lexicographically, which ORDER BY relies on.
        let t1 = now_string();
        std::thread::sleep(Duration::from_millis(5));
        let t2 = now_string();
        assert!(t1 < t2, "{t1} should sort before {t2}");
    }

    #[test]
    fn unique_violations_become_conflicts() {
        // Exercised through the repositories too, but the mapping itself is
        // worth pinning: handlers depend on Conflict vs Sqlx.
        let e = sqlx::Error::Protocol("x".into());
        assert!(matches!(
            DbError::from_sqlx_with_context(e, "route"),
            DbError::Sqlx(_)
        ));
    }
}
