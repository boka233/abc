//! Audit log repository.
//!
//! Append-only: there is no update or delete method beyond an explicit retention
//! prune. An audit trail an operator can quietly edit is not an audit trail.
//!
//! # Secret redaction
//!
//! Detail payloads come from request bodies, which is exactly where passwords,
//! tokens and PSKs live. [`redact`] strips them by key name before anything is
//! written, so a "create node" audit entry cannot archive the enrolment token it
//! just issued.

use serde_json::Value;

use crate::db::{now_string, Database, Result};
use crate::models::{AuditEntry, AuditRow};

/// Key fragments whose values are replaced with `***`. Matched
/// case-insensitively as substrings, so `agent_token_hash` and `tunnelPsk` are
/// both caught.
const SENSITIVE_KEYS: &[&str] = &[
    "password", "passwd", "secret", "token", "psk", "key", "hash", "credential", "authorization",
    "cookie", "session",
];

fn is_sensitive(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SENSITIVE_KEYS.iter().any(|k| lower.contains(k))
}

/// Recursively replace sensitive values with `***`.
///
/// Structure is preserved so the entry stays useful: you can still see *that* a
/// token was rotated, just not its value.
pub fn redact(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| {
                    if is_sensitive(k) {
                        (k.clone(), Value::String("***".into()))
                    } else {
                        (k.clone(), redact(v))
                    }
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(redact).collect()),
        other => other.clone(),
    }
}

/// Cap on a serialised detail payload, so a large request body cannot bloat the
/// table.
const MAX_DETAIL_LEN: usize = 8 * 1024;

pub struct AuditRepo<'a> {
    db: &'a Database,
}

impl<'a> AuditRepo<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Append an entry. Redaction happens here, not at the call site, so a
    /// forgetful caller cannot leak a secret.
    pub async fn record(&self, entry: AuditEntry) -> Result<()> {
        let detail_json = entry.detail.as_ref().map(|d| {
            let mut s = serde_json::to_string(&redact(d)).unwrap_or_else(|_| "{}".into());
            if s.len() > MAX_DETAIL_LEN {
                s.truncate(MAX_DETAIL_LEN);
                // Truncated JSON is no longer parseable; store a marker instead
                // of a broken document.
                s = format!("{{\"truncated\":true,\"bytes\":{}}}", s.len());
            }
            s
        });

        sqlx::query(
            "INSERT INTO audit_logs
             (at, user_id, username, action, target_type, target_id, target_name,
              source_ip, detail_json, success)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(now_string())
        .bind(&entry.user_id)
        .bind(&entry.username)
        .bind(&entry.action)
        .bind(&entry.target_type)
        .bind(&entry.target_id)
        .bind(&entry.target_name)
        .bind(&entry.source_ip)
        .bind(detail_json)
        .bind(i64::from(entry.success))
        .execute(self.db.pool())
        .await?;
        Ok(())
    }

    /// Most recent entries first, optionally filtered by action prefix.
    pub async fn list(&self, limit: i64, action_filter: Option<&str>) -> Result<Vec<AuditRow>> {
        let limit = limit.clamp(1, 1000);
        let rows: Vec<AuditRow> = match action_filter {
            Some(filter) if !filter.trim().is_empty() => {
                sqlx::query_as(
                    "SELECT * FROM audit_logs WHERE action LIKE ? ORDER BY id DESC LIMIT ?",
                )
                .bind(format!("{}%", filter.trim()))
                .bind(limit)
                .fetch_all(self.db.pool())
                .await?
            }
            _ => {
                sqlx::query_as("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?")
                    .bind(limit)
                    .fetch_all(self.db.pool())
                    .await?
            }
        };
        Ok(rows)
    }

    pub async fn count(&self) -> Result<i64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_logs")
            .fetch_one(self.db.pool())
            .await?;
        Ok(row.0)
    }

    /// Retention sweep. The only removal path.
    pub async fn prune(&self, days: i64) -> Result<u64> {
        let cutoff = (chrono::Utc::now() - chrono::Duration::days(days.max(1))).to_rfc3339();
        let result = sqlx::query("DELETE FROM audit_logs WHERE at < ?")
            .bind(cutoff)
            .execute(self.db.pool())
            .await?;
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::CreateNode;
    use crate::nodes::NodeRepo;
    use serde_json::json;

    async fn db() -> Database {
        Database::connect_in_memory().await.unwrap()
    }

    #[test]
    fn sensitive_keys_are_redacted() {
        let input = json!({
            "name": "sh-01",
            "password": "hunter2",
            "agent_token": "abc123",
            "tunnel_psk": "shared",
            "private_key": "-----BEGIN-----",
            "password_hash": "$argon2id$x",
            "Authorization": "Bearer xyz",
        });
        let out = redact(&input);
        let text = out.to_string();

        assert!(text.contains("sh-01"), "non-secret fields must survive");
        for leaked in ["hunter2", "abc123", "shared", "BEGIN", "argon2id", "Bearer"] {
            assert!(!text.contains(leaked), "`{leaked}` leaked: {text}");
        }
        assert_eq!(out["password"], "***");
        assert_eq!(out["agent_token"], "***");
    }

    #[test]
    fn redaction_reaches_nested_structures() {
        let input = json!({
            "route": { "name": "sh-hk", "psk": "inner-secret" },
            "nodes": [
                { "id": "n1", "token": "tok1" },
                { "id": "n2", "token": "tok2" }
            ]
        });
        let text = redact(&input).to_string();
        assert!(!text.contains("inner-secret"));
        assert!(!text.contains("tok1") && !text.contains("tok2"));
        assert!(text.contains("sh-hk") && text.contains("n1"));
    }

    #[test]
    fn redaction_is_case_insensitive_and_substring_matched() {
        let input = json!({
            "PASSWORD": "a",
            "AgentTokenHash": "b",
            "tunnelPsk": "c",
            "some_secret_value": "d",
        });
        let out = redact(&input);
        assert_eq!(out["PASSWORD"], "***");
        assert_eq!(out["AgentTokenHash"], "***");
        assert_eq!(out["tunnelPsk"], "***");
        assert_eq!(out["some_secret_value"], "***");
    }

    #[test]
    fn non_secret_payloads_pass_through_unchanged() {
        let input = json!({ "pool_size": 8, "enabled": true, "listen": "0.0.0.0:443" });
        assert_eq!(redact(&input), input);
    }

    #[tokio::test]
    async fn record_and_list() {
        let db = db().await;
        let repo = AuditRepo::new(&db);

        repo.record(
            AuditEntry::new("route.create")
                .actor(None, Some("admin".into()))
                .target("route", "r1", Some("sh-hk".into()))
                .source_ip(Some("198.51.100.7".into()))
                .detail(json!({ "pool_size": 8 })),
        )
        .await
        .unwrap();

        let rows = repo.list(10, None).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, "route.create");
        assert_eq!(rows[0].target_name.as_deref(), Some("sh-hk"));
        assert_eq!(rows[0].source_ip.as_deref(), Some("198.51.100.7"));
        assert_eq!(rows[0].success, 1);
    }

    #[tokio::test]
    async fn secrets_never_reach_the_stored_row() {
        // The end-to-end version of the redaction test: a real insert.
        let db = db().await;
        let repo = AuditRepo::new(&db);
        repo.record(
            AuditEntry::new("node.create")
                .detail(json!({ "name": "hk-01", "agent_token": "super-secret-token" })),
        )
        .await
        .unwrap();

        let rows = repo.list(10, None).await.unwrap();
        let detail = rows[0].detail_json.as_deref().unwrap();
        assert!(
            !detail.contains("super-secret-token"),
            "token persisted to the audit log: {detail}"
        );
        assert!(detail.contains("hk-01"));
    }

    #[tokio::test]
    async fn newest_entries_come_first() {
        let db = db().await;
        let repo = AuditRepo::new(&db);
        for i in 0..5 {
            repo.record(AuditEntry::new(format!("action.{i}")))
                .await
                .unwrap();
        }
        let rows = repo.list(10, None).await.unwrap();
        assert_eq!(rows[0].action, "action.4");
        assert_eq!(rows[4].action, "action.0");
    }

    #[tokio::test]
    async fn action_filter_matches_by_prefix() {
        let db = db().await;
        let repo = AuditRepo::new(&db);
        repo.record(AuditEntry::new("route.create")).await.unwrap();
        repo.record(AuditEntry::new("route.delete")).await.unwrap();
        repo.record(AuditEntry::new("node.create")).await.unwrap();

        assert_eq!(repo.list(10, Some("route")).await.unwrap().len(), 2);
        assert_eq!(repo.list(10, Some("node")).await.unwrap().len(), 1);
        assert_eq!(repo.list(10, Some("")).await.unwrap().len(), 3);
        assert_eq!(repo.list(10, None).await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn limit_is_clamped_to_a_sane_range() {
        let db = db().await;
        let repo = AuditRepo::new(&db);
        for i in 0..5 {
            repo.record(AuditEntry::new(format!("a.{i}"))).await.unwrap();
        }
        // Zero and negative limits must not return an empty page or error.
        assert_eq!(repo.list(0, None).await.unwrap().len(), 1);
        assert_eq!(repo.list(-10, None).await.unwrap().len(), 1);
        // An absurd limit is capped rather than fetching the world.
        assert_eq!(repo.list(i64::MAX, None).await.unwrap().len(), 5);
    }

    #[tokio::test]
    async fn failed_actions_are_recorded_too() {
        // An audit log that only keeps successes hides exactly the events you
        // most want to review.
        let db = db().await;
        let repo = AuditRepo::new(&db);
        repo.record(AuditEntry::new("auth.login").failed()).await.unwrap();
        let rows = repo.list(10, None).await.unwrap();
        assert_eq!(rows[0].success, 0);
    }

    #[tokio::test]
    async fn oversized_detail_is_replaced_with_a_marker() {
        let db = db().await;
        let repo = AuditRepo::new(&db);
        repo.record(AuditEntry::new("x").detail(json!({ "blob": "y".repeat(50_000) })))
            .await
            .unwrap();
        let rows = repo.list(1, None).await.unwrap();
        let detail = rows[0].detail_json.as_deref().unwrap();
        assert!(detail.len() < 200, "detail not bounded: {} bytes", detail.len());
        assert!(detail.contains("truncated"));
        // Whatever is stored must still be valid JSON.
        serde_json::from_str::<Value>(detail).expect("stored detail must parse");
    }

    #[tokio::test]
    async fn deleting_a_user_keeps_their_audit_trail() {
        // ON DELETE SET NULL, not CASCADE: removing an operator must not erase
        // the record of what they did.
        let db = db().await;
        let users = crate::users::UserRepo::new(&db);
        users
            .create("admin", "keep-this-account-1", "admin", false)
            .await
            .unwrap();
        let victim = users
            .create("operator", "initial-password-1", "admin", false)
            .await
            .unwrap();

        let repo = AuditRepo::new(&db);
        repo.record(
            AuditEntry::new("route.delete")
                .actor(Some(victim.id.clone()), Some("operator".into())),
        )
        .await
        .unwrap();

        users.delete(&victim.id).await.unwrap();

        let rows = repo.list(10, None).await.unwrap();
        assert_eq!(rows.len(), 1, "audit entry was deleted with the user");
        assert!(rows[0].user_id.is_none(), "user_id should be nulled");
        assert_eq!(
            rows[0].username.as_deref(),
            Some("operator"),
            "the username must survive for accountability"
        );
    }

    #[tokio::test]
    async fn prune_respects_the_retention_window() {
        let db = db().await;
        let repo = AuditRepo::new(&db);
        repo.record(AuditEntry::new("recent")).await.unwrap();

        assert_eq!(repo.prune(90).await.unwrap(), 0);
        assert_eq!(repo.count().await.unwrap(), 1);

        sqlx::query("UPDATE audit_logs SET at = '2000-01-01T00:00:00+00:00'")
            .execute(db.pool())
            .await
            .unwrap();
        assert_eq!(repo.prune(1).await.unwrap(), 1);
        assert_eq!(repo.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn agent_actions_need_no_user() {
        let db = db().await;
        let group = crate::groups::DeviceGroupRepo::new(&db)
            .create(crate::models::CreateDeviceGroup {
                name: "上海入口".into(),
                region: "cn".into(),
                kind: "inbound".into(),
                note: None,
            })
            .await
            .unwrap()
            .0;
        let nodes = NodeRepo::new(&db);
        let node = nodes
            .create(CreateNode {
                group_id: group.id.clone(),
                name: "sh-01".into(),
                region: "cn".into(),
                role: "entry".into(),
                public_address: None,
                management_address: None,
                note: None,
            })
            .await
            .unwrap();

        let repo = AuditRepo::new(&db);
        repo.record(
            AuditEntry::new("agent.register").target("node", &node.id, Some("sh-01".into())),
        )
        .await
        .unwrap();
        let rows = repo.list(10, None).await.unwrap();
        assert!(rows[0].user_id.is_none());
        assert_eq!(rows[0].target_name.as_deref(), Some("sh-01"));
    }
}
