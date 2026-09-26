//! 公网 IP → 国家的查询缓存。
//!
//! 只负责存取。查询外部 API 的逻辑在控制面（tunnel-control::geo），这里不碰网络 ——
//! 存储层不该因为一个第三方服务慢就拖住数据库操作。

use crate::db::{now_string, Database, Result};
use sqlx::FromRow;

#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct GeoEntry {
    pub ip: String,
    /// ISO 3166-1 alpha-2。查询失败或查不到时为 `None`。
    pub country: Option<String>,
    pub looked_up_at: String,
    pub failed: bool,
}

pub struct GeoRepo<'a> {
    db: &'a Database,
}

impl<'a> GeoRepo<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    pub async fn get(&self, ip: &str) -> Result<Option<GeoEntry>> {
        let row: Option<(String, Option<String>, String, i64)> = sqlx::query_as(
            "SELECT ip, country, looked_up_at, failed FROM ip_geo_cache WHERE ip = ?",
        )
        .bind(ip)
        .fetch_optional(self.db.pool())
        .await?;
        Ok(row.map(|(ip, country, looked_up_at, failed)| GeoEntry {
            ip,
            country,
            looked_up_at,
            failed: failed != 0,
        }))
    }

    /// 一次取多个 IP，返回 ip → 国家代码。查不到或查询失败的不在结果里。
    ///
    /// 机器列表一次渲染几十台，逐个查会打出同样数量的 SQL。
    pub async fn countries_for(
        &self,
        ips: &[String],
    ) -> Result<std::collections::HashMap<String, String>> {
        let mut out = std::collections::HashMap::new();
        if ips.is_empty() {
            return Ok(out);
        }
        // SQLite 的参数上限是 999（老版本）。机器数远小于它，但分批不费事。
        for chunk in ips.chunks(500) {
            let placeholders = vec!["?"; chunk.len()].join(",");
            let sql = format!(
                "SELECT ip, country FROM ip_geo_cache
                 WHERE country IS NOT NULL AND ip IN ({placeholders})"
            );
            let mut query = sqlx::query_as::<_, (String, String)>(&sql);
            for ip in chunk {
                query = query.bind(ip);
            }
            for (ip, country) in query.fetch_all(self.db.pool()).await? {
                out.insert(ip, country);
            }
        }
        Ok(out)
    }

    /// 记录一次成功的查询。
    pub async fn record_success(&self, ip: &str, country: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO ip_geo_cache (ip, country, looked_up_at, failed)
             VALUES (?, ?, ?, 0)
             ON CONFLICT (ip) DO UPDATE SET
               country = excluded.country,
               looked_up_at = excluded.looked_up_at,
               failed = 0",
        )
        .bind(ip)
        .bind(country)
        .bind(now_string())
        .execute(self.db.pool())
        .await?;
        Ok(())
    }

    /// 记录一次失败的查询。
    ///
    /// 保留已有的国家代码：一个曾经查到过的 IP 某次查询失败（对方限流、网络抖动），
    /// 不该让它在面板上从「香港」变回「—」。
    pub async fn record_failure(&self, ip: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO ip_geo_cache (ip, country, looked_up_at, failed)
             VALUES (?, NULL, ?, 1)
             ON CONFLICT (ip) DO UPDATE SET
               looked_up_at = excluded.looked_up_at,
               failed = 1",
        )
        .bind(ip)
        .bind(now_string())
        .execute(self.db.pool())
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_successful_lookup_is_cached() {
        let db = Database::connect_in_memory().await.unwrap();
        let repo = GeoRepo::new(&db);
        repo.record_success("151.244.134.139", "HK").await.unwrap();

        let entry = repo.get("151.244.134.139").await.unwrap().unwrap();
        assert_eq!(entry.country.as_deref(), Some("HK"));
        assert!(!entry.failed);
    }

    #[tokio::test]
    async fn a_failure_is_recorded_so_it_is_not_retried_every_heartbeat() {
        // 失败不落库的话，每 10 秒一次的心跳会让一个查不到的 IP 永远被重查。
        let db = Database::connect_in_memory().await.unwrap();
        let repo = GeoRepo::new(&db);
        repo.record_failure("203.0.113.9").await.unwrap();

        let entry = repo.get("203.0.113.9").await.unwrap().unwrap();
        assert!(entry.failed);
        assert!(entry.country.is_none());
    }

    #[tokio::test]
    async fn a_later_failure_keeps_the_known_country() {
        // 曾经查到过「香港」，某次查询被限流失败了 —— 面板上不该变回「—」。
        let db = Database::connect_in_memory().await.unwrap();
        let repo = GeoRepo::new(&db);
        repo.record_success("151.244.134.139", "HK").await.unwrap();
        repo.record_failure("151.244.134.139").await.unwrap();

        let entry = repo.get("151.244.134.139").await.unwrap().unwrap();
        assert_eq!(entry.country.as_deref(), Some("HK"), "已知国家被失败覆盖了");
        assert!(entry.failed);
    }

    #[tokio::test]
    async fn a_success_after_a_failure_clears_the_flag() {
        let db = Database::connect_in_memory().await.unwrap();
        let repo = GeoRepo::new(&db);
        repo.record_failure("198.51.100.7").await.unwrap();
        repo.record_success("198.51.100.7", "JP").await.unwrap();

        let entry = repo.get("198.51.100.7").await.unwrap().unwrap();
        assert!(!entry.failed);
        assert_eq!(entry.country.as_deref(), Some("JP"));
    }

    #[tokio::test]
    async fn bulk_lookup_returns_only_known_countries() {
        let db = Database::connect_in_memory().await.unwrap();
        let repo = GeoRepo::new(&db);
        repo.record_success("1.1.1.1", "AU").await.unwrap();
        repo.record_success("8.8.8.8", "US").await.unwrap();
        repo.record_failure("9.9.9.9").await.unwrap();

        let got = repo
            .countries_for(&[
                "1.1.1.1".into(),
                "8.8.8.8".into(),
                "9.9.9.9".into(),
                "never-seen".into(),
            ])
            .await
            .unwrap();
        assert_eq!(got.len(), 2, "失败与未查过的不该出现: {got:?}");
        assert_eq!(got["1.1.1.1"], "AU");
        assert_eq!(got["8.8.8.8"], "US");
    }

    #[tokio::test]
    async fn bulk_lookup_of_nothing_is_empty() {
        let db = Database::connect_in_memory().await.unwrap();
        assert!(GeoRepo::new(&db).countries_for(&[]).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn bulk_lookup_handles_more_ips_than_one_chunk() {
        // 分批的边界：超过单批大小时不能丢数据。
        let db = Database::connect_in_memory().await.unwrap();
        let repo = GeoRepo::new(&db);
        let ips: Vec<String> = (0..620).map(|i| format!("10.0.{}.{}", i / 256, i % 256)).collect();
        for ip in &ips {
            repo.record_success(ip, "HK").await.unwrap();
        }
        assert_eq!(repo.countries_for(&ips).await.unwrap().len(), 620);
    }
}
