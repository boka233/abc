//! 设备组仓储。
//!
//! # 为什么令牌属于组而不属于机器
//!
//! 线路引用的是组。换机器、加机器、下线一台，线路配置都不用动 —— 这是「一键
//! 对接」能成立的前提：同一条安装命令可以在多台机器上执行，它们自动加入同一
//! 个组并领到相同的线路配置。
//!
//! 如果令牌挂在单机上，每加一台机器都要回面板单独签发，还要把它手工塞进线路
//! 的机器列表，正是我们要消掉的那套流程。
//!
//! # 令牌存储
//!
//! 只存 Argon2id 哈希，明文仅在签发时返回一次。数据库被拖走也拿不到可用凭据。

use crate::db::{new_id, now_string, Database, DbError, Result};
use crate::models::{
    CreateDeviceGroup, DeviceGroupDto, DeviceGroupRow, GroupKind, UpdateDeviceGroup,
};
use crate::users::{hash_password, verify_password};
use sha2::{Digest, Sha256};

pub struct DeviceGroupRepo<'a> {
    db: &'a Database,
}

fn validate_name(name: &str) -> Result<()> {
    let n = name.trim();
    if n.is_empty() || n.chars().count() > 64 {
        return Err(DbError::Invalid("组名长度必须在 1-64 个字符之间".into()));
    }
    Ok(())
}

fn validate_kind(kind: &str) -> Result<()> {
    match kind {
        "inbound" | "outbound" | "both" => Ok(()),
        other => Err(DbError::Invalid(format!(
            "组类型必须是 inbound、outbound 或 both（收到 `{other}`）"
        ))),
    }
}

fn normalise(value: Option<String>) -> Option<String> {
    value.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn token_digest(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}

impl<'a> DeviceGroupRepo<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// 创建设备组，返回组信息与一次性注册令牌。
    ///
    /// 令牌只在此处返回一次，之后无法取回，只能轮换。
    pub async fn create(&self, input: CreateDeviceGroup) -> Result<(DeviceGroupDto, String)> {
        validate_name(&input.name)?;
        validate_kind(&input.kind)?;

        let token = crate::users::generate_password(40);
        let hash = hash_password(&token)?;
        let id = new_id();
        let now = now_string();

        sqlx::query(
            "INSERT INTO device_groups
             (id, name, region, kind, enroll_token_hash, note, enabled,
              config_revision, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, 1, 1, ?, ?)",
        )
        .bind(&id)
        .bind(input.name.trim())
        .bind(input.region.trim())
        .bind(&input.kind)
        .bind(&hash)
        .bind(normalise(input.note))
        .bind(&now)
        .bind(&now)
        .execute(self.db.pool())
        .await
        .map_err(|e| DbError::from_sqlx_with_context(e, "组名"))?;

        Ok((self.get(&id).await?, token))
    }

    pub async fn get(&self, id: &str) -> Result<DeviceGroupDto> {
        let row = self.get_row(id).await?;
        let (nodes_total, nodes_online) = self.member_counts(id).await?;
        Ok(DeviceGroupDto::new(row, nodes_total, nodes_online))
    }

    pub async fn get_row(&self, id: &str) -> Result<DeviceGroupRow> {
        let row: Option<DeviceGroupRow> =
            sqlx::query_as("SELECT * FROM device_groups WHERE id = ?")
                .bind(id)
                .fetch_optional(self.db.pool())
                .await?;
        row.ok_or_else(|| DbError::NotFound(format!("设备组 {id}")))
    }

    /// 组内机器总数与在线数。
    ///
    /// 在线判断走 node_status 的持久化状态；实时数据由控制面的内存遥测覆盖，
    /// 这里给的是重启后仍可用的基线值。
    async fn member_counts(&self, group_id: &str) -> Result<(i64, i64)> {
        let row: (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*),
                    COALESCE(SUM(CASE WHEN s.status = 'online' THEN 1 ELSE 0 END), 0)
             FROM nodes n
             LEFT JOIN node_status s ON s.node_id = n.id
             WHERE n.group_id = ?",
        )
        .bind(group_id)
        .fetch_one(self.db.pool())
        .await?;
        Ok(row)
    }

    pub async fn list(&self) -> Result<Vec<DeviceGroupDto>> {
        let rows: Vec<DeviceGroupRow> = sqlx::query_as(
            // 入口组排在前面，符合「用户 → 入口 → 出口」的阅读顺序。
            "SELECT * FROM device_groups
             ORDER BY CASE kind WHEN 'inbound' THEN 0 WHEN 'both' THEN 1 ELSE 2 END,
                      region, name",
        )
        .fetch_all(self.db.pool())
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let (total, online) = self.member_counts(&row.id).await?;
            out.push(DeviceGroupDto::new(row, total, online));
        }
        Ok(out)
    }

    pub async fn update(&self, id: &str, input: UpdateDeviceGroup) -> Result<DeviceGroupDto> {
        let existing = self.get_row(id).await?;

        if let Some(name) = &input.name {
            validate_name(name)?;
        }
        if let Some(kind) = &input.kind {
            validate_kind(kind)?;
            // 已被线路引用的组不允许改变方向：inbound 组突然变 outbound 会让
            // 引用它的线路失去入口。
            if kind != &existing.kind {
                let refs: (i64,) = sqlx::query_as(
                    "SELECT COUNT(*) FROM routes
                     WHERE entry_group_id = ? OR exit_group_id = ?",
                )
                .bind(id)
                .bind(id)
                .fetch_one(self.db.pool())
                .await?;
                if refs.0 > 0 {
                    return Err(DbError::Conflict(format!(
                        "该组已被 {} 条线路引用，不能更改类型；请先调整线路",
                        refs.0
                    )));
                }
            }
        }

        sqlx::query(
            "UPDATE device_groups
             SET name = ?, region = ?, kind = ?, note = ?, enabled = ?,
                 config_revision = config_revision + 1, updated_at = ?
             WHERE id = ?",
        )
        .bind(input.name.unwrap_or(existing.name).trim())
        .bind(input.region.unwrap_or(existing.region).trim())
        .bind(input.kind.unwrap_or(existing.kind))
        .bind(normalise(input.note.or(existing.note)))
        .bind(input.enabled.map(i64::from).unwrap_or(existing.enabled))
        .bind(now_string())
        .bind(id)
        .execute(self.db.pool())
        .await
        .map_err(|e| DbError::from_sqlx_with_context(e, "组名"))?;

        self.get(id).await
    }

    /// 删除组。仍被线路引用时拒绝 —— 静默丢掉转发规则比报错更糟。
    pub async fn delete(&self, id: &str) -> Result<()> {
        let refs: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM routes WHERE entry_group_id = ? OR exit_group_id = ?",
        )
        .bind(id)
        .bind(id)
        .fetch_one(self.db.pool())
        .await?;
        if refs.0 > 0 {
            return Err(DbError::Conflict(format!(
                "该组仍被 {} 条线路使用，请先删除或改指这些线路",
                refs.0
            )));
        }

        // 组内机器随组级联删除（migration 里定义的 ON DELETE CASCADE）。
        let result = sqlx::query("DELETE FROM device_groups WHERE id = ?")
            .bind(id)
            .execute(self.db.pool())
            .await
            .map_err(|e| DbError::from_sqlx_with_context(e, "设备组"))?;
        if result.rows_affected() == 0 {
            return Err(DbError::NotFound(format!("设备组 {id}")));
        }
        Ok(())
    }

    /// 为新的安装命令签发额外令牌，保留已部署机器正在使用的令牌。
    pub async fn issue_token(&self, id: &str) -> Result<String> {
        self.get_row(id).await?;
        let token = crate::users::generate_password(40);
        sqlx::query(
            "INSERT INTO device_group_tokens (id, group_id, token_digest, created_at)
             VALUES (?, ?, ?, ?)",
        )
        .bind(new_id())
        .bind(id)
        .bind(token_digest(&token))
        .bind(now_string())
        .execute(self.db.pool())
        .await?;
        Ok(token)
    }

    /// 显式轮换整个组的凭据；所有旧令牌（包括已部署机器使用的）立即失效。
    pub async fn rotate_token(&self, id: &str) -> Result<String> {
        let token = crate::users::generate_password(40);
        let hash = hash_password(&token)?;
        let mut tx = self.db.pool().begin().await?;
        let result = sqlx::query(
            "UPDATE device_groups SET enroll_token_hash = ?, updated_at = ? WHERE id = ?",
        )
        .bind(hash)
        .bind(now_string())
        .bind(id)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::NotFound(format!("设备组 {id}")));
        }
        sqlx::query("DELETE FROM device_group_tokens WHERE group_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(token)
    }

    /// 用组令牌认证。未知组与错误令牌返回同一结果，不给攻击者区分依据。
    pub async fn verify_token(&self, group_id: &str, token: &str) -> Result<Option<DeviceGroupRow>> {
        let Some(row) = sqlx::query_as::<_, DeviceGroupRow>(
            "SELECT * FROM device_groups WHERE id = ?",
        )
        .bind(group_id)
        .fetch_optional(self.db.pool())
        .await?
        else {
            return Ok(None);
        };
        if row.enabled == 0 {
            return Ok(None);
        }
        if verify_password(token, &row.enroll_token_hash) {
            return Ok(Some(row));
        }
        let extra: Option<(i64,)> = sqlx::query_as(
            "SELECT 1 FROM device_group_tokens WHERE group_id = ? AND token_digest = ?",
        )
        .bind(group_id)
        .bind(token_digest(token))
        .fetch_optional(self.db.pool())
        .await?;
        Ok(extra.map(|_| row))
    }

    /// 仅凭令牌查找组，供 agent 自注册使用。
    ///
    /// 一键对接的命令里只有令牌，没有组 id —— 让用户从面板复制两个值是多余的
    /// 摩擦。新令牌先用摘要索引查找；旧版组令牌仍按 Argon2 哈希逐组校验。
    pub async fn find_by_token(&self, token: &str) -> Result<Option<DeviceGroupRow>> {
        let extra: Option<(String,)> = sqlx::query_as(
            "SELECT t.group_id FROM device_group_tokens t
             JOIN device_groups g ON g.id = t.group_id
             WHERE g.enabled = 1 AND t.token_digest = ?",
        )
        .bind(token_digest(token))
        .fetch_optional(self.db.pool())
        .await?;
        if let Some((group_id,)) = extra {
            return Ok(Some(self.get_row(&group_id).await?));
        }
        let rows: Vec<DeviceGroupRow> =
            sqlx::query_as("SELECT * FROM device_groups WHERE enabled = 1")
                .fetch_all(self.db.pool())
                .await?;
        for row in rows {
            if verify_password(token, &row.enroll_token_hash) {
                return Ok(Some(row));
            }
        }
        Ok(None)
    }

    /// 递增配置版本，组内 agent 下次轮询时会重载。
    pub async fn bump_revision(&self, id: &str) -> Result<i64> {
        sqlx::query(
            "UPDATE device_groups
             SET config_revision = config_revision + 1, updated_at = ?
             WHERE id = ?",
        )
        .bind(now_string())
        .bind(id)
        .execute(self.db.pool())
        .await?;
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT config_revision FROM device_groups WHERE id = ?")
                .bind(id)
                .fetch_optional(self.db.pool())
                .await?;
        row.map(|r| r.0)
            .ok_or_else(|| DbError::NotFound(format!("设备组 {id}")))
    }

    pub async fn count(&self) -> Result<i64> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM device_groups")
            .fetch_one(self.db.pool())
            .await?;
        Ok(row.0)
    }
}

impl GroupKind {
    /// 该类型的组能否承担入口（监听用户连接、拨隧道）。
    pub fn can_entry(self) -> bool {
        matches!(self, GroupKind::Inbound | GroupKind::Both)
    }

    /// 该类型的组能否承担出口（终结隧道、拨目标）。
    pub fn can_exit(self) -> bool {
        matches!(self, GroupKind::Outbound | GroupKind::Both)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn db() -> Database {
        Database::connect_in_memory().await.unwrap()
    }

    fn new_group(name: &str, kind: &str) -> CreateDeviceGroup {
        CreateDeviceGroup {
            name: name.into(),
            region: "test".into(),
            kind: kind.into(),
            note: None,
        }
    }

    #[tokio::test]
    async fn create_and_fetch() {
        let db = db().await;
        let repo = DeviceGroupRepo::new(&db);
        let (group, token) = repo.create(new_group("香港出口", "outbound")).await.unwrap();

        assert_eq!(group.name, "香港出口");
        assert_eq!(group.kind, "outbound");
        assert_eq!(group.nodes_total, 0);
        assert_eq!(group.nodes_online, 0);
        assert_eq!(group.config_revision, 1);
        assert!(token.len() >= 40);

        assert_eq!(repo.get(&group.id).await.unwrap().id, group.id);
    }

    #[tokio::test]
    async fn token_is_stored_hashed_only() {
        let db = db().await;
        let repo = DeviceGroupRepo::new(&db);
        let (group, token) = repo.create(new_group("g", "inbound")).await.unwrap();

        let row = repo.get_row(&group.id).await.unwrap();
        assert_ne!(row.enroll_token_hash, token, "令牌以明文存储了");
        assert!(row.enroll_token_hash.starts_with("$argon2id$"));
        assert!(!row.enroll_token_hash.contains(&token));
    }

    #[tokio::test]
    async fn dto_never_carries_the_token_hash() {
        let db = db().await;
        let repo = DeviceGroupRepo::new(&db);
        let (group, _) = repo.create(new_group("g", "inbound")).await.unwrap();
        let json = serde_json::to_string(&group).unwrap();
        assert!(!json.contains("argon2"), "令牌哈希泄露到 API: {json}");
    }

    #[tokio::test]
    async fn token_authentication() {
        let db = db().await;
        let repo = DeviceGroupRepo::new(&db);
        let (group, token) = repo.create(new_group("g", "inbound")).await.unwrap();

        assert!(repo.verify_token(&group.id, &token).await.unwrap().is_some());
        assert!(repo.verify_token(&group.id, "wrong").await.unwrap().is_none());
        assert!(repo.verify_token("no-such-group", &token).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn find_by_token_enables_one_command_enrolment() {
        // 一键对接的命令里只有令牌，没有组 id。
        let db = db().await;
        let repo = DeviceGroupRepo::new(&db);
        let (a, token_a) = repo.create(new_group("上海入口", "inbound")).await.unwrap();
        let (_b, token_b) = repo.create(new_group("香港出口", "outbound")).await.unwrap();

        let found = repo.find_by_token(&token_a).await.unwrap().expect("应能按令牌找到组");
        assert_eq!(found.id, a.id);

        // 不同组的令牌不能互相认证。
        assert_ne!(
            repo.find_by_token(&token_b).await.unwrap().unwrap().id,
            a.id
        );
        assert!(repo.find_by_token("不存在的令牌").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn disabled_group_rejects_enrolment() {
        let db = db().await;
        let repo = DeviceGroupRepo::new(&db);
        let (group, token) = repo.create(new_group("g", "inbound")).await.unwrap();

        repo.update(
            &group.id,
            UpdateDeviceGroup {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        assert!(repo.verify_token(&group.id, &token).await.unwrap().is_none());
        assert!(
            repo.find_by_token(&token).await.unwrap().is_none(),
            "停用的组不应接受新机器注册"
        );
    }

    #[tokio::test]
    async fn rotating_invalidates_the_old_token() {
        let db = db().await;
        let repo = DeviceGroupRepo::new(&db);
        let (group, old) = repo.create(new_group("g", "inbound")).await.unwrap();

        let additional = repo.issue_token(&group.id).await.unwrap();
        assert_ne!(old, additional);
        assert!(repo.verify_token(&group.id, &old).await.unwrap().is_some());
        assert!(repo.verify_token(&group.id, &additional).await.unwrap().is_some());
        assert_eq!(repo.find_by_token(&additional).await.unwrap().unwrap().id, group.id);
        let stored: (String,) = sqlx::query_as(
            "SELECT token_digest FROM device_group_tokens WHERE group_id = ?",
        )
        .bind(&group.id)
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(stored.0, token_digest(&additional));
        assert_ne!(stored.0, additional);

        let new = repo.rotate_token(&group.id).await.unwrap();
        assert_ne!(old, new);
        assert!(repo.verify_token(&group.id, &old).await.unwrap().is_none());
        assert!(repo.verify_token(&group.id, &additional).await.unwrap().is_none());
        assert!(repo.find_by_token(&additional).await.unwrap().is_none());
        assert!(repo.verify_token(&group.id, &new).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn duplicate_name_is_a_conflict() {
        let db = db().await;
        let repo = DeviceGroupRepo::new(&db);
        repo.create(new_group("hk", "outbound")).await.unwrap();
        assert!(matches!(
            repo.create(new_group("hk", "inbound")).await,
            Err(DbError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn invalid_kind_is_rejected_before_writing() {
        let db = db().await;
        let repo = DeviceGroupRepo::new(&db);
        assert!(matches!(
            repo.create(new_group("g", "sideways")).await,
            Err(DbError::Invalid(_))
        ));
        assert_eq!(repo.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn update_bumps_the_revision() {
        let db = db().await;
        let repo = DeviceGroupRepo::new(&db);
        let (group, _) = repo.create(new_group("g", "inbound")).await.unwrap();

        let updated = repo
            .update(
                &group.id,
                UpdateDeviceGroup {
                    region: Some("cn-shanghai".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.region, "cn-shanghai");
        assert_eq!(updated.config_revision, 2);
    }

    #[tokio::test]
    async fn member_counts_reflect_the_group() {
        let db = db().await;
        let groups = DeviceGroupRepo::new(&db);
        let (group, _) = groups.create(new_group("hk", "outbound")).await.unwrap();

        let nodes = crate::nodes::NodeRepo::new(&db);
        for name in ["hk-01", "hk-02", "hk-03"] {
            nodes
                .register(&group.id, name, Some("host".into()), "exit")
                .await
                .unwrap();
        }

        let dto = groups.get(&group.id).await.unwrap();
        assert_eq!(dto.nodes_total, 3, "一组多机是本次改动的核心");
        assert_eq!(dto.nodes_online, 0, "尚无心跳");
    }

    #[tokio::test]
    async fn listing_puts_inbound_first() {
        let db = db().await;
        let repo = DeviceGroupRepo::new(&db);
        repo.create(new_group("z-出口", "outbound")).await.unwrap();
        repo.create(new_group("a-入口", "inbound")).await.unwrap();

        let list = repo.list().await.unwrap();
        assert_eq!(list[0].kind, "inbound", "入口组应排在前面");
        assert_eq!(list[1].kind, "outbound");
    }

    #[tokio::test]
    async fn kind_capabilities() {
        assert!(GroupKind::Inbound.can_entry() && !GroupKind::Inbound.can_exit());
        assert!(!GroupKind::Outbound.can_entry() && GroupKind::Outbound.can_exit());
        assert!(GroupKind::Both.can_entry() && GroupKind::Both.can_exit());
    }
}
