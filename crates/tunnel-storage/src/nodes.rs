//! Node and endpoint repositories.

use crate::db::{new_id, now_string, Database, DbError, Result};
use crate::models::{
    CreateEndpoint, CreateNode, EndpointDto, EndpointRow, NodeDto, NodeRow, NodeStatusRow,
    UpdateEndpoint, UpdateNode,
};
// 令牌相关的哈希/校验已上移到 groups.rs —— 机器本身不再持有凭据。

pub struct NodeRepo<'a> {
    db: &'a Database,
}

fn validate_name(name: &str, what: &str) -> Result<()> {
    let n = name.trim();
    if n.is_empty() || n.chars().count() > 64 {
        return Err(DbError::Invalid(format!(
            "{what} name must be 1-64 characters"
        )));
    }
    Ok(())
}

fn validate_role(role: &str) -> Result<()> {
    match role {
        "entry" | "exit" | "both" => Ok(()),
        other => Err(DbError::Invalid(format!(
            "role must be entry, exit or both (got `{other}`)"
        ))),
    }
}

fn validate_kind(kind: &str) -> Result<()> {
    match kind {
        "public" | "private" | "iepl" => Ok(()),
        other => Err(DbError::Invalid(format!(
            "endpoint kind must be public, private or iepl (got `{other}`)"
        ))),
    }
}

fn validate_priority(priority: &str) -> Result<()> {
    match priority {
        "primary" | "backup" => Ok(()),
        other => Err(DbError::Invalid(format!(
            "priority must be primary or backup (got `{other}`)"
        ))),
    }
}

/// Reject a source IP that is not parseable. Whether it exists on the *agent's*
/// host cannot be checked here, so the agent validates that at apply time.
fn validate_optional_ip(value: Option<&str>, field: &str) -> Result<()> {
    if let Some(v) = value {
        let v = v.trim();
        if v.is_empty() {
            return Ok(());
        }
        if v.parse::<std::net::IpAddr>().is_err() {
            return Err(DbError::Invalid(format!("{field} `{v}` is not a valid IP")));
        }
    }
    Ok(())
}

fn normalise_optional(value: Option<String>) -> Option<String> {
    value
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

impl<'a> NodeRepo<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// 在面板上手工添加机器。
    ///
    /// 不再返回令牌 —— 认证凭据在组上。装机用组的一键对接命令。
    pub async fn create(&self, input: CreateNode) -> Result<NodeDto> {
        validate_name(&input.name, "机器")?;
        validate_role(&input.role)?;

        let id = new_id();
        let now = now_string();

        sqlx::query(
            "INSERT INTO nodes
             (id, group_id, name, hostname, region, role, public_address,
              management_address, note, enabled, config_revision, created_at, updated_at)
             VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?, 1, 1, ?, ?)",
        )
        .bind(&id)
        .bind(&input.group_id)
        .bind(input.name.trim())
        .bind(input.region.trim())
        .bind(&input.role)
        .bind(normalise_optional(input.public_address))
        .bind(normalise_optional(input.management_address))
        .bind(normalise_optional(input.note))
        .bind(&now)
        .bind(&now)
        .execute(self.db.pool())
        .await
        .map_err(|e| DbError::from_sqlx_with_context(e, "该组内的机器名"))?;

        self.get(&id).await
    }

    /// agent 自注册：凭组令牌把自己登记进组。
    ///
    /// 幂等性按 (group_id, name) 判定：同一台机器重装 agent 后会更新既有记录，
    /// 而不是在组里堆出一堆重复条目。这是一键对接可以反复执行的前提。
    pub async fn register(
        &self,
        group_id: &str,
        name: &str,
        hostname: Option<String>,
        role: &str,
    ) -> Result<NodeDto> {
        validate_name(name, "机器")?;
        validate_role(role)?;

        let existing: Option<(String,)> =
            sqlx::query_as("SELECT id FROM nodes WHERE group_id = ? AND name = ?")
                .bind(group_id)
                .bind(name.trim())
                .fetch_optional(self.db.pool())
                .await?;

        let now = now_string();
        let id = match existing {
            Some((id,)) => {
                // 重新注册：刷新主机名与角色，保留 id 以免 traffic_stats 断档。
                sqlx::query(
                    "UPDATE nodes SET hostname = ?, role = ?, enabled = 1, updated_at = ?
                     WHERE id = ?",
                )
                .bind(&hostname)
                .bind(role)
                .bind(&now)
                .bind(&id)
                .execute(self.db.pool())
                .await?;
                id
            }
            None => {
                let id = new_id();
                sqlx::query(
                    "INSERT INTO nodes
                     (id, group_id, name, hostname, region, role, enabled,
                      config_revision, created_at, updated_at)
                     VALUES (?, ?, ?, ?, '', ?, 1, 1, ?, ?)",
                )
                .bind(&id)
                .bind(group_id)
                .bind(name.trim())
                .bind(&hostname)
                .bind(role)
                .bind(&now)
                .bind(&now)
                .execute(self.db.pool())
                .await
                .map_err(|e| DbError::from_sqlx_with_context(e, "该组内的机器名"))?;
                id
            }
        };

        self.get(&id).await
    }

    pub async fn get(&self, id: &str) -> Result<NodeDto> {
        let node: Option<NodeRow> = sqlx::query_as("SELECT * FROM nodes WHERE id = ?")
            .bind(id)
            .fetch_optional(self.db.pool())
            .await?;
        let node = node.ok_or_else(|| DbError::NotFound(format!("机器 {id}")))?;
        let status: Option<NodeStatusRow> =
            sqlx::query_as("SELECT * FROM node_status WHERE node_id = ?")
                .bind(id)
                .fetch_optional(self.db.pool())
                .await?;
        let group_name: Option<(String,)> =
            sqlx::query_as("SELECT name FROM device_groups WHERE id = ?")
                .bind(&node.group_id)
                .fetch_optional(self.db.pool())
                .await?;
        Ok(NodeDto::with_group(node, status, group_name.map(|g| g.0)))
    }

    /// 组内所有机器。
    pub async fn list_for_group(&self, group_id: &str) -> Result<Vec<NodeDto>> {
        let nodes: Vec<NodeRow> =
            sqlx::query_as("SELECT * FROM nodes WHERE group_id = ? ORDER BY name")
                .bind(group_id)
                .fetch_all(self.db.pool())
                .await?;
        let statuses: Vec<NodeStatusRow> = sqlx::query_as("SELECT * FROM node_status")
            .fetch_all(self.db.pool())
            .await?;
        let group_name: Option<(String,)> =
            sqlx::query_as("SELECT name FROM device_groups WHERE id = ?")
                .bind(group_id)
                .fetch_optional(self.db.pool())
                .await?;
        let group_name = group_name.map(|g| g.0);

        Ok(nodes
            .into_iter()
            .map(|n| {
                let status = statuses.iter().find(|s| s.node_id == n.id).cloned();
                NodeDto::with_group(n, status, group_name.clone())
            })
            .collect())
    }

    pub async fn get_row(&self, id: &str) -> Result<NodeRow> {
        let node: Option<NodeRow> = sqlx::query_as("SELECT * FROM nodes WHERE id = ?")
            .bind(id)
            .fetch_optional(self.db.pool())
            .await?;
        node.ok_or_else(|| DbError::NotFound(format!("机器 {id}")))
    }

    pub async fn list(&self) -> Result<Vec<NodeDto>> {
        let rows: Vec<(NodeRow, Option<String>)> = sqlx::query_as::<_, NodeGroupJoinRow>(
            "SELECT n.*, g.name AS group_name
             FROM nodes n LEFT JOIN device_groups g ON g.id = n.group_id
             ORDER BY g.name, n.name",
        )
        .fetch_all(self.db.pool())
        .await
        .map(|rows| rows.into_iter().map(|r| (r.node, r.group_name)).collect())?;

        let statuses: Vec<NodeStatusRow> = sqlx::query_as("SELECT * FROM node_status")
            .fetch_all(self.db.pool())
            .await?;

        Ok(rows
            .into_iter()
            .map(|(n, group_name)| {
                let status = statuses.iter().find(|s| s.node_id == n.id).cloned();
                NodeDto::with_group(n, status, group_name)
            })
            .collect())
    }

    pub async fn update(&self, id: &str, input: UpdateNode) -> Result<NodeDto> {
        let existing = self.get_row(id).await?;

        if let Some(name) = &input.name {
            validate_name(name, "node")?;
        }
        if let Some(role) = &input.role {
            validate_role(role)?;
        }

        let name = input.name.unwrap_or(existing.name);
        let region = input.region.unwrap_or(existing.region);
        let role = input.role.unwrap_or(existing.role);
        let public_address = input.public_address.or(existing.public_address);
        let management_address = input.management_address.or(existing.management_address);
        let note = input.note.or(existing.note);
        let enabled = input.enabled.map(i64::from).unwrap_or(existing.enabled);

        sqlx::query(
            "UPDATE nodes
             SET name = ?, region = ?, role = ?, public_address = ?, management_address = ?,
                 note = ?, enabled = ?, config_revision = config_revision + 1, updated_at = ?
             WHERE id = ?",
        )
        .bind(name.trim())
        .bind(region.trim())
        .bind(role)
        .bind(normalise_optional(public_address))
        .bind(normalise_optional(management_address))
        .bind(normalise_optional(note))
        .bind(enabled)
        .bind(now_string())
        .bind(id)
        .execute(self.db.pool())
        .await
        .map_err(|e| DbError::from_sqlx_with_context(e, "node name"))?;

        self.get(id).await
    }

    /// 删除机器。
    ///
    /// 机器不再被线路直接引用（线路指向组），所以删一台机器是安全的 —— 组内
    /// 其余机器继续承载该线路。这正是一组多机的收益。
    pub async fn delete(&self, id: &str) -> Result<()> {
        let result = sqlx::query("DELETE FROM nodes WHERE id = ?")
            .bind(id)
            .execute(self.db.pool())
            .await
            .map_err(|e| DbError::from_sqlx_with_context(e, "机器"))?;
        if result.rows_affected() == 0 {
            return Err(DbError::NotFound(format!("机器 {id}")));
        }
        Ok(())
    }

    /// 机器所属组的 id。
    pub async fn group_of(&self, node_id: &str) -> Result<String> {
        let row: Option<(String,)> = sqlx::query_as("SELECT group_id FROM nodes WHERE id = ?")
            .bind(node_id)
            .fetch_optional(self.db.pool())
            .await?;
        row.map(|r| r.0)
            .ok_or_else(|| DbError::NotFound(format!("机器 {node_id}")))
    }

    /// Bump the config revision so agents pick up a new bundle.
    pub async fn bump_revision(&self, id: &str) -> Result<i64> {
        sqlx::query("UPDATE nodes SET config_revision = config_revision + 1, updated_at = ? WHERE id = ?")
            .bind(now_string())
            .bind(id)
            .execute(self.db.pool())
            .await?;
        let row: Option<(i64,)> = sqlx::query_as("SELECT config_revision FROM nodes WHERE id = ?")
            .bind(id)
            .fetch_optional(self.db.pool())
            .await?;
        row.map(|r| r.0)
            .ok_or_else(|| DbError::NotFound(format!("node {id}")))
    }

    /// Record a heartbeat. Upsert, because the status row may not exist yet.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_heartbeat(&self, status: NodeStatusRow) -> Result<()> {
        sqlx::query(
            "INSERT INTO node_status
             (node_id, status, cpu_percent, memory_used_bytes, memory_total_bytes, uptime_secs,
              host_uptime_secs, disk_used_bytes, disk_total_bytes, observed_ip,
              connections, rx_bytes, tx_bytes, rx_bps, tx_bps, tunnels_online, tunnels_total,
              agent_version, config_revision, interfaces_json, last_heartbeat_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT (node_id) DO UPDATE SET
               status = excluded.status,
               cpu_percent = excluded.cpu_percent,
               memory_used_bytes = excluded.memory_used_bytes,
               memory_total_bytes = excluded.memory_total_bytes,
               uptime_secs = excluded.uptime_secs,
               host_uptime_secs = excluded.host_uptime_secs,
               disk_used_bytes = excluded.disk_used_bytes,
               disk_total_bytes = excluded.disk_total_bytes,
               observed_ip = COALESCE(excluded.observed_ip, observed_ip),
               connections = excluded.connections,
               rx_bytes = excluded.rx_bytes,
               tx_bytes = excluded.tx_bytes,
               rx_bps = excluded.rx_bps,
               tx_bps = excluded.tx_bps,
               tunnels_online = excluded.tunnels_online,
               tunnels_total = excluded.tunnels_total,
               agent_version = excluded.agent_version,
               config_revision = excluded.config_revision,
               interfaces_json = excluded.interfaces_json,
               last_heartbeat_at = excluded.last_heartbeat_at",
        )
        .bind(&status.node_id)
        .bind(&status.status)
        .bind(status.cpu_percent)
        .bind(status.memory_used_bytes)
        .bind(status.memory_total_bytes)
        .bind(status.uptime_secs)
        .bind(status.host_uptime_secs)
        .bind(status.disk_used_bytes)
        .bind(status.disk_total_bytes)
        .bind(&status.observed_ip)
        .bind(status.connections)
        .bind(status.rx_bytes)
        .bind(status.tx_bytes)
        .bind(status.rx_bps)
        .bind(status.tx_bps)
        .bind(status.tunnels_online)
        .bind(status.tunnels_total)
        .bind(&status.agent_version)
        .bind(status.config_revision)
        .bind(&status.interfaces_json)
        .bind(now_string())
        .execute(self.db.pool())
        .await
        .map_err(|e| DbError::from_sqlx_with_context(e, "node status"))?;
        Ok(())
    }

    /// Mark nodes offline whose last heartbeat is older than `stale_secs`.
    ///
    /// Returns how many were changed. Called on a timer by the control plane: a
    /// node that stops reporting must not sit at "online" forever.
    pub async fn mark_stale_offline(&self, stale_secs: i64) -> Result<u64> {
        let cutoff = (chrono::Utc::now() - chrono::Duration::seconds(stale_secs)).to_rfc3339();
        let result = sqlx::query(
            "UPDATE node_status
             SET status = 'offline', connections = 0, rx_bps = 0, tx_bps = 0, tunnels_online = 0
             WHERE status <> 'offline'
               AND (last_heartbeat_at IS NULL OR last_heartbeat_at < ?)",
        )
        .bind(cutoff)
        .execute(self.db.pool())
        .await?;
        Ok(result.rows_affected())
    }
}

// ---------------------------------------------------------------------------
// endpoints
// ---------------------------------------------------------------------------

pub struct EndpointRepo<'a> {
    db: &'a Database,
}

impl<'a> EndpointRepo<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    pub async fn create(&self, input: CreateEndpoint) -> Result<EndpointDto> {
        validate_name(&input.name, "endpoint")?;
        validate_kind(&input.kind)?;
        validate_priority(&input.priority)?;
        validate_optional_ip(input.source_ip.as_deref(), "source_ip")?;
        if input.address.trim().is_empty() {
            return Err(DbError::Invalid("endpoint address is required".into()));
        }
        if input.port == 0 {
            return Err(DbError::Invalid("endpoint port must be 1-65535".into()));
        }

        let id = new_id();
        let now = now_string();
        sqlx::query(
            "INSERT INTO endpoints
             (id, node_id, name, address, port, kind, priority, interface, source_ip,
              tls_server_name, enabled, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
        )
        .bind(&id)
        .bind(&input.node_id)
        .bind(input.name.trim())
        .bind(input.address.trim())
        .bind(i64::from(input.port))
        .bind(&input.kind)
        .bind(&input.priority)
        .bind(normalise_optional(input.interface))
        .bind(normalise_optional(input.source_ip))
        .bind(normalise_optional(input.tls_server_name))
        .bind(&now)
        .bind(&now)
        .execute(self.db.pool())
        .await
        .map_err(|e| DbError::from_sqlx_with_context(e, "endpoint name on this node"))?;

        self.get(&id).await
    }

    pub async fn get(&self, id: &str) -> Result<EndpointDto> {
        let row: Option<EndpointRow> = sqlx::query_as("SELECT * FROM endpoints WHERE id = ?")
            .bind(id)
            .fetch_optional(self.db.pool())
            .await?;
        let row = row.ok_or_else(|| DbError::NotFound(format!("endpoint {id}")))?;
        let node_name: Option<(String,)> = sqlx::query_as("SELECT name FROM nodes WHERE id = ?")
            .bind(&row.node_id)
            .fetch_optional(self.db.pool())
            .await?;
        Ok(EndpointDto::new(row, node_name.map(|n| n.0)))
    }

    pub async fn list(&self) -> Result<Vec<EndpointDto>> {
        let rows: Vec<(EndpointRow, String)> = sqlx::query_as(
            "SELECT e.*, n.name AS node_name
             FROM endpoints e JOIN nodes n ON n.id = e.node_id
             ORDER BY n.name,
                      CASE e.priority WHEN 'primary' THEN 0 ELSE 1 END,
                      e.name",
        )
        .fetch_all(self.db.pool())
        .await
        .map(|rows: Vec<EndpointJoinRow>| {
            rows.into_iter()
                .map(|r| (r.endpoint, r.node_name))
                .collect()
        })?;
        Ok(rows
            .into_iter()
            .map(|(row, node_name)| EndpointDto::new(row, Some(node_name)))
            .collect())
    }

    /// Endpoints for a node, primary before backup.
    ///
    /// The ordering uses an explicit CASE rather than `ORDER BY priority`:
    /// alphabetically "backup" sorts before "primary", which would hand callers
    /// the failover list in exactly the wrong order.
    pub async fn list_for_node(&self, node_id: &str) -> Result<Vec<EndpointRow>> {
        let rows: Vec<EndpointRow> = sqlx::query_as(
            "SELECT * FROM endpoints WHERE node_id = ?
             ORDER BY CASE priority WHEN 'primary' THEN 0 ELSE 1 END, name",
        )
        .bind(node_id)
        .fetch_all(self.db.pool())
        .await?;
        Ok(rows)
    }

    pub async fn update(&self, id: &str, input: UpdateEndpoint) -> Result<EndpointDto> {
        let existing: Option<EndpointRow> = sqlx::query_as("SELECT * FROM endpoints WHERE id = ?")
            .bind(id)
            .fetch_optional(self.db.pool())
            .await?;
        let existing = existing.ok_or_else(|| DbError::NotFound(format!("endpoint {id}")))?;

        if let Some(name) = &input.name {
            validate_name(name, "endpoint")?;
        }
        if let Some(kind) = &input.kind {
            validate_kind(kind)?;
        }
        if let Some(priority) = &input.priority {
            validate_priority(priority)?;
        }
        validate_optional_ip(input.source_ip.as_deref(), "source_ip")?;
        if let Some(0) = input.port {
            return Err(DbError::Invalid("endpoint port must be 1-65535".into()));
        }

        sqlx::query(
            "UPDATE endpoints
             SET name = ?, address = ?, port = ?, kind = ?, priority = ?, interface = ?,
                 source_ip = ?, tls_server_name = ?, enabled = ?, updated_at = ?
             WHERE id = ?",
        )
        .bind(input.name.unwrap_or(existing.name).trim())
        .bind(input.address.unwrap_or(existing.address).trim())
        .bind(input.port.map(i64::from).unwrap_or(existing.port))
        .bind(input.kind.unwrap_or(existing.kind))
        .bind(input.priority.unwrap_or(existing.priority))
        .bind(normalise_optional(input.interface.or(existing.interface)))
        .bind(normalise_optional(input.source_ip.or(existing.source_ip)))
        .bind(normalise_optional(
            input.tls_server_name.or(existing.tls_server_name),
        ))
        .bind(input.enabled.map(i64::from).unwrap_or(existing.enabled))
        .bind(now_string())
        .bind(id)
        .execute(self.db.pool())
        .await
        .map_err(|e| DbError::from_sqlx_with_context(e, "endpoint name on this node"))?;

        self.get(id).await
    }

    /// Delete an endpoint. Refuses while a route still references it, since
    /// removing an endpoint out from under a route would leave it undialable.
    pub async fn delete(&self, id: &str) -> Result<()> {
        let referencing: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM route_endpoints WHERE endpoint_id = ?")
                .bind(id)
                .fetch_one(self.db.pool())
                .await?;
        if referencing.0 > 0 {
            return Err(DbError::Conflict(format!(
                "endpoint is still used by {} route(s)",
                referencing.0
            )));
        }
        let result = sqlx::query("DELETE FROM endpoints WHERE id = ?")
            .bind(id)
            .execute(self.db.pool())
            .await?;
        if result.rows_affected() == 0 {
            return Err(DbError::NotFound(format!("endpoint {id}")));
        }
        Ok(())
    }
}

/// node + 组名的联表行。
struct NodeGroupJoinRow {
    node: NodeRow,
    group_name: Option<String>,
}

impl<'r> sqlx::FromRow<'r, sqlx::sqlite::SqliteRow> for NodeGroupJoinRow {
    fn from_row(row: &'r sqlx::sqlite::SqliteRow) -> std::result::Result<Self, sqlx::Error> {
        Ok(Self {
            node: NodeRow::from_row(row)?,
            group_name: sqlx::Row::try_get(row, "group_name")?,
        })
    }
}

/// Helper for the endpoint+node join.
struct EndpointJoinRow {
    endpoint: EndpointRow,
    node_name: String,
}

impl<'r> sqlx::FromRow<'r, sqlx::sqlite::SqliteRow> for EndpointJoinRow {
    fn from_row(row: &'r sqlx::sqlite::SqliteRow) -> std::result::Result<Self, sqlx::Error> {
        Ok(Self {
            endpoint: EndpointRow::from_row(row)?,
            node_name: sqlx::Row::try_get(row, "node_name")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::groups::DeviceGroupRepo;
    use crate::models::CreateDeviceGroup;

    async fn db() -> Database {
        Database::connect_in_memory().await.unwrap()
    }

    /// 建一个设备组并返回其 id。机器必须归属某个组。
    async fn group(db: &Database, name: &str, kind: &str) -> String {
        DeviceGroupRepo::new(db)
            .create(CreateDeviceGroup {
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

    fn new_node(group_id: &str, name: &str, role: &str) -> CreateNode {
        CreateNode {
            group_id: group_id.into(),
            name: name.into(),
            region: "test".into(),
            role: role.into(),
            public_address: Some("203.0.113.1".into()),
            management_address: None,
            note: None,
        }
    }

    fn new_endpoint(node_id: &str, name: &str, kind: &str) -> CreateEndpoint {
        CreateEndpoint {
            node_id: node_id.into(),
            name: name.into(),
            address: "10.20.0.2".into(),
            port: 5000,
            kind: kind.into(),
            priority: "primary".into(),
            interface: Some("eth1".into()),
            source_ip: Some("10.20.0.1".into()),
            tls_server_name: Some("exit.internal".into()),
        }
    }

    #[tokio::test]
    async fn create_and_fetch_a_node() {
        let db = db().await;
        let g = group(&db, "上海入口", "inbound").await;
        let repo = NodeRepo::new(&db);
        let node = repo.create(new_node(&g, "sh-01", "entry")).await.unwrap();

        assert_eq!(node.name, "sh-01");
        assert_eq!(node.group_id, g);
        assert_eq!(node.group_name.as_deref(), Some("上海入口"));
        assert_eq!(node.status, "offline", "新机器还没上报过");
        assert_eq!(node.config_revision, 1);

        assert_eq!(repo.get(&node.id).await.unwrap().id, node.id);
    }

    #[tokio::test]
    async fn a_node_carries_no_token_of_its_own() {
        // 认证凭据已上移到组级别。NodeRow 里没有令牌字段，结构上就无法按单机签发。
        let db = db().await;
        let g = group(&db, "g", "inbound").await;
        let node = NodeRepo::new(&db)
            .create(new_node(&g, "sh-01", "entry"))
            .await
            .unwrap();
        let json = serde_json::to_string(&node).unwrap();
        assert!(!json.contains("token"), "机器 DTO 不应出现任何令牌字段: {json}");
    }

    #[tokio::test]
    async fn self_registration_is_idempotent() {
        // 一键对接的命令可以反复执行（重装、升级），不能每次都在组里堆一台新机器。
        let db = db().await;
        let g = group(&db, "hk", "outbound").await;
        let repo = NodeRepo::new(&db);

        let first = repo
            .register(&g, "hk-01", Some("host-a".into()), "exit")
            .await
            .unwrap();
        let second = repo
            .register(&g, "hk-01", Some("host-b".into()), "exit")
            .await
            .unwrap();

        assert_eq!(first.id, second.id, "重复注册必须复用原记录，否则流量统计会断档");
        assert_eq!(second.hostname.as_deref(), Some("host-b"), "主机名应被刷新");
        assert_eq!(repo.list_for_group(&g).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn one_group_holds_many_machines() {
        // 本次改动的核心能力：一条安装命令，多台机器加入同组。
        let db = db().await;
        let g = group(&db, "香港出口", "outbound").await;
        let repo = NodeRepo::new(&db);

        for name in ["hk-01", "hk-02", "hk-03"] {
            repo.register(&g, name, Some(format!("{name}.internal")), "exit")
                .await
                .unwrap();
        }

        let members = repo.list_for_group(&g).await.unwrap();
        assert_eq!(members.len(), 3);
        assert!(members.iter().all(|m| m.group_id == g));
        // 组名随成员一起返回，面板不用再查一次。
        assert!(members
            .iter()
            .all(|m| m.group_name.as_deref() == Some("香港出口")));
    }

    #[tokio::test]
    async fn machine_names_are_unique_per_group_only() {
        let db = db().await;
        let a = group(&db, "上海", "inbound").await;
        let b = group(&db, "香港", "outbound").await;
        let repo = NodeRepo::new(&db);

        repo.create(new_node(&a, "relay-01", "entry")).await.unwrap();
        // 同名机器在另一个组里是允许的。
        repo.create(new_node(&b, "relay-01", "exit")).await.unwrap();
        // 同组内重名则冲突。
        assert!(matches!(
            repo.create(new_node(&a, "relay-01", "entry")).await,
            Err(DbError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn invalid_role_is_rejected_before_touching_the_database() {
        let db = db().await;
        let g = group(&db, "g", "inbound").await;
        let repo = NodeRepo::new(&db);
        assert!(matches!(
            repo.create(new_node(&g, "sh-01", "sideways")).await,
            Err(DbError::Invalid(_))
        ));
        assert!(repo.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_node_in_a_missing_group_is_rejected() {
        let db = db().await;
        let err = NodeRepo::new(&db)
            .create(new_node("no-such-group", "x", "entry"))
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::Invalid(_)), "{err:?}");
    }

    #[tokio::test]
    async fn updating_a_node_bumps_its_config_revision() {
        let db = db().await;
        let g = group(&db, "g", "inbound").await;
        let repo = NodeRepo::new(&db);
        let node = repo.create(new_node(&g, "sh-01", "entry")).await.unwrap();
        assert_eq!(node.config_revision, 1);

        let updated = repo
            .update(
                &node.id,
                UpdateNode {
                    region: Some("cn-sh".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.region, "cn-sh");
        assert_eq!(updated.config_revision, 2);
    }

    #[tokio::test]
    async fn group_of_resolves_membership() {
        let db = db().await;
        let g = group(&db, "g", "inbound").await;
        let repo = NodeRepo::new(&db);
        let node = repo.create(new_node(&g, "sh-01", "entry")).await.unwrap();
        assert_eq!(repo.group_of(&node.id).await.unwrap(), g);
        assert!(matches!(
            repo.group_of("nope").await,
            Err(DbError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn heartbeat_upserts_and_then_updates() {
        let db = db().await;
        let g = group(&db, "g", "inbound").await;
        let repo = NodeRepo::new(&db);
        let node = repo.create(new_node(&g, "sh-01", "entry")).await.unwrap();

        let mut status = NodeStatusRow {
            node_id: node.id.clone(),
            status: "online".into(),
            cpu_percent: 12.5,
            observed_ip: Some("203.0.113.10".into()),
            host_uptime_secs: 7200,
            disk_used_bytes: 25,
            disk_total_bytes: 100,
            connections: 42,
            rx_bytes: 1000,
            tx_bytes: 2000,
            tunnels_online: 8,
            tunnels_total: 8,
            agent_version: Some("0.1.0".into()),
            interfaces_json: Some(r#"[{"name":"eth0"}]"#.into()),
            ..Default::default()
        };
        repo.record_heartbeat(status.clone()).await.unwrap();

        let dto = repo.get(&node.id).await.unwrap();
        assert_eq!(dto.status, "online");
        assert_eq!(dto.connections, 42);
        assert_eq!(dto.observed_ip.as_deref(), Some("203.0.113.10"));
        assert_eq!((dto.disk_used_bytes, dto.disk_total_bytes), (25, 100));
        assert_eq!(dto.host_uptime_secs, 7200);
        assert!(dto.last_heartbeat_at.is_some());
        assert!(dto.interfaces.is_array());

        // Second heartbeat must update in place, not insert a second row.
        status.connections = 99;
        repo.record_heartbeat(status).await.unwrap();
        assert_eq!(repo.get(&node.id).await.unwrap().connections, 99);

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM node_status")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(count.0, 1);
    }

    #[tokio::test]
    async fn stale_nodes_are_marked_offline() {
        let db = db().await;
        let g = group(&db, "g", "inbound").await;
        let repo = NodeRepo::new(&db);
        let node = repo.create(new_node(&g, "sh-01", "entry")).await.unwrap();
        repo.record_heartbeat(NodeStatusRow {
            node_id: node.id.clone(),
            status: "online".into(),
            connections: 10,
            tunnels_online: 4,
            ..Default::default()
        })
        .await
        .unwrap();

        // Nothing to do while the heartbeat is fresh.
        assert_eq!(repo.mark_stale_offline(60).await.unwrap(), 0);
        assert_eq!(repo.get(&node.id).await.unwrap().status, "online");

        // A zero-second staleness window makes the existing heartbeat old.
        assert_eq!(repo.mark_stale_offline(0).await.unwrap(), 1);
        let dto = repo.get(&node.id).await.unwrap();
        assert_eq!(dto.status, "offline");
        assert_eq!(dto.connections, 0, "stale live counters must be cleared");
        assert_eq!(dto.tunnels_online, 0);

        // Idempotent: a second sweep changes nothing.
        assert_eq!(repo.mark_stale_offline(0).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn removing_one_machine_does_not_break_the_route() {
        // 一组多机的直接收益：线路指向组，下线一台机器其余继续承载。
        // 改造前这里会因为线路引用单机而报冲突。
        let db = db().await;
        let entry_g = group(&db, "上海入口", "inbound").await;
        let exit_g = group(&db, "香港出口", "outbound").await;
        let nodes = NodeRepo::new(&db);
        let endpoints = EndpointRepo::new(&db);

        nodes.create(new_node(&entry_g, "sh-01", "entry")).await.unwrap();
        let hk1 = nodes.create(new_node(&exit_g, "hk-01", "exit")).await.unwrap();
        let hk2 = nodes.create(new_node(&exit_g, "hk-02", "exit")).await.unwrap();

        let ep1 = endpoints
            .create(new_endpoint(&hk1.id, "hk1-iepl", "iepl"))
            .await
            .unwrap();
        let ep2 = endpoints
            .create(new_endpoint(&hk2.id, "hk2-iepl", "iepl"))
            .await
            .unwrap();

        let route = crate::routes::RouteRepo::new(&db)
            .create(crate::models::CreateRoute {
                name: "sh-hk".into(),
                mode: "tunnel".into(),
                entry_group_id: entry_g.clone(),
                listen_address: "0.0.0.0".into(),
                listen_port: Some(443),
                exit_group_id: Some(exit_g.clone()),
                target_host: "127.0.0.1".into(),
                target_port: 8443,
                targets: vec![],
                target_strategy: "random".into(),
                // 一条线路同时引用组内两台机器的隧道地址。
                endpoint_ids: vec![ep1.id.clone(), ep2.id.clone()],
                tunnel_pool_size: 8,
                load_balance: "round_robin".into(),
                max_connections: 0,
                egress_source_ip: None,
                egress_interface: None,
            })
            .await
            .unwrap();

        // 删掉一台机器应当成功，线路仍然存在。
        nodes.delete(&hk2.id).await.unwrap();
        let after = crate::routes::RouteRepo::new(&db).get(&route.id).await.unwrap();
        assert_eq!(
            after.endpoints.len(),
            1,
            "该机器的隧道地址随它级联删除，另一台的保留"
        );
        assert_eq!(after.endpoints[0].name, "hk1-iepl");
    }

    #[tokio::test]
    async fn deleting_a_node_cascades_to_its_endpoints() {
        let db = db().await;
        let g = group(&db, "g", "outbound").await;
        let nodes = NodeRepo::new(&db);
        let endpoints = EndpointRepo::new(&db);
        let node = nodes.create(new_node(&g, "hk-01", "exit")).await.unwrap();
        endpoints
            .create(new_endpoint(&node.id, "hk-iepl", "iepl"))
            .await
            .unwrap();
        endpoints
            .create(new_endpoint(&node.id, "hk-public", "public"))
            .await
            .unwrap();
        assert_eq!(endpoints.list().await.unwrap().len(), 2);

        nodes.delete(&node.id).await.unwrap();
        assert!(
            endpoints.list().await.unwrap().is_empty(),
            "endpoints should not outlive their node"
        );
    }

    #[tokio::test]
    async fn endpoint_crud() {
        let db = db().await;
        let g = group(&db, "g", "outbound").await;
        let nodes = NodeRepo::new(&db);
        let repo = EndpointRepo::new(&db);
        let node = nodes.create(new_node(&g, "hk-01", "exit")).await.unwrap();

        let ep = repo
            .create(new_endpoint(&node.id, "hk-iepl", "iepl"))
            .await
            .unwrap();
        assert_eq!(ep.kind, "iepl");
        assert_eq!(ep.node_name.as_deref(), Some("hk-01"));
        assert_eq!(ep.source_ip.as_deref(), Some("10.20.0.1"));

        let updated = repo
            .update(
                &ep.id,
                UpdateEndpoint {
                    port: Some(6000),
                    priority: Some("backup".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.port, 6000);
        assert_eq!(updated.priority, "backup");
        // Untouched fields must survive a partial update.
        assert_eq!(updated.address, "10.20.0.2");
        assert_eq!(updated.interface.as_deref(), Some("eth1"));

        repo.delete(&ep.id).await.unwrap();
        assert!(matches!(repo.get(&ep.id).await, Err(DbError::NotFound(_))));
    }

    #[tokio::test]
    async fn endpoint_validation_rejects_bad_input() {
        let db = db().await;
        let g = group(&db, "g", "outbound").await;
        let nodes = NodeRepo::new(&db);
        let repo = EndpointRepo::new(&db);
        let node = nodes.create(new_node(&g, "hk-01", "exit")).await.unwrap();

        let mut bad = new_endpoint(&node.id, "x", "iepl");
        bad.kind = "carrier-pigeon".into();
        assert!(matches!(repo.create(bad).await, Err(DbError::Invalid(_))));

        let mut bad = new_endpoint(&node.id, "x", "iepl");
        bad.port = 0;
        assert!(matches!(repo.create(bad).await, Err(DbError::Invalid(_))));

        let mut bad = new_endpoint(&node.id, "x", "iepl");
        bad.source_ip = Some("not-an-ip".into());
        assert!(matches!(repo.create(bad).await, Err(DbError::Invalid(_))));

        let mut bad = new_endpoint(&node.id, "", "iepl");
        bad.address = "  ".into();
        assert!(matches!(repo.create(bad).await, Err(DbError::Invalid(_))));
    }

    #[tokio::test]
    async fn endpoint_for_a_missing_node_is_rejected() {
        let db = db().await;
        let repo = EndpointRepo::new(&db);
        let err = repo
            .create(new_endpoint("no-such-node", "x", "public"))
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::Invalid(_)), "{err:?}");
    }

    #[tokio::test]
    async fn duplicate_endpoint_name_on_one_node_is_a_conflict() {
        let db = db().await;
        let g = group(&db, "g", "outbound").await;
        let nodes = NodeRepo::new(&db);
        let repo = EndpointRepo::new(&db);
        let a = nodes.create(new_node(&g, "hk-01", "exit")).await.unwrap();
        let b = nodes.create(new_node(&g, "hk-02", "exit")).await.unwrap();

        repo.create(new_endpoint(&a.id, "primary-link", "iepl"))
            .await
            .unwrap();
        assert!(matches!(
            repo.create(new_endpoint(&a.id, "primary-link", "public")).await,
            Err(DbError::Conflict(_))
        ));
        // The same name on a *different* node is fine.
        repo.create(new_endpoint(&b.id, "primary-link", "iepl"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn iepl_and_public_endpoints_coexist_on_one_node() {
        // This is the dual-NIC failover shape the whole system is built around.
        let db = db().await;
        let g = group(&db, "g", "outbound").await;
        let nodes = NodeRepo::new(&db);
        let repo = EndpointRepo::new(&db);
        let node = nodes.create(new_node(&g, "hk-01", "exit")).await.unwrap();

        let mut iepl = new_endpoint(&node.id, "hk-iepl", "iepl");
        iepl.priority = "primary".into();
        repo.create(iepl).await.unwrap();

        let mut public = new_endpoint(&node.id, "hk-public", "public");
        public.priority = "backup".into();
        public.address = "203.0.113.9".into();
        public.interface = Some("eth0".into());
        public.source_ip = None;
        repo.create(public).await.unwrap();

        let rows = repo.list_for_node(&node.id).await.unwrap();
        assert_eq!(rows.len(), 2);
        // Ordered primary-first, which is the failover order.
        assert_eq!(rows[0].priority, "primary");
        assert_eq!(rows[1].priority, "backup");
    }
}
