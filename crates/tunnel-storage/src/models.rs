//! Database row types and their API-facing DTOs.
//!
//! These are distinct from [`tunnel_common::model`] on purpose. The common model
//! is the *wire* contract shared with agents; these are *storage* rows carrying
//! extra fields that must never leave the control plane (token hashes) or that
//! only exist in the database (timestamps, revisions).

use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use tunnel_common::model::{
    Endpoint, EndpointKind, EndpointPriority, LoadBalance, Node, NodeRole, Route,
};

// ---------------------------------------------------------------------------
// users
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, FromRow)]
pub struct UserRow {
    pub id: String,
    pub username: String,
    /// Argon2id PHC string. Never serialised: this struct has no `Serialize`.
    pub password_hash: String,
    pub role: String,
    pub must_change_password: i64,
    pub disabled: i64,
    pub last_login_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// User as returned by the API. No hash, by construction rather than by
/// remembering to strip it.
#[derive(Debug, Clone, Serialize)]
pub struct UserDto {
    pub id: String,
    pub username: String,
    pub role: String,
    pub must_change_password: bool,
    pub disabled: bool,
    pub last_login_at: Option<String>,
    pub created_at: String,
}

impl From<UserRow> for UserDto {
    fn from(r: UserRow) -> Self {
        Self {
            id: r.id,
            username: r.username,
            role: r.role,
            must_change_password: r.must_change_password != 0,
            disabled: r.disabled != 0,
            last_login_at: r.last_login_at,
            created_at: r.created_at,
        }
    }
}

// ---------------------------------------------------------------------------
// device groups
// ---------------------------------------------------------------------------

/// 设备组方向。入口组接用户、拨隧道；出口组终结隧道、拨目标。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GroupKind {
    Inbound,
    Outbound,
    Both,
}

impl GroupKind {
    pub fn as_str(self) -> &'static str {
        match self {
            GroupKind::Inbound => "inbound",
            GroupKind::Outbound => "outbound",
            GroupKind::Both => "both",
        }
    }

    /// 中文显示名，面板直接用。
    pub fn label(self) -> &'static str {
        match self {
            GroupKind::Inbound => "入口",
            GroupKind::Outbound => "出口",
            GroupKind::Both => "入口+出口",
        }
    }
}

impl std::str::FromStr for GroupKind {
    type Err = crate::DbError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "inbound" => Ok(GroupKind::Inbound),
            "outbound" => Ok(GroupKind::Outbound),
            "both" => Ok(GroupKind::Both),
            other => Err(crate::DbError::Invalid(format!("未知组类型 `{other}`"))),
        }
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct DeviceGroupRow {
    pub id: String,
    pub name: String,
    pub region: String,
    pub kind: String,
    /// 注册令牌的 Argon2id 哈希。没有 Serialize，无法泄露到 API。
    pub enroll_token_hash: String,
    pub note: Option<String>,
    pub enabled: i64,
    pub config_revision: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl DeviceGroupRow {
    pub fn kind(&self) -> GroupKind {
        self.kind.parse().unwrap_or(GroupKind::Both)
    }
}

/// 返回给面板的组信息。结构上不含令牌哈希，而非靠记得剥离。
#[derive(Debug, Clone, Serialize)]
pub struct DeviceGroupDto {
    pub id: String,
    pub name: String,
    pub region: String,
    pub kind: String,
    pub kind_label: &'static str,
    pub note: Option<String>,
    pub enabled: bool,
    pub config_revision: i64,
    pub created_at: String,
    pub nodes_total: i64,
    pub nodes_online: i64,
}

impl DeviceGroupDto {
    pub fn new(row: DeviceGroupRow, nodes_total: i64, nodes_online: i64) -> Self {
        let kind = row.kind();
        Self {
            id: row.id,
            name: row.name,
            region: row.region,
            kind: row.kind,
            kind_label: kind.label(),
            note: row.note,
            enabled: row.enabled != 0,
            config_revision: row.config_revision,
            created_at: row.created_at,
            nodes_total,
            nodes_online,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateDeviceGroup {
    pub name: String,
    #[serde(default)]
    pub region: String,
    pub kind: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct UpdateDeviceGroup {
    pub name: Option<String>,
    pub region: Option<String>,
    pub kind: Option<String>,
    pub note: Option<String>,
    pub enabled: Option<bool>,
}

// ---------------------------------------------------------------------------
// nodes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, FromRow)]
pub struct NodeRow {
    pub id: String,
    /// 所属设备组。认证凭据在组上，节点本身不再持有令牌。
    pub group_id: String,
    pub name: String,
    /// agent 自注册时上报的主机名，用于区分同组机器。
    pub hostname: Option<String>,
    pub region: String,
    pub role: String,
    pub public_address: Option<String>,
    pub management_address: Option<String>,
    pub agent_version: Option<String>,
    pub note: Option<String>,
    pub enabled: i64,
    pub config_revision: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl NodeRow {
    pub fn role(&self) -> NodeRole {
        self.role.parse().unwrap_or(NodeRole::Both)
    }

    /// Convert to the wire model sent to agents.
    pub fn to_model(&self) -> Node {
        Node {
            id: self.id.clone(),
            name: self.name.clone(),
            region: self.region.clone(),
            role: self.role(),
            public_address: self.public_address.clone(),
            management_address: self.management_address.clone(),
            agent_version: self.agent_version.clone(),
            note: self.note.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, FromRow)]
pub struct NodeStatusRow {
    pub node_id: String,
    pub status: String,
    pub cpu_percent: f64,
    pub memory_used_bytes: i64,
    pub memory_total_bytes: i64,
    pub uptime_secs: i64,
    pub connections: i64,
    pub rx_bytes: i64,
    pub tx_bytes: i64,
    pub rx_bps: i64,
    pub tx_bps: i64,
    pub tunnels_online: i64,
    pub tunnels_total: i64,
    pub agent_version: Option<String>,
    pub config_revision: i64,
    pub interfaces_json: Option<String>,
    pub last_heartbeat_at: Option<String>,
}

/// Node plus live status, as the Nodes page needs it.
#[derive(Debug, Clone, Serialize)]
pub struct NodeDto {
    pub id: String,
    pub group_id: String,
    #[serde(default)]
    pub group_name: Option<String>,
    pub name: String,
    pub hostname: Option<String>,
    pub region: String,
    pub role: String,
    pub public_address: Option<String>,
    pub management_address: Option<String>,
    pub agent_version: Option<String>,
    pub note: Option<String>,
    pub enabled: bool,
    pub config_revision: i64,
    pub created_at: String,
    // --- live status ---
    pub status: String,
    pub cpu_percent: f64,
    pub memory_used_bytes: i64,
    pub memory_total_bytes: i64,
    pub uptime_secs: i64,
    pub connections: i64,
    pub rx_bytes: i64,
    pub tx_bytes: i64,
    pub rx_bps: i64,
    pub tx_bps: i64,
    pub tunnels_online: i64,
    pub tunnels_total: i64,
    pub interfaces: serde_json::Value,
    pub last_heartbeat_at: Option<String>,
}

impl NodeDto {
    pub fn new(node: NodeRow, status: Option<NodeStatusRow>) -> Self {
        Self::with_group(node, status, None)
    }

    pub fn with_group(
        node: NodeRow,
        status: Option<NodeStatusRow>,
        group_name: Option<String>,
    ) -> Self {
        let st = status.unwrap_or_default();
        let interfaces = st
            .interfaces_json
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or(serde_json::Value::Array(vec![]));
        Self {
            id: node.id,
            group_id: node.group_id,
            group_name,
            name: node.name,
            hostname: node.hostname,
            region: node.region,
            role: node.role,
            public_address: node.public_address,
            management_address: node.management_address,
            // Prefer what the agent last reported over the stored value.
            agent_version: st.agent_version.or(node.agent_version),
            note: node.note,
            enabled: node.enabled != 0,
            config_revision: node.config_revision,
            created_at: node.created_at,
            status: if st.status.is_empty() {
                "offline".into()
            } else {
                st.status
            },
            cpu_percent: st.cpu_percent,
            memory_used_bytes: st.memory_used_bytes,
            memory_total_bytes: st.memory_total_bytes,
            uptime_secs: st.uptime_secs,
            connections: st.connections,
            rx_bytes: st.rx_bytes,
            tx_bytes: st.tx_bytes,
            rx_bps: st.rx_bps,
            tx_bps: st.tx_bps,
            tunnels_online: st.tunnels_online,
            tunnels_total: st.tunnels_total,
            interfaces,
            last_heartbeat_at: st.last_heartbeat_at,
        }
    }
}

/// 手工在面板上添加机器。一键对接走 [`crate::nodes::NodeRepo::register`]。
#[derive(Debug, Clone, Deserialize)]
pub struct CreateNode {
    pub group_id: String,
    pub name: String,
    #[serde(default)]
    pub region: String,
    pub role: String,
    #[serde(default)]
    pub public_address: Option<String>,
    #[serde(default)]
    pub management_address: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct UpdateNode {
    pub name: Option<String>,
    pub region: Option<String>,
    pub role: Option<String>,
    pub public_address: Option<String>,
    pub management_address: Option<String>,
    pub note: Option<String>,
    pub enabled: Option<bool>,
}

// ---------------------------------------------------------------------------
// endpoints
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, FromRow)]
pub struct EndpointRow {
    pub id: String,
    pub node_id: String,
    pub name: String,
    pub address: String,
    pub port: i64,
    pub kind: String,
    pub priority: String,
    pub interface: Option<String>,
    pub source_ip: Option<String>,
    pub tls_server_name: Option<String>,
    pub enabled: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl EndpointRow {
    pub fn to_model(&self) -> Endpoint {
        Endpoint {
            id: self.id.clone(),
            node_id: self.node_id.clone(),
            name: self.name.clone(),
            address: self.address.clone(),
            // Port is CHECK-constrained in the schema, so this cast is safe;
            // clamp anyway rather than risk a panic on a hand-edited database.
            port: self.port.clamp(1, 65535) as u16,
            kind: self.kind.parse().unwrap_or(EndpointKind::Public),
            priority: self.priority.parse().unwrap_or(EndpointPriority::Primary),
            interface: self.interface.clone(),
            source_ip: self.source_ip.as_deref().and_then(|s| s.parse().ok()),
            tls_server_name: self.tls_server_name.clone(),
            enabled: self.enabled != 0,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EndpointDto {
    pub id: String,
    pub node_id: String,
    pub node_name: Option<String>,
    pub name: String,
    pub address: String,
    pub port: i64,
    pub kind: String,
    pub priority: String,
    pub interface: Option<String>,
    pub source_ip: Option<String>,
    pub tls_server_name: Option<String>,
    pub enabled: bool,
    pub created_at: String,
}

impl EndpointDto {
    pub fn new(row: EndpointRow, node_name: Option<String>) -> Self {
        Self {
            id: row.id,
            node_id: row.node_id,
            node_name,
            name: row.name,
            address: row.address,
            port: row.port,
            kind: row.kind,
            priority: row.priority,
            interface: row.interface,
            source_ip: row.source_ip,
            tls_server_name: row.tls_server_name,
            enabled: row.enabled != 0,
            created_at: row.created_at,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateEndpoint {
    pub node_id: String,
    pub name: String,
    pub address: String,
    pub port: u16,
    pub kind: String,
    #[serde(default = "default_primary")]
    pub priority: String,
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub source_ip: Option<String>,
    #[serde(default)]
    pub tls_server_name: Option<String>,
}

fn default_primary() -> String {
    "primary".into()
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct UpdateEndpoint {
    pub name: Option<String>,
    pub address: Option<String>,
    pub port: Option<u16>,
    pub kind: Option<String>,
    pub priority: Option<String>,
    pub interface: Option<String>,
    pub source_ip: Option<String>,
    pub tls_server_name: Option<String>,
    pub enabled: Option<bool>,
}

// ---------------------------------------------------------------------------
// routes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, FromRow)]
pub struct RouteRow {
    pub id: String,
    pub name: String,
    /// `tunnel` 或 `direct`。
    pub mode: String,
    /// 入口设备组。引用组而非单机，组内加减机器不影响线路。
    pub entry_group_id: String,
    pub listen_address: String,
    pub listen_port: i64,
    pub exit_group_id: String,
    pub target_host: String,
    pub target_port: i64,
    /// 全部目标的 JSON 数组，形如 `["1.2.3.4:443"]`。
    ///
    /// NULL 表示旧数据，回落到 `target_host:target_port`。
    pub targets: Option<String>,
    /// 多目标分配策略：`random`/`round_robin`/`ip_hash`/`least_conn`/`failover`。
    pub target_strategy: String,
    pub tunnel_pool_size: i64,
    pub load_balance: String,
    pub max_connections: i64,
    pub egress_source_ip: Option<String>,
    pub egress_interface: Option<String>,
    pub enabled: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl RouteRow {
    /// 解析 targets 列。
    ///
    /// 解析失败时返回空列表而非报错 —— 手工编辑过的数据库不该让整个线路读不出来，
    /// 上层会回落到 `target_host:target_port`。
    pub fn target_list(&self) -> Vec<String> {
        self.targets
            .as_deref()
            .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
            .unwrap_or_default()
    }

    pub fn mode(&self) -> tunnel_common::model::RouteMode {
        self.mode.parse().unwrap_or_default()
    }

    /// 解析策略列。无法解析时回落到默认（随机），不让一条坏数据读不出来。
    pub fn target_strategy(&self) -> tunnel_common::model::TargetStrategy {
        self.target_strategy.parse().unwrap_or_default()
    }

    pub fn to_model(&self, endpoint_ids: Vec<String>) -> Route {
        Route {
            id: self.id.clone(),
            name: self.name.clone(),
            mode: self.mode(),
            entry_node_id: self.entry_group_id.clone(),
            listen_address: self.listen_address.clone(),
            listen_port: self.listen_port.clamp(1, 65535) as u16,
            exit_node_id: self.exit_group_id.clone(),
            target_host: self.target_host.clone(),
            target_port: self.target_port.clamp(1, 65535) as u16,
            targets: self.target_list(),
            target_strategy: self.target_strategy(),
            endpoint_ids,
            tunnel_pool_size: self.tunnel_pool_size.clamp(1, 256) as u16,
            load_balance: self.load_balance.parse().unwrap_or(LoadBalance::RoundRobin),
            max_connections: self.max_connections.max(0) as u32,
            egress_source_ip: self.egress_source_ip.as_deref().and_then(|s| s.parse().ok()),
            egress_interface: self.egress_interface.clone(),
            enabled: self.enabled != 0,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteDto {
    pub id: String,
    pub name: String,
    pub mode: String,
    pub mode_label: &'static str,
    pub entry_group_id: String,
    pub entry_group_name: Option<String>,
    pub listen_address: String,
    pub listen_port: i64,
    pub exit_group_id: String,
    pub exit_group_name: Option<String>,
    pub target_host: String,
    pub target_port: i64,
    /// 全部目标地址。单目标时只有一项。
    pub targets: Vec<String>,
    /// 多目标分配策略。
    pub target_strategy: String,
    /// 策略的中文名，面板直接显示，不必自己维护一份映射。
    pub target_strategy_label: &'static str,
    pub endpoints: Vec<EndpointDto>,
    pub tunnel_pool_size: i64,
    pub load_balance: String,
    pub max_connections: i64,
    pub egress_source_ip: Option<String>,
    pub egress_interface: Option<String>,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateRoute {
    pub name: String,
    /// `tunnel`（默认）或 `direct`。
    #[serde(default = "default_route_mode")]
    pub mode: String,
    pub entry_group_id: String,
    #[serde(default = "default_listen_address")]
    pub listen_address: String,
    /// 监听端口。留空时由服务端在 10000-60000 随机分配一个该入口组尚未占用的端口。
    ///
    /// 为什么支持随机：一台入口机上会有多条线路，硬编码 443 会让第二条起全部冲突。
    /// 让用户每次手工挑一个没被占的端口是没必要的摩擦。
    #[serde(default)]
    pub listen_port: Option<u16>,
    /// 直连模式下可省略 —— 单机转发没有对端出口组。省略时取入口组。
    #[serde(default)]
    pub exit_group_id: Option<String>,
    pub target_host: String,
    pub target_port: u16,
    /// 额外目标，形如 `["1.2.3.4:443","5.6.7.8:443"]`。
    ///
    /// 给出时以它为准（`target_host`/`target_port` 取其首项）；为空则按单目标处理。
    /// 多目标按 `target_strategy` 分配新连接，失败的会被熔断跳过。
    #[serde(default)]
    pub targets: Vec<String>,
    /// 多目标分配策略，默认 `random`。单目标时不起作用。
    #[serde(default = "default_target_strategy")]
    pub target_strategy: String,
    /// 隧道地址，按故障转移顺序排列。隧道模式必填，直连模式忽略。
    #[serde(default)]
    pub endpoint_ids: Vec<String>,
    #[serde(default = "default_pool_size")]
    pub tunnel_pool_size: u16,
    #[serde(default = "default_load_balance")]
    pub load_balance: String,
    #[serde(default)]
    pub max_connections: u32,
    #[serde(default)]
    pub egress_source_ip: Option<String>,
    #[serde(default)]
    pub egress_interface: Option<String>,
}

fn default_listen_address() -> String {
    "0.0.0.0".into()
}
fn default_route_mode() -> String {
    "tunnel".into()
}
fn default_pool_size() -> u16 {
    8
}
fn default_load_balance() -> String {
    "round_robin".into()
}
fn default_target_strategy() -> String {
    "random".into()
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct UpdateRoute {
    pub name: Option<String>,
    /// 切换 `tunnel` / `direct`。
    ///
    /// 改成隧道模式时必须同时（或此前已经）有出口组与隧道地址；改成直连模式会清空
    /// 隧道地址 —— 本机直接拨目标，没有对端隧道可拨。
    pub mode: Option<String>,
    /// 更换出口组。改动后会重新校验隧道地址是否属于新组内的机器。
    pub exit_group_id: Option<String>,
    /// 更换入口组。
    ///
    /// 监听端口的唯一性是按 (入口组, 监听地址, 端口) 算的，所以换组可能撞上目标组
    /// 里已有的线路 —— 那种情况会报冲突而不是静默覆盖。
    pub entry_group_id: Option<String>,
    pub listen_address: Option<String>,
    pub listen_port: Option<u16>,
    pub target_host: Option<String>,
    pub target_port: Option<u16>,
    /// 全量替换目标列表。`Some(vec![])` 被拒绝 —— 线路必须有至少一个目标。
    pub targets: Option<Vec<String>>,
    pub target_strategy: Option<String>,
    pub endpoint_ids: Option<Vec<String>>,
    pub tunnel_pool_size: Option<u16>,
    pub load_balance: Option<String>,
    pub max_connections: Option<u32>,
    pub egress_source_ip: Option<String>,
    pub egress_interface: Option<String>,
    pub enabled: Option<bool>,
}

// ---------------------------------------------------------------------------
// stats & audit
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct TrafficPoint {
    pub bucket_at: String,
    pub rx_bytes: i64,
    pub tx_bytes: i64,
    pub rx_bps: i64,
    pub tx_bps: i64,
    pub connections: i64,
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct AuditRow {
    pub id: i64,
    pub at: String,
    pub user_id: Option<String>,
    pub username: Option<String>,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub target_name: Option<String>,
    pub source_ip: Option<String>,
    pub detail_json: Option<String>,
    pub success: i64,
}

/// A privileged action to record.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub user_id: Option<String>,
    pub username: Option<String>,
    pub action: String,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub target_name: Option<String>,
    pub source_ip: Option<String>,
    pub detail: Option<serde_json::Value>,
    pub success: bool,
}

impl AuditEntry {
    pub fn new(action: impl Into<String>) -> Self {
        Self {
            user_id: None,
            username: None,
            action: action.into(),
            target_type: None,
            target_id: None,
            target_name: None,
            source_ip: None,
            detail: None,
            success: true,
        }
    }

    pub fn actor(mut self, user_id: Option<String>, username: Option<String>) -> Self {
        self.user_id = user_id;
        self.username = username;
        self
    }

    pub fn target(
        mut self,
        target_type: impl Into<String>,
        id: impl Into<String>,
        name: Option<String>,
    ) -> Self {
        self.target_type = Some(target_type.into());
        self.target_id = Some(id.into());
        self.target_name = name;
        self
    }

    pub fn source_ip(mut self, ip: Option<String>) -> Self {
        self.source_ip = ip;
        self
    }

    pub fn detail(mut self, detail: serde_json::Value) -> Self {
        self.detail = Some(detail);
        self
    }

    pub fn failed(mut self) -> Self {
        self.success = false;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_row() -> NodeRow {
        NodeRow {
            id: "n1".into(),
            group_id: "g1".into(),
            name: "sh-01".into(),
            hostname: Some("sh-01.internal".into()),
            region: "cn-sh".into(),
            role: "entry".into(),
            public_address: Some("203.0.113.1".into()),
            management_address: Some("10.0.0.1".into()),
            agent_version: Some("0.1.0".into()),
            note: None,
            enabled: 1,
            config_revision: 3,
            created_at: "2024-01-01T00:00:00Z".into(),
            updated_at: "2024-01-01T00:00:00Z".into(),
        }
    }

    fn group_row() -> DeviceGroupRow {
        DeviceGroupRow {
            id: "g1".into(),
            name: "上海入口".into(),
            region: "cn-sh".into(),
            kind: "inbound".into(),
            enroll_token_hash: "$argon2id$secret-hash".into(),
            note: None,
            enabled: 1,
            config_revision: 3,
            created_at: "2024-01-01T00:00:00Z".into(),
            updated_at: "2024-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn group_dto_never_carries_the_token_hash() {
        // 行结构里有密钥；DTO 在类型上就无法表达它。
        let dto = DeviceGroupDto::new(group_row(), 2, 1);
        let json = serde_json::to_string(&dto).unwrap();
        assert!(
            !json.contains("argon2") && !json.contains("secret-hash"),
            "令牌哈希泄露到 API DTO: {json}"
        );
        assert_eq!(dto.nodes_total, 2);
        assert_eq!(dto.nodes_online, 1);
        assert_eq!(dto.kind_label, "入口");
    }

    #[test]
    fn node_dto_carries_group_membership() {
        let dto = NodeDto::with_group(node_row(), None, Some("上海入口".into()));
        assert_eq!(dto.group_id, "g1");
        assert_eq!(dto.group_name.as_deref(), Some("上海入口"));
        assert_eq!(dto.hostname.as_deref(), Some("sh-01.internal"));
        // 机器本身不再持有令牌，序列化里不该出现任何 token 字段。
        let json = serde_json::to_string(&dto).unwrap();
        assert!(!json.contains("token"), "{json}");
    }

    #[test]
    fn group_kind_labels_are_chinese() {
        assert_eq!(GroupKind::Inbound.label(), "入口");
        assert_eq!(GroupKind::Outbound.label(), "出口");
        assert_eq!(GroupKind::Both.label(), "入口+出口");
    }

    #[test]
    fn group_kind_round_trips() {
        for (text, expected) in [
            ("inbound", GroupKind::Inbound),
            ("outbound", GroupKind::Outbound),
            ("both", GroupKind::Both),
        ] {
            assert_eq!(text.parse::<GroupKind>().unwrap(), expected);
            assert_eq!(expected.as_str(), text);
        }
        assert!("nonsense".parse::<GroupKind>().is_err());
    }

    #[test]
    fn user_dto_never_carries_the_password_hash() {
        let row = UserRow {
            id: "u1".into(),
            username: "admin".into(),
            password_hash: "$argon2id$v=19$super-secret".into(),
            role: "admin".into(),
            must_change_password: 1,
            disabled: 0,
            last_login_at: None,
            created_at: "2024-01-01T00:00:00Z".into(),
            updated_at: "2024-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&UserDto::from(row)).unwrap();
        assert!(!json.contains("argon2"), "password hash leaked: {json}");
        assert!(!json.contains("super-secret"), "password hash leaked: {json}");
    }

    #[test]
    fn missing_status_renders_as_offline() {
        let dto = NodeDto::new(node_row(), None);
        assert_eq!(dto.status, "offline");
        assert_eq!(dto.connections, 0);
        assert!(dto.interfaces.is_array());
    }

    #[test]
    fn agent_reported_version_wins_over_the_stored_one() {
        let status = NodeStatusRow {
            status: "online".into(),
            agent_version: Some("0.2.0".into()),
            ..Default::default()
        };
        let dto = NodeDto::new(node_row(), Some(status));
        assert_eq!(dto.agent_version.as_deref(), Some("0.2.0"));
    }

    #[test]
    fn endpoint_row_parses_into_the_wire_model() {
        let row = EndpointRow {
            id: "e1".into(),
            node_id: "n1".into(),
            name: "hk-iepl".into(),
            address: "10.20.0.2".into(),
            port: 5000,
            kind: "iepl".into(),
            priority: "backup".into(),
            interface: Some("eth1".into()),
            source_ip: Some("10.20.0.1".into()),
            tls_server_name: Some("exit.internal".into()),
            enabled: 1,
            created_at: "x".into(),
            updated_at: "x".into(),
        };
        let m = row.to_model();
        assert_eq!(m.kind, EndpointKind::Iepl);
        assert_eq!(m.priority, EndpointPriority::Backup);
        assert_eq!(m.port, 5000);
        assert_eq!(m.source_ip.unwrap().to_string(), "10.20.0.1");
        assert!(m.enabled);
    }

    #[test]
    fn unparsable_enum_values_fall_back_instead_of_panicking() {
        // A hand-edited database must not crash the control plane.
        let mut row = EndpointRow {
            id: "e1".into(),
            node_id: "n1".into(),
            name: "x".into(),
            address: "1.2.3.4".into(),
            port: 99_999,
            kind: "nonsense".into(),
            priority: "whatever".into(),
            interface: None,
            source_ip: Some("not-an-ip".into()),
            tls_server_name: None,
            enabled: 0,
            created_at: "x".into(),
            updated_at: "x".into(),
        };
        let m = row.to_model();
        assert_eq!(m.kind, EndpointKind::Public);
        assert_eq!(m.priority, EndpointPriority::Primary);
        assert_eq!(m.port, 65535, "out-of-range port must clamp, not wrap");
        assert!(m.source_ip.is_none());
        assert!(!m.enabled);

        row.port = 0;
        assert_eq!(row.to_model().port, 1);
    }

    #[test]
    fn route_row_parses_into_the_wire_model() {
        let row = RouteRow {
            id: "r1".into(),
            name: "sh-hk".into(),
            mode: "tunnel".into(),
            entry_group_id: "g1".into(),
            listen_address: "0.0.0.0".into(),
            listen_port: 443,
            exit_group_id: "g2".into(),
            target_host: "127.0.0.1".into(),
            target_port: 8443,
            targets: Some(r#"["127.0.0.1:8443"]"#.into()),
            target_strategy: "ip_hash".into(),
            tunnel_pool_size: 8,
            load_balance: "least_streams".into(),
            max_connections: 5000,
            egress_source_ip: Some("203.0.113.9".into()),
            egress_interface: None,
            enabled: 1,
            created_at: "x".into(),
            updated_at: "x".into(),
        };
        let m = row.to_model(vec!["e1".into(), "e2".into()]);
        assert_eq!(m.load_balance, LoadBalance::LeastStreams);
        assert_eq!(m.endpoint_ids.len(), 2);
        assert_eq!(m.tunnel_pool_size, 8);
        assert_eq!(m.egress_source_ip.unwrap().to_string(), "203.0.113.9");
        // 策略要一路传到下发给 agent 的线路模型上。
        assert_eq!(
            m.target_strategy,
            tunnel_common::model::TargetStrategy::IpHash
        );
    }

    #[test]
    fn an_unparsable_strategy_falls_back_to_random() {
        // 手工写库或将来放宽 CHECK 约束时，一条坏值不该让整条线路读不出来。
        let mut row = RouteRow {
            id: "r1".into(),
            name: "x".into(),
            mode: "tunnel".into(),
            entry_group_id: "g1".into(),
            listen_address: "0.0.0.0".into(),
            listen_port: 443,
            exit_group_id: "g2".into(),
            target_host: "h".into(),
            target_port: 1,
            targets: None,
            target_strategy: "nonsense".into(),
            tunnel_pool_size: 8,
            load_balance: "round_robin".into(),
            max_connections: 0,
            egress_source_ip: None,
            egress_interface: None,
            enabled: 1,
            created_at: "x".into(),
            updated_at: "x".into(),
        };
        assert_eq!(
            row.to_model(vec![]).target_strategy,
            tunnel_common::model::TargetStrategy::Random
        );

        row.target_strategy = "least_conn".into();
        assert_eq!(
            row.to_model(vec![]).target_strategy,
            tunnel_common::model::TargetStrategy::LeastConn
        );
    }

    #[test]
    fn oversized_pool_size_clamps() {
        let mut row = RouteRow {
            id: "r1".into(),
            name: "x".into(),
            mode: "tunnel".into(),
            entry_group_id: "g1".into(),
            listen_address: "0.0.0.0".into(),
            listen_port: 443,
            exit_group_id: "g2".into(),
            target_host: "h".into(),
            target_port: 1,
            targets: None,
            target_strategy: "random".into(),
            tunnel_pool_size: 100_000,
            load_balance: "round_robin".into(),
            max_connections: -5,
            egress_source_ip: None,
            egress_interface: None,
            enabled: 1,
            created_at: "x".into(),
            updated_at: "x".into(),
        };
        let m = row.to_model(vec![]);
        assert_eq!(m.tunnel_pool_size, 256);
        assert_eq!(m.max_connections, 0, "negative must not wrap to 4 billion");

        row.tunnel_pool_size = 0;
        assert_eq!(row.to_model(vec![]).tunnel_pool_size, 1);
    }

    #[test]
    fn node_role_round_trips_through_storage() {
        for (text, expected) in [
            ("entry", NodeRole::Entry),
            ("exit", NodeRole::Exit),
            ("both", NodeRole::Both),
            ("garbage", NodeRole::Both),
        ] {
            let mut row = node_row();
            row.role = text.into();
            assert_eq!(row.role(), expected, "role `{text}`");
        }
    }

    #[test]
    fn audit_entry_builder_composes() {
        let e = AuditEntry::new("route.delete")
            .actor(Some("u1".into()), Some("admin".into()))
            .target("route", "r1", Some("sh-hk".into()))
            .source_ip(Some("198.51.100.7".into()))
            .detail(serde_json::json!({ "pool_size": 8 }))
            .failed();
        assert_eq!(e.action, "route.delete");
        assert_eq!(e.target_name.as_deref(), Some("sh-hk"));
        assert!(!e.success);
    }
}
