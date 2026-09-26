//! Serialisable domain model shared by control plane, agent and web UI.
//!
//! Design note that drives the whole file: **an endpoint address is not a node
//! address**. A node has a public address (how users reach it) and a set of
//! endpoints (how the tunnel reaches its peer). On an IEPL box these live on
//! different NICs with different routing. Conflating them is the single most
//! common way this class of system breaks, so the types keep them apart.

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::secret::Secret;

// ---------------------------------------------------------------------------
// Node
// ---------------------------------------------------------------------------

/// What a node is allowed to do in a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeRole {
    /// Accepts user TCP connections, dials the tunnel.
    Entry,
    /// Accepts tunnel connections, dials targets.
    Exit,
    /// Both of the above; one binary, two hats.
    Both,
}

impl NodeRole {
    pub fn can_entry(self) -> bool {
        matches!(self, NodeRole::Entry | NodeRole::Both)
    }
    pub fn can_exit(self) -> bool {
        matches!(self, NodeRole::Exit | NodeRole::Both)
    }
    pub fn as_str(self) -> &'static str {
        match self {
            NodeRole::Entry => "entry",
            NodeRole::Exit => "exit",
            NodeRole::Both => "both",
        }
    }
}

impl fmt::Display for NodeRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for NodeRole {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "entry" => Ok(NodeRole::Entry),
            "exit" => Ok(NodeRole::Exit),
            "both" => Ok(NodeRole::Both),
            other => Err(crate::Error::config(format!("unknown node role `{other}`"))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeStatus {
    Online,
    /// Heartbeat is late but not gone; still serving traffic.
    Degraded,
    Offline,
}

impl NodeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            NodeStatus::Online => "online",
            NodeStatus::Degraded => "degraded",
            NodeStatus::Offline => "offline",
        }
    }
}

impl fmt::Display for NodeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A managed machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub name: String,
    pub region: String,
    pub role: NodeRole,
    /// Address users connect to. Display/diagnostics only — never used to dial
    /// a tunnel.
    #[serde(default)]
    pub public_address: Option<String>,
    /// Address the operator uses for SSH/ops. Also never used to dial a tunnel.
    #[serde(default)]
    pub management_address: Option<String>,
    #[serde(default)]
    pub agent_version: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

// ---------------------------------------------------------------------------
// Endpoint
// ---------------------------------------------------------------------------

/// Transport class of an endpoint. Purely descriptive: the data plane treats
/// all three identically, the UI and failover ordering use it for intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EndpointKind {
    Public,
    Private,
    Iepl,
}

impl EndpointKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EndpointKind::Public => "public",
            EndpointKind::Private => "private",
            EndpointKind::Iepl => "iepl",
        }
    }
}

impl fmt::Display for EndpointKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for EndpointKind {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "public" => Ok(EndpointKind::Public),
            "private" => Ok(EndpointKind::Private),
            "iepl" => Ok(EndpointKind::Iepl),
            other => Err(crate::Error::config(format!(
                "unknown endpoint kind `{other}`"
            ))),
        }
    }
}

/// Failover priority. Primary is tried first; backup only after the health
/// tracker demotes primary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EndpointPriority {
    Primary,
    Backup,
}

impl EndpointPriority {
    pub fn as_str(self) -> &'static str {
        match self {
            EndpointPriority::Primary => "primary",
            EndpointPriority::Backup => "backup",
        }
    }
}

impl fmt::Display for EndpointPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for EndpointPriority {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "primary" => Ok(EndpointPriority::Primary),
            "backup" => Ok(EndpointPriority::Backup),
            other => Err(crate::Error::config(format!(
                "unknown endpoint priority `{other}`"
            ))),
        }
    }
}

/// One dialable tunnel address on a node.
///
/// On a dual-NIC IEPL box you typically define two endpoints for the same exit
/// node: `10.20.0.2:5000` over `eth1` (primary, IEPL) and `203.0.113.9:5000`
/// over `eth0` (backup, public). Same exit process, same listener, two paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub id: String,
    pub node_id: String,
    pub name: String,
    /// Host the *entry* side dials. IP or DNS name.
    pub address: String,
    pub port: u16,
    pub kind: EndpointKind,
    #[serde(default = "default_priority")]
    pub priority: EndpointPriority,
    /// Informational: which NIC on the exit node this address lives on.
    #[serde(default)]
    pub interface: Option<String>,
    /// Source IP the *entry* binds before connecting, to force egress out of a
    /// specific NIC. `None` lets the kernel routing table decide.
    #[serde(default)]
    pub source_ip: Option<IpAddr>,
    /// TLS SNI / certificate name to verify. Required when `address` is a bare
    /// IP but the certificate carries a hostname.
    #[serde(default)]
    pub tls_server_name: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_priority() -> EndpointPriority {
    EndpointPriority::Primary
}
fn default_true() -> bool {
    true
}

impl Endpoint {
    /// `host:port` string for dialling. Kept as a string because `address` may
    /// be a DNS name resolved at dial time.
    pub fn dial_target(&self) -> String {
        if self.address.contains(':') && !self.address.starts_with('[') {
            // bare IPv6 literal
            format!("[{}]:{}", self.address, self.port)
        } else {
            format!("{}:{}", self.address, self.port)
        }
    }

    /// Name presented in the TLS ClientHello and verified against the cert.
    pub fn server_name(&self) -> &str {
        self.tls_server_name.as_deref().unwrap_or(&self.address)
    }
}

// ---------------------------------------------------------------------------
// Route
// ---------------------------------------------------------------------------

/// 线路模式。
///
/// # 两种模式的区别
///
/// * [`RouteMode::Tunnel`] —— 用户 → 入口 → 加密隧道 → 出口 → 目标。两端各一台
///   机器，需要证书与隧道地址。加密的价值在于隐藏已加密流量的形状（防 TLS-in-TLS
///   指纹），而不是给明文加密。
/// * [`RouteMode::Direct`] —— 用户 → 单机 → 目标。只有一台机器，accept 后直接
///   dial，不建隧道、不需要证书。
///
/// 直连模式存在的理由：最常见的部署就是一台三网优化机直转落地机，或 IEPL 商家
/// 只交付出口 root（入口侧只给一个转发 IP，装不了 agent，因此不可能建隧道）。
/// 强行用隧道模式自环会在同一台机器上加密再解密一次，纯属浪费。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RouteMode {
    #[default]
    Tunnel,
    Direct,
}

impl RouteMode {
    pub fn as_str(self) -> &'static str {
        match self {
            RouteMode::Tunnel => "tunnel",
            RouteMode::Direct => "direct",
        }
    }

    /// 中文显示名，面板直接用。
    pub fn label(self) -> &'static str {
        match self {
            RouteMode::Tunnel => "隧道转发",
            RouteMode::Direct => "直连转发",
        }
    }

    /// 该模式是否需要隧道地址与 TLS 材料。
    pub fn needs_tunnel(self) -> bool {
        matches!(self, RouteMode::Tunnel)
    }
}

impl fmt::Display for RouteMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for RouteMode {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "tunnel" => Ok(RouteMode::Tunnel),
            "direct" => Ok(RouteMode::Direct),
            other => Err(crate::Error::config(format!("未知线路模式 `{other}`"))),
        }
    }
}

/// How logical streams are spread over the tunnel connection pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalance {
    #[default]
    RoundRobin,
    /// Pick the tunnel with the fewest live streams. Slightly more work per
    /// dispatch, much better under uneven stream lifetimes.
    LeastStreams,
}

impl LoadBalance {
    pub fn as_str(self) -> &'static str {
        match self {
            LoadBalance::RoundRobin => "round_robin",
            LoadBalance::LeastStreams => "least_streams",
        }
    }
}

impl std::str::FromStr for LoadBalance {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "round_robin" | "roundrobin" | "rr" => Ok(LoadBalance::RoundRobin),
            "least_streams" | "leaststreams" | "lc" => Ok(LoadBalance::LeastStreams),
            other => Err(crate::Error::config(format!(
                "unknown load balance strategy `{other}`"
            ))),
        }
    }
}

/// 多目标的分配策略。
///
/// # 与 [`LoadBalance`] 的区别
///
/// [`LoadBalance`] 决定一条连接走**隧道池里的哪条隧道**，是传输层的事。这里决定
/// 连接落到**哪个目标机器**，是业务层的事。两者正交：一条线路可以「隧道用最少流
/// 分配、目标用 IP 哈希」。
///
/// # 只在多目标时有意义
///
/// 单目标时五种策略的结果完全相同，所以面板上只有配了多行目标才需要关心它。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TargetStrategy {
    /// 随机挑一个可用目标。
    ///
    /// 作为默认：无共享游标、无跨连接状态，并发下天然均匀，也不会像轮询那样在
    /// 多台入口机上产生同步的分配节奏（几台机器同时把第 N 个连接投向同一个目标）。
    #[default]
    Random,
    /// 按配置顺序轮流。
    ///
    /// 目标性能一致且连接寿命相近时分布最均匀。
    RoundRobin,
    /// 按客户端 IP 哈希，同一个客户端固定落到同一个目标。
    ///
    /// 目标侧有会话状态（登录态、本地缓存）时需要它。
    IpHash,
    /// 挑当前活跃连接最少的目标。
    ///
    /// 连接寿命差异大时（有的几秒、有的几小时）比轮询更均衡 —— 轮询只看分配次数，
    /// 不看已经分出去的连接是否还活着。
    LeastConn,
    /// 总是用最靠前的可用目标，主备关系。
    ///
    /// 与其他策略的区别：备用机平时完全不承载流量。前面的目标恢复后新连接自动切回。
    Failover,
}

impl TargetStrategy {
    pub fn as_str(self) -> &'static str {
        match self {
            TargetStrategy::Random => "random",
            TargetStrategy::RoundRobin => "round_robin",
            TargetStrategy::IpHash => "ip_hash",
            TargetStrategy::LeastConn => "least_conn",
            TargetStrategy::Failover => "failover",
        }
    }

    /// 中文显示名，面板直接用。
    pub fn label(self) -> &'static str {
        match self {
            TargetStrategy::Random => "随机",
            TargetStrategy::RoundRobin => "轮询",
            TargetStrategy::IpHash => "IP 哈希",
            TargetStrategy::LeastConn => "最少连接数",
            TargetStrategy::Failover => "故障转移",
        }
    }

    /// 全部策略，面板下拉按这个顺序渲染。
    pub const ALL: [TargetStrategy; 5] = [
        TargetStrategy::Random,
        TargetStrategy::RoundRobin,
        TargetStrategy::IpHash,
        TargetStrategy::LeastConn,
        TargetStrategy::Failover,
    ];
}

impl fmt::Display for TargetStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for TargetStrategy {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "random" | "rand" => Ok(TargetStrategy::Random),
            "round_robin" | "roundrobin" | "rr" => Ok(TargetStrategy::RoundRobin),
            "ip_hash" | "iphash" | "ip-hash" => Ok(TargetStrategy::IpHash),
            "least_conn" | "leastconn" | "least_connections" | "lc" => {
                Ok(TargetStrategy::LeastConn)
            }
            "failover" | "fail_over" => Ok(TargetStrategy::Failover),
            other => Err(crate::Error::config(format!(
                "未知的负载均衡策略 `{other}`"
            ))),
        }
    }
}

/// A relay rule: listen on the entry node, deliver to a target behind the exit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub id: String,
    pub name: String,
    /// 转发模式。直连模式下 `endpoint_ids` 与 `tunnel_pool_size` 不参与运行。
    #[serde(default)]
    pub mode: RouteMode,
    pub entry_node_id: String,
    /// `0.0.0.0:443` style bind address on the entry node.
    pub listen_address: String,
    pub listen_port: u16,
    pub exit_node_id: String,
    /// Where the exit dials, e.g. `127.0.0.1:8443`.
    ///
    /// 保留为「第一个目标」，与 `targets` 的首项一致。
    pub target_host: String,
    pub target_port: u16,
    /// 全部目标，形如 `["1.2.3.4:443", "5.6.7.8:443"]`。
    ///
    /// 多个目标时按 [`Route::target_strategy`] 分配新连接；某个目标连续失败会被
    /// 熔断跳过，之后定期试探恢复。为空时回落到 `target_host:target_port`。
    #[serde(default)]
    pub targets: Vec<String>,
    /// 多目标的分配策略。单目标时不起作用。
    #[serde(default)]
    pub target_strategy: TargetStrategy,
    /// Endpoints usable for this route, ordered primary-first. Multiple entries
    /// enable IEPL→public failover.
    #[serde(default)]
    pub endpoint_ids: Vec<String>,
    #[serde(default = "default_pool_size")]
    pub tunnel_pool_size: u16,
    #[serde(default)]
    pub load_balance: LoadBalance,
    /// 0 = inherit the agent-wide limit.
    #[serde(default)]
    pub max_connections: u32,
    /// Source IP the **exit** binds when dialling the target. This is how you
    /// make traffic that arrived over IEPL leave through the public NIC.
    #[serde(default)]
    pub egress_source_ip: Option<IpAddr>,
    /// `SO_BINDTODEVICE` name. Needs `CAP_NET_RAW`; prefer `egress_source_ip`.
    #[serde(default)]
    pub egress_interface: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_pool_size() -> u16 {
    8
}

impl Route {
    pub fn listen_socket_addr(&self) -> String {
        if self.listen_address.contains(':') && !self.listen_address.starts_with('[') {
            format!("[{}]:{}", self.listen_address, self.listen_port)
        } else {
            format!("{}:{}", self.listen_address, self.listen_port)
        }
    }

    pub fn target_socket_addr(&self) -> String {
        if self.target_host.contains(':') && !self.target_host.starts_with('[') {
            format!("[{}]:{}", self.target_host, self.target_port)
        } else {
            format!("{}:{}", self.target_host, self.target_port)
        }
    }

    /// 全部目标地址，至少一个。
    ///
    /// `targets` 为空时回落到 `target_host:target_port`，所以调用方永远拿到非空
    /// 列表，不需要处理「没有目标」这种状态。
    pub fn effective_targets(&self) -> Vec<String> {
        let filtered: Vec<String> = self
            .targets
            .iter()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect();
        if filtered.is_empty() {
            vec![self.target_socket_addr()]
        } else {
            filtered
        }
    }
}

// ---------------------------------------------------------------------------
// Tunable limits
// ---------------------------------------------------------------------------

/// Every value here bounds memory or syscall pressure. Defaults are tuned for
/// a 2-core/2 GB VPS carrying a few thousand concurrent streams.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Limits {
    /// Hard cap on a single frame's payload. Guards against a hostile peer
    /// announcing a 4 GiB length. Must be identical on both ends.
    pub max_frame_payload: u32,
    /// Per-stream receive window in bytes. The sender may not exceed this
    /// without a credit update — this is the backpressure mechanism.
    pub stream_window: u32,
    /// Bounded queue depth for frames waiting on the TLS writer.
    pub tunnel_send_queue: usize,
    /// Bounded queue depth for data frames waiting on one stream's reader.
    pub stream_recv_queue: usize,
    /// Concurrent logical streams per tunnel connection.
    pub max_streams_per_tunnel: u32,
    /// Agent-wide accepted-connection ceiling across all routes.
    pub max_connections: u32,
    /// Relay copy buffer size. 16 KiB matches the TLS record ceiling closely
    /// enough to avoid splitting records for no reason.
    pub relay_buffer: usize,
    #[serde(with = "humantime_serde")]
    pub handshake_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Duration,
    /// Idle time after which a logical stream is reaped.
    #[serde(with = "humantime_serde")]
    pub stream_idle_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub ping_interval: Duration,
    #[serde(with = "humantime_serde")]
    pub ping_timeout: Duration,
    /// Consecutive missed PONGs before the tunnel is torn down.
    pub ping_max_failures: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frame_payload: 64 * 1024,
            stream_window: 512 * 1024,
            tunnel_send_queue: 1024,
            stream_recv_queue: 64,
            max_streams_per_tunnel: 4096,
            max_connections: 20_000,
            relay_buffer: 16 * 1024,
            handshake_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(10),
            stream_idle_timeout: Duration::from_secs(300),
            ping_interval: Duration::from_secs(15),
            ping_timeout: Duration::from_secs(10),
            ping_max_failures: 3,
        }
    }
}

impl Limits {
    /// Reject nonsense before it reaches the data plane.
    pub fn validate(&self) -> crate::Result<()> {
        if self.max_frame_payload < 1024 {
            return Err(crate::Error::config(
                "limits.max_frame_payload must be >= 1024",
            ));
        }
        if self.max_frame_payload > 1024 * 1024 {
            return Err(crate::Error::config(
                "limits.max_frame_payload must be <= 1 MiB",
            ));
        }
        if self.stream_window < self.max_frame_payload {
            return Err(crate::Error::config(
                "limits.stream_window must be >= max_frame_payload, otherwise a single \
                 full-size frame can never be sent",
            ));
        }
        if self.tunnel_send_queue == 0 || self.stream_recv_queue == 0 {
            return Err(crate::Error::config(
                "queue depths must be > 0 (unbounded queues are forbidden)",
            ));
        }
        if self.relay_buffer < 1024 {
            return Err(crate::Error::config("limits.relay_buffer must be >= 1024"));
        }
        if self.ping_timeout >= self.ping_interval.saturating_mul(4) {
            return Err(crate::Error::config(
                "limits.ping_timeout should be well under 4x ping_interval",
            ));
        }
        if self.ping_max_failures == 0 {
            return Err(crate::Error::config("limits.ping_max_failures must be >= 1"));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// TLS material
// ---------------------------------------------------------------------------

/// Paths to on-disk PEM material. Contents are loaded at runtime and never sent
/// to the control plane.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsConfig {
    /// Server certificate chain, leaf first. Required for the exit role.
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    /// CA bundle used to verify the peer. When set, the system trust store is
    /// ignored — which is what you want for a private pinned CA.
    pub ca_path: Option<String>,
    /// Require and verify a client certificate on the exit side (mTLS).
    pub require_client_auth: bool,
    /// Client certificate presented by the entry when the exit demands mTLS.
    pub client_cert_path: Option<String>,
    pub client_key_path: Option<String>,
    /// Escape hatch for lab use. Refused when the control plane marks the
    /// deployment as production.
    pub insecure_skip_verify: bool,
}

// ---------------------------------------------------------------------------
// Config bundle pushed to agents
// ---------------------------------------------------------------------------

/// Everything an agent needs to run, in one atomically-swappable document.
///
/// The agent persists the last bundle that validated and applied cleanly. If
/// the control plane is down at boot, that cached bundle is what comes back up.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfigBundle {
    /// Monotonic generation counter from the control plane. Lets the agent skip
    /// re-applying an identical config.
    pub revision: u64,
    pub model_version: u32,
    pub node: Node,
    /// Endpoints this agent should *listen* on (exit role).
    #[serde(default)]
    pub listen_endpoints: Vec<Endpoint>,
    /// Endpoints this agent may *dial* (entry role), keyed by id.
    #[serde(default)]
    pub remote_endpoints: Vec<Endpoint>,
    #[serde(default)]
    pub routes: Vec<Route>,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub tls: TlsConfig,
    /// Pre-shared key authenticating the tunnel handshake, on top of TLS.
    #[serde(default)]
    pub tunnel_psk: Option<Secret>,
    #[serde(default)]
    pub issued_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl AgentConfigBundle {
    pub fn endpoint(&self, id: &str) -> Option<&Endpoint> {
        self.remote_endpoints
            .iter()
            .chain(self.listen_endpoints.iter())
            .find(|e| e.id == id)
    }

    /// Structural validation. Runs *before* the bundle is applied, so a bad
    /// push from the control plane leaves the previous config in place.
    pub fn validate(&self) -> crate::Result<()> {
        if self.model_version != crate::MODEL_VERSION {
            return Err(crate::Error::config(format!(
                "config model version {} not supported (agent speaks {})",
                self.model_version,
                crate::MODEL_VERSION
            )));
        }
        self.limits.validate()?;

        for ep in self.listen_endpoints.iter().chain(&self.remote_endpoints) {
            if ep.port == 0 {
                return Err(crate::Error::config(format!(
                    "endpoint `{}` has port 0",
                    ep.name
                )));
            }
            if ep.address.trim().is_empty() {
                return Err(crate::Error::config(format!(
                    "endpoint `{}` has an empty address",
                    ep.name
                )));
            }
        }

        let mut seen_binds = std::collections::HashSet::new();
        for route in &self.routes {
            if !route.enabled {
                continue;
            }
            if route.listen_port == 0 {
                return Err(crate::Error::config(format!(
                    "route `{}` listens on port 0",
                    route.name
                )));
            }
            if route.target_port == 0 {
                return Err(crate::Error::config(format!(
                    "route `{}` targets port 0",
                    route.name
                )));
            }
            if route.tunnel_pool_size == 0 {
                return Err(crate::Error::config(format!(
                    "route `{}` has tunnel_pool_size 0",
                    route.name
                )));
            }
            if route.tunnel_pool_size > 256 {
                return Err(crate::Error::config(format!(
                    "route `{}` tunnel_pool_size {} is unreasonably large (max 256)",
                    route.name, route.tunnel_pool_size
                )));
            }
            // Only entry-side routes bind a listener on this node.
            if route.entry_node_id == self.node.id {
                let bind = route.listen_socket_addr();
                if !seen_binds.insert(bind.clone()) {
                    return Err(crate::Error::config(format!(
                        "route `{}` duplicates listen address {bind}",
                        route.name
                    )));
                }
                // 隧道地址只有隧道模式才需要 —— 直连模式下本机直接 dial 目标，
                // 没有对端可拨。
                if route.mode.needs_tunnel() {
                    if route.endpoint_ids.is_empty() {
                        return Err(crate::Error::config(format!(
                            "隧道线路 `{}` 没有可拨的隧道地址",
                            route.name
                        )));
                    }
                    for id in &route.endpoint_ids {
                        if self.endpoint(id).is_none() {
                            return Err(crate::Error::config(format!(
                                "线路 `{}` 引用了不存在的隧道地址 `{id}`",
                                route.name
                            )));
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Runtime telemetry reported upward
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelState {
    Connecting,
    Online,
    /// Connected but unhealthy: RTT spikes or missed pings short of the cutoff.
    Degraded,
    Offline,
}

impl TunnelState {
    pub fn as_str(self) -> &'static str {
        match self {
            TunnelState::Connecting => "connecting",
            TunnelState::Online => "online",
            TunnelState::Degraded => "degraded",
            TunnelState::Offline => "offline",
        }
    }
}

impl fmt::Display for TunnelState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelSnapshot {
    pub tunnel_id: u64,
    pub route_id: String,
    pub endpoint_id: String,
    pub endpoint_name: String,
    pub endpoint_kind: EndpointKind,
    pub state: TunnelState,
    pub streams: u32,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rtt_ms: Option<u32>,
    pub established_secs: u64,
    pub reconnects: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteSnapshot {
    pub route_id: String,
    pub name: String,
    pub enabled: bool,
    pub listen: String,
    pub target: String,
    pub active_endpoint_id: Option<String>,
    pub tunnels_online: u32,
    pub tunnels_total: u32,
    pub connections: u32,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_bps: u64,
    pub tx_bps: u64,
    pub accepted_total: u64,
    pub rejected_total: u64,
    pub failed_total: u64,
    /// 各转发目标的健康状态。单目标时一项，多目标时逐个上报。
    ///
    /// 用 [`TargetHealth`] 而不是直接引用 tunnel-core 的 `TargetStatus`：这个结构
    /// 是入口与控制面之间的**协议**，不能跟着数据面的内部类型一起变。
    #[serde(default)]
    pub targets: Vec<TargetHealth>,
}

/// 一个转发目标的健康状态，随遥测上报给面板。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetHealth {
    pub addr: String,
    /// 当前是否会被分配到新连接。
    pub available: bool,
    /// 是否已熔断。`available && tripped` 表示冷却已过、正在试探。
    pub tripped: bool,
    /// 当前活跃连接数。
    pub active: u64,
    pub consecutive_failures: u32,
    pub total_ok: u64,
    pub total_failed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionSnapshot {
    pub id: u64,
    pub route_id: String,
    pub route_name: String,
    pub tunnel_id: u64,
    pub stream_id: u32,
    pub client_addr: String,
    pub target: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub age_secs: u64,
    pub idle_secs: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostStats {
    pub cpu_percent: f32,
    pub memory_used_bytes: u64,
    pub memory_total_bytes: u64,
    pub uptime_secs: u64,
    #[serde(default)]
    pub host_uptime_secs: u64,
    #[serde(default)]
    pub disk_used_bytes: u64,
    #[serde(default)]
    pub disk_total_bytes: u64,
    pub open_fds: Option<u64>,
    pub load_avg_1m: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub addresses: Vec<IpAddr>,
    pub is_loopback: bool,
    pub is_up: bool,
}

/// Periodic agent → control report. Also the payload broadcast to the web UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentReport {
    pub node_id: String,
    pub agent_version: String,
    pub config_revision: u64,
    pub role: NodeRole,
    pub host: HostStats,
    #[serde(default)]
    pub interfaces: Vec<InterfaceInfo>,
    #[serde(default)]
    pub routes: Vec<RouteSnapshot>,
    #[serde(default)]
    pub tunnels: Vec<TunnelSnapshot>,
    /// Sample of live connections for the Connections page.
    ///
    /// Deliberately a bounded sample, not the full table: at 10k concurrent
    /// streams a complete list would be a multi-megabyte report every few
    /// seconds, and no operator reads 10k rows. The agent caps it.
    #[serde(default)]
    pub connection_samples: Vec<ConnectionSnapshot>,
    pub connections: u32,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_bps: u64,
    pub tx_bps: u64,
    pub reported_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str) -> Node {
        Node {
            id: id.into(),
            name: id.into(),
            region: "test".into(),
            role: NodeRole::Both,
            public_address: None,
            management_address: None,
            agent_version: None,
            note: None,
        }
    }

    fn endpoint(id: &str, node_id: &str) -> Endpoint {
        Endpoint {
            id: id.into(),
            node_id: node_id.into(),
            name: id.into(),
            address: "10.20.0.2".into(),
            port: 5000,
            kind: EndpointKind::Iepl,
            priority: EndpointPriority::Primary,
            interface: Some("eth1".into()),
            source_ip: None,
            tls_server_name: Some("exit.internal".into()),
            enabled: true,
        }
    }

    fn route(entry: &str, exit: &str, eps: Vec<String>) -> Route {
        Route {
            id: "r1".into(),
            name: "sh-hk".into(),
            mode: RouteMode::Tunnel,
            entry_node_id: entry.into(),
            listen_address: "0.0.0.0".into(),
            listen_port: 443,
            exit_node_id: exit.into(),
            target_host: "127.0.0.1".into(),
            target_port: 8443,
            targets: vec![],
            target_strategy: TargetStrategy::default(),
            endpoint_ids: eps,
            tunnel_pool_size: 8,
            load_balance: LoadBalance::RoundRobin,
            max_connections: 0,
            egress_source_ip: None,
            egress_interface: None,
            enabled: true,
        }
    }

    fn bundle(routes: Vec<Route>, remote: Vec<Endpoint>) -> AgentConfigBundle {
        AgentConfigBundle {
            revision: 1,
            model_version: crate::MODEL_VERSION,
            node: node("sh-01"),
            listen_endpoints: vec![],
            remote_endpoints: remote,
            routes,
            limits: Limits::default(),
            tls: TlsConfig::default(),
            tunnel_psk: Some(Secret::new("psk")),
            issued_at: None,
        }
    }

    #[test]
    fn default_limits_are_self_consistent() {
        Limits::default().validate().unwrap();
    }

    #[test]
    fn window_smaller_than_frame_is_rejected() {
        let l = Limits {
            stream_window: 1024,
            max_frame_payload: 64 * 1024,
            ..Default::default()
        };
        assert!(l.validate().is_err());
    }

    #[test]
    fn unbounded_queue_is_rejected() {
        let l = Limits {
            tunnel_send_queue: 0,
            ..Default::default()
        };
        assert!(l.validate().is_err());
    }

    #[test]
    fn valid_bundle_passes() {
        let b = bundle(
            vec![route("sh-01", "hk-01", vec!["ep1".into()])],
            vec![endpoint("ep1", "hk-01")],
        );
        b.validate().unwrap();
    }

    #[test]
    fn a_tunnel_route_without_an_endpoint_is_rejected() {
        let b = bundle(vec![route("sh-01", "hk-01", vec![])], vec![]);
        assert!(b.validate().is_err());
    }

    #[test]
    fn a_direct_route_needs_no_endpoint() {
        // 直连模式下本机直接 dial 目标，没有对端隧道可拨 —— 要求隧道地址会让
        // 单机转发这种最常见的部署根本无法配置。
        let mut r = route("sh-01", "sh-01", vec![]);
        r.mode = RouteMode::Direct;
        let b = bundle(vec![r], vec![]);
        b.validate().unwrap();
    }

    #[test]
    fn a_direct_route_still_validates_ports_and_bind_uniqueness() {
        // 模式放宽的只有隧道地址，端口与监听冲突仍然要拦。
        let mut r = route("sh-01", "sh-01", vec![]);
        r.mode = RouteMode::Direct;
        r.target_port = 0;
        assert!(bundle(vec![r], vec![]).validate().is_err());

        let mut a = route("sh-01", "sh-01", vec![]);
        a.mode = RouteMode::Direct;
        let mut dup = a.clone();
        dup.id = "r2".into();
        dup.name = "另一条".into();
        assert!(
            bundle(vec![a, dup], vec![]).validate().is_err(),
            "同一监听地址的两条直连线路仍应冲突"
        );
    }

    #[test]
    fn effective_targets_falls_back_to_the_single_target() {
        // 调用方永远拿到非空列表，不必处理「没有目标」这种状态。
        let r = route("sh-01", "hk-01", vec!["ep1".into()]);
        assert_eq!(r.effective_targets(), vec!["127.0.0.1:8443".to_string()]);
    }

    #[test]
    fn effective_targets_uses_the_list_when_present() {
        let mut r = route("sh-01", "hk-01", vec!["ep1".into()]);
        r.targets = vec!["1.2.3.4:443".into(), "5.6.7.8:443".into()];
        assert_eq!(
            r.effective_targets(),
            vec!["1.2.3.4:443".to_string(), "5.6.7.8:443".to_string()]
        );
    }

    #[test]
    fn effective_targets_drops_blank_entries() {
        // 导入的数据可能带空串或空白项，不该让它们变成一个拨不通的目标。
        let mut r = route("sh-01", "hk-01", vec!["ep1".into()]);
        r.targets = vec!["  ".into(), "1.2.3.4:443".into(), "".into()];
        assert_eq!(r.effective_targets(), vec!["1.2.3.4:443".to_string()]);

        // 全是空白时回落到单目标，而不是返回空列表。
        r.targets = vec!["".into(), "   ".into()];
        assert_eq!(r.effective_targets(), vec!["127.0.0.1:8443".to_string()]);
    }

    #[test]
    fn target_strategy_round_trips_and_labels() {
        for (text, expected, label) in [
            ("random", TargetStrategy::Random, "随机"),
            ("round_robin", TargetStrategy::RoundRobin, "轮询"),
            ("ip_hash", TargetStrategy::IpHash, "IP 哈希"),
            ("least_conn", TargetStrategy::LeastConn, "最少连接数"),
            ("failover", TargetStrategy::Failover, "故障转移"),
        ] {
            assert_eq!(text.parse::<TargetStrategy>().unwrap(), expected);
            assert_eq!(expected.as_str(), text);
            assert_eq!(expected.label(), label);
        }
        assert!("sideways".parse::<TargetStrategy>().is_err());
        // 默认随机：无共享游标，并发下天然均匀，也不会让多台入口机产生同步节奏。
        assert_eq!(TargetStrategy::default(), TargetStrategy::Random);
        assert_eq!(TargetStrategy::ALL.len(), 5);
    }

    #[test]
    fn target_strategy_accepts_common_aliases() {
        // 导入的数据可能来自别的面板，写法不尽相同。
        for (text, expected) in [
            ("rr", TargetStrategy::RoundRobin),
            ("RoundRobin", TargetStrategy::RoundRobin),
            ("ip-hash", TargetStrategy::IpHash),
            ("IPHash", TargetStrategy::IpHash),
            ("least_connections", TargetStrategy::LeastConn),
            ("lc", TargetStrategy::LeastConn),
            ("  Random  ", TargetStrategy::Random),
        ] {
            assert_eq!(text.parse::<TargetStrategy>().unwrap(), expected, "`{text}`");
        }
    }

    #[test]
    fn a_route_without_a_strategy_field_deserialises_as_random() {
        // 既有配置（0001-0004 建的线路）反序列化时没有这个字段，不能报错。
        let json = r#"{
            "id":"r1","name":"x","entry_node_id":"n1","listen_address":"0.0.0.0",
            "listen_port":443,"exit_node_id":"n2","target_host":"1.2.3.4",
            "target_port":443,"enabled":true
        }"#;
        let r: Route = serde_json::from_str(json).unwrap();
        assert_eq!(r.target_strategy, TargetStrategy::Random);
        assert_eq!(r.mode, RouteMode::Tunnel);
        assert!(r.targets.is_empty());
    }

    #[test]
    fn route_mode_round_trips_and_labels() {
        for (text, expected, label) in [
            ("tunnel", RouteMode::Tunnel, "隧道转发"),
            ("direct", RouteMode::Direct, "直连转发"),
        ] {
            assert_eq!(text.parse::<RouteMode>().unwrap(), expected);
            assert_eq!(expected.as_str(), text);
            assert_eq!(expected.label(), label);
        }
        assert!("sideways".parse::<RouteMode>().is_err());
        // 默认必须是隧道模式：既有配置反序列化时没有 mode 字段，不能被当成直连。
        assert_eq!(RouteMode::default(), RouteMode::Tunnel);
        assert!(RouteMode::Tunnel.needs_tunnel());
        assert!(!RouteMode::Direct.needs_tunnel());
    }

    #[test]
    fn unknown_endpoint_reference_is_rejected() {
        let b = bundle(
            vec![route("sh-01", "hk-01", vec!["nope".into()])],
            vec![endpoint("ep1", "hk-01")],
        );
        assert!(b.validate().is_err());
    }

    #[test]
    fn duplicate_listen_address_is_rejected() {
        let mut r2 = route("sh-01", "hk-01", vec!["ep1".into()]);
        r2.id = "r2".into();
        let b = bundle(
            vec![route("sh-01", "hk-01", vec!["ep1".into()]), r2],
            vec![endpoint("ep1", "hk-01")],
        );
        assert!(b.validate().is_err());
    }

    #[test]
    fn exit_side_route_does_not_need_local_endpoints() {
        // This node is the exit; the route's endpoints live in the entry's bundle.
        let mut b = bundle(vec![route("sh-99", "sh-01", vec![])], vec![]);
        b.node = node("sh-01");
        b.validate().unwrap();
    }

    #[test]
    fn dial_target_brackets_ipv6() {
        let mut ep = endpoint("ep1", "hk-01");
        ep.address = "fd00::2".into();
        assert_eq!(ep.dial_target(), "[fd00::2]:5000");
    }

    #[test]
    fn server_name_falls_back_to_address() {
        let mut ep = endpoint("ep1", "hk-01");
        assert_eq!(ep.server_name(), "exit.internal");
        ep.tls_server_name = None;
        assert_eq!(ep.server_name(), "10.20.0.2");
    }

    #[test]
    fn role_capabilities() {
        assert!(NodeRole::Both.can_entry() && NodeRole::Both.can_exit());
        assert!(NodeRole::Entry.can_entry() && !NodeRole::Entry.can_exit());
        assert!(!NodeRole::Exit.can_entry() && NodeRole::Exit.can_exit());
    }
}
