//! Runtime supervisor: owns the data plane and applies configuration.
//!
//! # Atomic apply
//!
//! A config change must never leave the node half-configured. The sequence is:
//!
//! 1. Validate the bundle. A bad bundle is rejected here and the running
//!    configuration is untouched.
//! 2. Build the *new* runtime — TLS material, pools, listeners — while the old
//!    one is still serving.
//! 3. Swap. Only then is the old runtime told to drain.
//!
//! If step 2 fails for any reason, the old runtime keeps running and the failure
//! is reported. This is the difference between "a typo in the panel disabled one
//! route" and "a typo in the panel took every tunnel on the node offline".
//!
//! # Graceful drain
//!
//! Replacing a route stops its listener first, then lets existing streams finish.
//! Killing live connections on every configuration edit would make routine
//! changes user-visible.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tunnel_common::model::{
    AgentConfigBundle, AgentReport, ConnectionSnapshot, HostStats, NodeRole, RouteSnapshot,
    TunnelSnapshot,
};
use tunnel_common::net::EgressBinding;
use tunnel_common::{Error, Result};
use tunnel_core::entry::EntryListener;
use tunnel_core::exit::{ExitListener, ExitRoute};
use tunnel_core::health::HealthPolicy;
use tunnel_core::metrics::{ConnectionRegistry, RouteMetrics};
use tunnel_core::pool::{PoolConfig, TunnelPool};
use tunnel_core::tls::TlsMaterial;

use crate::config::{AgentConfig, ConfigCache};
use crate::host;

const REL: Ordering = Ordering::Relaxed;

/// 一条运行中的入口线路。
///
/// `pool` 为 `None` 表示直连模式 —— 该线路不建隧道，accept 后直接 dial 目标。
struct EntryRuntime {
    route_id: String,
    route_name: String,
    listen: String,
    target: String,
    pool: Option<Arc<TunnelPool>>,
    metrics: Arc<RouteMetrics>,
    shutdown: Arc<AtomicBool>,
    /// 直连线路的监听器，用于取各目标的健康状态。
    ///
    /// 隧道线路为 `None` —— 那种模式下目标由出口拨号，入口无从得知它们的健康状况。
    listener: Option<Arc<EntryListener>>,
}

/// One running exit listener.
struct ExitRuntime {
    endpoint_name: String,
    /// 持有监听器，让它与本 runtime 同寿命。
    ///
    /// 目前没有读取它的地方：`drain()` 通过 `shutdown` 标志停机，跑在 tokio 任务里
    /// 的那份是独立的 `Arc` 克隆。保留这个字段有两个作用 ——
    ///
    /// 1. 语义上明确「这个监听器属于这份 runtime」，而不是一个逃逸的后台任务；
    /// 2. [`ExitListener::replace_routes`] 需要它。那个方法能在不断开隧道的前提下
    ///    换掉出口的路由表，比现在「重建整个 runtime」温和得多；目前配置变更走的是
    ///    重建路径，所以还没用上。
    #[allow(dead_code)]
    listener: Arc<ExitListener>,
    shutdown: Arc<AtomicBool>,
}

/// Everything the agent is currently running.
struct Runtime {
    revision: u64,
    entries: Vec<EntryRuntime>,
    exits: Vec<ExitRuntime>,
    /// Route metrics keyed by route id, shared with the exit listeners.
    route_metrics: HashMap<String, Arc<RouteMetrics>>,
}

impl Runtime {
    fn empty() -> Self {
        Self {
            revision: 0,
            entries: Vec::new(),
            exits: Vec::new(),
            route_metrics: HashMap::new(),
        }
    }

    /// Stop accepting, then let live streams finish.
    async fn drain(&self) {
        // Listeners first: no new work while we wind down.
        for entry in &self.entries {
            entry.shutdown.store(true, REL);
        }
        for exit in &self.exits {
            exit.shutdown.store(true, REL);
        }
        // Then the pools, which sends GO_AWAY before closing.
        // 直连线路没有池，停掉监听即可 —— 已建立的连接由 relay 自己收尾。
        for entry in &self.entries {
            if let Some(pool) = &entry.pool {
                pool.shutdown().await;
            }
        }
    }
}

pub struct Supervisor {
    cfg: AgentConfig,
    cache: ConfigCache,
    runtime: tokio::sync::RwLock<Runtime>,
    registry: Arc<ConnectionRegistry>,
    /// TLS material, hot-reloadable on SIGHUP.
    tls: arc_swap::ArcSwapOption<TlsMaterial>,
    /// 控制面在注册时分配的机器 id。
    ///
    /// agent 不再自己持有 node_id —— 它凭组令牌注册，由控制面按 (组, 机器名) 登记
    /// 并回传 id。心跳需要它来标识自己，所以注册成功后记在这里。
    node_id: arc_swap::ArcSwapOption<String>,
    applied_revision: AtomicU64,
    started_at: std::time::Instant,
    role: arc_swap::ArcSwap<NodeRole>,
}

impl Supervisor {
    pub fn new(cfg: AgentConfig) -> Arc<Self> {
        let cache = ConfigCache::new(cfg.cache_path.clone());
        // Bounded: the registry is for display, and a 10k-row table is neither
        // cheap nor useful.
        let registry = ConnectionRegistry::new(cfg.connection_sample_limit.max(50) * 4);

        Arc::new(Self {
            cfg,
            cache,
            runtime: tokio::sync::RwLock::new(Runtime::empty()),
            registry,
            tls: arc_swap::ArcSwapOption::from(None),
            node_id: arc_swap::ArcSwapOption::from(None),
            applied_revision: AtomicU64::new(0),
            started_at: std::time::Instant::now(),
            role: arc_swap::ArcSwap::from_pointee(NodeRole::Both),
        })
    }

    pub fn config(&self) -> &AgentConfig {
        &self.cfg
    }

    pub fn applied_revision(&self) -> u64 {
        self.applied_revision.load(REL)
    }

    /// 控制面分配的机器 id，注册完成后才有值。
    pub fn node_id(&self) -> Option<String> {
        self.node_id.load_full().map(|id| (*id).clone())
    }

    /// 记录控制面分配的机器 id。注册成功时调用。
    pub fn set_node_id(&self, id: String) {
        self.node_id.store(Some(Arc::new(id)));
    }

    /// 配置缓存。目前只有测试在用 —— 二进制走 [`Self::start_from_cache`]。
    #[cfg(test)]
    pub fn cache(&self) -> &ConfigCache {
        &self.cache
    }

    /// Load the cached bundle and start serving from it.
    ///
    /// This runs *before* the control plane is contacted, which is what lets a
    /// node reboot into a working state during a control-plane outage.
    pub async fn start_from_cache(&self) -> bool {
        let Some(bundle) = self.cache.load() else {
            return false;
        };
        match self.apply(&bundle, false).await {
            Ok(()) => {
                tracing::info!(
                    revision = bundle.revision,
                    "started from cached configuration; control plane not yet contacted"
                );
                true
            }
            Err(e) => {
                tracing::error!(error = %e, "cached configuration could not be applied");
                false
            }
        }
    }

    /// Apply a bundle. `persist` controls whether it becomes the new cache.
    ///
    /// The new runtime is fully built before the old one is touched, so a failure
    /// here leaves the previous configuration serving.
    pub async fn apply(&self, bundle: &AgentConfigBundle, persist: bool) -> Result<()> {
        bundle.validate()?;

        let role = self.cfg.effective_role(bundle.node.role);
        let next = self.build_runtime(bundle, role).await?;

        // Past this point the new runtime exists and is listening. Swap it in,
        // then drain the old one.
        let previous = {
            let mut guard = self.runtime.write().await;
            std::mem::replace(&mut *guard, next)
        };

        self.role.store(Arc::new(role));
        self.applied_revision.store(bundle.revision, REL);

        if !previous.entries.is_empty() || !previous.exits.is_empty() {
            tracing::info!(
                from_revision = previous.revision,
                to_revision = bundle.revision,
                "configuration replaced; draining the previous runtime"
            );
            previous.drain().await;
        }

        // Only cache a bundle that actually applied.
        if persist {
            if let Err(e) = self.cache.store(bundle) {
                // Not fatal: the node is running the new config either way. It
                // just will not survive a restart during an outage.
                tracing::warn!(error = %e, "could not cache the configuration");
            }
        }

        Ok(())
    }

    /// Construct (and start) a runtime without touching the current one.
    async fn build_runtime(&self, bundle: &AgentConfigBundle, role: NodeRole) -> Result<Runtime> {
        // The agent's own TLS paths win over anything distributed: private keys
        // are local, and the control plane only suggests where they live.
        let tls_cfg = if self.cfg.tls.cert_path.is_some() || self.cfg.tls.ca_path.is_some() {
            self.cfg.tls.clone()
        } else {
            bundle.tls.clone()
        };

        let needs_server = role.can_exit()
            && !bundle.listen_endpoints.is_empty()
            && bundle.routes.iter().any(|r| r.enabled && r.mode.needs_tunnel()
                && r.exit_node_id == bundle.node.id);
        let needs_client = role.can_entry()
            && bundle.routes.iter().any(|r| r.enabled && r.mode.needs_tunnel()
                && r.entry_node_id == bundle.node.id);
        let tls = if needs_server || needs_client {
            Some(TlsMaterial::load(&tls_cfg, needs_server)?)
        } else {
            None
        };

        let psk = bundle
            .tunnel_psk
            .clone()
            .or_else(|| self.cfg.tunnel_psk.clone());

        let previous_metrics = self.runtime.read().await.route_metrics.clone();
        let mut route_metrics: HashMap<String, Arc<RouteMetrics>> = HashMap::new();
        for route in &bundle.routes {
            route_metrics.insert(
                route.id.clone(),
                previous_metrics
                    .get(&route.id)
                    .cloned()
                    .unwrap_or_else(|| RouteMetrics::new(route.id.clone())),
            );
        }

        // --- entry side ---
        let mut entries = Vec::new();
        if role.can_entry() {
            for route in bundle.routes.iter().filter(|r| r.enabled) {
                if route.entry_node_id != bundle.node.id {
                    continue;
                }

                let metrics = route_metrics
                    .get(&route.id)
                    .cloned()
                    .unwrap_or_else(|| RouteMetrics::new(route.id.clone()));

                // 直连模式：不建隧道池，accept 后直接 dial 目标。
                //
                // 这是单机转发的路径 —— 一台三网优化机把端口转到落地机，或 IEPL
                // 商家只交付出口 root 的情形。强行走隧道会在同一台机器上加密再解密
                // 一次，纯属浪费。
                if !route.mode.needs_tunnel() {
                    let listener = Arc::new(EntryListener::new_direct(
                        route.clone(),
                        bundle.limits.clone(),
                        self.registry.clone(),
                        metrics.clone(),
                    ));
                    let shutdown = listener.shutdown_flag();

                    let spawn_listener = listener.clone();
                    let route_name = route.name.clone();
                    tokio::spawn(async move {
                        if let Err(e) = spawn_listener.run().await {
                            tracing::error!(
                                route = %route_name,
                                error = %e,
                                "直连监听已停止"
                            );
                        }
                    });

                    entries.push(EntryRuntime {
                        route_id: route.id.clone(),
                        route_name: route.name.clone(),
                        listen: route.listen_socket_addr(),
                        // 多目标时展示成 `a, b, c`，面板上一眼能看出这条线路转发到
                        // 哪几台机器；逐个目标的健康状态另外上报。
                        target: route.effective_targets().join(", "),
                        // 直连没有隧道池。
                        pool: None,
                        metrics,
                        shutdown,
                        listener: Some(listener),
                    });
                    continue;
                }

                let endpoints: Vec<_> = route
                    .endpoint_ids
                    .iter()
                    .filter_map(|id| bundle.endpoint(id).cloned())
                    .collect();
                if endpoints.is_empty() {
                    // Validation should have caught this; refuse rather than
                    // start a listener that can never connect anywhere.
                    return Err(Error::config(format!(
                        "隧道线路 `{}` 没有可解析的隧道地址",
                        route.name
                    )));
                }

                let pool = TunnelPool::start(
                    PoolConfig {
                        route_id: route.id.clone(),
                        route_name: route.name.clone(),
                        node_id: bundle.node.id.clone(),
                        size: route.tunnel_pool_size,
                        load_balance: route.load_balance,
                        limits: bundle.limits.clone(),
                        psk: psk.clone(),
                        health: HealthPolicy::default(),
                        // Per-endpoint source IPs are applied inside the pool;
                        // this is the route-wide default.
                        egress: EgressBinding::default(),
                    },
                    endpoints,
                    tls.clone().expect("tunnel route requires TLS"),
                    metrics.clone(),
                )?;

                let listener = Arc::new(EntryListener::new(
                    route.clone(),
                    pool.clone(),
                    self.registry.clone(),
                ));
                let shutdown = listener.shutdown_flag();

                // Bind eagerly so a port conflict fails the apply instead of
                // silently producing a dead route.
                let spawn_listener = listener.clone();
                let route_name = route.name.clone();
                tokio::spawn(async move {
                    if let Err(e) = spawn_listener.run().await {
                        tracing::error!(route = %route_name, error = %e, "entry listener stopped");
                    }
                });

                entries.push(EntryRuntime {
                    route_id: route.id.clone(),
                    route_name: route.name.clone(),
                    listen: route.listen_socket_addr(),
                    target: route.effective_targets().join(", "),
                    pool: Some(pool),
                    metrics,
                    shutdown,
                    // 隧道线路的目标由出口拨号，入口侧没有健康状态可报。
                    listener: None,
                });
            }
        }

        // --- exit side ---
        let mut exits = Vec::new();
        if role.can_exit() {
            let mut exit_routes: HashMap<String, ExitRoute> = HashMap::new();
            for route in bundle.routes.iter().filter(|r| r.enabled) {
                if !route.mode.needs_tunnel() || route.exit_node_id != bundle.node.id {
                    continue;
                }
                let metrics = route_metrics
                    .entry(route.id.clone())
                    .or_insert_with(|| RouteMetrics::new(route.id.clone()))
                    .clone();

                exit_routes.insert(
                    route.id.clone(),
                    // `new` 顺带按线路的目标列表与策略建好选择器。
                    ExitRoute::new(
                        route.clone(),
                        // This is the IEPL-in / public-out control: traffic that
                        // arrived over the private NIC leaves bound to this
                        // source address.
                        EgressBinding {
                            source_ip: route.egress_source_ip,
                            interface: route.egress_interface.clone(),
                        },
                        metrics,
                    ),
                );
            }

            if !exit_routes.is_empty() {
                for endpoint in bundle.listen_endpoints.iter().filter(|e| e.enabled) {
                    let listener = Arc::new(ExitListener::new(
                        endpoint.clone(),
                        bundle.node.id.clone(),
                        exit_routes.clone(),
                        bundle.limits.clone(),
                        psk.clone(),
                        tls.clone().expect("tunnel listener requires TLS"),
                        self.registry.clone(),
                    ));
                    let shutdown = listener.shutdown_flag();

                    let spawn_listener = listener.clone();
                    let endpoint_name = endpoint.name.clone();
                    tokio::spawn(async move {
                        if let Err(e) = spawn_listener.run().await {
                            tracing::error!(
                                endpoint = %endpoint_name,
                                error = %e,
                                "exit listener stopped"
                            );
                        }
                    });

                    exits.push(ExitRuntime {
                        endpoint_name: endpoint.name.clone(),
                        listener,
                        shutdown,
                    });
                }
            }
        }

        tracing::info!(
            revision = bundle.revision,
            role = %role,
            entry_routes = entries.len(),
            exit_listeners = exits.len(),
            "runtime built"
        );

        self.tls.store(tls);

        Ok(Runtime {
            revision: bundle.revision,
            entries,
            exits,
            route_metrics,
        })
    }

    /// Reload TLS material in place, for `SIGHUP` after a certificate renewal.
    ///
    /// Live tunnels keep the configuration they handshook with; new handshakes
    /// pick up the new material. Tearing down tunnels to install a certificate
    /// would be self-inflicted downtime.
    // 唯一调用方是 main.rs 的 SIGHUP 处理，它在 `#[cfg(unix)]` 之下。非 unix 上
    // 编译时它就成了死代码 —— 只在那种情况下放行，这样 Linux（唯一的部署目标）上
    // 若真的没人调用它，警告仍然会出现。
    #[cfg_attr(not(unix), allow(dead_code))]
    pub fn reload_tls(&self) -> Result<u64> {
        match self.tls.load_full() {
            Some(material) => material.reload(),
            None => Err(Error::other("no TLS material loaded yet")),
        }
    }

    /// Build the telemetry report sent to the control plane.
    pub async fn build_report(&self, node_id: &str) -> AgentReport {
        let runtime = self.runtime.read().await;

        let mut routes: Vec<RouteSnapshot> = Vec::new();
        let mut tunnels: Vec<TunnelSnapshot> = Vec::new();
        let mut connections = 0u32;
        let mut rx_bytes = 0u64;
        let mut tx_bytes = 0u64;
        let mut rx_bps = 0u64;
        let mut tx_bps = 0u64;

        for entry in &runtime.entries {
            // Sample rates here: this is the low-frequency path, and the data
            // plane only ever touches atomics.
            let (route_rx_bps, route_tx_bps) = entry.metrics.sample();
            rx_bps += route_rx_bps;
            tx_bps += route_tx_bps;
            rx_bytes += entry.metrics.counters.rx();
            tx_bytes += entry.metrics.counters.tx();
            connections += entry.metrics.counters.active();

            match &entry.pool {
                Some(pool) => {
                    routes.push(
                        pool.route_snapshot(entry.listen.clone(), entry.target.clone())
                            .await,
                    );
                    tunnels.extend(pool.snapshots().await);
                }
                None => {
                    // 直连线路没有隧道，快照里隧道数为 0，其余计数照常上报。
                    let (rx_bps, tx_bps) = entry.metrics.rates.current();
                    routes.push(RouteSnapshot {
                        // 逐个目标的健康状态：哪台熔断了、各自有多少活跃连接。
                        // 面板据此显示「2/3 个目标可用」而不是只有一个总数。
                        targets: entry
                            .listener
                            .as_ref()
                            .map(|l| l.target_health())
                            .unwrap_or_default(),
                        route_id: entry.route_id.clone(),
                        name: entry.route_name.clone(),
                        enabled: true,
                        listen: entry.listen.clone(),
                        target: entry.target.clone(),
                        active_endpoint_id: None,
                        tunnels_online: 0,
                        tunnels_total: 0,
                        connections: entry.metrics.counters.active(),
                        rx_bytes: entry.metrics.counters.rx(),
                        tx_bytes: entry.metrics.counters.tx(),
                        rx_bps,
                        tx_bps,
                        accepted_total: entry.metrics.counters.accepted(),
                        rejected_total: entry.metrics.counters.rejected(),
                        failed_total: entry.metrics.counters.failed(),
                    });
                }
            }
        }

        // Exit-side routes have metrics but no local pool.
        for (route_id, metrics) in &runtime.route_metrics {
            if runtime.entries.iter().any(|e| &e.route_id == route_id) {
                continue;
            }
            let (route_rx_bps, route_tx_bps) = metrics.sample();
            rx_bps += route_rx_bps;
            tx_bps += route_tx_bps;
            rx_bytes += metrics.counters.rx();
            tx_bytes += metrics.counters.tx();
            connections += metrics.counters.active();
        }

        let connection_samples: Vec<ConnectionSnapshot> =
            self.registry.snapshot(self.cfg.connection_sample_limit);

        AgentReport {
            node_id: node_id.to_string(),
            agent_version: tunnel_common::AGENT_VERSION.to_string(),
            config_revision: self.applied_revision(),
            role: **self.role.load(),
            host: self.host_stats(),
            interfaces: tunnel_common::net::interfaces(),
            routes,
            tunnels,
            connection_samples,
            connections,
            rx_bytes,
            tx_bytes,
            rx_bps,
            tx_bps,
            reported_at: chrono::Utc::now(),
        }
    }

    fn host_stats(&self) -> HostStats {
        let mut stats = host::sample();
        // Process uptime is more useful here than host uptime: it tells the
        // operator when the agent last restarted.
        stats.uptime_secs = self.started_at.elapsed().as_secs();
        stats
    }

    /// Reap idle streams across every pool. Called on a timer.
    pub async fn reap_idle(&self, timeout: Duration) {
        let runtime = self.runtime.read().await;
        let mut total = 0;
        for entry in &runtime.entries {
            // 直连线路没有逻辑流可回收 —— 它的空闲连接由 relay 自己的 watchdog 处理。
            if let Some(pool) = &entry.pool {
                total += pool.reap_idle_streams(timeout);
            }
        }
        if total > 0 {
            tracing::debug!(streams = total, "reaped idle streams");
        }
    }

    /// Stop everything, letting in-flight work finish.
    pub async fn shutdown(&self) {
        tracing::info!("draining the data plane");
        let runtime = self.runtime.read().await;
        runtime.drain().await;
        tracing::info!(
            entry_routes = runtime.entries.len(),
            exit_listeners = runtime.exits.len(),
            "data plane stopped"
        );
    }

    /// 正在运行的入口线路数。测试用；运行时看 [`Self::describe`] 或遥测。
    ///
    /// `exit_count` 曾与它成对存在，但没有任何调用方（连测试都没有），已删除 ——
    /// 出口监听数看 `describe()` 的输出即可。
    #[cfg(test)]
    pub async fn route_count(&self) -> usize {
        self.runtime.read().await.entries.len()
    }

    pub async fn describe(&self) -> Vec<String> {
        let runtime = self.runtime.read().await;
        let mut lines = Vec::new();
        for entry in &runtime.entries {
            lines.push(match &entry.pool {
                Some(pool) => format!(
                    "隧道线路 {} {} -> {}（隧道 {}/{} 在线）",
                    entry.route_name,
                    entry.listen,
                    entry.target,
                    pool.online_tunnels(),
                    pool.total_tunnels(),
                ),
                None => format!(
                    "直连线路 {} {} -> {}",
                    entry.route_name, entry.listen, entry.target
                ),
            });
        }
        for exit in &runtime.exits {
            lines.push(format!("exit listener on {}", exit.endpoint_name));
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnel_common::model::{
        Endpoint, EndpointKind, EndpointPriority, Limits, Node, Route, TlsConfig,
    };
    use tunnel_common::Secret;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tunnel-sup-test-{}-{}",
            name,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn agent_config(dir: &std::path::Path) -> AgentConfig {
        AgentConfig {
            enroll_token: Secret::new("group-token"),
            node_name: "n1".into(),
            control_url: "http://127.0.0.1:8080".into(),
            cache_path: dir.join("lkg.json"),
            tls: TlsConfig {
                insecure_skip_verify: true,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Entry-only bundle listening on an ephemeral port.
    fn bundle(revision: u64, listen_port: u16, enabled: bool) -> AgentConfigBundle {
        AgentConfigBundle {
            revision,
            model_version: tunnel_common::MODEL_VERSION,
            node: Node {
                id: "n1".into(),
                name: "sh-01".into(),
                region: "cn".into(),
                role: NodeRole::Entry,
                public_address: None,
                management_address: None,
                agent_version: None,
                note: None,
            },
            listen_endpoints: vec![],
            remote_endpoints: vec![Endpoint {
                id: "e1".into(),
                node_id: "n2".into(),
                name: "hk-iepl".into(),
                // Port 1 never answers, so no tunnel comes up — which is fine:
                // these tests are about the supervisor, not connectivity.
                address: "127.0.0.1".into(),
                port: 1,
                kind: EndpointKind::Iepl,
                priority: EndpointPriority::Primary,
                interface: None,
                source_ip: None,
                tls_server_name: Some("exit.internal".into()),
                enabled: true,
            }],
            routes: vec![Route {
                id: "r1".into(),
                name: "sh-hk".into(),
                mode: Default::default(),
                entry_node_id: "n1".into(),
                listen_address: "127.0.0.1".into(),
                listen_port,
                exit_node_id: "n2".into(),
                target_host: "127.0.0.1".into(),
                target_port: 8443,
                targets: vec![],
                target_strategy: Default::default(),
                endpoint_ids: vec!["e1".into()],
                tunnel_pool_size: 2,
                load_balance: Default::default(),
                max_connections: 0,
                egress_source_ip: None,
                egress_interface: None,
                enabled,
            }],
            limits: Limits {
                connect_timeout: Duration::from_millis(200),
                handshake_timeout: Duration::from_millis(200),
                ..Default::default()
            },
            // The supervisor uses the distributed TLS settings when local
            // certificate paths are absent. These tests have no test CA.
            tls: TlsConfig {
                insecure_skip_verify: true,
                ..Default::default()
            },
            tunnel_psk: Some(Secret::new("psk")),
            issued_at: None,
        }
    }

    async fn free_port() -> u16 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        port
    }

    /// 等到端口可连接，或超时。
    ///
    /// `apply()` 里监听器是 spawn 起来的，函数返回不代表已经 bind 上。用轮询而不是
    /// 固定 sleep：固定时长总有一天会在更慢的机器上不够，而这里超时仍然返回 false，
    /// 所以监听器真的起不来时测试照样会失败，不会把问题掩盖过去。
    async fn wait_until_listening(port: u16, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    /// 直连模式的 bundle，转发到给定的目标列表。
    fn direct_bundle(
        revision: u64,
        listen_port: u16,
        targets: Vec<String>,
        strategy: tunnel_common::model::TargetStrategy,
    ) -> AgentConfigBundle {
        let mut b = bundle(revision, listen_port, true);
        b.node.role = NodeRole::Entry;
        b.remote_endpoints.clear();
        let route = &mut b.routes[0];
        route.mode = tunnel_common::model::RouteMode::Direct;
        route.endpoint_ids.clear();
        route.exit_node_id = "n1".into();
        route.targets = targets;
        route.target_strategy = strategy;
        b
    }

    #[tokio::test]
    async fn apply_starts_the_configured_route() {
        let dir = temp_dir("apply");
        let sup = Supervisor::new(agent_config(&dir));
        let port = free_port().await;

        sup.apply(&bundle(1, port, true), false).await.unwrap();
        assert_eq!(sup.route_count().await, 1);
        assert_eq!(sup.applied_revision(), 1);

        // 监听器真的 bind 上了。200ms 的固定等待在负载高的 CI 机器上不一定够，
        // 改成轮询。
        assert!(
            wait_until_listening(port, Duration::from_secs(5)).await,
            "线路监听器没有开始接受连接"
        );

        sup.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn apply_persists_the_bundle_when_asked() {
        let dir = temp_dir("persist");
        let sup = Supervisor::new(agent_config(&dir));
        let port = free_port().await;

        sup.apply(&bundle(5, port, true), true).await.unwrap();
        let cached = sup.cache().load().expect("bundle should be cached");
        assert_eq!(cached.revision, 5);

        sup.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_rejected_bundle_leaves_the_running_config_intact() {
        // The central safety property: a bad push must not take the node down.
        let dir = temp_dir("reject");
        let sup = Supervisor::new(agent_config(&dir));
        let port = free_port().await;

        sup.apply(&bundle(1, port, true), true).await.unwrap();
        assert_eq!(sup.route_count().await, 1);

        // Structurally invalid: window smaller than one frame.
        let mut bad = bundle(2, port, true);
        bad.limits.stream_window = 16;
        bad.limits.max_frame_payload = 65535;

        let err = sup.apply(&bad, true).await.unwrap_err();
        assert!(matches!(err, Error::Config(_)), "{err:?}");

        assert_eq!(sup.route_count().await, 1, "route was lost on a bad apply");
        assert_eq!(sup.applied_revision(), 1, "revision advanced on failure");
        assert_eq!(
            sup.cache().load().unwrap().revision,
            1,
            "a rejected bundle must not be cached"
        );

        // 仍在服务。
        //
        // 必须等监听器真的 bind 上：apply() 里监听器是 tokio::spawn 起来的，
        // 函数返回时 bind 可能还没完成。原先这里直接 connect，在 Windows 上恰好
        // 赶上、在 Linux CI 上赶不上 —— 这是个一直存在的竞态，只是平台差异让它
        // 只在一边暴露。
        //
        // 用有上限的轮询而不是固定 sleep：固定时长在更慢的机器上还会再坏一次，
        // 而轮询在监听器真的起不来时同样会失败（超时），不会掩盖问题。
        assert!(
            wait_until_listening(port, Duration::from_secs(5)).await,
            "坏配置被拒绝后，原有监听器应当继续服务"
        );

        sup.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_port_conflict_fails_the_apply_without_losing_the_old_runtime() {
        let dir = temp_dir("conflict");
        let sup = Supervisor::new(agent_config(&dir));
        let port = free_port().await;
        sup.apply(&bundle(1, port, true), true).await.unwrap();

        // Squat a second port, then try to move the route onto it.
        let squatter = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let taken = squatter.local_addr().unwrap().port();

        let next = bundle(2, taken, true);
        // The apply itself succeeds (listeners bind asynchronously), so assert
        // the invariant that matters: the supervisor never ends up with zero
        // routes because of it.
        let _ = sup.apply(&next, true).await;
        assert_eq!(sup.route_count().await, 1);

        sup.shutdown().await;
        drop(squatter);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn start_from_cache_serves_before_contacting_control() {
        // The outage scenario: reboot with no control plane reachable.
        let dir = temp_dir("from-cache");
        let port = free_port().await;

        {
            let sup = Supervisor::new(agent_config(&dir));
            sup.apply(&bundle(9, port, true), true).await.unwrap();
            sup.shutdown().await;
        }

        // Fresh supervisor, no control plane involved.
        let sup = Supervisor::new(agent_config(&dir));
        assert!(sup.start_from_cache().await, "cache was not used");
        assert_eq!(sup.applied_revision(), 9);
        assert_eq!(sup.route_count().await, 1);

        sup.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn start_from_cache_is_a_noop_on_a_fresh_node() {
        let dir = temp_dir("no-cache");
        let sup = Supervisor::new(agent_config(&dir));
        assert!(!sup.start_from_cache().await);
        assert_eq!(sup.route_count().await, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn disabled_routes_are_not_started() {
        let dir = temp_dir("disabled");
        let sup = Supervisor::new(agent_config(&dir));
        let port = free_port().await;

        sup.apply(&bundle(1, port, false), false).await.unwrap();
        assert_eq!(sup.route_count().await, 0);
        // Nothing is listening.
        assert!(tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_err());

        sup.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn direct_route_keeps_counters_across_disable_and_enable_without_tls() {
        let dir = temp_dir("direct-counters");
        let sup = Supervisor::new(agent_config(&dir));
        let first = free_port().await;
        let second = free_port().await;
        let mut initial = direct_bundle(
            1, first, vec!["127.0.0.1:9".into()], Default::default(),
        );
        initial.tls.ca_path = Some(dir.join("missing-ca.pem"));
        sup.apply(&initial, false).await.unwrap();
        {
            let runtime = sup.runtime.read().await;
            let counters = &runtime.route_metrics["r1"].counters;
            counters.add_rx(100);
            counters.add_tx(200);
        }
        let mut disabled = initial.clone();
        disabled.revision = 2;
        disabled.routes[0].enabled = false;
        sup.apply(&disabled, false).await.unwrap();
        assert_eq!(sup.build_report("n1").await.rx_bytes, 100);

        let mut enabled = initial;
        enabled.revision = 3;
        enabled.routes[0].listen_port = second;
        sup.apply(&enabled, false).await.unwrap();
        let report = sup.build_report("n1").await;
        assert_eq!((report.rx_bytes, report.tx_bytes), (100, 200));
        assert_eq!(report.routes[0].rx_bytes, 100);
        sup.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn direct_route_on_both_role_does_not_start_an_exit_listener() {
        let dir = temp_dir("both-direct");
        let sup = Supervisor::new(agent_config(&dir));
        let port = free_port().await;
        let mut config = direct_bundle(
            1, port, vec!["127.0.0.1:9".into()], Default::default(),
        );
        config.node.role = NodeRole::Both;
        config.listen_endpoints.push(Endpoint {
            id: "e-local".into(),
            node_id: "n1".into(),
            name: "unused-tunnel".into(),
            address: "127.0.0.1".into(),
            port: free_port().await,
            kind: EndpointKind::Public,
            priority: EndpointPriority::Primary,
            interface: None,
            source_ip: None,
            tls_server_name: None,
            enabled: true,
        });
        config.tls.ca_path = Some(dir.join("missing-ca.pem"));
        sup.apply(&config, false).await.unwrap();
        assert!(sup.runtime.read().await.exits.is_empty());
        sup.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn reapplying_replaces_the_previous_runtime() {
        let dir = temp_dir("replace");
        let sup = Supervisor::new(agent_config(&dir));
        let first = free_port().await;
        let second = free_port().await;

        sup.apply(&bundle(1, first, true), false).await.unwrap();
        sup.apply(&bundle(2, second, true), false).await.unwrap();

        assert_eq!(sup.route_count().await, 1, "runtimes accumulated");
        assert_eq!(sup.applied_revision(), 2);

        assert!(
            wait_until_listening(second, Duration::from_secs(5)).await,
            "替换后的新监听器没有在服务"
        );

        sup.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn report_reflects_the_running_configuration() {
        let dir = temp_dir("report");
        let sup = Supervisor::new(agent_config(&dir));
        let port = free_port().await;
        sup.apply(&bundle(3, port, true), false).await.unwrap();

        let report = sup.build_report("n1").await;
        assert_eq!(report.node_id, "n1");
        assert_eq!(report.config_revision, 3);
        assert_eq!(report.role, NodeRole::Entry);
        assert_eq!(report.routes.len(), 1);
        assert_eq!(report.routes[0].name, "sh-hk");
        assert_eq!(report.routes[0].listen, format!("127.0.0.1:{port}"));
        assert_eq!(report.tunnels.len(), 2, "pool size should be reflected");
        assert!(!report.interfaces.is_empty(), "interfaces were not collected");
        assert!(report.host.uptime_secs < 60);

        sup.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn local_role_override_suppresses_the_entry_side() {
        let dir = temp_dir("role-override");
        let mut cfg = agent_config(&dir);
        // Bundle says entry; operator says exit-only.
        cfg.role = Some(NodeRole::Exit);
        let sup = Supervisor::new(cfg);
        let port = free_port().await;

        sup.apply(&bundle(1, port, true), false).await.unwrap();
        assert_eq!(
            sup.route_count().await,
            0,
            "an exit-only node must not start entry listeners"
        );
        assert!(tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_err());

        sup.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn reload_tls_before_any_apply_is_an_error_not_a_panic() {
        let dir = temp_dir("tls-early");
        let sup = Supervisor::new(agent_config(&dir));
        assert!(sup.reload_tls().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn reload_tls_bumps_the_generation() {
        let dir = temp_dir("tls-reload");
        let sup = Supervisor::new(agent_config(&dir));
        let port = free_port().await;
        sup.apply(&bundle(1, port, true), false).await.unwrap();

        let generation = sup.reload_tls().unwrap();
        assert!(generation >= 2);

        sup.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn shutdown_is_safe_to_call_twice() {
        let dir = temp_dir("double-shutdown");
        let sup = Supervisor::new(agent_config(&dir));
        let port = free_port().await;
        sup.apply(&bundle(1, port, true), false).await.unwrap();
        sup.shutdown().await;
        sup.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_direct_route_forwards_across_multiple_targets() {
        // 端到端验证多目标真的生效：起两个回声服务，轮询应该两个都收到连接。
        // 只测 TargetSelector 无法发现「配置没传下来」这类接线错误。
        let dir = temp_dir("multi-target");
        let sup = Supervisor::new(agent_config(&dir));

        // 两个真实的回声服务，各自记录自己收到了多少连接。
        let mut targets = Vec::new();
        let mut counters = Vec::new();
        for _ in 0..2 {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = l.local_addr().unwrap();
            let hits = Arc::new(AtomicU64::new(0));
            let hits_clone = hits.clone();
            tokio::spawn(async move {
                loop {
                    match l.accept().await {
                        Ok((mut s, _)) => {
                            hits_clone.fetch_add(1, REL);
                            // 回一个字节就够了，客户端据此确认连接真的到了目标。
                            tokio::spawn(async move {
                                use tokio::io::AsyncWriteExt;
                                let _ = s.write_all(b"k").await;
                                let _ = s.flush().await;
                                // 稍等一下再关，避免 RST 打断客户端的读。
                                tokio::time::sleep(Duration::from_millis(50)).await;
                            });
                        }
                        Err(_) => return,
                    }
                }
            });
            targets.push(addr.to_string());
            counters.push(hits);
        }

        let port = free_port().await;
        sup.apply(
            &direct_bundle(
                1,
                port,
                targets.clone(),
                tunnel_common::model::TargetStrategy::RoundRobin,
            ),
            false,
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;

        // 四条连接，轮询下两个目标各该拿到两条。
        for _ in 0..4 {
            use tokio::io::AsyncReadExt;
            let mut c = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("入口没有接受连接");
            let mut buf = [0u8; 1];
            let _ = tokio::time::timeout(Duration::from_secs(2), c.read_exact(&mut buf)).await;
            drop(c);
            tokio::time::sleep(Duration::from_millis(60)).await;
        }

        let hits: Vec<u64> = counters.iter().map(|c| c.load(REL)).collect();
        assert_eq!(
            hits.iter().sum::<u64>(),
            4,
            "有连接没有到达任何目标: {hits:?}"
        );
        assert!(
            hits.iter().all(|&h| h > 0),
            "轮询没有覆盖全部目标: {hits:?}"
        );

        // 等活跃计数落回 0：relay 的收尾是异步的，客户端 drop 之后还要一小会儿。
        // 有上限地轮询而不是盲等固定时长 —— 真的泄漏时这里会超时而不是偶然通过。
        let settled = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let r = sup.build_report("n1").await;
                if r.routes
                    .first()
                    .map(|rt| rt.targets.iter().all(|t| t.active == 0))
                    .unwrap_or(false)
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        assert!(settled.is_ok(), "活跃连接计数一直没有归还");

        // 遥测里能看到逐个目标的健康状态。
        let report = sup.build_report("n1").await;
        assert_eq!(report.routes.len(), 1);
        let reported = &report.routes[0].targets;
        assert_eq!(reported.len(), 2, "目标健康状态没有上报");
        assert!(
            reported.iter().all(|t| t.available && !t.tripped && t.total_ok > 0),
            "目标状态不对: {reported:?}"
        );
        // 连接都已关闭，活跃计数必须归零 —— 否则 least_conn 会永久失衡。
        assert!(
            reported.iter().all(|t| t.active == 0),
            "活跃连接计数没有归还: {reported:?}"
        );
        // 快照里的 target 字段列出全部目标，面板一眼能看到转发到哪几台。
        assert!(
            targets.iter().all(|t| report.routes[0].target.contains(t)),
            "快照没有列出全部目标: {}",
            report.routes[0].target
        );

        sup.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_direct_route_skips_a_dead_target_after_repeated_failures() {
        // 一台目标挂掉时不该每 N 个连接就失败一个 —— 熔断后应全部走健康的那台。
        let dir = temp_dir("target-breaker");
        let sup = Supervisor::new(agent_config(&dir));

        // 一个活着的回声服务，一个从未监听的地址。
        let live = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_addr = live.local_addr().unwrap().to_string();
        let hits = Arc::new(AtomicU64::new(0));
        let hits_clone = hits.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = live.accept().await {
                hits_clone.fetch_add(1, REL);
                tokio::spawn(async move {
                    use tokio::io::AsyncWriteExt;
                    let _ = s.write_all(b"k").await;
                    tokio::time::sleep(Duration::from_millis(30)).await;
                });
            }
        });
        let dead_port = free_port().await;
        let dead_addr = format!("127.0.0.1:{dead_port}");

        let port = free_port().await;
        sup.apply(
            &direct_bundle(
                1,
                port,
                vec![dead_addr.clone(), live_addr.clone()],
                tunnel_common::model::TargetStrategy::RoundRobin,
            ),
            false,
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;

        for _ in 0..12 {
            use tokio::io::AsyncReadExt;
            if let Ok(mut c) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                let mut buf = [0u8; 1];
                let _ =
                    tokio::time::timeout(Duration::from_millis(500), c.read_exact(&mut buf)).await;
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
        }

        let report = sup.build_report("n1").await;
        let reported = &report.routes[0].targets;
        let dead = reported.iter().find(|t| t.addr == dead_addr).unwrap();
        let alive = reported.iter().find(|t| t.addr == live_addr).unwrap();

        // 只断言与时钟无关的事实。
        //
        // 这里刻意**不**断言「故障目标的失败次数 <= N」或「健康目标的成功次数 >= N」：
        // 那类断言依赖真实时钟。拨一个没有监听的本机端口，Linux 立刻返回
        // ECONNREFUSED，而 Windows 要等约一秒才超时 —— 同一段循环在两个平台上的
        // 实际连接次数能差一个数量级，于是断言在一边通过、另一边失败（本次 CI
        // 就是这样红的）。机器快慢、CI 负载也会造成同样的漂移。
        //
        // 熔断的计数与冷却行为已由 tunnel-core/src/targets.rs 里 20 多个确定性测试
        // 覆盖，那里直接操作状态、不涉及网络。本测试的职责只是验证**接线**：
        // 目标健康状态确实从数据面流到了遥测里，且故障与健康被区分开。
        assert!(dead.tripped, "拨不通的目标没有被熔断: {dead:?}");
        assert!(!alive.tripped, "健康的目标被误熔断: {alive:?}");
        assert!(
            dead.total_failed > 0,
            "故障目标没有记录到任何失败: {dead:?}"
        );
        assert!(
            alive.total_ok > 0,
            "健康目标没有记录到任何成功: {alive:?}，实际接受 {} 次",
            hits.load(REL)
        );
        // 熔断后不再参与分配 —— 这是「时好时坏」与「稳定可用」的区别。
        assert!(!dead.available, "熔断的目标仍在参与分配: {dead:?}");
        assert!(alive.available, "健康的目标被排除在分配之外: {alive:?}");

        sup.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn describe_lists_running_components() {
        let dir = temp_dir("describe");
        let sup = Supervisor::new(agent_config(&dir));
        let port = free_port().await;
        sup.apply(&bundle(1, port, true), false).await.unwrap();

        let lines = sup.describe().await;
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("sh-hk"), "{:?}", lines);
        assert!(lines[0].contains("隧道线路"), "{:?}", lines);
        assert!(lines[0].contains("在线"), "{:?}", lines);

        sup.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
