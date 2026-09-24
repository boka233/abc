//! Entry role: accept user TCP connections, carry them over the tunnel.
//!
//! ```text
//!   user TCP ──▶ EntryListener ──▶ TunnelPool.open_stream() ──▶ relay
//! ```
//!
//! The listener's only jobs are to accept, enforce the connection ceiling, and
//! hand off. Everything slow — the stream open, the relay — happens in a spawned
//! task so the accept loop never blocks. An accept loop that awaits a tunnel
//! handshake is an accept loop that drops connections under load.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tunnel_common::model::Route;
use tunnel_common::net::TcpTuning;
use tunnel_common::{Error, Result};

use crate::metrics::ConnectionRegistry;
use crate::pool::TunnelPool;
use crate::relay;

const REL: Ordering = Ordering::Relaxed;

/// Listener backlog. Larger than the default 128 because a reconnect storm from
/// a downstream service arrives all at once; the kernel caps this at
/// `net.core.somaxconn` regardless (see `docs/linux-tuning.md`).
const LISTEN_BACKLOG: u32 = 1024;

/// 直连模式下没有隧道池，改用这组参数直接拨目标。
struct DirectConfig {
    limits: tunnel_common::model::Limits,
    egress: tunnel_common::net::EgressBinding,
    metrics: Arc<crate::metrics::RouteMetrics>,
    /// 多目标选择与熔断。单目标时也走它，省掉一条分支。
    targets: Arc<crate::targets::TargetSelector>,
}

pub struct EntryListener {
    route: Route,
    /// 隧道模式下的连接池。直连模式为 `None`。
    pool: Option<Arc<TunnelPool>>,
    /// 直连模式下的拨号参数。隧道模式为 `None`。
    direct: Option<DirectConfig>,
    registry: Arc<ConnectionRegistry>,
    shutdown: Arc<AtomicBool>,
}

impl EntryListener {
    /// 隧道模式：accept 后在池中开一条逻辑流。
    pub fn new(
        route: Route,
        pool: Arc<TunnelPool>,
        registry: Arc<ConnectionRegistry>,
    ) -> Self {
        Self {
            route,
            pool: Some(pool),
            direct: None,
            registry,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// 直连模式：accept 后直接 dial 目标，不经过隧道。
    ///
    /// 这是单机转发的路径 —— 一台三网优化机把端口转到落地机，或 IEPL 商家只交付
    /// 出口 root 的情形（入口侧装不了 agent，因此不可能建隧道）。
    ///
    /// 复用同一个 [`relay::relay`]：双向拷贝、半关闭传播、空闲回收的语义两种模式
    /// 完全一致，差别只在「另一端」是逻辑流还是真实 socket。
    pub fn new_direct(
        route: Route,
        limits: tunnel_common::model::Limits,
        registry: Arc<ConnectionRegistry>,
        metrics: Arc<crate::metrics::RouteMetrics>,
    ) -> Self {
        let egress = tunnel_common::net::EgressBinding {
            source_ip: route.egress_source_ip,
            interface: route.egress_interface.clone(),
        };
        // `effective_targets` 保证非空 —— 单目标时回落到 target_host:target_port。
        let targets = Arc::new(crate::targets::TargetSelector::from_route(&route));
        Self {
            route,
            pool: None,
            direct: Some(DirectConfig {
                limits,
                egress,
                metrics,
                targets,
            }),
            registry,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// 直连模式下各目标的健康状态。隧道模式返回空列表。
    pub fn target_status(&self) -> Vec<crate::targets::TargetStatus> {
        self.direct
            .as_ref()
            .map(|d| d.targets.status())
            .unwrap_or_default()
    }

    /// 上报给控制面的目标健康状态。
    pub fn target_health(&self) -> Vec<tunnel_common::model::TargetHealth> {
        self.direct
            .as_ref()
            .map(|d| d.targets.health())
            .unwrap_or_default()
    }

    /// 本线路的计数器，两种模式共用同一套指标类型。
    fn metrics(&self) -> Arc<crate::metrics::RouteMetrics> {
        match (&self.pool, &self.direct) {
            (Some(pool), _) => pool.metrics().clone(),
            (_, Some(direct)) => direct.metrics.clone(),
            // 构造函数保证二者必有其一。
            _ => unreachable!("EntryListener 必须处于隧道或直连模式之一"),
        }
    }

    fn limits(&self) -> tunnel_common::model::Limits {
        match (&self.pool, &self.direct) {
            (Some(pool), _) => pool.config().limits.clone(),
            (_, Some(direct)) => direct.limits.clone(),
            _ => unreachable!("EntryListener 必须处于隧道或直连模式之一"),
        }
    }

    pub fn shutdown_flag(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }

    /// Bind and serve until shutdown.
    ///
    /// Binding happens here rather than in `new` so a port conflict is reported
    /// when the route starts, with the route name attached.
    pub async fn run(self: Arc<Self>) -> Result<()> {
        let bind = self.route.listen_socket_addr();
        let tuning = TcpTuning::default();
        let listener = tunnel_common::net::listen(&bind, LISTEN_BACKLOG, &tuning)
            .await
            .map_err(|e| {
                Error::config(format!("route `{}` cannot bind {bind}: {e}", self.route.name))
            })?;

        tracing::info!(
            route = %self.route.name,
            mode = %self.route.mode,
            listen = %bind,
            target = %self.route.target_socket_addr(),
            pool_size = self.pool.as_ref().map(|p| p.config().size).unwrap_or(0),
            "入口监听已启动"
        );

        let limits = self.limits();
        let max_conns = if self.route.max_connections > 0 {
            self.route.max_connections
        } else {
            limits.max_connections
        };

        loop {
            if self.shutdown.load(REL) {
                tracing::info!(route = %self.route.name, "entry listener stopping");
                return Ok(());
            }

            // Bounded wait so the shutdown flag is observed promptly even with
            // no incoming connections.
            let accepted = match tokio::time::timeout(
                Duration::from_millis(500),
                listener.accept(),
            )
            .await
            {
                Ok(Ok(pair)) => pair,
                Ok(Err(e)) => {
                    // EMFILE/ENFILE are the ones that matter here: the process
                    // is out of file descriptors. Backing off briefly is the
                    // only sane response — spinning makes it worse.
                    if is_fd_exhaustion(&e) {
                        tracing::error!(
                            route = %self.route.name,
                            error = %e,
                            "out of file descriptors; raise LimitNOFILE (see docs/linux-tuning.md)"
                        );
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    } else {
                        tracing::warn!(route = %self.route.name, error = %e, "accept failed");
                    }
                    continue;
                }
                Err(_) => continue,
            };

            let (socket, peer) = accepted;
            let metrics = self.metrics();

            if metrics.counters.active() >= max_conns {
                metrics.counters.on_reject();
                tracing::warn!(
                    route = %self.route.name,
                    limit = max_conns,
                    "connection limit reached; refusing"
                );
                // Drop immediately: the client sees a reset, which is better
                // than a hang while we hold a descriptor we cannot serve.
                drop(socket);
                continue;
            }

            if let Err(e) = tuning.apply_to_stream(&socket) {
                tracing::debug!(error = %e, "could not apply socket tuning");
            }

            metrics.counters.on_accept();

            let this = self.clone();
            tokio::spawn(async move {
                let result = this.serve_connection(socket, peer).await;
                this.metrics().counters.on_close();
                if let Err(e) = result {
                    // One connection failing is routine. It must never
                    // propagate further than this log line.
                    tracing::debug!(
                        route = %this.route.name,
                        error = %e,
                        "connection ended with an error"
                    );
                }
            });
        }
    }

    async fn serve_connection(
        &self,
        socket: tokio::net::TcpStream,
        peer: std::net::SocketAddr,
    ) -> Result<()> {
        match (&self.pool, &self.direct) {
            (Some(pool), _) => self.serve_via_tunnel(socket, peer, pool.clone()).await,
            (_, Some(direct)) => self.serve_direct(socket, peer, direct).await,
            _ => unreachable!("EntryListener 必须处于隧道或直连模式之一"),
        }
    }

    /// 隧道模式：在池中开一条逻辑流并与本地 socket 对拷。
    async fn serve_via_tunnel(
        &self,
        socket: tokio::net::TcpStream,
        peer: std::net::SocketAddr,
        pool: Arc<TunnelPool>,
    ) -> Result<()> {
        let limits = pool.config().limits.clone();
        let metrics = pool.metrics().clone();

        // 开一条逻辑流。失败意味着没有任何隧道能承载它。
        let stream = match pool.open_stream(Some(peer.to_string())).await {
            Ok(s) => s,
            Err(e) => {
                metrics.counters.on_fail();
                return Err(e);
            }
        };

        let conn = self.registry.register(
            &self.route.id,
            &self.route.name,
            0,
            stream.stream_id,
            peer.to_string(),
            self.route.target_socket_addr(),
        );
        let conn_id = conn.id;

        let result = relay::relay(
            socket,
            stream,
            limits.relay_buffer,
            limits.stream_idle_timeout,
            metrics.counters.clone(),
            Some(conn),
        )
        .await;

        self.registry.unregister(conn_id);
        result.map(|_| ())
    }

    /// 直连模式：直接 dial 目标，两个真实 socket 对拷。
    ///
    /// 不经过 mux 与 TLS，所以没有帧开销、没有流控配额、也没有队头阻塞的问题 ——
    /// 这条路径本身就只有一跳。
    async fn serve_direct(
        &self,
        socket: tokio::net::TcpStream,
        peer: std::net::SocketAddr,
        direct: &DirectConfig,
    ) -> Result<()> {
        let metrics = &direct.metrics;

        // 按线路配置的策略挑一个目标。多目标时失败的会被熔断跳过，所以这里拨到的
        // 通常是健康的。
        //
        // `lease` 必须活到 relay 结束 —— 它持有这个目标的活跃连接计数，
        // `least_conn` 靠它判断哪台机器更空。提前 drop 会让所有目标看起来都空闲。
        let Some(lease) = direct.targets.pick(Some(peer.ip())) else {
            metrics.counters.on_fail();
            return Err(Error::config(format!(
                "线路 `{}` 没有可用目标",
                self.route.name
            )));
        };
        let target = lease.addr().to_string();

        // `egress` 决定这条出站连接从哪块网卡走 —— IEPL 单机双网卡场景下，若不绑
        // 公网源地址，内核可能把去落地机的流量也从专线网卡送出去，绕回对端再出国。
        let upstream = match relay::dial_target(
            &target,
            &tunnel_common::net::TcpTuning::default(),
            &direct.egress,
            direct.limits.connect_timeout,
        )
        .await
        {
            Ok(s) => {
                lease.record_success();
                s
            }
            Err(e) => {
                // 记在这个目标头上：连续失败达阈值后它会被熔断，后续连接自动
                // 绕开，而不是每 N 个连接就必然失败一个。
                lease.record_failure();
                metrics.counters.on_fail();
                return Err(e);
            }
        };

        let conn = self.registry.register(
            &self.route.id,
            &self.route.name,
            // 直连没有隧道与流的概念，两者留 0 —— 面板据此可区分两类连接。
            0,
            0,
            peer.to_string(),
            target.clone(),
        );
        let conn_id = conn.id;

        let result = relay::relay_sockets(
            socket,
            upstream,
            direct.limits.relay_buffer,
            direct.limits.stream_idle_timeout,
            metrics.counters.clone(),
            Some(conn),
        )
        .await;

        self.registry.unregister(conn_id);
        // 到这里 lease 才析构，活跃连接计数随之归还。
        drop(lease);
        result.map(|_| ())
    }
}

/// `true` for the errno values that mean "no more file descriptors".
fn is_fd_exhaustion(e: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        matches!(e.raw_os_error(), Some(libc_emfile) if libc_emfile == 24 || libc_emfile == 23)
    }
    #[cfg(not(unix))]
    {
        let _ = e;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::HealthPolicy;
    use crate::metrics::RouteMetrics;
    use crate::pool::PoolConfig;
    use crate::tls::TlsMaterial;
    use tokio::io::AsyncWriteExt;
    use tunnel_common::model::{
        Endpoint, EndpointKind, EndpointPriority, Limits, LoadBalance, TlsConfig,
    };
    use tunnel_common::net::EgressBinding;
    use tunnel_common::Secret;

    fn route(listen_port: u16) -> Route {
        Route {
            id: "r1".into(),
            name: "test-route".into(),
            mode: tunnel_common::model::RouteMode::Tunnel,
            entry_node_id: "sh-01".into(),
            listen_address: "127.0.0.1".into(),
            listen_port,
            exit_node_id: "hk-01".into(),
            target_host: "127.0.0.1".into(),
            target_port: 9999,
            targets: vec![],
            target_strategy: Default::default(),
            endpoint_ids: vec!["ep".into()],
            tunnel_pool_size: 1,
            load_balance: LoadBalance::RoundRobin,
            max_connections: 0,
            egress_source_ip: None,
            egress_interface: None,
            enabled: true,
        }
    }

    fn dead_pool() -> Arc<TunnelPool> {
        let endpoints = vec![Endpoint {
            id: "ep".into(),
            node_id: "hk-01".into(),
            name: "ep".into(),
            // Port 1: nothing listens, so no tunnel ever comes up.
            address: "127.0.0.1".into(),
            port: 1,
            kind: EndpointKind::Public,
            priority: EndpointPriority::Primary,
            interface: None,
            source_ip: None,
            tls_server_name: Some("exit.internal".into()),
            enabled: true,
        }];
        let tls = TlsMaterial::load(
            &TlsConfig {
                insecure_skip_verify: true,
                ..Default::default()
            },
            false,
        )
        .unwrap();
        TunnelPool::start(
            PoolConfig {
                route_id: "r1".into(),
                route_name: "test-route".into(),
                node_id: "sh-01".into(),
                size: 1,
                load_balance: LoadBalance::RoundRobin,
                limits: Limits {
                    connect_timeout: Duration::from_millis(200),
                    handshake_timeout: Duration::from_millis(200),
                    ..Default::default()
                },
                psk: Some(Secret::new("psk")),
                health: HealthPolicy::default(),
                egress: EgressBinding::default(),
            },
            endpoints,
            tls,
            RouteMetrics::new("r1"),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn binding_a_busy_port_is_a_config_error() {
        // Hold the port, then try to start a route on it.
        let squatter = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = squatter.local_addr().unwrap().port();

        let listener = Arc::new(EntryListener::new(
            route(port),
            dead_pool(),
            ConnectionRegistry::new(100),
        ));
        let err = listener.run().await.unwrap_err();
        assert!(matches!(err, Error::Config(_)), "{err:?}");
        assert!(err.to_string().contains("test-route"), "{err}");
    }

    #[tokio::test]
    async fn accepted_connection_is_dropped_when_no_tunnel_is_available() {
        // The listener must accept, fail to get a stream, close the socket, and
        // keep serving — not die.
        let listener = Arc::new(EntryListener::new(
            route(0),
            dead_pool(),
            ConnectionRegistry::new(100),
        ));
        // Bind an ephemeral port by asking the OS, then re-target the route.
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let pool = listener.pool.clone().expect("隧道模式下池必然存在");
        let listener = Arc::new(EntryListener::new(
            route(port),
            pool.clone(),
            ConnectionRegistry::new(100),
        ));
        let flag = listener.shutdown_flag();
        let serve = tokio::spawn({
            let l = listener.clone();
            async move { l.run().await }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;

        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("listener should accept");
        let _ = client.write_all(b"hello").await;

        // Give the failing path time to run, then confirm the listener is alive
        // by connecting a second time.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok(),
            "listener died after a failed connection"
        );

        let metrics = pool.metrics();
        assert!(metrics.counters.accepted() >= 1);
        assert!(metrics.counters.failed() >= 1, "failure was not counted");

        flag.store(true, REL);
        let _ = tokio::time::timeout(Duration::from_secs(3), serve).await;
        pool.shutdown().await;
    }

    #[tokio::test]
    async fn connection_limit_rejects_and_counts() {
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let mut r = route(port);
        r.max_connections = 1;
        let pool = dead_pool();
        let listener = Arc::new(EntryListener::new(r, pool.clone(), ConnectionRegistry::new(100)));
        let flag = listener.shutdown_flag();
        let serve = tokio::spawn({
            let l = listener.clone();
            async move { l.run().await }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Saturate the single slot with a connection that will sit in the
        // failing open_stream path, then pile on more.
        let mut held = Vec::new();
        for _ in 0..6 {
            if let Ok(s) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                held.push(s);
            }
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(
            pool.metrics().counters.rejected() > 0,
            "limit never triggered a rejection"
        );

        flag.store(true, REL);
        let _ = tokio::time::timeout(Duration::from_secs(3), serve).await;
        pool.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_flag_stops_the_accept_loop() {
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let pool = dead_pool();
        let listener = Arc::new(EntryListener::new(
            route(port),
            pool.clone(),
            ConnectionRegistry::new(10),
        ));
        let flag = listener.shutdown_flag();
        let serve = tokio::spawn({
            let l = listener.clone();
            async move { l.run().await }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        flag.store(true, REL);

        let result = tokio::time::timeout(Duration::from_secs(3), serve)
            .await
            .expect("accept loop ignored the shutdown flag")
            .unwrap();
        assert!(result.is_ok());
        pool.shutdown().await;
    }
}
