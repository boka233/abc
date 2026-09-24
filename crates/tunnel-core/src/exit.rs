//! Exit role: terminate tunnels, dial the configured target.
//!
//! ```text
//!   TLS accept ──▶ handshake ──▶ Multiplexer ──▶ per-stream: dial target ──▶ relay
//! ```
//!
//! # The security property that matters here
//!
//! The target address comes from **this node's own route table**, never from the
//! `OPEN` frame. An entry can only ask "open a stream for route R"; the exit
//! decides what R points at. If the target were taken from the wire, every exit
//! would be an open proxy that any authenticated entry could aim anywhere. The
//! `OPEN` payload's optional `client_addr` is used for the connections table and
//! nothing else.
//!
//! # Anti-probe behaviour
//!
//! The listener is a plain TLS endpoint. A scanner that connects without a valid
//! certificate/PSK gets a TLS failure or a rejected handshake and nothing else —
//! no banner, no protocol hint, no distinguishing error. Rejections are
//! deliberately uniform so the reason cannot be used as an oracle.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tunnel_common::model::{Endpoint, Limits, Route};
use tunnel_common::net::{EgressBinding, TcpTuning};
use tunnel_common::{Error, Result, Secret};
use tunnel_protocol::codec::{FrameReader, FrameWriter};
use tunnel_protocol::handshake::{self, ClientHello, ServerHello};

use crate::metrics::{ConnectionRegistry, RouteMetrics, TunnelMetrics};
use crate::mux::{IncomingStream, MuxConfig, MuxRole, Multiplexer};
use crate::relay;
use crate::tls::TlsMaterial;

const REL: Ordering = Ordering::Relaxed;
const LISTEN_BACKLOG: u32 = 1024;

/// Everything the exit needs to serve one route.
#[derive(Debug, Clone)]
pub struct ExitRoute {
    pub route: Route,
    /// Egress binding for the target connection. This is how traffic that
    /// arrived over IEPL leaves via the public NIC.
    pub egress: EgressBinding,
    pub metrics: Arc<RouteMetrics>,
    /// 多目标选择与熔断。
    ///
    /// 放在 `ExitRoute` 而不是每条流各建一个：熔断状态和活跃连接计数必须跨流累积，
    /// 每次新建就等于没有记忆。配置替换时会连同新的 `ExitRoute` 一起换掉，此时熔断
    /// 状态归零是正确的 —— 目标列表已经变了。
    pub targets: Arc<crate::targets::TargetSelector>,
}

impl ExitRoute {
    /// 从线路构造，目标与策略都取自它。
    pub fn new(route: Route, egress: EgressBinding, metrics: Arc<RouteMetrics>) -> Self {
        let targets = Arc::new(crate::targets::TargetSelector::from_route(&route));
        Self {
            route,
            egress,
            metrics,
            targets,
        }
    }
}

pub struct ExitListener {
    endpoint: Endpoint,
    node_id: String,
    routes: Arc<tokio::sync::RwLock<HashMap<String, ExitRoute>>>,
    limits: Limits,
    psk: Option<Secret>,
    tls: Arc<TlsMaterial>,
    registry: Arc<ConnectionRegistry>,
    shutdown: Arc<AtomicBool>,
}

impl ExitListener {
    pub fn new(
        endpoint: Endpoint,
        node_id: String,
        routes: HashMap<String, ExitRoute>,
        limits: Limits,
        psk: Option<Secret>,
        tls: Arc<TlsMaterial>,
        registry: Arc<ConnectionRegistry>,
    ) -> Self {
        Self {
            endpoint,
            node_id,
            routes: Arc::new(tokio::sync::RwLock::new(routes)),
            limits,
            psk,
            tls,
            registry,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn shutdown_flag(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }

    /// Swap the route table without dropping live tunnels.
    ///
    /// A config push that changes a target must not disconnect existing
    /// sessions; new streams pick up the new table, in-flight ones finish
    /// against the target they already dialled.
    pub async fn replace_routes(&self, routes: HashMap<String, ExitRoute>) {
        let mut guard = self.routes.write().await;
        *guard = routes;
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
        let bind = format!("{}:{}", self.endpoint.address, self.endpoint.port);
        let tuning = TcpTuning::tunnel();
        let listener = tunnel_common::net::listen(&bind, LISTEN_BACKLOG, &tuning)
            .await
            .map_err(|e| {
                Error::config(format!(
                    "exit endpoint `{}` cannot bind {bind}: {e}",
                    self.endpoint.name
                ))
            })?;

        tracing::info!(
            endpoint = %self.endpoint.name,
            kind = %self.endpoint.kind,
            listen = %bind,
            "exit listener started"
        );

        loop {
            if self.shutdown.load(REL) {
                tracing::info!(endpoint = %self.endpoint.name, "exit listener stopping");
                return Ok(());
            }

            let accepted =
                match tokio::time::timeout(Duration::from_millis(500), listener.accept()).await {
                    Ok(Ok(pair)) => pair,
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, "tunnel accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                    Err(_) => continue,
                };

            let (socket, peer) = accepted;
            if let Err(e) = tuning.apply_to_stream(&socket) {
                tracing::debug!(error = %e, "could not apply socket tuning");
            }

            let this = self.clone();
            tokio::spawn(async move {
                if let Err(e) = this.serve_tunnel(socket, peer).await {
                    // Probes and scanners land here constantly; DEBUG keeps the
                    // log usable while still being available when needed.
                    tracing::debug!(
                        peer = %tunnel_common::net::redact_port(&peer),
                        error = %e,
                        "tunnel connection rejected"
                    );
                }
            });
        }
    }

    /// TLS accept → handshake → multiplexer → stream accept loop.
    async fn serve_tunnel(
        self: Arc<Self>,
        socket: tokio::net::TcpStream,
        peer: std::net::SocketAddr,
    ) -> Result<()> {
        let acceptor = self.tls.acceptor()?;

        // Timeout the TLS handshake: a client that opens a connection and sends
        // nothing would otherwise hold a task and a descriptor indefinitely.
        // This is the classic slowloris shape.
        let tls = tokio::time::timeout(self.limits.handshake_timeout, acceptor.accept(socket))
            .await
            .map_err(|_| Error::Timeout("tls handshake"))?
            .map_err(|e| Error::tls(e.to_string()))?;

        let (read_half, write_half) = tokio::io::split(tls);
        let mut reader = FrameReader::new(read_half, self.limits.max_frame_payload as usize);
        let mut writer = FrameWriter::new(write_half, self.limits.max_frame_payload as usize);

        let hello: ClientHello =
            tokio::time::timeout(self.limits.handshake_timeout, reader.read_handshake())
                .await
                .map_err(|_| Error::Timeout("tunnel handshake"))??;

        // Validate in order: version, PSK, route. Every rejection sends the same
        // shape of reply so a prober learns nothing from the difference.
        let verdict = self.validate_hello(&hello).await;

        let (payload, window) = match &verdict {
            Ok((p, w)) => (*p, *w),
            Err(reason) => {
                let reply = ServerHello {
                    version: tunnel_protocol::PROTOCOL_VERSION,
                    accepted: false,
                    reason: Some(reason.clone()),
                    max_frame_payload: self.limits.max_frame_payload,
                    stream_window: self.limits.stream_window,
                    node_id: self.node_id.clone(),
                    agent_version: tunnel_common::AGENT_VERSION.to_string(),
                };
                let _ = writer.write_handshake(&reply).await;
                return Err(Error::Auth("tunnel handshake rejected"));
            }
        };

        let reply = ServerHello {
            version: tunnel_protocol::PROTOCOL_VERSION,
            accepted: true,
            reason: None,
            max_frame_payload: payload,
            stream_window: window,
            node_id: self.node_id.clone(),
            agent_version: tunnel_common::AGENT_VERSION.to_string(),
        };
        writer.write_handshake(&reply).await?;

        let conn = reader.into_inner().unsplit(writer.into_inner());
        let (incoming_tx, incoming_rx) = mpsc::channel::<IncomingStream>(64);

        let tunnel_id = next_tunnel_id();
        let metrics = TunnelMetrics::new(tunnel_id);
        metrics.set_state(tunnel_common::model::TunnelState::Online);

        let mux_cfg = MuxConfig::from_limits(MuxRole::Responder, &self.limits, payload, window);
        let mux = Multiplexer::start(conn, mux_cfg, metrics.clone(), Some(incoming_tx));

        tracing::info!(
            tunnel = tunnel_id,
            route = %hello.route_id,
            peer_node = %hello.node_id,
            pool_index = hello.pool_index,
            peer = %tunnel_common::net::redact_port(&peer),
            "tunnel accepted"
        );

        self.accept_streams(incoming_rx, mux.clone(), tunnel_id).await;

        mux.shutdown().await;
        tracing::info!(tunnel = tunnel_id, "tunnel closed");
        Ok(())
    }

    /// Returns the negotiated limits, or a rejection reason.
    async fn validate_hello(&self, hello: &ClientHello) -> std::result::Result<(u32, u32), String> {
        if hello.check_version().is_err() {
            return Err("unsupported protocol version".into());
        }
        // Uniform message on auth failure: no distinction between "bad PSK" and
        // "malformed nonce", so it cannot be probed.
        if handshake::verify_proof(self.psk.as_ref(), hello).is_err() {
            return Err("authentication failed".into());
        }
        {
            let routes = self.routes.read().await;
            let Some(entry) = routes.get(&hello.route_id) else {
                return Err("unknown route".into());
            };
            if !entry.route.enabled {
                return Err("route disabled".into());
            }
        }
        handshake::negotiate(
            self.limits.max_frame_payload,
            self.limits.stream_window,
            hello.max_frame_payload,
            hello.stream_window,
        )
        .map_err(|e| e.to_string())
    }

    /// Serve streams until the tunnel dies.
    async fn accept_streams(
        &self,
        mut incoming: mpsc::Receiver<IncomingStream>,
        mux: Arc<Multiplexer>,
        tunnel_id: u64,
    ) {
        loop {
            let stream = tokio::select! {
                s = incoming.recv() => match s {
                    Some(s) => s,
                    None => return,
                },
                _ = async {
                    while !mux.is_closed() && !self.shutdown.load(REL) {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                } => {
                    if self.shutdown.load(REL) {
                        mux.go_away("exit shutting down").await;
                    }
                    return;
                }
            };

            // Resolve the target from *our* configuration.
            let route_entry = {
                let routes = self.routes.read().await;
                routes.get(&stream.route_id).cloned()
            };

            let Some(exit_route) = route_entry else {
                tracing::warn!(
                    route = %stream.route_id,
                    "stream for an unknown route; resetting"
                );
                let mut handle = stream.handle;
                handle.reset().await;
                continue;
            };

            let limits = self.limits.clone();
            let registry = self.registry.clone();
            tokio::spawn(async move {
                serve_stream(stream, exit_route, limits, registry, tunnel_id).await;
            });
        }
    }
}

/// Dial the target for one inbound stream and relay it.
async fn serve_stream(
    incoming: IncomingStream,
    exit_route: ExitRoute,
    limits: Limits,
    registry: Arc<ConnectionRegistry>,
    tunnel_id: u64,
) {
    let mut handle = incoming.handle;
    let metrics = exit_route.metrics.clone();

    metrics.counters.on_accept();

    // `client_addr` 来自 OPEN 帧，只用于 ip_hash 与连接表 —— 目标地址始终取自本机
    // 配置，入口无法指定拨向哪里（见模块文档）。伪造它最多影响自己落到哪个等价
    // 目标上，不能拨到列表外的地址。
    let client_ip = incoming
        .client_addr
        .as_deref()
        .and_then(|a| a.parse::<std::net::SocketAddr>().ok())
        .map(|a| a.ip());

    // lease 必须活到 relay 结束：它持有该目标的活跃连接计数。
    let Some(lease) = exit_route.targets.pick(client_ip) else {
        metrics.counters.on_fail();
        metrics.counters.on_close();
        tracing::error!(route = %exit_route.route.name, "线路没有可用目标");
        handle.reject("no target configured").await;
        return;
    };
    let target = lease.addr().to_string();

    let socket = match relay::dial_target(
        &target,
        &TcpTuning::default(),
        &exit_route.egress,
        limits.connect_timeout,
    )
    .await
    {
        Ok(s) => {
            lease.record_success();
            s
        }
        Err(e) => {
            // 连续失败达阈值后该目标被熔断，后续流自动绕开。
            lease.record_failure();
            metrics.counters.on_fail();
            metrics.counters.on_close();
            tracing::warn!(
                route = %exit_route.route.name,
                target = %target,
                error = %e,
                "target dial failed"
            );
            // The entry is blocked in open_stream(); OPEN_ERROR releases it with
            // a diagnosable reason instead of a bare timeout.
            handle.reject(&e.to_string()).await;
            return;
        }
    };

    // Target is up: only now is the stream confirmed to the entry.
    if let Err(e) = handle.accept().await {
        metrics.counters.on_fail();
        metrics.counters.on_close();
        tracing::debug!(error = %e, "tunnel died before the stream could be confirmed");
        return;
    }

    let conn = registry.register(
        &exit_route.route.id,
        &exit_route.route.name,
        tunnel_id,
        handle.stream_id,
        incoming.client_addr.unwrap_or_else(|| "-".into()),
        target.clone(),
    );
    let conn_id = conn.id;

    let result = relay::relay(
        socket,
        handle,
        limits.relay_buffer,
        limits.stream_idle_timeout,
        metrics.counters.clone(),
        Some(conn),
    )
    .await;

    registry.unregister(conn_id);
    metrics.counters.on_close();
    // 到这里 lease 才析构，活跃连接计数随之归还。
    drop(lease);

    if let Err(e) = result {
        tracing::debug!(
            route = %exit_route.route.name,
            error = %e,
            "exit relay ended with an error"
        );
    }
}

/// Tunnel ids for exit-side tunnels.
///
/// Starts high so exit-side ids never collide with the entry-side pool's ids in
/// the admin panel's tunnel list.
fn next_tunnel_id() -> u64 {
    use std::sync::atomic::AtomicU64;
    static SEQ: AtomicU64 = AtomicU64::new(1_000_000);
    SEQ.fetch_add(1, REL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnel_common::model::{EndpointKind, EndpointPriority, LoadBalance, TlsConfig};

    fn endpoint(port: u16) -> Endpoint {
        Endpoint {
            id: "listen-ep".into(),
            node_id: "hk-01".into(),
            name: "hk-public".into(),
            address: "127.0.0.1".into(),
            port,
            kind: EndpointKind::Public,
            priority: EndpointPriority::Primary,
            interface: None,
            source_ip: None,
            tls_server_name: None,
            enabled: true,
        }
    }

    fn route(target_port: u16) -> Route {
        Route {
            id: "r1".into(),
            name: "test-route".into(),
            mode: tunnel_common::model::RouteMode::Tunnel,
            entry_node_id: "sh-01".into(),
            listen_address: "0.0.0.0".into(),
            listen_port: 443,
            exit_node_id: "hk-01".into(),
            target_host: "127.0.0.1".into(),
            target_port,
            targets: vec![],
            target_strategy: Default::default(),
            endpoint_ids: vec![],
            tunnel_pool_size: 1,
            load_balance: LoadBalance::RoundRobin,
            max_connections: 0,
            egress_source_ip: None,
            egress_interface: None,
            enabled: true,
        }
    }

    fn exit_routes(target_port: u16) -> HashMap<String, ExitRoute> {
        let mut map = HashMap::new();
        map.insert(
            "r1".to_string(),
            ExitRoute::new(
                route(target_port),
                EgressBinding::default(),
                RouteMetrics::new("r1"),
            ),
        );
        map
    }

    fn insecure_material() -> Arc<TlsMaterial> {
        // No certificate: the exit cannot serve, which is exactly what the
        // config-error test wants to prove.
        TlsMaterial::load(
            &TlsConfig {
                insecure_skip_verify: true,
                ..Default::default()
            },
            false,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn binding_a_busy_port_is_a_config_error() {
        let squatter = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = squatter.local_addr().unwrap().port();

        let listener = Arc::new(ExitListener::new(
            endpoint(port),
            "hk-01".into(),
            exit_routes(9999),
            Limits::default(),
            Some(Secret::new("psk")),
            insecure_material(),
            ConnectionRegistry::new(10),
        ));
        let err = listener.run().await.unwrap_err();
        assert!(matches!(err, Error::Config(_)), "{err:?}");
        assert!(err.to_string().contains("hk-public"), "{err}");
    }

    #[tokio::test]
    async fn serving_without_a_certificate_fails_per_connection_not_fatally() {
        // No server certificate is loaded, so every TLS accept must fail while
        // the listener itself keeps running.
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let listener = Arc::new(ExitListener::new(
            endpoint(port),
            "hk-01".into(),
            exit_routes(9999),
            Limits::default(),
            Some(Secret::new("psk")),
            insecure_material(),
            ConnectionRegistry::new(10),
        ));
        let flag = listener.shutdown_flag();
        let serve = tokio::spawn({
            let l = listener.clone();
            async move { l.run().await }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Two probes in a row; the second proves the listener survived the first.
        assert!(tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok());
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok(),
            "listener died after a failed TLS handshake"
        );

        flag.store(true, REL);
        let _ = tokio::time::timeout(Duration::from_secs(3), serve).await;
    }

    #[tokio::test]
    async fn route_table_can_be_swapped_at_runtime() {
        let listener = ExitListener::new(
            endpoint(0),
            "hk-01".into(),
            exit_routes(1111),
            Limits::default(),
            None,
            insecure_material(),
            ConnectionRegistry::new(10),
        );
        {
            let routes = listener.routes.read().await;
            assert_eq!(routes.get("r1").unwrap().route.target_port, 1111);
        }
        listener.replace_routes(exit_routes(2222)).await;
        let routes = listener.routes.read().await;
        assert_eq!(
            routes.get("r1").unwrap().route.target_port,
            2222,
            "route table was not replaced"
        );
    }

    #[tokio::test]
    async fn the_exit_side_also_selects_among_multiple_targets() {
        // 隧道模式下拨目标的是出口，所以多目标与策略在这一侧同样要生效 —— 只在
        // 直连路径实现就等于隧道线路无法用多目标。
        let mut r = route(8443);
        r.targets = vec!["10.0.0.1:443".into(), "10.0.0.2:443".into()];
        r.target_strategy = tunnel_common::model::TargetStrategy::RoundRobin;
        let exit_route = ExitRoute::new(r, EgressBinding::default(), RouteMetrics::new("r1"));

        assert_eq!(exit_route.targets.len(), 2);
        assert_eq!(exit_route.targets.pick(None).unwrap().addr(), "10.0.0.1:443");
        assert_eq!(exit_route.targets.pick(None).unwrap().addr(), "10.0.0.2:443");
    }

    #[tokio::test]
    async fn a_single_target_exit_route_falls_back_to_host_and_port() {
        // targets 为空的旧线路仍然要能工作。
        let exit_route = ExitRoute::new(
            route(8443),
            EgressBinding::default(),
            RouteMetrics::new("r1"),
        );
        assert_eq!(exit_route.targets.len(), 1);
        assert_eq!(
            exit_route.targets.pick(None).unwrap().addr(),
            "127.0.0.1:8443"
        );
    }

    #[tokio::test]
    async fn unknown_route_is_rejected_at_handshake() {
        let listener = ExitListener::new(
            endpoint(0),
            "hk-01".into(),
            exit_routes(9999),
            Limits::default(),
            None,
            insecure_material(),
            ConnectionRegistry::new(10),
        );
        let hello = ClientHello::new("sh-01", "no-such-route", 0, None, 65535, 524288);
        let err = listener.validate_hello(&hello).await.unwrap_err();
        assert_eq!(err, "unknown route");
    }

    #[tokio::test]
    async fn disabled_route_is_rejected_at_handshake() {
        let mut routes = exit_routes(9999);
        routes.get_mut("r1").unwrap().route.enabled = false;
        let listener = ExitListener::new(
            endpoint(0),
            "hk-01".into(),
            routes,
            Limits::default(),
            None,
            insecure_material(),
            ConnectionRegistry::new(10),
        );
        let hello = ClientHello::new("sh-01", "r1", 0, None, 65535, 524288);
        assert_eq!(
            listener.validate_hello(&hello).await.unwrap_err(),
            "route disabled"
        );
    }

    #[tokio::test]
    async fn bad_psk_is_rejected_with_a_uniform_message() {
        let listener = ExitListener::new(
            endpoint(0),
            "hk-01".into(),
            exit_routes(9999),
            Limits::default(),
            Some(Secret::new("correct-psk")),
            insecure_material(),
            ConnectionRegistry::new(10),
        );
        let hello = ClientHello::new(
            "sh-01",
            "r1",
            0,
            Some(&Secret::new("wrong-psk")),
            65535,
            524288,
        );
        let err = listener.validate_hello(&hello).await.unwrap_err();
        assert_eq!(err, "authentication failed");
        // The reason must not distinguish between failure causes.
        assert!(!err.contains("psk") && !err.contains("nonce"), "{err}");
    }

    #[tokio::test]
    async fn valid_hello_negotiates_limits() {
        let listener = ExitListener::new(
            endpoint(0),
            "hk-01".into(),
            exit_routes(9999),
            Limits::default(),
            Some(Secret::new("psk")),
            insecure_material(),
            ConnectionRegistry::new(10),
        );
        // Client offers smaller values; the minimum must win.
        let hello = ClientHello::new("sh-01", "r1", 0, Some(&Secret::new("psk")), 32768, 262144);
        let (payload, window) = listener.validate_hello(&hello).await.unwrap();
        assert_eq!(payload, 32768);
        assert_eq!(window, 262144);
    }

    #[tokio::test]
    async fn protocol_version_mismatch_is_rejected() {
        let listener = ExitListener::new(
            endpoint(0),
            "hk-01".into(),
            exit_routes(9999),
            Limits::default(),
            None,
            insecure_material(),
            ConnectionRegistry::new(10),
        );
        let mut hello = ClientHello::new("sh-01", "r1", 0, None, 65535, 524288);
        hello.version = 99;
        assert_eq!(
            listener.validate_hello(&hello).await.unwrap_err(),
            "unsupported protocol version"
        );
    }

    #[tokio::test]
    async fn target_is_taken_from_local_config_not_the_wire() {
        // The OPEN payload carries no target field at all, which is the
        // structural guarantee. Assert the type shape so a future change that
        // adds one has to confront this test.
        let open = tunnel_protocol::StreamOpen {
            route_id: "r1".into(),
            client_addr: Some("1.2.3.4:5".into()),
        };
        let json = serde_json::to_string(&open).unwrap();
        assert!(
            !json.contains("target") && !json.contains("host") && !json.contains("port"),
            "OPEN payload must not be able to specify a target: {json}"
        );
    }
}
