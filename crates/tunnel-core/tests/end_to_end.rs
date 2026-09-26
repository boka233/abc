//! End-to-end integration tests over a real TLS 1.3 tunnel.
//!
//! These run the full production path — TCP accept → mux → TLS 1.3 → exit →
//! target — with real rustls, a real generated PKI, and real sockets. The unit
//! tests use in-memory duplex pipes; these do not.
//!
//! The central assertion throughout is the system's contract: **the byte stream
//! that goes in comes out identical**, with connection lifecycle preserved.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tunnel_common::model::{
    Endpoint, EndpointKind, EndpointPriority, Limits, LoadBalance, Route, TlsConfig,
};
use tunnel_common::net::EgressBinding;
use tunnel_common::Secret;
use tunnel_core::entry::EntryListener;
use tunnel_core::exit::{ExitListener, ExitRoute};
use tunnel_core::health::HealthPolicy;
use tunnel_core::metrics::{ConnectionRegistry, RouteMetrics};
use tunnel_core::pool::{PoolConfig, TunnelPool};
use tunnel_core::tls::TlsMaterial;

const PSK: &str = "integration-test-pre-shared-key";
const ROUTE_ID: &str = "r1";

/// Throwaway CA + server certificate, so the tests exercise real certificate
/// verification rather than `insecure_skip_verify`.
struct Pki {
    dir: std::path::PathBuf,
    ca: std::path::PathBuf,
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
}

impl Pki {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "tunnel-e2e-{}-{}-{}",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "tunnel-e2e-ca");
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let mut leaf = rcgen::CertificateParams::new(vec!["exit.internal".to_string()]).unwrap();
        leaf.distinguished_name
            .push(rcgen::DnType::CommonName, "exit.internal");
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf_cert = leaf.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();

        let ca = dir.join("ca.pem");
        let cert = dir.join("exit.pem");
        let key = dir.join("exit.key");
        std::fs::write(&ca, ca_cert.pem()).unwrap();
        std::fs::write(&cert, leaf_cert.pem()).unwrap();
        std::fs::write(&key, leaf_key.serialize_pem()).unwrap();

        Self { dir, ca, cert, key }
    }

    fn server_tls(&self) -> TlsConfig {
        TlsConfig {
            cert_path: Some(self.cert.display().to_string()),
            key_path: Some(self.key.display().to_string()),
            ca_path: Some(self.ca.display().to_string()),
            ..Default::default()
        }
    }

    fn client_tls(&self) -> TlsConfig {
        TlsConfig {
            ca_path: Some(self.ca.display().to_string()),
            ..Default::default()
        }
    }
}

impl Drop for Pki {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn limits() -> Limits {
    Limits {
        connect_timeout: Duration::from_secs(5),
        handshake_timeout: Duration::from_secs(5),
        // Small window on purpose: forces credit-based flow control to actually
        // cycle during the bulk transfers below.
        stream_window: 128 * 1024,
        max_frame_payload: 32 * 1024,
        ..Default::default()
    }
}

async fn free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

fn route(listen_port: u16, target_port: u16, pool_size: u16) -> Route {
    Route {
        id: ROUTE_ID.into(),
        name: "e2e".into(),
        mode: Default::default(),
        entry_node_id: "entry".into(),
        listen_address: "127.0.0.1".into(),
        listen_port,
        exit_node_id: "exit".into(),
        target_host: "127.0.0.1".into(),
        target_port,
        targets: vec![],
        target_strategy: Default::default(),
        endpoint_ids: vec!["ep".into()],
        tunnel_pool_size: pool_size,
        load_balance: LoadBalance::RoundRobin,
        max_connections: 0,
        egress_source_ip: None,
        egress_interface: None,
        enabled: true,
    }
}

fn endpoint(tunnel_port: u16) -> Endpoint {
    Endpoint {
        id: "ep".into(),
        node_id: "exit".into(),
        name: "exit-endpoint".into(),
        address: "127.0.0.1".into(),
        port: tunnel_port,
        kind: EndpointKind::Public,
        priority: EndpointPriority::Primary,
        interface: None,
        source_ip: None,
        // The certificate is for exit.internal; the address is a literal IP, so
        // an explicit SNI is required for verification to succeed.
        tls_server_name: Some("exit.internal".into()),
        enabled: true,
    }
}

/// A live entry+exit pair wired together over TLS.
struct Deployment {
    entry_port: u16,
    entry_metrics: Arc<RouteMetrics>,
    pool: Arc<TunnelPool>,
    entry_shutdown: Arc<std::sync::atomic::AtomicBool>,
    exit_shutdown: Arc<std::sync::atomic::AtomicBool>,
    _pki: Pki,
}

impl Deployment {
    /// Stand up an exit, then an entry pointed at it, and wait for the pool.
    async fn start(name: &str, target_port: u16, pool_size: u16) -> Self {
        let pki = Pki::new(name);
        let tunnel_port = free_port().await;
        let entry_port = free_port().await;
        let route = route(entry_port, target_port, pool_size);

        // --- exit ---
        let exit_tls = TlsMaterial::load(&pki.server_tls(), true).unwrap();
        let mut exit_routes = HashMap::new();
        exit_routes.insert(
            ROUTE_ID.to_string(),
            ExitRoute::new(
                route.clone(),
                EgressBinding::default(),
                RouteMetrics::new(ROUTE_ID),
            ),
        );
        let exit = Arc::new(ExitListener::new(
            endpoint(tunnel_port),
            "exit".into(),
            exit_routes,
            limits(),
            Some(Secret::new(PSK)),
            exit_tls,
            ConnectionRegistry::new(500),
        ));
        let exit_shutdown = exit.shutdown_flag();
        tokio::spawn({
            let exit = exit.clone();
            async move {
                let _ = exit.run().await;
            }
        });

        // --- entry ---
        let entry_tls = TlsMaterial::load(&pki.client_tls(), false).unwrap();
        let entry_metrics = RouteMetrics::new(ROUTE_ID);
        let pool = TunnelPool::start(
            PoolConfig {
                route_id: ROUTE_ID.into(),
                route_name: "e2e".into(),
                node_id: "entry".into(),
                size: pool_size,
                load_balance: LoadBalance::RoundRobin,
                limits: limits(),
                psk: Some(Secret::new(PSK)),
                health: HealthPolicy::default(),
                egress: EgressBinding::default(),
            },
            vec![endpoint(tunnel_port)],
            entry_tls,
            entry_metrics.clone(),
        )
        .unwrap();

        let entry = Arc::new(EntryListener::new(
            route,
            pool.clone(),
            ConnectionRegistry::new(500),
        ));
        let entry_shutdown = entry.shutdown_flag();
        tokio::spawn({
            let entry = entry.clone();
            async move {
                let _ = entry.run().await;
            }
        });

        // Wait for at least one tunnel to come up.
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while pool.online_tunnels() == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "no tunnel came online within 20s"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // Give the listener a moment to bind.
        tokio::time::sleep(Duration::from_millis(200)).await;

        Self {
            entry_port,
            entry_metrics,
            pool,
            entry_shutdown,
            exit_shutdown,
            _pki: pki,
        }
    }

    async fn connect(&self) -> tokio::net::TcpStream {
        tokio::net::TcpStream::connect(("127.0.0.1", self.entry_port))
            .await
            .expect("entry listener should accept")
    }

    async fn stop(&self) {
        self.entry_shutdown
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.exit_shutdown
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.pool.shutdown().await;
    }
}

/// Echo server standing in for the service behind the exit.
async fn echo_server() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let (mut r, mut w) = sock.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    port
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn small_payload_round_trips_over_tls() {
    let target = echo_server().await;
    let dep = Deployment::start("small", target, 2).await;

    let mut client = dep.connect().await;
    client.write_all(b"hello over the tunnel").await.unwrap();
    client.flush().await.unwrap();

    let mut buf = vec![0u8; 21];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello over the tunnel");

    dep.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bulk_transfer_is_byte_exact() {
    // The headline guarantee, through real TLS with a window far smaller than the
    // payload — so this only passes if flow control and framing are both correct.
    let target = echo_server().await;
    let dep = Deployment::start("bulk", target, 4).await;

    const N: usize = 2 * 1024 * 1024;
    let payload: Vec<u8> = (0..N).map(|i| ((i * 31 + i / 997) % 256) as u8).collect();
    let expected = payload.clone();

    let mut client = dep.connect().await;
    let (mut r, mut w) = client.split();

    // Read and write concurrently; writing 2 MiB before reading would deadlock
    // against the 128 KiB window by construction.
    let writer = async move {
        w.write_all(&payload).await.unwrap();
        w.flush().await.unwrap();
        w.shutdown().await.unwrap();
    };
    let reader = async move {
        let mut got = Vec::with_capacity(N);
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            let n = r.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&chunk[..n]);
        }
        got
    };

    let (_, got) = tokio::time::timeout(Duration::from_secs(120), async {
        tokio::join!(writer, reader)
    })
    .await
    .expect("bulk transfer stalled");

    assert_eq!(got.len(), expected.len(), "length mismatch");
    assert_eq!(got, expected, "payload corrupted end to end");

    dep.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_connections_stay_isolated() {
    // Many user connections share one tunnel pool. Any cross-talk between
    // multiplexed streams shows up as a wrong byte pattern.
    let target = echo_server().await;
    let dep = Deployment::start("concurrent", target, 4).await;

    let mut tasks = Vec::new();
    for i in 0..32u8 {
        let port = dep.entry_port;
        tasks.push(tokio::spawn(async move {
            let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            let payload = vec![i; 16 * 1024];
            client.write_all(&payload).await.unwrap();
            client.flush().await.unwrap();

            let mut got = vec![0u8; payload.len()];
            client.read_exact(&mut got).await.unwrap();
            assert!(
                got.iter().all(|&b| b == i),
                "connection {i} received another connection's data"
            );
            got.len()
        }));
    }

    for task in tasks {
        let n = tokio::time::timeout(Duration::from_secs(60), task)
            .await
            .expect("a connection stalled")
            .unwrap();
        assert_eq!(n, 16 * 1024);
    }

    dep.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn half_close_reaches_the_target_and_back() {
    // A target that replies only after seeing EOF. Passing requires FIN to
    // survive: client → entry → tunnel CLOSE → exit → target shutdown.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut received = Vec::new();
                sock.read_to_end(&mut received).await.unwrap();
                let reply = format!("received {} bytes", received.len());
                sock.write_all(reply.as_bytes()).await.unwrap();
                sock.shutdown().await.unwrap();
            });
        }
    });

    let dep = Deployment::start("half-close", target, 2).await;
    let mut client = dep.connect().await;
    client.write_all(b"0123456789").await.unwrap();
    client.flush().await.unwrap();
    client.shutdown().await.unwrap();

    let mut reply = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), client.read_to_end(&mut reply))
        .await
        .expect("target never observed EOF; half-close was not propagated")
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&reply), "received 10 bytes");

    dep.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn target_refusal_does_not_break_the_tunnel() {
    // Nothing listens on the target port. Each connection must fail on its own
    // while the tunnel stays up and later connections still work.
    let dead_target = free_port().await;
    let dep = Deployment::start("refused", dead_target, 2).await;

    for _ in 0..3 {
        let mut client = dep.connect().await;
        let _ = client.write_all(b"probe").await;
        let mut buf = [0u8; 8];
        // Either a reset or a clean EOF is acceptable; a hang is not.
        let result = tokio::time::timeout(Duration::from_secs(10), client.read(&mut buf)).await;
        assert!(result.is_ok(), "connection hung instead of failing");
    }

    assert!(
        dep.pool.online_tunnels() > 0,
        "a failed target dial should not tear down the tunnel"
    );
    assert!(dep.entry_metrics.counters.failed() > 0);

    dep.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pool_spreads_streams_over_several_tunnels() {
    let target = echo_server().await;
    let dep = Deployment::start("pool", target, 4).await;

    // Wait for the whole pool, not just the first connection.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while dep.pool.online_tunnels() < 4 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        dep.pool.online_tunnels(),
        4,
        "the pool did not reach its configured size"
    );

    // Hold several connections open so streams overlap across tunnels.
    let mut held = Vec::new();
    for _ in 0..8 {
        let mut client = dep.connect().await;
        client.write_all(b"x").await.unwrap();
        client.flush().await.unwrap();
        let mut buf = [0u8; 1];
        client.read_exact(&mut buf).await.unwrap();
        held.push(client);
    }

    let snapshots = dep.pool.snapshots().await;
    assert_eq!(snapshots.len(), 4);
    let carrying = snapshots.iter().filter(|s| s.streams > 0).count();
    assert!(
        carrying > 1,
        "round-robin put all {} streams on one tunnel, which defeats the pool",
        held.len()
    );

    dep.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_psk_is_rejected_at_the_handshake() {
    // TLS succeeds, the PSK proof fails: the tunnel must never come up.
    let pki = Pki::new("bad-psk");
    let tunnel_port = free_port().await;
    let target = echo_server().await;

    let mut exit_routes = HashMap::new();
    exit_routes.insert(
        ROUTE_ID.to_string(),
        ExitRoute::new(
            route(0, target, 1),
            EgressBinding::default(),
            RouteMetrics::new(ROUTE_ID),
        ),
    );
    let exit = Arc::new(ExitListener::new(
        endpoint(tunnel_port),
        "exit".into(),
        exit_routes,
        limits(),
        Some(Secret::new("the-correct-psk")),
        TlsMaterial::load(&pki.server_tls(), true).unwrap(),
        ConnectionRegistry::new(100),
    ));
    tokio::spawn({
        let exit = exit.clone();
        async move {
            let _ = exit.run().await;
        }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let pool = TunnelPool::start(
        PoolConfig {
            route_id: ROUTE_ID.into(),
            route_name: "e2e".into(),
            node_id: "entry".into(),
            size: 1,
            load_balance: LoadBalance::RoundRobin,
            limits: limits(),
            psk: Some(Secret::new("the-wrong-psk")),
            health: HealthPolicy::default(),
            egress: EgressBinding::default(),
        },
        vec![endpoint(tunnel_port)],
        TlsMaterial::load(&pki.client_tls(), false).unwrap(),
        RouteMetrics::new(ROUTE_ID),
    )
    .unwrap();

    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        pool.online_tunnels(),
        0,
        "a tunnel came up despite a wrong PSK"
    );
    assert!(pool.open_stream(None).await.is_err());

    pool.shutdown().await;
    exit.shutdown_flag()
        .store(true, std::sync::atomic::Ordering::Relaxed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn untrusted_certificate_prevents_the_tunnel() {
    // The entry trusts a different CA than the exit presents.
    let server_pki = Pki::new("untrusted-a");
    let other_pki = Pki::new("untrusted-b");
    let tunnel_port = free_port().await;
    let target = echo_server().await;

    let mut exit_routes = HashMap::new();
    exit_routes.insert(
        ROUTE_ID.to_string(),
        ExitRoute::new(
            route(0, target, 1),
            EgressBinding::default(),
            RouteMetrics::new(ROUTE_ID),
        ),
    );
    let exit = Arc::new(ExitListener::new(
        endpoint(tunnel_port),
        "exit".into(),
        exit_routes,
        limits(),
        Some(Secret::new(PSK)),
        TlsMaterial::load(&server_pki.server_tls(), true).unwrap(),
        ConnectionRegistry::new(100),
    ));
    tokio::spawn({
        let exit = exit.clone();
        async move {
            let _ = exit.run().await;
        }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let pool = TunnelPool::start(
        PoolConfig {
            route_id: ROUTE_ID.into(),
            route_name: "e2e".into(),
            node_id: "entry".into(),
            size: 1,
            load_balance: LoadBalance::RoundRobin,
            limits: limits(),
            psk: Some(Secret::new(PSK)),
            health: HealthPolicy::default(),
            egress: EgressBinding::default(),
        },
        vec![endpoint(tunnel_port)],
        // Trusts the wrong CA.
        TlsMaterial::load(&other_pki.client_tls(), false).unwrap(),
        RouteMetrics::new(ROUTE_ID),
    )
    .unwrap();

    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        pool.online_tunnels(),
        0,
        "a tunnel came up against an untrusted certificate"
    );

    pool.shutdown().await;
    exit.shutdown_flag()
        .store(true, std::sync::atomic::Ordering::Relaxed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn traffic_counters_reflect_real_bytes() {
    let target = echo_server().await;
    let dep = Deployment::start("counters", target, 2).await;

    const N: usize = 64 * 1024;
    let mut client = dep.connect().await;
    let payload = vec![0xABu8; N];
    let (mut r, mut w) = client.split();

    let writer = async move {
        w.write_all(&payload).await.unwrap();
        w.flush().await.unwrap();
    };
    let reader = async move {
        let mut got = vec![0u8; N];
        r.read_exact(&mut got).await.unwrap();
        got
    };
    let (_, got) = tokio::time::timeout(Duration::from_secs(60), async {
        tokio::join!(writer, reader)
    })
    .await
    .expect("transfer stalled");
    assert_eq!(got.len(), N);

    let counters = &dep.entry_metrics.counters;
    // Reading the last bytes from the socket can win the race with the relay
    // task's counter update after write_all. Wait for accounting to catch up
    // rather than treating that scheduler timing as lost traffic.
    tokio::time::timeout(Duration::from_secs(5), async {
        while counters.rx() < N as u64 || counters.tx() < N as u64 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("relay counters did not catch up after transfer");
    assert_eq!(counters.rx(), N as u64, "upload bytes miscounted");
    assert_eq!(counters.tx(), N as u64, "download bytes miscounted");
    assert!(counters.accepted() >= 1);

    dep.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn graceful_shutdown_stops_accepting() {
    let target = echo_server().await;
    let dep = Deployment::start("shutdown", target, 2).await;

    // Working before shutdown.
    let mut client = dep.connect().await;
    client.write_all(b"ping").await.unwrap();
    client.flush().await.unwrap();
    let mut buf = [0u8; 4];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
    drop(client);

    dep.stop().await;
    tokio::time::sleep(Duration::from_millis(800)).await;

    // New connections must no longer be served.
    let attempt = tokio::net::TcpStream::connect(("127.0.0.1", dep.entry_port)).await;
    if let Ok(mut sock) = attempt {
        let _ = sock.write_all(b"after").await;
        let mut buf = [0u8; 4];
        let result = tokio::time::timeout(Duration::from_secs(3), sock.read(&mut buf)).await;
        match result {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(_)) => panic!("the listener still served traffic after shutdown"),
            Err(_) => {}
        }
    }
}
