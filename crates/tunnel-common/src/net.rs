//! Socket construction, tuning and multi-NIC egress control.
//!
//! ## Why this module exists
//!
//! On a dual-NIC IEPL box, *which* socket option you use decides which cable
//! the bytes leave on. The two mechanisms are not interchangeable:
//!
//! ### `bind(source_ip)` — preferred
//!
//! Binding the local source address before `connect()` makes the kernel pick a
//! route whose source matches. It needs no privileges, works identically on
//! every Unix and on Windows, and shows up correctly in `ss -tnp`. It relies on
//! the routing table being correct: with policy routing (`ip rule from
//! 10.20.0.1 lookup iepl`) the source address *is* the route selector. This is
//! what `Endpoint::source_ip` and `Route::egress_source_ip` drive.
//!
//! Failure mode to know about: if the address is not present on any local
//! interface, `bind` fails with `EADDRNOTAVAIL`. That is a loud, diagnosable
//! error, which is exactly what you want.
//!
//! ### `SO_BINDTODEVICE` — fallback
//!
//! Pins the socket to a named device regardless of the routing table. It is
//! Linux-only, requires `CAP_NET_RAW` (so the unit needs
//! `AmbientCapabilities=CAP_NET_RAW`, or root), and bypasses policy routing in
//! ways that are easy to misdiagnose. It is genuinely useful in one case:
//! overlapping/duplicate subnets on two NICs, where a source IP no longer
//! uniquely identifies the path. Supported here, but never the default.
//!
//! Related kernel knobs are documented in `docs/networking-iepl.md`; this code
//! never touches `sysctl` or the routing table.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, Socket, TcpKeepalive, Type};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

use crate::{Error, Result};
use crate::model::InterfaceInfo;

/// TCP tuning applied to every socket we create or accept.
#[derive(Debug, Clone, Copy)]
pub struct TcpTuning {
    /// Disable Nagle. Mandatory for a relay: coalescing 40-byte interactive
    /// writes into 40 ms bursts is the difference between a usable and an
    /// unusable tunnel.
    pub nodelay: bool,
    /// Idle time before the first keepalive probe.
    pub keepalive: Option<Duration>,
    /// Gap between probes. Ignored on platforms that do not expose it.
    pub keepalive_interval: Option<Duration>,
    /// `SO_SNDBUF` / `SO_RCVBUF` overrides. `None` keeps kernel autotuning,
    /// which is the right default — setting these disables autotuning.
    pub send_buffer: Option<usize>,
    pub recv_buffer: Option<usize>,
}

impl Default for TcpTuning {
    fn default() -> Self {
        Self {
            nodelay: true,
            keepalive: Some(Duration::from_secs(30)),
            keepalive_interval: Some(Duration::from_secs(10)),
            send_buffer: None,
            recv_buffer: None,
        }
    }
}

impl TcpTuning {
    /// Tuning for the long-lived tunnel connections: slower probes, since these
    /// carry PING/PONG at the application layer anyway.
    pub fn tunnel() -> Self {
        Self {
            keepalive: Some(Duration::from_secs(60)),
            keepalive_interval: Some(Duration::from_secs(15)),
            ..Default::default()
        }
    }

    fn keepalive_params(&self) -> Option<TcpKeepalive> {
        let time = self.keepalive?;
        let mut ka = TcpKeepalive::new().with_time(time);
        #[cfg(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "windows"
        ))]
        if let Some(iv) = self.keepalive_interval {
            ka = ka.with_interval(iv);
        }
        Some(ka)
    }

    fn apply_to_socket(&self, sock: &Socket) -> Result<()> {
        sock.set_nodelay(self.nodelay)?;
        if let Some(ka) = self.keepalive_params() {
            sock.set_tcp_keepalive(&ka)?;
        }
        if let Some(n) = self.send_buffer {
            sock.set_send_buffer_size(n)?;
        }
        if let Some(n) = self.recv_buffer {
            sock.set_recv_buffer_size(n)?;
        }
        Ok(())
    }

    /// Apply to an already-connected stream (i.e. one returned by `accept`).
    pub fn apply_to_stream(&self, stream: &TcpStream) -> Result<()> {
        stream.set_nodelay(self.nodelay)?;
        let sock = socket2::SockRef::from(stream);
        if let Some(ka) = self.keepalive_params() {
            sock.set_tcp_keepalive(&ka)?;
        }
        if let Some(n) = self.send_buffer {
            sock.set_send_buffer_size(n)?;
        }
        if let Some(n) = self.recv_buffer {
            sock.set_recv_buffer_size(n)?;
        }
        Ok(())
    }
}

/// How an outbound connection should leave the host.
#[derive(Debug, Clone, Default)]
pub struct EgressBinding {
    /// Local source address to `bind()` before connecting. Port is always 0 so
    /// the kernel assigns an ephemeral one.
    pub source_ip: Option<IpAddr>,
    /// `SO_BINDTODEVICE` name. Linux only, needs `CAP_NET_RAW`.
    pub interface: Option<String>,
}

impl EgressBinding {
    pub fn is_empty(&self) -> bool {
        self.source_ip.is_none() && self.interface.is_none()
    }

    pub fn from_source(ip: Option<IpAddr>) -> Self {
        Self {
            source_ip: ip,
            interface: None,
        }
    }
}

/// Resolve a `host:port` string, preferring the family of `prefer_like` when
/// the name yields both A and AAAA records.
///
/// DNS resolution happens on the blocking pool: a stalled resolver must never
/// block a runtime worker thread that is also driving live relay traffic.
pub async fn resolve(target: &str, prefer_like: Option<IpAddr>) -> Result<Vec<SocketAddr>> {
    // Fast path: already a literal, no resolver involved.
    if let Ok(addr) = target.parse::<SocketAddr>() {
        return Ok(vec![addr]);
    }

    let owned = target.to_string();
    let mut addrs: Vec<SocketAddr> = tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        owned.to_socket_addrs().map(|it| it.collect::<Vec<_>>())
    })
    .await
    .map_err(|e| Error::other(format!("resolver task failed: {e}")))??;

    if addrs.is_empty() {
        return Err(Error::NotFound(format!("no addresses for `{target}`")));
    }

    // When a source IP is pinned we must connect to a matching family, or bind
    // will succeed and connect will fail with EINVAL/EAFNOSUPPORT.
    if let Some(pref) = prefer_like {
        addrs.sort_by_key(|a| a.is_ipv4() != pref.is_ipv4());
    }
    Ok(addrs)
}

/// Build an unconnected, tuned, optionally source-bound TCP socket.
fn prepare_socket(
    remote: &SocketAddr,
    tuning: &TcpTuning,
    egress: &EgressBinding,
) -> Result<TcpSocket> {
    let domain = if remote.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    tuning.apply_to_socket(&sock)?;

    // Device pinning must happen before bind/connect to affect route lookup.
    if let Some(dev) = egress.interface.as_deref() {
        bind_device(&sock, dev)?;
    }

    if let Some(ip) = egress.source_ip {
        if ip.is_ipv4() != remote.is_ipv4() {
            return Err(Error::config(format!(
                "egress source {ip} family does not match remote {remote}"
            )));
        }
        let local = SocketAddr::new(ip, 0);
        sock.bind(&SockAddr::from(local)).map_err(|e| {
            // EADDRNOTAVAIL here almost always means the configured source IP
            // is not on this host. Say so instead of leaking a bare errno.
            Error::Io(std::io::Error::new(
                e.kind(),
                format!("bind source {ip} failed: {e} (is the address present on a local NIC?)"),
            ))
        })?;
    }

    // Tokio drives the connect; it requires a non-blocking, unconnected socket.
    sock.set_nonblocking(true)?;
    let std_stream: std::net::TcpStream = sock.into();
    Ok(TcpSocket::from_std_stream(std_stream))
}

#[cfg(target_os = "linux")]
fn bind_device(sock: &Socket, device: &str) -> Result<()> {
    sock.bind_device(Some(device.as_bytes())).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!(
                "SO_BINDTODEVICE({device}) failed: {e} — this option needs CAP_NET_RAW; \
                 prefer binding a source IP instead"
            ),
        ))
    })
}

#[cfg(not(target_os = "linux"))]
fn bind_device(_sock: &Socket, device: &str) -> Result<()> {
    Err(Error::config(format!(
        "egress_interface (`{device}`) uses SO_BINDTODEVICE, which is Linux-only; \
         use a source IP on this platform"
    )))
}

/// Connect to `target` with a timeout, honouring the egress binding.
///
/// `target` may be a DNS name. Candidate addresses are tried in order so an
/// exit whose AAAA record is black-holed still connects over IPv4.
pub async fn connect(
    target: &str,
    tuning: &TcpTuning,
    egress: &EgressBinding,
    timeout: Duration,
) -> Result<TcpStream> {
    let addrs = resolve(target, egress.source_ip).await?;
    let mut last_err = None;

    for addr in &addrs {
        // Skip families we structurally cannot reach from the pinned source.
        if let Some(ip) = egress.source_ip {
            if ip.is_ipv4() != addr.is_ipv4() {
                continue;
            }
        }
        let sock = match prepare_socket(addr, tuning, egress) {
            Ok(s) => s,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };
        match tokio::time::timeout(timeout, sock.connect(*addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => last_err = Some(Error::Io(e)),
            Err(_) => last_err = Some(Error::Timeout("tcp connect")),
        }
    }

    Err(last_err.unwrap_or_else(|| {
        Error::NotFound(format!("no reachable address for `{target}`"))
    }))
}

/// Bind a listener with `SO_REUSEADDR` and an explicit backlog.
///
/// The backlog matters under connection storms: the default of 128 combined
/// with a low `net.core.somaxconn` silently drops SYNs. See
/// `docs/linux-tuning.md`.
pub async fn listen(bind_addr: &str, backlog: u32, tuning: &TcpTuning) -> Result<TcpListener> {
    let addr: SocketAddr = bind_addr
        .parse()
        .map_err(|_| Error::config(format!("invalid listen address `{bind_addr}`")))?;

    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    // Lets the process restart without waiting out TIME_WAIT on the listener.
    // Deliberately *not* SO_REUSEPORT: two agents silently sharing a port is a
    // debugging nightmare, and a failed bind is the signal we want.
    #[cfg(not(windows))]
    sock.set_reuse_address(true)?;

    if addr.is_ipv6() {
        // Dual-stack listeners are surprising on multi-NIC hosts; keep v6
        // sockets v6-only and let the operator bind v4 explicitly.
        let _ = sock.set_only_v6(true);
    }
    tuning.apply_to_socket(&sock)?;

    sock.bind(&SockAddr::from(addr)).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("bind {addr} failed: {e}"),
        ))
    })?;
    sock.listen(backlog as i32)?;
    sock.set_nonblocking(true)?;

    let std_listener: std::net::TcpListener = sock.into();
    TcpListener::from_std(std_listener).map_err(Error::Io)
}

/// Local interfaces, for display and for validating configured source IPs.
///
/// Read-only by design: the panel shows what exists, it never edits the host's
/// network configuration.
pub fn interfaces() -> Vec<InterfaceInfo> {
    let mut map: std::collections::BTreeMap<String, InterfaceInfo> = Default::default();
    let Ok(addrs) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    for iface in addrs {
        let ip = iface.ip();
        let entry = map.entry(iface.name.clone()).or_insert_with(|| InterfaceInfo {
            name: iface.name.clone(),
            addresses: Vec::new(),
            is_loopback: iface.is_loopback(),
            is_up: true,
        });
        if !entry.addresses.contains(&ip) {
            entry.addresses.push(ip);
        }
    }
    map.into_values().collect()
}

/// `true` when `ip` is configured on some local interface.
///
/// Used to reject an `egress_source_ip` at config-validation time rather than
/// discovering it at the first `connect()` under load.
pub fn has_local_address(ip: IpAddr) -> bool {
    interfaces().iter().any(|i| i.addresses.contains(&ip))
}

/// Strip the port from a `SocketAddr` for logging without leaking client ports.
pub fn redact_port(addr: &SocketAddr) -> String {
    format!("{}:*", addr.ip())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn loopback_is_a_local_address() {
        // Every host we support has loopback configured.
        assert!(has_local_address(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn interfaces_include_loopback() {
        let ifs = interfaces();
        assert!(!ifs.is_empty(), "expected at least one interface");
        assert!(ifs.iter().any(|i| i.is_loopback));
    }

    #[tokio::test]
    async fn resolve_literal_skips_dns() {
        let addrs = resolve("127.0.0.1:8080", None).await.unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].port(), 8080);
    }

    #[tokio::test]
    async fn resolve_prefers_matching_family() {
        let addrs = resolve("localhost:80", Some(IpAddr::V4(Ipv4Addr::LOCALHOST)))
            .await
            .unwrap();
        assert!(addrs[0].is_ipv4(), "v4 source should sort v4 first");
    }

    #[tokio::test]
    async fn listen_then_connect_roundtrip() {
        let tuning = TcpTuning::default();
        let listener = listen("127.0.0.1:0", 128, &tuning).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let accept = tokio::spawn(async move { listener.accept().await });
        let stream = connect(
            &addr.to_string(),
            &tuning,
            &EgressBinding::default(),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert!(stream.peer_addr().is_ok());
        let (accepted, _) = accept.await.unwrap().unwrap();
        tuning.apply_to_stream(&accepted).unwrap();
    }

    #[tokio::test]
    async fn source_bind_to_loopback_works() {
        let tuning = TcpTuning::default();
        let listener = listen("127.0.0.1:0", 128, &tuning).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await });

        let egress = EgressBinding::from_source(Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        let stream = connect(&addr.to_string(), &tuning, &egress, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(stream.local_addr().unwrap().ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        let _ = accept.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn mismatched_source_family_is_rejected() {
        let tuning = TcpTuning::default();
        let egress = EgressBinding::from_source(Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        // v6 source against a v4 literal: no candidate survives the filter.
        let err = connect("127.0.0.1:1", &tuning, &egress, Duration::from_millis(500))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::NotFound(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn unavailable_source_ip_reports_clearly() {
        let tuning = TcpTuning::default();
        // 192.0.2.0/24 is TEST-NET-1; it is not configured on a real host.
        let egress = EgressBinding::from_source(Some("192.0.2.77".parse().unwrap()));
        let err = connect("127.0.0.1:9", &tuning, &egress, Duration::from_millis(500))
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("192.0.2.77"), "unhelpful error: {msg}");
    }

    #[tokio::test]
    async fn connect_is_bounded_by_the_timeout() {
        // Deliberately does not assert *which* outcome occurs: some hosts run a
        // transparent proxy that answers unrouted ranges. What must hold is that
        // the call returns within the budget instead of hanging, and that any
        // failure is classified as retryable so the supervisor backs off rather
        // than marking the endpoint structurally dead.
        let tuning = TcpTuning::default();
        let start = std::time::Instant::now();
        let outcome = connect(
            "192.0.2.1:443",
            &tuning,
            &EgressBinding::default(),
            Duration::from_millis(300),
        )
        .await;
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "connect ignored its timeout budget"
        );
        if let Err(e) = outcome {
            assert!(e.is_transient(), "connect failure should be retryable: {e:?}");
        }
    }

    #[test]
    fn timeout_and_reset_are_classified_retryable() {
        // The supervisor relies on this classification to choose "reconnect with
        // backoff" over "mark this endpoint structurally broken".
        assert!(Error::Timeout("tcp connect").is_transient());
        assert!(Error::Io(std::io::Error::from(
            std::io::ErrorKind::ConnectionRefused
        ))
        .is_transient());
        assert!(!Error::config("bad source ip").is_transient());
        assert!(!Error::protocol("bad frame").is_transient());
    }

    #[tokio::test]
    async fn invalid_listen_address_is_a_config_error() {
        let err = listen("not-an-address", 128, &TcpTuning::default())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn redacted_addr_hides_port() {
        let a: SocketAddr = "203.0.113.5:54321".parse().unwrap();
        assert_eq!(redact_port(&a), "203.0.113.5:*");
    }
}
