//! Bidirectional copy between a TCP socket and a logical tunnel stream.
//!
//! # The contract
//!
//! Bytes in equal bytes out, in order, with the connection lifecycle preserved.
//! This module never inspects, buffers-for-inspection, reorders or rewrites
//! payload. It has no idea whether it is carrying TLS, SSH or plain HTTP.
//!
//! # Why not `tokio::io::copy_bidirectional`
//!
//! `copy_bidirectional` works on two `AsyncRead + AsyncWrite` halves. Our tunnel
//! side is not a socket — it is a credit-controlled logical stream where
//! returning flow-control credit must be sequenced *after* the downstream write
//! completes. Wrapping the stream in an `AsyncWrite` shim would hide exactly the
//! sequencing point that makes backpressure work, so the copy loops are written
//! out. It also lets each direction report its own byte count for the stats, and
//! lets us translate EOF into a half-close rather than a full teardown.
//!
//! # Half-close
//!
//! A relay that closes both directions when one side EOFs breaks any protocol
//! that does `shutdown(SHUT_WR)` and then keeps reading. So:
//!
//! * socket EOF → `CLOSE` frame (peer sees FIN), keep reading the tunnel
//! * tunnel FIN → `shutdown()` on the socket, keep reading the socket
//! * either direction erroring → `RESET`, tear down both
//!
//! The relay finishes only when both directions have ended.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tunnel_common::{Error, Result};

use crate::metrics::{ConnectionHandle, Counters};
use crate::mux::StreamHandle;

/// Outcome of a completed relay, for logging and stats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RelayStats {
    /// Bytes read from the local socket and sent into the tunnel.
    pub to_tunnel: u64,
    /// Bytes received from the tunnel and written to the local socket.
    pub to_socket: u64,
    /// Both directions closed cleanly (FIN both ways), no reset.
    pub clean: bool,
}

/// Relay a local TCP socket against a logical tunnel stream until both
/// directions finish.
///
/// # Why two tasks, not one `select!`
///
/// The two directions must make progress independently. A single `select!` loop
/// deadlocks on a bulk transfer: the upload arm blocks in `stream.write()`
/// waiting for flow-control credit, credit only arrives once the peer drains the
/// download direction, and draining the download requires the *same* loop to
/// reach its other arm — which it cannot, because it is parked in the upload
/// arm. Two tasks make the dependency acyclic.
///
/// `idle_timeout` bounds a connection where *neither* direction moves a byte,
/// which is how half-open TCP connections left behind by a NAT rebind get
/// reclaimed. Zero disables it.
pub async fn relay<S>(
    socket: S,
    stream: StreamHandle,
    buffer_size: usize,
    idle_timeout: Duration,
    counters: Arc<Counters>,
    conn: Option<ConnectionHandle>,
) -> Result<RelayStats>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let stream_id = stream.stream_id;
    let (mut sock_reader, mut sock_writer) = tokio::io::split(socket);
    let (mut tun_reader, mut tun_writer) = stream.split();
    let buf_size = buffer_size.max(1024);

    // Shared "last activity" tick, so the idle watchdog sees progress in either
    // direction. Relaxed is fine: an off-by-one-interval reading cannot matter
    // for a multi-second timeout.
    let activity = Arc::new(AtomicU64::new(0));

    // --- socket → tunnel (upload) ---
    let up_activity = activity.clone();
    let up_counters = counters.clone();
    let up_conn = conn.clone();
    let upload = async move {
        let mut buf = vec![0u8; buf_size];
        let mut total = 0u64;
        loop {
            let n = match sock_reader.read(&mut buf).await {
                Ok(0) => {
                    // Client sent FIN. Propagate as a half-close so the target
                    // sees EOF while our download direction stays open.
                    let _ = tun_writer.shutdown_write().await;
                    return Ok(total);
                }
                Ok(n) => n,
                Err(e) => return Err((total, Error::Io(e))),
            };
            // `write` splits to the frame cap and awaits credit internally, so a
            // slow far end throttles this loop instead of buffering here.
            if let Err(e) = tun_writer.write(&buf[..n]).await {
                return Err((total, e));
            }
            total += n as u64;
            up_counters.add_rx(n as u64);
            if let Some(c) = &up_conn {
                c.add_rx(n as u64);
            }
            up_activity.fetch_add(1, Ordering::Relaxed);
        }
    };

    // --- tunnel → socket (download) ---
    let down_activity = activity.clone();
    let down_counters = counters.clone();
    let down_conn = conn.clone();
    let download = async move {
        let mut total = 0u64;
        loop {
            match tun_reader.read().await {
                Ok(Some(chunk)) => {
                    let n = chunk.len();
                    if let Err(e) = sock_writer.write_all(&chunk).await {
                        return Err((total, Error::Io(e)));
                    }
                    // Credit is returned only now, after the bytes have reached
                    // the kernel. Returning it on receipt would decouple the two
                    // connections' rates and allow unbounded buffering here.
                    tun_reader.credit_consumed(n);
                    total += n as u64;
                    down_counters.add_tx(n as u64);
                    if let Some(c) = &down_conn {
                        c.add_tx(n as u64);
                    }
                    down_activity.fetch_add(1, Ordering::Relaxed);
                }
                Ok(None) => {
                    // Peer half-closed: mirror it as a TCP FIN.
                    let _ = sock_writer.shutdown().await;
                    return Ok(total);
                }
                Err(e) => {
                    let _ = sock_writer.shutdown().await;
                    return Err((total, e));
                }
            }
        }
    };

    let idle_watchdog = async {
        if idle_timeout.is_zero() {
            // Never completes; the select simply never takes this branch.
            std::future::pending::<()>().await;
            return;
        }
        let mut last = activity.load(Ordering::Relaxed);
        loop {
            tokio::time::sleep(idle_timeout).await;
            let now = activity.load(Ordering::Relaxed);
            if now == last {
                return;
            }
            last = now;
        }
    };

    let mut to_tunnel = 0u64;
    let mut to_socket = 0u64;
    let mut reset = false;

    tokio::pin!(upload, download, idle_watchdog);

    let mut upload_done = false;
    let mut download_done = false;

    while !(upload_done && download_done) {
        tokio::select! {
            result = &mut upload, if !upload_done => {
                upload_done = true;
                match result {
                    Ok(n) => to_tunnel = n,
                    Err((n, e)) => {
                        to_tunnel = n;
                        tracing::debug!(stream = stream_id, error = %e, "upload direction failed");
                        reset = true;
                        break;
                    }
                }
            }
            result = &mut download, if !download_done => {
                download_done = true;
                match result {
                    Ok(n) => to_socket = n,
                    Err((n, e)) => {
                        to_socket = n;
                        tracing::debug!(stream = stream_id, error = %e, "download direction failed");
                        reset = true;
                        break;
                    }
                }
            }
            _ = &mut idle_watchdog => {
                tracing::debug!(
                    stream = stream_id,
                    timeout_secs = idle_timeout.as_secs(),
                    "connection idle; closing"
                );
                reset = true;
                break;
            }
        }
    }

    if reset {
        counters.on_fail();
    }

    Ok(RelayStats {
        to_tunnel,
        to_socket,
        clean: !reset,
    })
}

/// 两个真实 socket 之间的双向转发，用于直连模式。
///
/// 与 [`relay`] 的区别只在另一端是真实 socket 而非逻辑流，所以不涉及流控配额 ——
/// 两条 TCP 连接的速率由内核缓冲天然耦合：下游停读 → 发送缓冲满 → 我们的写阻塞
/// → 停止从上游读 → 上游被反压。这正是 [`relay`] 需要用 credit 机制人工重建的
/// 那套语义，在这里免费得到。
///
/// 半关闭同样保留：一端 EOF 只关对应方向，另一方向继续，直到两端都结束。
pub async fn relay_sockets<A, B>(
    downstream: A,
    upstream: B,
    buffer_size: usize,
    idle_timeout: Duration,
    counters: Arc<Counters>,
    conn: Option<ConnectionHandle>,
) -> Result<RelayStats>
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut down_r, mut down_w) = tokio::io::split(downstream);
    let (mut up_r, mut up_w) = tokio::io::split(upstream);
    let buf_size = buffer_size.max(1024);

    let activity = Arc::new(AtomicU64::new(0));

    // 与 relay() 同样用两个独立任务而非单个 select：一个方向阻塞在写上时，另一个
    // 方向必须能继续推进，否则大流量传输会死锁。
    let up_activity = activity.clone();
    let up_counters = counters.clone();
    let up_conn = conn.clone();
    let uplink = async move {
        let mut buf = vec![0u8; buf_size];
        let mut total = 0u64;
        loop {
            let n = match down_r.read(&mut buf).await {
                Ok(0) => {
                    // 客户端发了 FIN：只关上行，让目标看到 EOF，下行仍可继续。
                    let _ = up_w.shutdown().await;
                    return Ok(total);
                }
                Ok(n) => n,
                Err(e) => return Err((total, Error::Io(e))),
            };
            if let Err(e) = up_w.write_all(&buf[..n]).await {
                return Err((total, Error::Io(e)));
            }
            total += n as u64;
            up_counters.add_rx(n as u64);
            if let Some(c) = &up_conn {
                c.add_rx(n as u64);
            }
            up_activity.fetch_add(1, Ordering::Relaxed);
        }
    };

    let down_activity = activity.clone();
    let down_counters = counters.clone();
    let down_conn = conn.clone();
    let downlink = async move {
        let mut buf = vec![0u8; buf_size];
        let mut total = 0u64;
        loop {
            let n = match up_r.read(&mut buf).await {
                Ok(0) => {
                    let _ = down_w.shutdown().await;
                    return Ok(total);
                }
                Ok(n) => n,
                Err(e) => return Err((total, Error::Io(e))),
            };
            if let Err(e) = down_w.write_all(&buf[..n]).await {
                return Err((total, Error::Io(e)));
            }
            total += n as u64;
            down_counters.add_tx(n as u64);
            if let Some(c) = &down_conn {
                c.add_tx(n as u64);
            }
            down_activity.fetch_add(1, Ordering::Relaxed);
        }
    };

    let idle_watchdog = async {
        if idle_timeout.is_zero() {
            std::future::pending::<()>().await;
            return;
        }
        let mut last = activity.load(Ordering::Relaxed);
        loop {
            tokio::time::sleep(idle_timeout).await;
            let now = activity.load(Ordering::Relaxed);
            if now == last {
                return;
            }
            last = now;
        }
    };

    let mut to_tunnel = 0u64;
    let mut to_socket = 0u64;
    let mut reset = false;

    tokio::pin!(uplink, downlink, idle_watchdog);
    let mut up_done = false;
    let mut down_done = false;

    while !(up_done && down_done) {
        tokio::select! {
            result = &mut uplink, if !up_done => {
                up_done = true;
                match result {
                    Ok(n) => to_tunnel = n,
                    Err((n, e)) => {
                        to_tunnel = n;
                        tracing::debug!(error = %e, "直连上行方向失败");
                        reset = true;
                        break;
                    }
                }
            }
            result = &mut downlink, if !down_done => {
                down_done = true;
                match result {
                    Ok(n) => to_socket = n,
                    Err((n, e)) => {
                        to_socket = n;
                        tracing::debug!(error = %e, "直连下行方向失败");
                        reset = true;
                        break;
                    }
                }
            }
            _ = &mut idle_watchdog => {
                tracing::debug!(
                    timeout_secs = idle_timeout.as_secs(),
                    "直连连接空闲超时，关闭"
                );
                reset = true;
                break;
            }
        }
    }

    if reset {
        counters.on_fail();
    }

    Ok(RelayStats {
        to_tunnel,
        to_socket,
        clean: !reset,
    })
}

/// Dial the target for an inbound stream, honouring the egress binding.
///
/// Separated from [`relay`] so the exit can answer `OPEN_OK`/`OPEN_ERROR` before
/// any payload is copied.
pub async fn dial_target(
    target: &str,
    tuning: &tunnel_common::net::TcpTuning,
    egress: &tunnel_common::net::EgressBinding,
    timeout: Duration,
) -> Result<tokio::net::TcpStream> {
    tunnel_common::net::connect(target, tuning, egress, timeout)
        .await
        .map_err(|e| {
            // Keep the reason short: it goes into an OPEN_ERROR frame.
            match e {
                Error::Timeout(_) => Error::other(format!("target {target} connect timed out")),
                other => Error::other(format!("target {target}: {other}")),
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::TunnelMetrics;
    use crate::mux::{IncomingStream, MuxConfig, MuxRole, Multiplexer};
    use tokio::io::duplex;
    use tokio::sync::mpsc;

    fn cfg(role: MuxRole) -> MuxConfig {
        MuxConfig {
            role,
            max_frame_payload: 16 * 1024,
            stream_window: 64 * 1024,
            send_queue_depth: 256,
            stream_queue_depth: 16,
            max_streams: 64,
            ping_interval: Duration::from_secs(3600),
            ping_timeout: Duration::from_secs(5),
            ping_max_failures: 3,
        }
    }

    fn mux_pair() -> (
        Arc<Multiplexer>,
        Arc<Multiplexer>,
        mpsc::Receiver<IncomingStream>,
    ) {
        let (a, b) = duplex(1024 * 1024);
        let (tx, rx) = mpsc::channel(16);
        let init = Multiplexer::start(a, cfg(MuxRole::Initiator), TunnelMetrics::new(1), None);
        let resp = Multiplexer::start(b, cfg(MuxRole::Responder), TunnelMetrics::new(2), Some(tx));
        (init, resp, rx)
    }

    /// Spawn an exit-side relay that connects each inbound stream to `target`.
    fn spawn_exit_relay(mut incoming: mpsc::Receiver<IncomingStream>, target: String) {
        tokio::spawn(async move {
            while let Some(mut s) = incoming.recv().await {
                let target = target.clone();
                tokio::spawn(async move {
                    let sock = tokio::net::TcpStream::connect(&target).await.unwrap();
                    // Mirror the real exit: confirm only after the target is up.
                    if s.handle.accept().await.is_err() {
                        return;
                    }
                    let _ = relay(
                        sock,
                        s.handle,
                        16 * 1024,
                        Duration::ZERO,
                        Counters::new(),
                        None,
                    )
                    .await;
                });
            }
        });
    }

    /// Echo server used as the "target" behind the exit.
    async fn spawn_echo_server() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
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
        addr
    }

    #[tokio::test]
    async fn end_to_end_echo_through_the_tunnel() {
        let target = spawn_echo_server().await;
        let (init, _resp, incoming) = mux_pair();
        spawn_exit_relay(incoming, target);

        // Client side: a duplex standing in for the accepted user socket.
        let (mut client, client_side) = duplex(64 * 1024);
        let stream = init
            .open_stream("r1", None, Duration::from_secs(5))
            .await
            .unwrap();
        tokio::spawn(async move {
            relay(
                client_side,
                stream,
                16 * 1024,
                Duration::ZERO,
                Counters::new(),
                None,
            )
            .await
        });

        client.write_all(b"hello through the tunnel").await.unwrap();
        client.flush().await.unwrap();
        let mut buf = vec![0u8; 24];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello through the tunnel");
    }

    #[tokio::test]
    async fn large_transfer_is_byte_exact() {
        // The headline guarantee, over the full entry→mux→exit→target path.
        let target = spawn_echo_server().await;
        let (init, _resp, incoming) = mux_pair();
        spawn_exit_relay(incoming, target);

        let (mut client, client_side) = duplex(256 * 1024);
        let stream = init
            .open_stream("r1", None, Duration::from_secs(5))
            .await
            .unwrap();
        let counters = Counters::new();
        let relay_counters = counters.clone();
        tokio::spawn(async move {
            relay(
                client_side,
                stream,
                16 * 1024,
                Duration::ZERO,
                relay_counters,
                None,
            )
            .await
        });

        // 1 MiB with a non-repeating pattern: any dropped, duplicated or
        // reordered chunk changes the comparison.
        const N: usize = 1024 * 1024;
        let payload: Vec<u8> = (0..N).map(|i| ((i * 7 + i / 251) % 256) as u8).collect();
        let expected = payload.clone();

        let writer = tokio::spawn(async move {
            client.write_all(&payload).await.unwrap();
            client.flush().await.unwrap();
            let mut got = vec![0u8; N];
            client.read_exact(&mut got).await.unwrap();
            got
        });

        let got = tokio::time::timeout(Duration::from_secs(60), writer)
            .await
            .expect("transfer stalled")
            .unwrap();
        assert_eq!(got.len(), expected.len());
        assert_eq!(got, expected, "payload corrupted end to end");
        assert_eq!(counters.rx(), N as u64);
        assert_eq!(counters.tx(), N as u64);
    }

    #[tokio::test]
    async fn half_close_reaches_the_target() {
        // A target that replies only after it sees EOF. This only works if the
        // relay translates socket EOF into a tunnel CLOSE, and the exit relay
        // translates that into shutdown() on the target socket.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            sock.read_to_end(&mut received).await.unwrap();
            sock.write_all(format!("got {} bytes", received.len()).as_bytes())
                .await
                .unwrap();
            sock.shutdown().await.unwrap();
        });

        let (init, _resp, incoming) = mux_pair();
        spawn_exit_relay(incoming, addr);

        let (mut client, client_side) = duplex(64 * 1024);
        let stream = init
            .open_stream("r1", None, Duration::from_secs(5))
            .await
            .unwrap();
        tokio::spawn(async move {
            relay(
                client_side,
                stream,
                16 * 1024,
                Duration::ZERO,
                Counters::new(),
                None,
            )
            .await
        });

        client.write_all(b"0123456789").await.unwrap();
        client.flush().await.unwrap();
        client.shutdown().await.unwrap();

        let mut reply = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut reply))
            .await
            .expect("target never saw EOF; half-close was not propagated")
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&reply),
            "got 10 bytes",
            "half-close did not reach the target"
        );
    }

    #[tokio::test]
    async fn target_close_propagates_back_to_the_client() {
        // Target closes immediately; the client must observe EOF, not a hang.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(b"bye").await.unwrap();
            sock.shutdown().await.unwrap();
        });

        let (init, _resp, incoming) = mux_pair();
        spawn_exit_relay(incoming, addr);

        let (mut client, client_side) = duplex(64 * 1024);
        let stream = init
            .open_stream("r1", None, Duration::from_secs(5))
            .await
            .unwrap();
        tokio::spawn(async move {
            relay(
                client_side,
                stream,
                16 * 1024,
                Duration::ZERO,
                Counters::new(),
                None,
            )
            .await
        });

        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut got))
            .await
            .expect("client never saw EOF")
            .unwrap();
        assert_eq!(&got, b"bye");
    }

    #[tokio::test]
    async fn idle_timeout_closes_a_silent_connection() {
        let target = spawn_echo_server().await;
        let (init, _resp, incoming) = mux_pair();
        spawn_exit_relay(incoming, target);

        let (client, client_side) = duplex(64 * 1024);
        let stream = init
            .open_stream("r1", None, Duration::from_secs(5))
            .await
            .unwrap();
        let counters = Counters::new();
        let handle = tokio::spawn({
            let counters = counters.clone();
            async move {
                relay(
                    client_side,
                    stream,
                    16 * 1024,
                    Duration::from_millis(200),
                    counters,
                    None,
                )
                .await
            }
        });

        // Never write anything; the relay should give up on its own.
        let stats = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("idle timeout never fired")
            .unwrap()
            .unwrap();
        assert!(!stats.clean, "idle close should be reported as unclean");
        assert_eq!(stats.to_tunnel, 0);
        drop(client);
    }

    #[tokio::test]
    async fn stats_count_both_directions() {
        let target = spawn_echo_server().await;
        let (init, _resp, incoming) = mux_pair();
        spawn_exit_relay(incoming, target);

        let (mut client, client_side) = duplex(64 * 1024);
        let stream = init
            .open_stream("r1", None, Duration::from_secs(5))
            .await
            .unwrap();
        let handle = tokio::spawn(async move {
            relay(
                client_side,
                stream,
                16 * 1024,
                Duration::ZERO,
                Counters::new(),
                None,
            )
            .await
        });

        client.write_all(&vec![9u8; 5000]).await.unwrap();
        client.flush().await.unwrap();
        let mut buf = vec![0u8; 5000];
        client.read_exact(&mut buf).await.unwrap();
        client.shutdown().await.unwrap();
        drop(client);

        let stats = tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("relay did not finish")
            .unwrap()
            .unwrap();
        assert_eq!(stats.to_tunnel, 5000);
        assert_eq!(stats.to_socket, 5000);
    }

    #[tokio::test]
    async fn tunnel_death_terminates_the_relay() {
        // A relay must never outlive its tunnel; leaking these is how an agent
        // ends up with thousands of zombie tasks.
        let target = spawn_echo_server().await;
        let (init, _resp, incoming) = mux_pair();
        spawn_exit_relay(incoming, target);

        let (_client, client_side) = duplex(64 * 1024);
        let stream = init
            .open_stream("r1", None, Duration::from_secs(5))
            .await
            .unwrap();
        let handle = tokio::spawn(async move {
            relay(
                client_side,
                stream,
                16 * 1024,
                Duration::ZERO,
                Counters::new(),
                None,
            )
            .await
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        init.force_close();

        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("relay outlived its tunnel")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn direct_relay_is_byte_exact() {
        // 直连模式的核心保证与隧道模式相同：进出字节完全一致。
        let target = spawn_echo_server().await;
        let upstream = tokio::net::TcpStream::connect(&target).await.unwrap();
        let (mut client, client_side) = duplex(256 * 1024);

        let counters = Counters::new();
        let handle = tokio::spawn({
            let counters = counters.clone();
            async move {
                relay_sockets(
                    client_side,
                    upstream,
                    16 * 1024,
                    Duration::ZERO,
                    counters,
                    None,
                )
                .await
            }
        });

        const N: usize = 512 * 1024;
        let payload: Vec<u8> = (0..N).map(|i| ((i * 13 + i / 97) % 256) as u8).collect();
        let expected = payload.clone();

        let writer = tokio::spawn(async move {
            client.write_all(&payload).await.unwrap();
            client.flush().await.unwrap();
            let mut got = vec![0u8; N];
            client.read_exact(&mut got).await.unwrap();
            got
        });

        let got = tokio::time::timeout(Duration::from_secs(60), writer)
            .await
            .expect("直连传输卡住")
            .unwrap();
        assert_eq!(got, expected, "直连转发的字节流被破坏");
        assert_eq!(counters.rx(), N as u64);
        assert_eq!(counters.tx(), N as u64);
        handle.abort();
    }

    #[tokio::test]
    async fn direct_relay_propagates_half_close() {
        // 目标只在看到 EOF 后才回复 —— 只有半关闭被正确传播才能通过。
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            sock.read_to_end(&mut received).await.unwrap();
            sock.write_all(format!("收到 {} 字节", received.len()).as_bytes())
                .await
                .unwrap();
            sock.shutdown().await.unwrap();
        });

        let upstream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut client, client_side) = duplex(64 * 1024);
        let counters = Counters::new();
        let relay_counters = counters.clone();
        tokio::spawn(async move {
            relay_sockets(
                client_side,
                upstream,
                16 * 1024,
                Duration::ZERO,
                relay_counters,
                None,
            )
            .await
        });

        client.write_all(b"0123456789").await.unwrap();
        client.flush().await.unwrap();
        client.shutdown().await.unwrap();

        let mut reply = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut reply))
            .await
            .expect("目标从未看到 EOF，半关闭没有传播")
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&reply), "收到 10 字节");
        assert_eq!(counters.rx(), 10, "接收记录客户端发往目标的字节");
        assert_eq!(counters.tx(), reply.len() as u64, "发送记录目标返回的字节");
    }

    #[tokio::test]
    async fn direct_relay_honours_the_idle_timeout() {
        let target = spawn_echo_server().await;
        let upstream = tokio::net::TcpStream::connect(&target).await.unwrap();
        let (client, client_side) = duplex(64 * 1024);

        let handle = tokio::spawn(async move {
            relay_sockets(
                client_side,
                upstream,
                16 * 1024,
                Duration::from_millis(200),
                Counters::new(),
                None,
            )
            .await
        });

        let stats = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("空闲超时没有触发")
            .unwrap()
            .unwrap();
        assert!(!stats.clean, "空闲关闭应记为非正常结束");
        drop(client);
    }

    #[tokio::test]
    async fn direct_relay_ends_when_the_target_closes() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(b"bye").await.unwrap();
            sock.shutdown().await.unwrap();
        });

        let upstream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut client, client_side) = duplex(64 * 1024);
        tokio::spawn(async move {
            relay_sockets(
                client_side,
                upstream,
                16 * 1024,
                Duration::ZERO,
                Counters::new(),
                None,
            )
            .await
        });

        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut got))
            .await
            .expect("客户端没有收到 EOF")
            .unwrap();
        assert_eq!(&got, b"bye");
    }

    #[tokio::test]
    async fn dial_failure_is_reported_with_the_target() {
        let err = dial_target(
            "127.0.0.1:1",
            &tunnel_common::net::TcpTuning::default(),
            &tunnel_common::net::EgressBinding::default(),
            Duration::from_millis(500),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("127.0.0.1:1"), "{err}");
    }

    #[tokio::test]
    async fn dial_succeeds_against_a_live_listener() {
        let target = spawn_echo_server().await;
        let sock = dial_target(
            &target,
            &tunnel_common::net::TcpTuning::default(),
            &tunnel_common::net::EgressBinding::default(),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert!(sock.peer_addr().is_ok());
    }
}
