//! Stream multiplexer: one TLS connection, N logical TCP streams.
//!
//! # Task topology
//!
//! ```text
//!                    ┌──────────────── writer task ◀── mpsc(bounded) ◀── many stream writers
//!   TLS conn ────────┤                                                   + ping task
//!                    └──────────────── reader task ──▶ per-stream mpsc(bounded) ──▶ stream readers
//! ```
//!
//! Exactly two tasks own the TLS connection: one reads, one writes. No mutex on
//! the socket. Everything else talks to them through bounded channels.
//!
//! # Flow control, and why it is not optional
//!
//! Without credit accounting, a fast sender on one stream fills the writer queue
//! and starves every other stream on the tunnel — and if the queue were
//! unbounded it would simply consume all RAM until the OOM killer arrives.
//!
//! The scheme is per-stream credit:
//!
//! * A receiver grants `stream_window` bytes at OPEN time.
//! * A sender decrements its credit by each DATA payload it sends, and blocks
//!   when credit reaches zero.
//! * As the receiver drains bytes into the real TCP socket, it returns credit
//!   with `WINDOW_UPDATE`.
//!
//! The important part is *when* credit is returned: only after the bytes have
//! been written to the downstream socket, never on receipt. That is what couples
//! the two TCP connections' rates together. If the target stops reading, the
//! kernel send buffer fills, our write blocks, credit stops flowing, and the
//! original client's socket applies backpressure to its own sender. End-to-end
//! backpressure with bounded memory, which is the whole point.
//!
//! Credit is batched: sending a `WINDOW_UPDATE` per 1 KiB chunk would drown the
//! tunnel in control frames, so updates are deferred until half the window is
//! consumed.
//!
//! # Head-of-line blocking
//!
//! This is a real and unavoidable limitation. All streams on one tunnel share
//! one TCP connection, so a lost segment stalls *every* stream behind it until
//! retransmission. Multiplexing cannot fix that; it is a property of running
//! streams over a single ordered transport.
//!
//! The mitigation is architectural, in [`crate::pool`]: a route runs several
//! tunnel connections and spreads streams across them, so one stalled TCP
//! connection affects a fraction of traffic rather than all of it. That is why
//! `tunnel_pool_size` defaults to 8 and why a single-connection design was
//! rejected.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot, Notify};
use tunnel_common::model::TunnelState;
use tunnel_common::{Error, Result};
use tunnel_protocol::{
    codec::{FrameReader, FrameWriter},
    frame::{Frame, FrameType, StreamId},
};

use crate::metrics::TunnelMetrics;

const REL: Ordering = Ordering::Relaxed;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxRole {
    /// Allocates stream ids and sends OPEN. Only the entry does this.
    Initiator,
    /// Accepts OPEN and dials the target.
    Responder,
}

#[derive(Debug, Clone)]
pub struct MuxConfig {
    pub role: MuxRole,
    pub max_frame_payload: usize,
    pub stream_window: u32,
    pub send_queue_depth: usize,
    pub stream_queue_depth: usize,
    pub max_streams: u32,
    pub ping_interval: Duration,
    pub ping_timeout: Duration,
    pub ping_max_failures: u32,
}

impl MuxConfig {
    pub fn from_limits(
        role: MuxRole,
        limits: &tunnel_common::model::Limits,
        negotiated_payload: u32,
        negotiated_window: u32,
    ) -> Self {
        Self {
            role,
            max_frame_payload: negotiated_payload as usize,
            stream_window: negotiated_window,
            send_queue_depth: limits.tunnel_send_queue,
            stream_queue_depth: limits.stream_recv_queue,
            max_streams: limits.max_streams_per_tunnel,
            ping_interval: limits.ping_interval,
            ping_timeout: limits.ping_timeout,
            ping_max_failures: limits.ping_max_failures,
        }
    }
}

/// What the writer task accepts.
enum Outbound {
    Frame(Frame),
    /// Flush and stop. The oneshot fires once the TLS connection is shut down.
    Shutdown(Option<oneshot::Sender<()>>),
}

/// Messages delivered to a stream's reader.
#[derive(Debug)]
enum Inbound {
    Data(Bytes),
    /// Peer half-closed: no more data, but our direction may still be open.
    Fin,
    /// Abortive close.
    Reset,
}

/// Send-side credit for one stream.
///
/// `Notify` rather than a semaphore: credit arrives in arbitrary byte amounts,
/// and a semaphore's permit model does not express "wake anyone waiting, there
/// are now N more bytes available" without awkward permit arithmetic.
#[derive(Debug)]
struct Credit {
    available: AtomicU64,
    notify: Notify,
    closed: AtomicBool,
}

impl Credit {
    fn new(initial: u32) -> Self {
        Self {
            available: AtomicU64::new(initial as u64),
            notify: Notify::new(),
            closed: AtomicBool::new(false),
        }
    }

    /// Reserve up to `wanted` bytes, waiting if nothing is available.
    ///
    /// Returns the amount actually reserved, which may be less than `wanted` —
    /// the caller must send only that much. Returns `Err` if the stream closed
    /// while waiting.
    async fn reserve(&self, wanted: usize) -> Result<usize> {
        loop {
            if self.closed.load(REL) {
                return Err(Error::Closed);
            }
            let current = self.available.load(REL);
            if current > 0 {
                let take = current.min(wanted as u64);
                // CAS so two writers on the same stream cannot both claim it.
                if self
                    .available
                    .compare_exchange(current, current - take, REL, REL)
                    .is_ok()
                {
                    return Ok(take as usize);
                }
                continue;
            }
            // Register before re-checking to avoid missing a concurrent grant.
            let waiter = self.notify.notified();
            if self.available.load(REL) > 0 || self.closed.load(REL) {
                continue;
            }
            waiter.await;
        }
    }

    fn grant(&self, amount: u32) {
        self.available.fetch_add(amount as u64, REL);
        self.notify.notify_waiters();
    }

    fn close(&self) {
        self.closed.store(true, REL);
        self.notify.notify_waiters();
    }
}

/// Receive-side window accounting. Defers `WINDOW_UPDATE` until enough has been
/// consumed to be worth a frame.
#[derive(Debug)]
struct Window {
    window: u32,
    consumed: AtomicU32,
}

impl Window {
    fn new(window: u32) -> Self {
        Self {
            window,
            consumed: AtomicU32::new(0),
        }
    }

    /// Record `n` bytes handed downstream; returns credit to return, if any.
    fn consume(&self, n: u32) -> Option<u32> {
        let threshold = (self.window / 2).max(1);
        let prev = self.consumed.fetch_add(n, REL);
        let total = prev.saturating_add(n);
        if total >= threshold {
            // Swap to zero and return whatever we accumulated. A concurrent
            // consume may have added more; swap captures the true total.
            let to_return = self.consumed.swap(0, REL);
            (to_return > 0).then_some(to_return)
        } else {
            None
        }
    }
}

struct StreamEntry {
    inbound: mpsc::Sender<Inbound>,
    credit: Arc<Credit>,
    /// Fires once when OPEN_OK / OPEN_ERROR arrives (initiator side only).
    open_result: std::sync::Mutex<Option<oneshot::Sender<Result<()>>>>,
    last_activity: AtomicU64,
    created: Instant,
}

impl StreamEntry {
    fn touch(&self) {
        self.last_activity
            .store(self.created.elapsed().as_secs(), REL);
    }

    fn idle_secs(&self) -> u64 {
        self.created
            .elapsed()
            .as_secs()
            .saturating_sub(self.last_activity.load(REL))
    }
}

/// State shared by a stream's read and write halves.
///
/// Cleanup lives in this type's `Drop`, so a stream releases its slot and wakes
/// its blocked writer exactly once, when the *last* half goes away — no matter
/// which half is dropped first or which error path got us here.
struct StreamShared {
    stream_id: StreamId,
    outbound: mpsc::Sender<Outbound>,
    credit: Arc<Credit>,
    max_payload: usize,
    /// Set once a CLOSE/RESET/OPEN_ERROR has been sent, so `Drop` does not
    /// follow a clean shutdown with a spurious RST.
    closed_tx: AtomicBool,
    streams: Arc<DashMap<StreamId, Arc<StreamEntry>>>,
    stream_count: Arc<AtomicU32>,
}

impl Drop for StreamShared {
    fn drop(&mut self) {
        if self.streams.remove(&self.stream_id).is_some() {
            let _ = self
                .stream_count
                .fetch_update(REL, REL, |v| Some(v.saturating_sub(1)));
        }
        self.credit.close();
        if !self.closed_tx.load(REL) {
            // Best-effort RST so the peer does not keep a half-open stream.
            let _ = self
                .outbound
                .try_send(Outbound::Frame(Frame::reset(self.stream_id)));
        }
    }
}

/// Receive half of a logical stream.
pub struct StreamReadHalf {
    shared: Arc<StreamShared>,
    inbound: mpsc::Receiver<Inbound>,
    window: Arc<Window>,
    peer_fin: bool,
}

impl StreamReadHalf {
    pub fn stream_id(&self) -> StreamId {
        self.shared.stream_id
    }

    /// Read the next chunk of peer data.
    ///
    /// `Ok(None)` is a clean half-close (peer sent FIN) and must be translated
    /// into a TCP FIN on the downstream socket, not a full close — that is how
    /// protocols doing a one-way shutdown keep working through the tunnel.
    pub async fn read(&mut self) -> Result<Option<Bytes>> {
        if self.peer_fin {
            return Ok(None);
        }
        match self.inbound.recv().await {
            Some(Inbound::Data(chunk)) => Ok(Some(chunk)),
            Some(Inbound::Fin) => {
                self.peer_fin = true;
                Ok(None)
            }
            Some(Inbound::Reset) => Err(Error::Closed),
            // Sender dropped: the tunnel died under us.
            None => Err(Error::Closed),
        }
    }

    /// Return flow-control credit after bytes have been written downstream.
    ///
    /// Must be called *after* the downstream write completes. Calling it on
    /// receipt would decouple the two TCP connections' rates and defeat the
    /// entire backpressure design.
    pub fn credit_consumed(&self, n: usize) {
        if let Some(credit) = self.window.consume(n as u32) {
            // A congested tunnel can refuse the update. Dropping it would stall
            // the stream permanently, so re-accumulate and retry on the next
            // consume.
            let frame = Frame::window_update(self.shared.stream_id, credit);
            if self
                .shared
                .outbound
                .try_send(Outbound::Frame(frame))
                .is_err()
            {
                self.window.consumed.fetch_add(credit, REL);
            }
        }
    }
}

/// Send half of a logical stream.
pub struct StreamWriteHalf {
    shared: Arc<StreamShared>,
}

impl StreamWriteHalf {
    pub fn stream_id(&self) -> StreamId {
        self.shared.stream_id
    }

    /// Write `data` to the peer, respecting credit and the frame cap.
    ///
    /// Splits into frames as needed and awaits credit between them, so a single
    /// large write paces itself against the far end's consumption.
    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
        if self.shared.closed_tx.load(REL) {
            return Err(Error::Closed);
        }
        let mut offset = 0;
        while offset < data.len() {
            let want = (data.len() - offset).min(self.shared.max_payload);
            let allowed = self.shared.credit.reserve(want).await?;
            let chunk = Bytes::copy_from_slice(&data[offset..offset + allowed]);
            self.shared
                .outbound
                .send(Outbound::Frame(Frame::data(self.shared.stream_id, chunk)))
                .await
                .map_err(|_| Error::Closed)?;
            offset += allowed;
        }
        Ok(())
    }

    /// Confirm the stream to the peer (`OPEN_OK`). Responder side only.
    ///
    /// Must be called **after** the target connection succeeds. That ordering
    /// lets the entry distinguish "the exit accepted and the target is
    /// reachable" from "the exit took the request but the target is down".
    /// Sending OPEN_OK eagerly would report success for connections that are
    /// about to fail.
    pub async fn accept(&mut self) -> Result<()> {
        self.shared
            .outbound
            .send(Outbound::Frame(Frame::open_ok(self.shared.stream_id)))
            .await
            .map_err(|_| Error::Closed)
    }

    /// Refuse the stream with a reason (`OPEN_ERROR`). Responder side only.
    pub async fn reject(&mut self, reason: &str) {
        self.shared.closed_tx.store(true, REL);
        let _ = self
            .shared
            .outbound
            .send(Outbound::Frame(Frame::open_error(
                self.shared.stream_id,
                reason,
            )))
            .await;
    }

    /// Signal half-close (FIN) to the peer. Idempotent.
    pub async fn shutdown_write(&mut self) -> Result<()> {
        if self.shared.closed_tx.swap(true, REL) {
            return Ok(());
        }
        self.shared
            .outbound
            .send(Outbound::Frame(Frame::close(self.shared.stream_id)))
            .await
            .map_err(|_| Error::Closed)
    }

    /// Abort the stream (RST). Used when the downstream socket errors.
    pub async fn reset(&mut self) {
        self.shared.closed_tx.store(true, REL);
        let _ = self
            .shared
            .outbound
            .send(Outbound::Frame(Frame::reset(self.shared.stream_id)))
            .await;
    }
}

/// Handle to one logical stream.
///
/// Split into independent halves with [`StreamHandle::split`] before relaying.
/// The relay *must* drive both directions concurrently; servicing them from a
/// single `select!` arm deadlocks as soon as one direction's write blocks while
/// the other still has data to move.
pub struct StreamHandle {
    pub stream_id: StreamId,
    r: StreamReadHalf,
    w: StreamWriteHalf,
}

impl StreamHandle {
    /// Split into read and write halves for concurrent use.
    pub fn split(self) -> (StreamReadHalf, StreamWriteHalf) {
        (self.r, self.w)
    }

    pub async fn read(&mut self) -> Result<Option<Bytes>> {
        self.r.read().await
    }

    pub fn credit_consumed(&self, n: usize) {
        self.r.credit_consumed(n);
    }

    pub async fn write(&mut self, data: &[u8]) -> Result<()> {
        self.w.write(data).await
    }

    pub async fn accept(&mut self) -> Result<()> {
        self.w.accept().await
    }

    pub async fn reject(&mut self, reason: &str) {
        self.w.reject(reason).await;
    }

    pub async fn shutdown_write(&mut self) -> Result<()> {
        self.w.shutdown_write().await
    }

    pub async fn reset(&mut self) {
        self.w.reset().await;
    }
}

impl std::fmt::Debug for StreamHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamHandle")
            .field("stream_id", &self.stream_id)
            .field("closed_tx", &self.w.shared.closed_tx.load(REL))
            .field("peer_fin", &self.r.peer_fin)
            .finish()
    }
}

/// An inbound stream opened by the peer, handed to the exit's accept loop.
pub struct IncomingStream {
    pub handle: StreamHandle,
    pub route_id: String,
    pub client_addr: Option<String>,
}

/// The multiplexer. Cloneable handle; the tasks live independently.
pub struct Multiplexer {
    cfg: MuxConfig,
    outbound: mpsc::Sender<Outbound>,
    streams: Arc<DashMap<StreamId, Arc<StreamEntry>>>,
    stream_count: Arc<AtomicU32>,
    next_stream_id: AtomicU32,
    metrics: Arc<TunnelMetrics>,
    closed: Arc<AtomicBool>,
    /// Set when the peer sends GO_AWAY: finish existing streams, open no new ones.
    draining: Arc<AtomicBool>,
    /// Incremented by the reader task on every PONG. The ping task snapshots it
    /// before sending and watches for a change, which is how two independent
    /// tasks agree that *this* ping was answered without sharing a channel.
    ///
    /// Per-multiplexer on purpose: a process-wide counter would let a healthy
    /// tunnel's PONG mask a dead tunnel's missed heartbeat.
    pong_tick: Arc<AtomicU64>,
    /// Notified alongside `pong_tick` so the ping task can await instead of
    /// polling on a timer.
    pong_signal: Arc<Notify>,
}

impl Multiplexer {
    /// Split a TLS connection into reader/writer tasks and return the handle.
    ///
    /// `incoming` receives streams the peer opens. On the entry side nothing is
    /// expected there; an OPEN arriving at an initiator is a protocol error.
    pub fn start<S>(
        conn: S,
        cfg: MuxConfig,
        metrics: Arc<TunnelMetrics>,
        incoming: Option<mpsc::Sender<IncomingStream>>,
    ) -> Arc<Self>
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (read_half, write_half) = tokio::io::split(conn);
        let (outbound_tx, outbound_rx) = mpsc::channel::<Outbound>(cfg.send_queue_depth);

        let streams: Arc<DashMap<StreamId, Arc<StreamEntry>>> = Arc::new(DashMap::new());
        let stream_count = Arc::new(AtomicU32::new(0));
        let closed = Arc::new(AtomicBool::new(false));
        let draining = Arc::new(AtomicBool::new(false));

        let mux = Arc::new(Self {
            cfg: cfg.clone(),
            outbound: outbound_tx.clone(),
            streams: streams.clone(),
            stream_count: stream_count.clone(),
            // Stream 0 is reserved for control frames, so ids start at 1.
            next_stream_id: AtomicU32::new(1),
            metrics: metrics.clone(),
            closed: closed.clone(),
            draining: draining.clone(),
            pong_tick: Arc::new(AtomicU64::new(0)),
            pong_signal: Arc::new(Notify::new()),
        });

        // --- writer task ---
        {
            let cfg = cfg.clone();
            let closed = closed.clone();
            tokio::spawn(async move {
                let mut writer = FrameWriter::new(write_half, cfg.max_frame_payload);
                let mut rx = outbound_rx;
                loop {
                    let Some(first) = rx.recv().await else { break };
                    let mut shutdown_ack = None;
                    let mut stop = false;

                    match first {
                        Outbound::Frame(f) => {
                            if let Err(e) = writer.queue(&f) {
                                tracing::warn!(error = %e, "dropping unencodable frame");
                            }
                        }
                        Outbound::Shutdown(ack) => {
                            shutdown_ack = ack;
                            stop = true;
                        }
                    }

                    // Drain whatever else is queued so one flush covers many
                    // frames. This is the difference between one TLS record per
                    // frame and one per batch.
                    if !stop {
                        while let Ok(next) = rx.try_recv() {
                            match next {
                                Outbound::Frame(f) => {
                                    if let Err(e) = writer.queue(&f) {
                                        tracing::warn!(error = %e, "dropping unencodable frame");
                                    }
                                    if writer.pending_bytes() >= 256 * 1024 {
                                        break;
                                    }
                                }
                                Outbound::Shutdown(ack) => {
                                    shutdown_ack = ack;
                                    stop = true;
                                    break;
                                }
                            }
                        }
                    }

                    if let Err(e) = writer.flush().await {
                        tracing::debug!(error = %e, "tunnel writer stopped");
                        break;
                    }
                    if stop {
                        let _ = writer.shutdown().await;
                        if let Some(ack) = shutdown_ack {
                            let _ = ack.send(());
                        }
                        break;
                    }
                }
                closed.store(true, REL);
            });
        }

        // --- reader task ---
        {
            let mux = mux.clone();
            let cfg = cfg.clone();
            tokio::spawn(async move {
                let mut reader = FrameReader::new(read_half, cfg.max_frame_payload);
                let result = mux.read_loop(&mut reader, incoming).await;
                match result {
                    Ok(()) => tracing::debug!(
                        tunnel = mux.metrics.tunnel_id,
                        "tunnel closed by peer"
                    ),
                    Err(e) => tracing::info!(
                        tunnel = mux.metrics.tunnel_id,
                        error = %e,
                        "tunnel read loop terminated"
                    ),
                }
                mux.force_close();
            });
        }

        // --- keepalive task ---
        {
            let mux = mux.clone();
            tokio::spawn(async move { mux.ping_loop().await });
        }

        mux
    }

    async fn read_loop<R>(
        &self,
        reader: &mut FrameReader<R>,
        incoming: Option<mpsc::Sender<IncomingStream>>,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin,
    {
        loop {
            let Some(frame) = reader.next_frame().await? else {
                return Ok(());
            };
            match frame.frame_type {
                FrameType::Data => {
                    let len = frame.payload.len() as u64;
                    self.metrics.counters.add_rx(len);
                    let Some(entry) = self.streams.get(&frame.stream_id).map(|e| e.clone()) else {
                        // Data for a stream we already closed. Not fatal: a RST
                        // and in-flight data can cross. Tell the peer to stop.
                        let _ = self
                            .outbound
                            .try_send(Outbound::Frame(Frame::reset(frame.stream_id)));
                        continue;
                    };
                    entry.touch();
                    // Bounded send: if the stream's reader is behind, this
                    // awaits, which stops us reading more frames off the TLS
                    // connection. That is the backpressure working as designed.
                    if entry.inbound.send(Inbound::Data(frame.payload)).await.is_err() {
                        self.streams.remove(&frame.stream_id);
                        let _ = self
                            .outbound
                            .try_send(Outbound::Frame(Frame::reset(frame.stream_id)));
                    }
                }
                FrameType::WindowUpdate => {
                    let credit = frame.credit()?;
                    if let Some(entry) = self.streams.get(&frame.stream_id) {
                        entry.credit.grant(credit);
                    }
                }
                FrameType::Open => {
                    if self.cfg.role == MuxRole::Initiator {
                        return Err(Error::protocol(
                            "received OPEN as initiator; peer roles are misconfigured",
                        ));
                    }
                    self.handle_open(frame, incoming.as_ref()).await?;
                }
                FrameType::OpenOk => {
                    if let Some(entry) = self.streams.get(&frame.stream_id) {
                        if let Ok(mut slot) = entry.open_result.lock() {
                            if let Some(tx) = slot.take() {
                                let _ = tx.send(Ok(()));
                            }
                        }
                    }
                }
                FrameType::OpenError => {
                    let reason = frame.reason();
                    if let Some(entry) = self.streams.get(&frame.stream_id) {
                        if let Ok(mut slot) = entry.open_result.lock() {
                            if let Some(tx) = slot.take() {
                                let _ = tx.send(Err(Error::other(reason)));
                            }
                        }
                    }
                }
                FrameType::Close => {
                    if let Some(entry) = self.streams.get(&frame.stream_id) {
                        let _ = entry.inbound.send(Inbound::Fin).await;
                    }
                }
                FrameType::Reset => {
                    if let Some((_, entry)) = self.streams.remove(&frame.stream_id) {
                        let _ = self.stream_count
                            .fetch_update(REL, REL, |v| Some(v.saturating_sub(1)));
                        entry.credit.close();
                        let _ = entry.inbound.try_send(Inbound::Reset);
                        if let Ok(mut slot) = entry.open_result.lock() {
                            if let Some(tx) = slot.take() {
                                let _ = tx.send(Err(Error::Closed));
                            }
                        }
                    }
                }
                FrameType::Ping => {
                    // Echo verbatim; the initiator matches on the payload.
                    let _ = self
                        .outbound
                        .try_send(Outbound::Frame(Frame::pong(frame.payload)));
                }
                FrameType::Pong => {
                    let sent_at = frame.nonce()?;
                    let now = tunnel_common::time::now_millis();
                    // Guard against a peer echoing a future timestamp.
                    let rtt = now.saturating_sub(sent_at).min(u32::MAX as u64) as u32;
                    self.metrics.set_rtt(rtt);
                    self.metrics.set_state(TunnelState::Online);
                    self.pong_tick.fetch_add(1, REL);
                    self.pong_signal.notify_waiters();
                }
                FrameType::GoAway => {
                    tracing::info!(
                        tunnel = self.metrics.tunnel_id,
                        reason = %frame.reason(),
                        "peer sent GO_AWAY; draining"
                    );
                    self.draining.store(true, REL);
                }
            }
        }
    }

    async fn handle_open(
        &self,
        frame: Frame,
        incoming: Option<&mpsc::Sender<IncomingStream>>,
    ) -> Result<()> {
        let stream_id = frame.stream_id;
        let Some(incoming) = incoming else {
            let _ = self.outbound.try_send(Outbound::Frame(Frame::open_error(
                stream_id,
                "this node does not accept streams",
            )));
            return Ok(());
        };

        if self.streams.contains_key(&stream_id) {
            return Err(Error::protocol(format!(
                "peer reused live stream id {stream_id}"
            )));
        }
        if self.stream_count.load(REL) >= self.cfg.max_streams {
            let _ = self.outbound.try_send(Outbound::Frame(Frame::open_error(
                stream_id,
                "stream limit reached",
            )));
            return Ok(());
        }

        let open: tunnel_protocol::StreamOpen = serde_json::from_slice(&frame.payload)
            .map_err(|e| Error::protocol(format!("malformed OPEN payload: {e}")))?;

        let (handle, _entry) = self.install_stream(stream_id, None);
        let incoming_stream = IncomingStream {
            handle,
            route_id: open.route_id,
            client_addr: open.client_addr,
        };
        if incoming.send(incoming_stream).await.is_err() {
            // Accept loop is gone; the tunnel is shutting down.
            return Err(Error::Closed);
        }
        Ok(())
    }

    /// Register a stream and build its handle.
    fn install_stream(
        &self,
        stream_id: StreamId,
        open_result: Option<oneshot::Sender<Result<()>>>,
    ) -> (StreamHandle, Arc<StreamEntry>) {
        let (inbound_tx, inbound_rx) = mpsc::channel::<Inbound>(self.cfg.stream_queue_depth);
        let credit = Arc::new(Credit::new(self.cfg.stream_window));
        let window = Arc::new(Window::new(self.cfg.stream_window));

        let entry = Arc::new(StreamEntry {
            inbound: inbound_tx,
            credit: credit.clone(),
            open_result: std::sync::Mutex::new(open_result),
            last_activity: AtomicU64::new(0),
            created: Instant::now(),
        });
        self.streams.insert(stream_id, entry.clone());
        self.stream_count.fetch_add(1, REL);

        let shared = Arc::new(StreamShared {
            stream_id,
            outbound: self.outbound.clone(),
            credit,
            max_payload: self.cfg.max_frame_payload,
            closed_tx: AtomicBool::new(false),
            streams: self.streams.clone(),
            stream_count: self.stream_count.clone(),
        });

        let handle = StreamHandle {
            stream_id,
            r: StreamReadHalf {
                shared: shared.clone(),
                inbound: inbound_rx,
                window,
                peer_fin: false,
            },
            w: StreamWriteHalf { shared },
        };
        (handle, entry)
    }

    /// Open a stream to the peer and wait for OPEN_OK.
    ///
    /// Only valid on the initiator side.
    pub async fn open_stream(
        &self,
        route_id: &str,
        client_addr: Option<String>,
        timeout: Duration,
    ) -> Result<StreamHandle> {
        if self.cfg.role != MuxRole::Initiator {
            return Err(Error::other("only the initiator may open streams"));
        }
        if self.closed.load(REL) {
            return Err(Error::Closed);
        }
        if self.draining.load(REL) {
            return Err(Error::other("tunnel is draining"));
        }
        if self.stream_count.load(REL) >= self.cfg.max_streams {
            return Err(Error::limit(format!(
                "tunnel {} reached its {} stream limit",
                self.metrics.tunnel_id, self.cfg.max_streams
            )));
        }

        let stream_id = self.allocate_stream_id()?;
        let (result_tx, result_rx) = oneshot::channel();
        let (handle, _entry) = self.install_stream(stream_id, Some(result_tx));

        let payload = serde_json::to_vec(&tunnel_protocol::StreamOpen {
            route_id: route_id.to_string(),
            client_addr,
        })?;
        self.outbound
            .send(Outbound::Frame(Frame::open(
                stream_id,
                Bytes::from(payload),
            )))
            .await
            .map_err(|_| Error::Closed)?;

        match tokio::time::timeout(timeout, result_rx).await {
            Ok(Ok(Ok(()))) => Ok(handle),
            Ok(Ok(Err(e))) => Err(e),
            // Tunnel died before a reply.
            Ok(Err(_)) => Err(Error::Closed),
            Err(_) => Err(Error::Timeout("stream open")),
        }
    }

    /// Allocate an unused stream id, skipping the reserved 0 and any live id.
    fn allocate_stream_id(&self) -> Result<StreamId> {
        // Wrapping is fine after 4 billion streams; we just need to skip ids
        // that are still in use.
        for _ in 0..1024 {
            let id = self.next_stream_id.fetch_add(1, REL);
            if id == tunnel_protocol::frame::CONTROL_STREAM {
                continue;
            }
            if !self.streams.contains_key(&id) {
                return Ok(id);
            }
        }
        Err(Error::limit("could not allocate a free stream id"))
    }

    /// Heartbeat loop.
    ///
    /// Sends PING on an interval and requires a PONG within `ping_timeout`.
    /// After `ping_max_failures` consecutive misses the tunnel is torn down so
    /// the pool can replace it — a TCP connection can stay "established" for
    /// minutes after the path has died, and only an application-level heartbeat
    /// notices in time.
    async fn ping_loop(self: Arc<Self>) {
        let mut ticker = tokio::time::interval(self.cfg.ping_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Skip the immediate first tick so a fresh tunnel is not pinged before
        // it has carried anything.
        ticker.tick().await;
        let mut failures = 0u32;

        loop {
            ticker.tick().await;
            if self.closed.load(REL) {
                return;
            }

            let before = self.pong_tick.load(REL);
            // Register for the wakeup *before* sending, so a PONG that arrives
            // while we are still in `send` cannot be missed.
            let waiter = self.pong_signal.notified();

            let nonce = tunnel_common::time::now_millis();
            if self
                .outbound
                .send(Outbound::Frame(Frame::ping(nonce)))
                .await
                .is_err()
            {
                return;
            }

            let answered = if self.pong_tick.load(REL) != before {
                true
            } else {
                tokio::time::timeout(self.cfg.ping_timeout, waiter)
                    .await
                    .is_ok()
                    && self.pong_tick.load(REL) != before
            };

            if answered {
                failures = 0;
                self.metrics.set_state(TunnelState::Online);
            } else {
                if self.closed.load(REL) {
                    return;
                }
                failures += 1;
                tracing::warn!(
                    tunnel = self.metrics.tunnel_id,
                    failures,
                    max = self.cfg.ping_max_failures,
                    "heartbeat missed"
                );
                if failures >= self.cfg.ping_max_failures {
                    tracing::warn!(
                        tunnel = self.metrics.tunnel_id,
                        failures,
                        "heartbeat failed repeatedly; closing tunnel so the pool can reconnect"
                    );
                    self.force_close();
                    return;
                }
                self.metrics.set_state(TunnelState::Degraded);
            }
        }
    }

    pub fn live_streams(&self) -> u32 {
        self.stream_count.load(REL)
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(REL)
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(REL)
    }

    pub fn metrics(&self) -> &Arc<TunnelMetrics> {
        &self.metrics
    }

    /// Ask the peer to stop opening streams, then close once drained.
    pub async fn go_away(&self, reason: &str) {
        self.draining.store(true, REL);
        let _ = self
            .outbound
            .send(Outbound::Frame(Frame::go_away(reason)))
            .await;
    }

    /// Graceful shutdown: flush pending frames, then close the TLS connection.
    pub async fn shutdown(&self) {
        if self.closed.swap(true, REL) {
            return;
        }
        let (ack_tx, ack_rx) = oneshot::channel();
        if self.outbound.send(Outbound::Shutdown(Some(ack_tx))).await.is_ok() {
            // Bounded wait: a wedged peer must not block process exit.
            let _ = tokio::time::timeout(Duration::from_secs(5), ack_rx).await;
        }
        self.teardown_streams();
        self.metrics.set_state(TunnelState::Offline);
    }

    /// Immediate teardown, used when the connection is already broken.
    pub fn force_close(&self) {
        self.closed.store(true, REL);
        let _ = self.outbound.try_send(Outbound::Shutdown(None));
        self.teardown_streams();
        self.metrics.set_state(TunnelState::Offline);
    }

    fn teardown_streams(&self) {
        // Wake every blocked writer and signal every reader, so relay tasks
        // observe the closure and exit instead of hanging forever.
        for entry in self.streams.iter() {
            entry.credit.close();
            let _ = entry.inbound.try_send(Inbound::Reset);
            if let Ok(mut slot) = entry.open_result.lock() {
                if let Some(tx) = slot.take() {
                    let _ = tx.send(Err(Error::Closed));
                }
            }
        }
        self.streams.clear();
        self.stream_count.store(0, REL);
    }

    /// Reap streams idle beyond `timeout`. Called by a periodic task.
    pub fn reap_idle_streams(&self, timeout: Duration) -> usize {
        let limit = timeout.as_secs();
        let mut reaped = Vec::new();
        for entry in self.streams.iter() {
            if entry.value().idle_secs() > limit {
                reaped.push(*entry.key());
            }
        }
        for id in &reaped {
            if let Some((_, entry)) = self.streams.remove(id) {
                let _ = self
                    .stream_count
                    .fetch_update(REL, REL, |v| Some(v.saturating_sub(1)));
                entry.credit.close();
                let _ = entry.inbound.try_send(Inbound::Reset);
                let _ = self.outbound.try_send(Outbound::Frame(Frame::reset(*id)));
            }
        }
        reaped.len()
    }

    /// Record bytes sent, for the tunnel's TX counter.
    pub fn account_tx(&self, n: u64) {
        self.metrics.counters.add_tx(n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn test_cfg(role: MuxRole) -> MuxConfig {
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

    /// Wire two multiplexers together over an in-memory duplex.
    fn pair() -> (
        Arc<Multiplexer>,
        Arc<Multiplexer>,
        mpsc::Receiver<IncomingStream>,
    ) {
        let (a, b) = duplex(1024 * 1024);
        let (incoming_tx, incoming_rx) = mpsc::channel(64);
        let initiator = Multiplexer::start(
            a,
            test_cfg(MuxRole::Initiator),
            TunnelMetrics::new(1),
            None,
        );
        let responder = Multiplexer::start(
            b,
            test_cfg(MuxRole::Responder),
            TunnelMetrics::new(2),
            Some(incoming_tx),
        );
        (initiator, responder, incoming_rx)
    }

    /// Accept a stream and echo everything back, preserving half-close.
    fn spawn_echo(mut incoming: mpsc::Receiver<IncomingStream>) {
        tokio::spawn(async move {
            while let Some(mut s) = incoming.recv().await {
                tokio::spawn(async move {
                    // Stand in for the exit's "target connected" confirmation.
                    if s.handle.accept().await.is_err() {
                        return;
                    }
                    while let Ok(Some(chunk)) = s.handle.read().await {
                        let n = chunk.len();
                        if s.handle.write(&chunk).await.is_err() {
                            break;
                        }
                        s.handle.credit_consumed(n);
                    }
                    let _ = s.handle.shutdown_write().await;
                });
            }
        });
    }

    #[tokio::test]
    async fn open_and_echo_roundtrip() {
        let (init, _resp, incoming) = pair();
        spawn_echo(incoming);

        let mut stream = init
            .open_stream("r1", Some("1.2.3.4:5".into()), Duration::from_secs(5))
            .await
            .unwrap();

        stream.write(b"hello tunnel").await.unwrap();
        let echoed = stream.read().await.unwrap().unwrap();
        assert_eq!(&echoed[..], b"hello tunnel");
        stream.credit_consumed(echoed.len());
    }

    #[tokio::test]
    async fn byte_stream_is_preserved_exactly() {
        // The system's core promise, through the full mux path.
        let (init, _resp, incoming) = pair();
        spawn_echo(incoming);

        let stream = init
            .open_stream("r1", None, Duration::from_secs(5))
            .await
            .unwrap();

        // Larger than one frame and much larger than the window, so this
        // exercises frame splitting and credit-based pacing together.
        let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 253) as u8).collect();
        let expected = payload.clone();

        // Send and receive concurrently. Writing the whole payload before
        // reading would deadlock against flow control by construction — the
        // window is 64 KiB — which is exactly why the relay uses two tasks.
        let (mut r, mut w) = stream.split();
        let writer = tokio::spawn(async move {
            w.write(&payload).await.unwrap();
            w.shutdown_write().await.unwrap();
        });
        let reader = tokio::spawn(async move {
            let mut received = Vec::new();
            while let Some(chunk) = r.read().await.unwrap() {
                r.credit_consumed(chunk.len());
                received.extend_from_slice(&chunk);
            }
            received
        });

        writer.await.unwrap();
        let received = tokio::time::timeout(Duration::from_secs(30), reader)
            .await
            .expect("transfer stalled")
            .unwrap();
        assert_eq!(received.len(), expected.len(), "length mismatch");
        assert_eq!(received, expected, "payload corrupted through the mux");
    }

    #[tokio::test]
    async fn many_concurrent_streams_stay_isolated() {
        let (init, _resp, incoming) = pair();
        spawn_echo(incoming);

        let mut tasks = Vec::new();
        for i in 0..24u8 {
            let init = init.clone();
            tasks.push(tokio::spawn(async move {
                let mut s = init
                    .open_stream("r1", None, Duration::from_secs(10))
                    .await
                    .unwrap();
                // Distinct payload per stream: any cross-talk shows up here.
                let payload = vec![i; 8192];
                s.write(&payload).await.unwrap();
                let mut got = Vec::new();
                while got.len() < payload.len() {
                    let chunk = s.read().await.unwrap().unwrap();
                    s.credit_consumed(chunk.len());
                    got.extend_from_slice(&chunk);
                }
                assert!(got.iter().all(|&b| b == i), "stream {i} received foreign data");
                got.len()
            }));
        }
        for t in tasks {
            assert_eq!(t.await.unwrap(), 8192);
        }
    }

    #[tokio::test]
    async fn half_close_propagates_as_fin_not_reset() {
        // Critical for protocols that shutdown(WR) then keep reading.
        let (init, _resp, mut incoming) = pair();

        let server = tokio::spawn(async move {
            let mut s = incoming.recv().await.unwrap();
            s.handle.accept().await.unwrap();
            // Read to EOF: this must arrive as a clean FIN.
            let mut total = 0;
            while let Some(chunk) = s.handle.read().await.unwrap() {
                total += chunk.len();
                s.handle.credit_consumed(chunk.len());
            }
            // The peer half-closed, but we can still send.
            s.handle.write(b"after-fin").await.unwrap();
            s.handle.shutdown_write().await.unwrap();
            total
        });

        let mut stream = init
            .open_stream("r1", None, Duration::from_secs(5))
            .await
            .unwrap();
        stream.write(b"request").await.unwrap();
        stream.shutdown_write().await.unwrap();

        let reply = stream.read().await.unwrap().unwrap();
        assert_eq!(&reply[..], b"after-fin");
        stream.credit_consumed(reply.len());
        assert!(stream.read().await.unwrap().is_none(), "expected clean EOF");
        assert_eq!(server.await.unwrap(), 7);
    }

    #[tokio::test]
    async fn credit_bounds_an_unread_stream() {
        // A receiver that never reads must not let the sender buffer without
        // limit. The write should block once the window plus queue is full.
        let (init, _resp, mut incoming) = pair();
        let held = tokio::spawn(async move {
            let mut s = incoming.recv().await.unwrap();
            s.handle.accept().await.unwrap();
            // Hold the stream open and deliberately never read.
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(s);
        });

        let mut stream = init
            .open_stream("r1", None, Duration::from_secs(5))
            .await
            .unwrap();

        // Window is 64 KiB; queue adds a bounded amount. 4 MiB cannot fit.
        let big = vec![0u8; 4 * 1024 * 1024];
        let result = tokio::time::timeout(Duration::from_millis(600), stream.write(&big)).await;
        assert!(
            result.is_err(),
            "write of 4 MiB completed with a 64 KiB window — flow control is not applied"
        );
        held.abort();
    }

    #[tokio::test]
    async fn window_update_unblocks_a_stalled_sender() {
        let (init, _resp, incoming) = pair();
        spawn_echo(incoming);

        let stream = init
            .open_stream("r1", None, Duration::from_secs(5))
            .await
            .unwrap();

        // 512 KiB through a 64 KiB window completes only if credit keeps being
        // returned as the echo server consumes. If WINDOW_UPDATE were broken,
        // the writer would stall permanently after the first window.
        let payload = vec![7u8; 512 * 1024];
        let expected = payload.len();
        let (mut r, mut w) = stream.split();

        let writer = tokio::spawn(async move {
            w.write(&payload).await.unwrap();
            w.shutdown_write().await.unwrap();
        });
        let reader = tokio::spawn(async move {
            let mut got = 0usize;
            while let Some(chunk) = r.read().await.unwrap() {
                got += chunk.len();
                r.credit_consumed(chunk.len());
            }
            got
        });

        tokio::time::timeout(Duration::from_secs(20), writer)
            .await
            .expect("credit was never returned; sender stayed blocked")
            .unwrap();
        let got = tokio::time::timeout(Duration::from_secs(20), reader)
            .await
            .expect("echo never came back")
            .unwrap();
        assert_eq!(got, expected);
    }

    #[tokio::test]
    async fn open_error_surfaces_to_the_caller() {
        // Responder with no accept channel replies OPEN_ERROR.
        let (a, b) = duplex(64 * 1024);
        let init = Multiplexer::start(a, test_cfg(MuxRole::Initiator), TunnelMetrics::new(1), None);
        let _resp =
            Multiplexer::start(b, test_cfg(MuxRole::Responder), TunnelMetrics::new(2), None);

        let err = init
            .open_stream("r1", None, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("does not accept"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn open_times_out_when_the_peer_is_silent() {
        // Peer that reads nothing and never replies.
        let (a, b) = duplex(64 * 1024);
        let init = Multiplexer::start(a, test_cfg(MuxRole::Initiator), TunnelMetrics::new(1), None);
        let keep = b; // hold the far end open without a mux driving it

        let err = init
            .open_stream("r1", None, Duration::from_millis(300))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Timeout(_)), "{err:?}");
        drop(keep);
    }

    #[tokio::test]
    async fn stream_limit_is_enforced() {
        let (a, b) = duplex(1024 * 1024);
        let (incoming_tx, incoming_rx) = mpsc::channel(64);
        let mut cfg = test_cfg(MuxRole::Initiator);
        cfg.max_streams = 4;
        let init = Multiplexer::start(a, cfg, TunnelMetrics::new(1), None);
        let _resp = Multiplexer::start(
            b,
            test_cfg(MuxRole::Responder),
            TunnelMetrics::new(2),
            Some(incoming_tx),
        );
        // Hold the accepted streams open so slots stay occupied.
        let holder = tokio::spawn(async move {
            let mut incoming = incoming_rx;
            let mut kept = Vec::new();
            while let Some(mut s) = incoming.recv().await {
                s.handle.accept().await.unwrap();
                kept.push(s);
            }
        });

        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(
                init.open_stream("r1", None, Duration::from_secs(5))
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(init.live_streams(), 4);
        let err = init
            .open_stream("r1", None, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Limit(_)), "{err:?}");
        holder.abort();
    }

    #[tokio::test]
    async fn dropping_a_handle_frees_its_slot() {
        let (init, _resp, incoming) = pair();
        spawn_echo(incoming);

        let s = init
            .open_stream("r1", None, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(init.live_streams(), 1);
        drop(s);
        assert_eq!(init.live_streams(), 0, "slot leaked on drop");
    }

    #[tokio::test]
    async fn reset_propagates_to_the_peer_reader() {
        let (init, _resp, mut incoming) = pair();
        let server = tokio::spawn(async move {
            let mut s = incoming.recv().await.unwrap();
            s.handle.accept().await.unwrap();
            // First read gets data, then the RST must surface as an error.
            let first = s.handle.read().await.unwrap().unwrap();
            assert_eq!(&first[..], b"data");
            s.handle.credit_consumed(first.len());
            s.handle.read().await
        });

        let mut stream = init
            .open_stream("r1", None, Duration::from_secs(5))
            .await
            .unwrap();
        stream.write(b"data").await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        stream.reset().await;

        let result = server.await.unwrap();
        assert!(result.is_err(), "peer should observe the reset");
    }

    #[tokio::test]
    async fn tunnel_shutdown_wakes_blocked_streams() {
        // Streams must not hang forever when the tunnel dies under them.
        let (init, _resp, mut incoming) = pair();
        let holder = tokio::spawn(async move {
            let mut s = incoming.recv().await.unwrap();
            s.handle.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(s);
        });

        let mut stream = init
            .open_stream("r1", None, Duration::from_secs(5))
            .await
            .unwrap();

        let reader = tokio::spawn(async move { stream.read().await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        init.force_close();

        let result = tokio::time::timeout(Duration::from_secs(2), reader)
            .await
            .expect("blocked reader was not woken by force_close")
            .unwrap();
        assert!(result.is_err());
        holder.abort();
    }

    #[tokio::test]
    async fn open_after_shutdown_is_refused() {
        let (init, _resp, incoming) = pair();
        spawn_echo(incoming);
        init.shutdown().await;
        assert!(init.is_closed());
        assert!(init
            .open_stream("r1", None, Duration::from_secs(1))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn go_away_stops_new_streams_on_the_peer() {
        let (init, resp, incoming) = pair();
        spawn_echo(incoming);

        // An existing stream keeps working.
        let mut existing = init
            .open_stream("r1", None, Duration::from_secs(5))
            .await
            .unwrap();

        resp.go_away("maintenance").await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(init.is_draining(), "initiator did not observe GO_AWAY");

        existing.write(b"still works").await.unwrap();
        let echo = existing.read().await.unwrap().unwrap();
        assert_eq!(&echo[..], b"still works");

        assert!(init
            .open_stream("r1", None, Duration::from_secs(1))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn responder_cannot_open_streams() {
        let (_init, resp, _incoming) = pair();
        assert!(resp
            .open_stream("r1", None, Duration::from_secs(1))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn counters_track_traffic() {
        let (init, _resp, incoming) = pair();
        spawn_echo(incoming);
        let mut s = init
            .open_stream("r1", None, Duration::from_secs(5))
            .await
            .unwrap();
        s.write(&vec![1u8; 4096]).await.unwrap();
        let chunk = s.read().await.unwrap().unwrap();
        s.credit_consumed(chunk.len());
        // The initiator's RX counter saw the echoed bytes.
        assert!(init.metrics().counters.rx() >= chunk.len() as u64);
    }

    #[tokio::test]
    async fn idle_streams_are_reaped() {
        let (init, _resp, incoming) = pair();
        spawn_echo(incoming);
        let _s = init
            .open_stream("r1", None, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(init.live_streams(), 1);

        // Not yet idle enough: the reaper must leave it alone.
        assert_eq!(init.reap_idle_streams(Duration::from_secs(60)), 0);
        assert_eq!(init.live_streams(), 1);

        // Now push past the threshold. The stream never carried a byte, so its
        // idle age equals its age.
        tokio::time::sleep(Duration::from_millis(2100)).await;
        assert_eq!(init.reap_idle_streams(Duration::from_secs(1)), 1);
        assert_eq!(init.live_streams(), 0);
    }

    #[tokio::test]
    async fn credit_accounting_is_exact_under_concurrency() {
        // Reserve from many tasks at once; the total handed out must never
        // exceed the window.
        let credit = Arc::new(Credit::new(1000));
        let mut tasks = Vec::new();
        for _ in 0..20 {
            let c = credit.clone();
            tasks.push(tokio::spawn(async move {
                let mut total = 0;
                for _ in 0..10 {
                    match tokio::time::timeout(Duration::from_millis(50), c.reserve(10)).await {
                        Ok(Ok(n)) => total += n,
                        _ => break,
                    }
                }
                total
            }));
        }
        let mut granted = 0;
        for t in tasks {
            granted += t.await.unwrap();
        }
        assert!(
            granted <= 1000,
            "handed out {granted} bytes from a 1000-byte window"
        );
    }

    #[test]
    fn window_defers_updates_until_half_consumed() {
        let w = Window::new(1000);
        assert!(w.consume(100).is_none(), "should defer a small update");
        assert!(w.consume(300).is_none());
        // Crossing 500 triggers a batched return of everything accumulated.
        let credit = w.consume(200).expect("update at the halfway mark");
        assert_eq!(credit, 600);
        assert!(w.consume(1).is_none(), "counter should have reset");
    }

    #[test]
    fn window_handles_a_single_oversized_consume() {
        let w = Window::new(1000);
        assert_eq!(w.consume(1000), Some(1000));
    }

    #[tokio::test]
    async fn credit_close_wakes_a_waiter() {
        let credit = Arc::new(Credit::new(0));
        let c = credit.clone();
        let waiter = tokio::spawn(async move { c.reserve(100).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        credit.close();
        assert!(tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("waiter was not woken")
            .unwrap()
            .is_err());
    }
}
