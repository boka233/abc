//! Async frame reader/writer over any `AsyncRead`/`AsyncWrite`.
//!
//! Split into separate reader and writer halves on purpose: the tunnel runs one
//! task pumping frames out and one task pumping frames in, and they must not
//! contend on a shared lock. `TlsStream` splits cleanly, so each task owns its
//! half outright.
//!
//! Buffering strategy: the reader keeps one `BytesMut` and decodes as many
//! frames as it can from each `read()`, so a TLS record carrying ten small
//! frames costs one syscall. The writer coalesces queued frames into one buffer
//! before flushing, for the same reason — writing each frame separately turns
//! every 40-byte interactive packet into its own TLS record and its own
//! `write()`.

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tunnel_common::{Error, Result};

use crate::frame::{Frame, HEADER_LEN, MAX_PAYLOAD_LEN};
use crate::handshake::MAX_HANDSHAKE_LEN;

/// Initial read buffer. Sized so a typical 16 KiB TLS record plus a partial
/// frame fits without a realloc.
const READ_BUF_CAPACITY: usize = 32 * 1024;

pub struct FrameReader<R> {
    inner: R,
    buf: BytesMut,
    max_payload: usize,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    pub fn new(inner: R, max_payload: usize) -> Self {
        Self {
            inner,
            buf: BytesMut::with_capacity(READ_BUF_CAPACITY),
            max_payload: max_payload.min(MAX_PAYLOAD_LEN),
        }
    }

    /// Tighten the cap once the handshake has negotiated it.
    pub fn set_max_payload(&mut self, max_payload: usize) {
        self.max_payload = max_payload.min(MAX_PAYLOAD_LEN);
    }

    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Read the next frame.
    ///
    /// `Ok(None)` means the peer closed cleanly at a frame boundary. A close in
    /// the *middle* of a frame is a protocol error, not a clean EOF — silently
    /// tolerating it would mask truncation.
    pub async fn next_frame(&mut self) -> Result<Option<Frame>> {
        loop {
            if let Some(frame) = Frame::decode(&mut self.buf, self.max_payload)? {
                return Ok(Some(frame));
            }
            // Ensure room for progress; decode() already reserved for a known
            // frame length, this covers the empty-buffer case.
            if self.buf.capacity() - self.buf.len() < HEADER_LEN {
                self.buf.reserve(READ_BUF_CAPACITY);
            }
            let n = self.inner.read_buf(&mut self.buf).await?;
            if n == 0 {
                return if self.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(Error::protocol(format!(
                        "peer closed mid-frame with {} bytes buffered",
                        self.buf.len()
                    )))
                };
            }
        }
    }

    /// Read a length-prefixed JSON handshake message.
    ///
    /// Framing is `u16be length || json`. The length is checked against
    /// [`MAX_HANDSHAKE_LEN`] before the body is buffered.
    pub async fn read_handshake<T: serde::de::DeserializeOwned>(&mut self) -> Result<T> {
        while self.buf.len() < 2 {
            let n = self.inner.read_buf(&mut self.buf).await?;
            if n == 0 {
                return Err(Error::protocol("peer closed during handshake"));
            }
        }
        let len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
        if len == 0 {
            return Err(Error::protocol("empty handshake message"));
        }
        if len > MAX_HANDSHAKE_LEN {
            return Err(Error::limit(format!(
                "handshake message {len} exceeds max {MAX_HANDSHAKE_LEN}"
            )));
        }
        while self.buf.len() < 2 + len {
            let n = self.inner.read_buf(&mut self.buf).await?;
            if n == 0 {
                return Err(Error::protocol("peer closed mid-handshake"));
            }
        }
        let _ = self.buf.split_to(2);
        let body = self.buf.split_to(len);
        serde_json::from_slice(&body)
            .map_err(|e| Error::protocol(format!("malformed handshake message: {e}")))
    }
}

pub struct FrameWriter<W> {
    inner: W,
    buf: BytesMut,
    max_payload: usize,
}

impl<W: AsyncWrite + Unpin> FrameWriter<W> {
    pub fn new(inner: W, max_payload: usize) -> Self {
        Self {
            inner,
            buf: BytesMut::with_capacity(READ_BUF_CAPACITY),
            max_payload: max_payload.min(MAX_PAYLOAD_LEN),
        }
    }

    pub fn set_max_payload(&mut self, max_payload: usize) {
        self.max_payload = max_payload.min(MAX_PAYLOAD_LEN);
    }

    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Append a frame to the pending buffer without touching the socket.
    pub fn queue(&mut self, frame: &Frame) -> Result<()> {
        frame.encode(&mut self.buf, self.max_payload)
    }

    pub fn pending_bytes(&self) -> usize {
        self.buf.len()
    }

    /// Flush everything queued. One `write_all` + one `flush` per batch.
    pub async fn flush(&mut self) -> Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        // `split` hands ownership of the queued bytes to this call, so frames
        // queued by another task while we await do not get lost or duplicated.
        let chunk = self.buf.split();
        self.inner.write_all(&chunk).await?;
        self.inner.flush().await?;
        // Reclaim the allocation for the next batch.
        if self.buf.capacity() < READ_BUF_CAPACITY {
            self.buf.reserve(READ_BUF_CAPACITY - self.buf.capacity());
        }
        Ok(())
    }

    /// Queue one frame and flush immediately. Used for control frames where
    /// latency beats batching.
    pub async fn write_frame(&mut self, frame: &Frame) -> Result<()> {
        self.queue(frame)?;
        self.flush().await
    }

    pub async fn write_handshake<T: serde::Serialize>(&mut self, msg: &T) -> Result<()> {
        let body = serde_json::to_vec(msg)?;
        if body.len() > MAX_HANDSHAKE_LEN {
            return Err(Error::limit(format!(
                "handshake message {} exceeds max {MAX_HANDSHAKE_LEN}",
                body.len()
            )));
        }
        let mut out = BytesMut::with_capacity(2 + body.len());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&body);
        self.inner.write_all(&out).await?;
        self.inner.flush().await?;
        Ok(())
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        self.flush().await?;
        self.inner.shutdown().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::FrameType;
    use crate::handshake::ClientHello;
    use bytes::Bytes;
    use tokio::io::duplex;

    const MAX: usize = 64 * 1024;

    #[tokio::test]
    async fn single_frame_roundtrip() {
        let (a, b) = duplex(64 * 1024);
        let mut w = FrameWriter::new(a, MAX);
        let mut r = FrameReader::new(b, MAX);

        let sent = Frame::data(3, Bytes::from_static(b"payload"));
        w.write_frame(&sent).await.unwrap();
        assert_eq!(r.next_frame().await.unwrap().unwrap(), sent);
    }

    #[tokio::test]
    async fn batched_frames_arrive_in_order() {
        let (a, b) = duplex(256 * 1024);
        let mut w = FrameWriter::new(a, MAX);
        let mut r = FrameReader::new(b, MAX);

        let frames: Vec<Frame> = (1..=50)
            .map(|i| Frame::data(i, Bytes::from(vec![i as u8; 100 + i as usize])))
            .collect();
        for f in &frames {
            w.queue(f).unwrap();
        }
        assert!(w.pending_bytes() > 0);
        w.flush().await.unwrap();
        assert_eq!(w.pending_bytes(), 0);

        for expected in &frames {
            assert_eq!(&r.next_frame().await.unwrap().unwrap(), expected);
        }
    }

    #[tokio::test]
    async fn clean_eof_at_a_frame_boundary_is_none() {
        let (a, b) = duplex(1024);
        let mut w = FrameWriter::new(a, MAX);
        let mut r = FrameReader::new(b, MAX);
        w.write_frame(&Frame::close(1)).await.unwrap();
        drop(w);

        assert_eq!(
            r.next_frame().await.unwrap().unwrap().frame_type,
            FrameType::Close
        );
        assert!(r.next_frame().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn truncated_frame_is_an_error_not_a_clean_eof() {
        let (mut a, b) = duplex(1024);
        let mut r = FrameReader::new(b, MAX);
        // A header promising 10 bytes, followed by only 4, then EOF.
        let mut wire = BytesMut::new();
        Frame::data(1, Bytes::from_static(b"0123456789"))
            .encode(&mut wire, MAX)
            .unwrap();
        wire.truncate(HEADER_LEN + 4);
        tokio::io::AsyncWriteExt::write_all(&mut a, &wire).await.unwrap();
        drop(a);

        let err = r.next_frame().await.unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "{err:?}");
    }

    #[tokio::test]
    async fn byte_for_byte_fidelity_over_many_sizes() {
        // The system's central promise, exercised through the real async path.
        let (a, b) = duplex(1024 * 1024);
        let mut w = FrameWriter::new(a, MAX);
        let mut r = FrameReader::new(b, MAX);

        let sizes = [1usize, 2, 7, 255, 256, 1000, 4096, 16384, 65535];
        let payloads: Vec<Vec<u8>> = sizes
            .iter()
            .map(|&n| (0..n).map(|i| (i % 251) as u8).collect())
            .collect();

        let writer = tokio::spawn(async move {
            for (i, p) in payloads.iter().enumerate() {
                w.queue(&Frame::data(i as u32 + 1, Bytes::from(p.clone())))
                    .unwrap();
            }
            w.flush().await.unwrap();
            payloads
        });
        let payloads = writer.await.unwrap();

        for (i, expected) in payloads.iter().enumerate() {
            let f = r.next_frame().await.unwrap().unwrap();
            assert_eq!(f.stream_id, i as u32 + 1);
            assert_eq!(&f.payload[..], &expected[..], "size {} corrupted", expected.len());
        }
    }

    #[tokio::test]
    async fn handshake_roundtrip() {
        let (a, b) = duplex(64 * 1024);
        let mut w = FrameWriter::new(a, MAX);
        let mut r = FrameReader::new(b, MAX);

        let hello = ClientHello::new("n1", "r1", 2, None, 65535, 524288);
        w.write_handshake(&hello).await.unwrap();
        let got: ClientHello = r.read_handshake().await.unwrap();
        assert_eq!(got.node_id, "n1");
        assert_eq!(got.route_id, "r1");
        assert_eq!(got.pool_index, 2);
    }

    #[tokio::test]
    async fn oversized_handshake_length_is_refused() {
        let (mut a, b) = duplex(1024);
        let mut r = FrameReader::new(b, MAX);
        // Announce 60000 bytes; the reader must bail on the prefix alone.
        a.write_all(&60000u16.to_be_bytes()).await.unwrap();
        let err = r.read_handshake::<ClientHello>().await.unwrap_err();
        assert!(matches!(err, Error::Limit(_)), "{err:?}");
    }

    #[tokio::test]
    async fn malformed_handshake_json_is_a_protocol_error() {
        let (mut a, b) = duplex(1024);
        let mut r = FrameReader::new(b, MAX);
        let body = b"{not json";
        a.write_all(&(body.len() as u16).to_be_bytes()).await.unwrap();
        a.write_all(body).await.unwrap();
        let err = r.read_handshake::<ClientHello>().await.unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "{err:?}");
    }

    #[tokio::test]
    async fn empty_handshake_is_refused() {
        let (mut a, b) = duplex(1024);
        let mut r = FrameReader::new(b, MAX);
        a.write_all(&0u16.to_be_bytes()).await.unwrap();
        assert!(r.read_handshake::<ClientHello>().await.is_err());
    }

    #[tokio::test]
    async fn tightened_cap_rejects_larger_frames() {
        let (a, b) = duplex(64 * 1024);
        let mut w = FrameWriter::new(a, MAX);
        let mut r = FrameReader::new(b, MAX);
        // Negotiation landed on 4 KiB; a 8 KiB frame must now be refused.
        r.set_max_payload(4096);
        w.set_max_payload(MAX);

        w.write_frame(&Frame::data(1, Bytes::from(vec![0u8; 8192])))
            .await
            .unwrap();
        let err = r.next_frame().await.unwrap_err();
        assert!(matches!(err, Error::Limit(_)), "{err:?}");
    }

    #[tokio::test]
    async fn writer_refuses_frames_over_its_cap() {
        let (a, _b) = duplex(64 * 1024);
        let mut w = FrameWriter::new(a, 4096);
        let err = w
            .write_frame(&Frame::data(1, Bytes::from(vec![0u8; 8192])))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Limit(_)), "{err:?}");
        assert_eq!(w.pending_bytes(), 0, "rejected frame must not be buffered");
    }

    #[tokio::test]
    async fn flush_on_empty_buffer_is_a_noop() {
        let (a, _b) = duplex(64);
        let mut w = FrameWriter::new(a, MAX);
        w.flush().await.unwrap();
        w.flush().await.unwrap();
    }

    #[tokio::test]
    async fn interleaved_streams_stay_distinct() {
        // Mux correctness at the codec level: frames for different streams share
        // one byte stream and must not bleed into each other.
        let (a, b) = duplex(256 * 1024);
        let mut w = FrameWriter::new(a, MAX);
        let mut r = FrameReader::new(b, MAX);

        for round in 0..20u8 {
            for stream in 1..=5u32 {
                w.queue(&Frame::data(
                    stream,
                    Bytes::from(vec![stream as u8 * 10 + round; 64]),
                ))
                .unwrap();
            }
        }
        w.flush().await.unwrap();

        for round in 0..20u8 {
            for stream in 1..=5u32 {
                let f = r.next_frame().await.unwrap().unwrap();
                assert_eq!(f.stream_id, stream);
                assert!(f.payload.iter().all(|&b| b == stream as u8 * 10 + round));
            }
        }
    }
}
