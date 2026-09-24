//! Frame types and header encoding.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tunnel_common::{Error, Result};

/// Bumped only on incompatible wire changes. Mismatch aborts the handshake
/// rather than attempting a guess.
pub const PROTOCOL_VERSION: u8 = 1;

/// `ver(1) + type(1) + stream_id(4) + len(2)`
pub const HEADER_LEN: usize = 8;

/// Structural ceiling imposed by the `u16` length field. The negotiated
/// `max_frame_payload` is always `<=` this.
pub const MAX_PAYLOAD_LEN: usize = u16::MAX as usize;

/// Identifies a logical stream within one tunnel connection.
///
/// Allocated by the entry side only, which removes any need for an
/// odd/even split or collision handling: the exit never invents a stream id.
/// Id 0 is reserved for tunnel-level control frames (PING/PONG/GOAWAY).
pub type StreamId = u32;

/// Reserved id for frames that belong to the tunnel itself, not to a stream.
pub const CONTROL_STREAM: StreamId = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FrameType {
    /// entry→exit: open a logical stream. Payload is a JSON [`StreamOpen`].
    ///
    /// [`StreamOpen`]: crate::handshake::StreamOpen
    Open = 0x01,
    /// exit→entry: target connected, stream is live. Empty payload.
    OpenOk = 0x02,
    /// exit→entry: target dial failed. Payload is a short UTF-8 reason, capped
    /// so a hostile/buggy peer cannot use it as an amplification vector.
    OpenError = 0x03,
    /// Either direction: opaque stream payload. Never inspected or rewritten.
    Data = 0x04,
    /// Graceful half-close: "I will send no more data on this stream."
    /// Maps onto TCP FIN so half-open connections survive the tunnel.
    Close = 0x05,
    /// Abortive close, equivalent to TCP RST. Discards buffered data.
    Reset = 0x06,
    /// Liveness probe on the control stream. Payload: 8-byte BE timestamp.
    Ping = 0x07,
    /// Echo of a [`FrameType::Ping`] payload, unmodified.
    Pong = 0x08,
    /// Flow-control credit: "I have consumed N more bytes on this stream, you
    /// may send N more." This is what makes backpressure work across the mux.
    WindowUpdate = 0x09,
    /// Tunnel is shutting down; stop opening new streams. Payload: reason.
    GoAway = 0x0A,
}

impl FrameType {
    pub fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            0x01 => FrameType::Open,
            0x02 => FrameType::OpenOk,
            0x03 => FrameType::OpenError,
            0x04 => FrameType::Data,
            0x05 => FrameType::Close,
            0x06 => FrameType::Reset,
            0x07 => FrameType::Ping,
            0x08 => FrameType::Pong,
            0x09 => FrameType::WindowUpdate,
            0x0A => FrameType::GoAway,
            other => {
                return Err(Error::protocol(format!("unknown frame type 0x{other:02x}")))
            }
        })
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn as_str(self) -> &'static str {
        match self {
            FrameType::Open => "OPEN",
            FrameType::OpenOk => "OPEN_OK",
            FrameType::OpenError => "OPEN_ERROR",
            FrameType::Data => "DATA",
            FrameType::Close => "CLOSE",
            FrameType::Reset => "RESET",
            FrameType::Ping => "PING",
            FrameType::Pong => "PONG",
            FrameType::WindowUpdate => "WINDOW_UPDATE",
            FrameType::GoAway => "GO_AWAY",
        }
    }

    /// Frames that must carry `stream_id == 0`.
    pub fn is_control(self) -> bool {
        matches!(
            self,
            FrameType::Ping | FrameType::Pong | FrameType::GoAway
        )
    }
}

impl std::fmt::Display for FrameType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A decoded frame. The payload is a [`Bytes`], so passing it from the tunnel
/// reader to a stream handler is a refcount bump, not a copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub frame_type: FrameType,
    pub stream_id: StreamId,
    pub payload: Bytes,
}

/// Cap on `OPEN_ERROR` / `GO_AWAY` reason strings. Long enough to be useful in
/// a log line, short enough that it cannot be abused.
pub const MAX_REASON_LEN: usize = 256;

impl Frame {
    pub fn new(frame_type: FrameType, stream_id: StreamId, payload: Bytes) -> Self {
        Self {
            frame_type,
            stream_id,
            payload,
        }
    }

    pub fn data(stream_id: StreamId, payload: Bytes) -> Self {
        Self::new(FrameType::Data, stream_id, payload)
    }

    pub fn open(stream_id: StreamId, payload: Bytes) -> Self {
        Self::new(FrameType::Open, stream_id, payload)
    }

    pub fn open_ok(stream_id: StreamId) -> Self {
        Self::new(FrameType::OpenOk, stream_id, Bytes::new())
    }

    pub fn open_error(stream_id: StreamId, reason: &str) -> Self {
        Self::new(
            FrameType::OpenError,
            stream_id,
            Bytes::copy_from_slice(truncate_reason(reason).as_bytes()),
        )
    }

    pub fn close(stream_id: StreamId) -> Self {
        Self::new(FrameType::Close, stream_id, Bytes::new())
    }

    pub fn reset(stream_id: StreamId) -> Self {
        Self::new(FrameType::Reset, stream_id, Bytes::new())
    }

    pub fn ping(nonce: u64) -> Self {
        let mut buf = BytesMut::with_capacity(8);
        buf.put_u64(nonce);
        Self::new(FrameType::Ping, CONTROL_STREAM, buf.freeze())
    }

    /// A PONG echoes the PING payload verbatim so the initiator can match it.
    pub fn pong(payload: Bytes) -> Self {
        Self::new(FrameType::Pong, CONTROL_STREAM, payload)
    }

    pub fn window_update(stream_id: StreamId, credit: u32) -> Self {
        let mut buf = BytesMut::with_capacity(4);
        buf.put_u32(credit);
        Self::new(FrameType::WindowUpdate, stream_id, buf.freeze())
    }

    pub fn go_away(reason: &str) -> Self {
        Self::new(
            FrameType::GoAway,
            CONTROL_STREAM,
            Bytes::copy_from_slice(truncate_reason(reason).as_bytes()),
        )
    }

    /// Total wire size including the header.
    pub fn wire_len(&self) -> usize {
        HEADER_LEN + self.payload.len()
    }

    /// Read a PING/PONG nonce.
    pub fn nonce(&self) -> Result<u64> {
        if self.payload.len() != 8 {
            return Err(Error::protocol(format!(
                "{} payload must be 8 bytes, got {}",
                self.frame_type,
                self.payload.len()
            )));
        }
        let mut slice = &self.payload[..];
        Ok(slice.get_u64())
    }

    /// Read a `WINDOW_UPDATE` credit.
    pub fn credit(&self) -> Result<u32> {
        if self.payload.len() != 4 {
            return Err(Error::protocol(format!(
                "WINDOW_UPDATE payload must be 4 bytes, got {}",
                self.payload.len()
            )));
        }
        let mut slice = &self.payload[..];
        let credit = slice.get_u32();
        if credit == 0 {
            // A zero credit is meaningless and would let a peer spin us.
            return Err(Error::protocol("WINDOW_UPDATE credit must be > 0"));
        }
        Ok(credit)
    }

    /// Lossy UTF-8 reason for `OPEN_ERROR` / `GO_AWAY`.
    ///
    /// Lossy on purpose: a peer sending invalid UTF-8 in a diagnostic string is
    /// not a reason to kill an otherwise healthy tunnel.
    pub fn reason(&self) -> String {
        String::from_utf8_lossy(&self.payload[..self.payload.len().min(MAX_REASON_LEN)]).into_owned()
    }

    /// Encode into `dst`, validating against the negotiated payload cap.
    pub fn encode(&self, dst: &mut BytesMut, max_payload: usize) -> Result<()> {
        let len = self.payload.len();
        if len > max_payload.min(MAX_PAYLOAD_LEN) {
            return Err(Error::limit(format!(
                "{} payload {len} exceeds max {}",
                self.frame_type,
                max_payload.min(MAX_PAYLOAD_LEN)
            )));
        }
        if self.frame_type.is_control() && self.stream_id != CONTROL_STREAM {
            return Err(Error::protocol(format!(
                "{} must use stream id 0, got {}",
                self.frame_type, self.stream_id
            )));
        }
        dst.reserve(HEADER_LEN + len);
        dst.put_u8(PROTOCOL_VERSION);
        dst.put_u8(self.frame_type.as_u8());
        dst.put_u32(self.stream_id);
        dst.put_u16(len as u16);
        dst.put_slice(&self.payload);
        Ok(())
    }

    /// Try to decode one frame from `src`.
    ///
    /// Returns `Ok(None)` when more bytes are needed; the caller must not
    /// consume anything in that case. On `Ok(Some(_))` the frame's bytes have
    /// been consumed from `src`.
    ///
    /// Every failure path here is a hostile-input path. None of them may panic:
    /// bounds are checked before any indexing and the length field is validated
    /// before a single byte is reserved.
    pub fn decode(src: &mut BytesMut, max_payload: usize) -> Result<Option<Frame>> {
        if src.len() < HEADER_LEN {
            return Ok(None);
        }

        // Peek without consuming: we may need to wait for the payload.
        let version = src[0];
        if version != PROTOCOL_VERSION {
            return Err(Error::protocol(format!(
                "unsupported protocol version {version} (expected {PROTOCOL_VERSION})"
            )));
        }
        let frame_type = FrameType::from_u8(src[1])?;
        let stream_id = u32::from_be_bytes([src[2], src[3], src[4], src[5]]);
        let payload_len = u16::from_be_bytes([src[6], src[7]]) as usize;

        // Reject over-long frames before allocating anything for them.
        let cap = max_payload.min(MAX_PAYLOAD_LEN);
        if payload_len > cap {
            return Err(Error::limit(format!(
                "{frame_type} announced payload {payload_len} over negotiated max {cap}"
            )));
        }
        if frame_type.is_control() && stream_id != CONTROL_STREAM {
            return Err(Error::protocol(format!(
                "{frame_type} arrived on stream {stream_id}, must be 0"
            )));
        }
        if !frame_type.is_control() && stream_id == CONTROL_STREAM {
            return Err(Error::protocol(format!(
                "{frame_type} arrived on the reserved control stream"
            )));
        }
        // A DATA frame with no payload is ambiguous with half-close; forbid it
        // so CLOSE stays the only way to signal end-of-stream.
        if frame_type == FrameType::Data && payload_len == 0 {
            return Err(Error::protocol("DATA frame with empty payload"));
        }

        if src.len() < HEADER_LEN + payload_len {
            // Hint the allocator at the full frame so we grow once, not twice.
            src.reserve(HEADER_LEN + payload_len - src.len());
            return Ok(None);
        }

        src.advance(HEADER_LEN);
        let payload = src.split_to(payload_len).freeze();
        Ok(Some(Frame {
            frame_type,
            stream_id,
            payload,
        }))
    }
}

/// Truncate a reason string on a char boundary so we never emit invalid UTF-8.
fn truncate_reason(reason: &str) -> &str {
    if reason.len() <= MAX_REASON_LEN {
        return reason;
    }
    let mut end = MAX_REASON_LEN;
    while end > 0 && !reason.is_char_boundary(end) {
        end -= 1;
    }
    &reason[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX: usize = 64 * 1024;

    fn roundtrip(frame: &Frame) -> Frame {
        let mut buf = BytesMut::new();
        frame.encode(&mut buf, MAX).unwrap();
        assert_eq!(buf.len(), frame.wire_len());
        let decoded = Frame::decode(&mut buf, MAX).unwrap().unwrap();
        assert!(buf.is_empty(), "decoder left {} bytes behind", buf.len());
        decoded
    }

    #[test]
    fn header_is_eight_bytes() {
        let f = Frame::data(1, Bytes::from_static(b"x"));
        let mut buf = BytesMut::new();
        f.encode(&mut buf, MAX).unwrap();
        assert_eq!(buf.len(), HEADER_LEN + 1);
        assert_eq!(buf[0], PROTOCOL_VERSION);
        assert_eq!(buf[1], FrameType::Data.as_u8());
        assert_eq!(&buf[2..6], &1u32.to_be_bytes());
        assert_eq!(&buf[6..8], &1u16.to_be_bytes());
    }

    #[test]
    fn every_frame_type_roundtrips() {
        let cases = vec![
            Frame::open(7, Bytes::from_static(b"{}")),
            Frame::open_ok(7),
            Frame::open_error(7, "connection refused"),
            Frame::data(7, Bytes::from_static(b"hello world")),
            Frame::close(7),
            Frame::reset(7),
            Frame::ping(0xDEAD_BEEF),
            Frame::pong(Bytes::from_static(&[0, 0, 0, 0, 0, 0, 0, 9])),
            Frame::window_update(7, 65536),
            Frame::go_away("shutting down"),
        ];
        for original in cases {
            let decoded = roundtrip(&original);
            assert_eq!(decoded, original, "{} failed", original.frame_type);
        }
    }

    #[test]
    fn payload_bytes_are_preserved_exactly() {
        // The core guarantee of the whole system: bytes in == bytes out.
        let payload: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let f = Frame::data(42, Bytes::from(payload.clone()));
        let decoded = roundtrip(&f);
        assert_eq!(&decoded.payload[..], &payload[..]);
    }

    #[test]
    fn partial_header_yields_none_and_consumes_nothing() {
        let mut buf = BytesMut::from(&[PROTOCOL_VERSION, 0x04, 0, 0][..]);
        assert!(Frame::decode(&mut buf, MAX).unwrap().is_none());
        assert_eq!(buf.len(), 4, "decoder must not consume a partial header");
    }

    #[test]
    fn partial_payload_yields_none_and_consumes_nothing() {
        let f = Frame::data(1, Bytes::from_static(b"0123456789"));
        let mut buf = BytesMut::new();
        f.encode(&mut buf, MAX).unwrap();
        let full = buf.len();
        buf.truncate(full - 3);
        let before = buf.len();
        assert!(Frame::decode(&mut buf, MAX).unwrap().is_none());
        assert_eq!(buf.len(), before, "decoder must not consume a partial frame");
    }

    #[test]
    fn streaming_decode_handles_arbitrary_chunking() {
        // Simulates TLS record boundaries landing anywhere in the byte stream.
        let frames: Vec<Frame> = (1..=20)
            .map(|i| Frame::data(i, Bytes::from(vec![i as u8; (i as usize) * 37])))
            .collect();
        let mut wire = BytesMut::new();
        for f in &frames {
            f.encode(&mut wire, MAX).unwrap();
        }
        let wire = wire.freeze();

        for chunk_size in [1usize, 3, 7, 8, 9, 64, 511, 4096] {
            let mut buf = BytesMut::new();
            let mut decoded = Vec::new();
            for chunk in wire.chunks(chunk_size) {
                buf.extend_from_slice(chunk);
                while let Some(f) = Frame::decode(&mut buf, MAX).unwrap() {
                    decoded.push(f);
                }
            }
            assert!(buf.is_empty(), "leftover bytes at chunk size {chunk_size}");
            assert_eq!(decoded, frames, "mismatch at chunk size {chunk_size}");
        }
    }

    // --- hostile input -----------------------------------------------------

    #[test]
    fn bad_version_is_rejected() {
        let mut buf = BytesMut::from(&[99u8, 0x04, 0, 0, 0, 1, 0, 0][..]);
        let err = Frame::decode(&mut buf, MAX).unwrap_err();
        assert!(matches!(err, Error::Protocol(_)), "{err:?}");
    }

    #[test]
    fn unknown_frame_type_is_rejected() {
        let mut buf = BytesMut::from(&[PROTOCOL_VERSION, 0xFF, 0, 0, 0, 1, 0, 0][..]);
        assert!(Frame::decode(&mut buf, MAX).is_err());
    }

    #[test]
    fn oversized_announced_length_is_rejected_without_allocating() {
        // Peer claims 60000 bytes but we negotiated 1024. Must fail on the
        // header alone, before any buffer growth.
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[PROTOCOL_VERSION, FrameType::Data.as_u8(), 0, 0, 0, 1]);
        buf.extend_from_slice(&60000u16.to_be_bytes());
        let err = Frame::decode(&mut buf, 1024).unwrap_err();
        assert!(matches!(err, Error::Limit(_)), "{err:?}");
    }

    #[test]
    fn encoding_over_the_cap_is_refused() {
        let f = Frame::data(1, Bytes::from(vec![0u8; 2048]));
        let mut buf = BytesMut::new();
        assert!(matches!(
            f.encode(&mut buf, 1024).unwrap_err(),
            Error::Limit(_)
        ));
    }

    #[test]
    fn max_size_payload_is_accepted() {
        let f = Frame::data(1, Bytes::from(vec![7u8; MAX_PAYLOAD_LEN]));
        let mut buf = BytesMut::new();
        f.encode(&mut buf, MAX_PAYLOAD_LEN).unwrap();
        let decoded = Frame::decode(&mut buf, MAX_PAYLOAD_LEN).unwrap().unwrap();
        assert_eq!(decoded.payload.len(), MAX_PAYLOAD_LEN);
    }

    #[test]
    fn control_frame_on_a_real_stream_is_rejected() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[PROTOCOL_VERSION, FrameType::Ping.as_u8(), 0, 0, 0, 5]);
        buf.extend_from_slice(&8u16.to_be_bytes());
        buf.extend_from_slice(&[0u8; 8]);
        assert!(Frame::decode(&mut buf, MAX).is_err());
    }

    #[test]
    fn stream_frame_on_the_control_stream_is_rejected() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[PROTOCOL_VERSION, FrameType::Data.as_u8(), 0, 0, 0, 0]);
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(b"x");
        assert!(Frame::decode(&mut buf, MAX).is_err());
    }

    #[test]
    fn empty_data_frame_is_rejected() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[PROTOCOL_VERSION, FrameType::Data.as_u8(), 0, 0, 0, 1, 0, 0]);
        assert!(Frame::decode(&mut buf, MAX).is_err());
    }

    #[test]
    fn encoding_a_control_frame_off_stream_zero_is_refused() {
        let bad = Frame::new(FrameType::Ping, 5, Bytes::from_static(&[0u8; 8]));
        let mut buf = BytesMut::new();
        assert!(bad.encode(&mut buf, MAX).is_err());
    }

    #[test]
    fn malformed_nonce_and_credit_error_instead_of_panicking() {
        let short = Frame::new(FrameType::Ping, CONTROL_STREAM, Bytes::from_static(b"abc"));
        assert!(short.nonce().is_err());
        let bad_credit = Frame::new(FrameType::WindowUpdate, 1, Bytes::from_static(b"ab"));
        assert!(bad_credit.credit().is_err());
        let zero_credit = Frame::window_update(1, 0);
        assert!(zero_credit.credit().is_err());
    }

    #[test]
    fn nonce_and_credit_roundtrip() {
        assert_eq!(Frame::ping(u64::MAX).nonce().unwrap(), u64::MAX);
        assert_eq!(Frame::window_update(3, 1).credit().unwrap(), 1);
        assert_eq!(Frame::window_update(3, u32::MAX).credit().unwrap(), u32::MAX);
    }

    #[test]
    fn long_reason_is_truncated_on_a_char_boundary() {
        let reason = "字".repeat(500); // 3 bytes each
        let f = Frame::open_error(1, &reason);
        assert!(f.payload.len() <= MAX_REASON_LEN);
        // Truncation must not split a codepoint.
        assert!(std::str::from_utf8(&f.payload).is_ok());
    }

    #[test]
    fn invalid_utf8_reason_does_not_error() {
        let f = Frame::new(
            FrameType::OpenError,
            1,
            Bytes::from_static(&[0xFF, 0xFE, 0xFD]),
        );
        assert!(!f.reason().is_empty());
    }

    #[test]
    fn max_stream_id_is_usable() {
        let f = Frame::data(u32::MAX, Bytes::from_static(b"z"));
        assert_eq!(roundtrip(&f).stream_id, u32::MAX);
    }

    #[test]
    fn garbage_input_never_panics() {
        // Deterministic pseudo-random fuzz over the decoder. The property under
        // test is "no panic", not any particular verdict.
        let mut state = 0x12345678u32;
        let mut next = || {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            (state >> 24) as u8
        };
        for _ in 0..2000 {
            let len = (next() % 64) as usize;
            let mut buf = BytesMut::with_capacity(len);
            for _ in 0..len {
                buf.put_u8(next());
            }
            // Must return, not unwind.
            let _ = Frame::decode(&mut buf, MAX);
        }
    }
}
