//! Binary frame protocol for the entry↔exit tunnel.
//!
//! # Scope
//!
//! This protocol multiplexes **opaque TCP byte streams** over one TLS 1.3
//! connection. It deliberately knows nothing about what rides inside a stream.
//! Dodobird frames, VLESS, plain HTTP — all identical from here: a sequence of
//! bytes that must come out the far end in the same order, unmodified, with the
//! connection's open/half-close/close lifecycle preserved.
//!
//! There is no UDP in this protocol. No `UDP_OPEN`, no datagram framing, no
//! QUIC. Upper layers that need UDP (Dodobird does) already encapsulate it in
//! their own TCP stream before it reaches us.
//!
//! # Layering
//!
//! ```text
//! TCP  ──▶  TLS 1.3  ──▶  [ frame | frame | frame … ]  ──▶  N logical streams
//! ```
//!
//! # Wire format
//!
//! ```text
//!  0       1       2               6               8
//!  ├───────┼───────┼───────────────┼───────────────┼─────────────────┐
//!  │  ver  │ type  │   stream id   │  payload len  │     payload     │
//!  │  u8   │  u8   │  u32be        │    u16be      │   len bytes     │
//!  └───────┴───────┴───────────────┴───────────────┴─────────────────┘
//! ```
//!
//! An 8-byte header. `u16` length caps a single frame at 65535 bytes of payload
//! and makes an over-long length structurally unrepresentable rather than
//! something we have to defend against — the `u32` length field found in many
//! hand-rolled protocols is where the OOM bugs live. A negotiated
//! [`Limits::max_frame_payload`] tightens it further.
//!
//! [`Limits::max_frame_payload`]: tunnel_common::model::Limits::max_frame_payload

pub mod codec;
pub mod frame;
pub mod handshake;

pub use codec::{FrameReader, FrameWriter};
pub use frame::{Frame, FrameType, StreamId, HEADER_LEN, MAX_PAYLOAD_LEN, PROTOCOL_VERSION};
pub use handshake::{ClientHello, HandshakeError, ServerHello, StreamOpen};
