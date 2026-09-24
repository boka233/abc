//! Tunnel handshake, layered on top of TLS 1.3.
//!
//! TLS already authenticates the *server* (and the client under mTLS). The
//! handshake here adds three things TLS does not give us:
//!
//! 1. **Protocol/limit negotiation** — both sides must agree on
//!    `max_frame_payload` and the initial stream window before any frame flows,
//!    otherwise one side's "valid frame" is the other's protocol violation.
//! 2. **Route binding** — the exit learns which route a tunnel serves, so it
//!    can apply that route's target and egress binding.
//! 3. **A PSK proof** — cheap defence in depth. If a certificate is
//!    mis-issued or `insecure_skip_verify` is left on in a lab config, the PSK
//!    still stops an unauthorised peer from opening streams.
//!
//! ## PSK proof construction
//!
//! The client sends a random nonce; the proof is
//! `HMAC-SHA256(psk, b"tunnel-v1" || node_id || route_id || nonce)`.
//! Verification is constant-time.
//!
//! This binds the proof to the nonce and to the claimed identity, so a captured
//! proof cannot be replayed for a different route. The server additionally
//! rejects a nonce it has seen recently, which closes the replay window inside
//! the same connection generation. Full replay protection comes from TLS 1.3
//! itself — this layer exists to survive a TLS misconfiguration, not to replace
//! it. The PSK itself never crosses the wire.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tunnel_common::{Error, Result, Secret};

use crate::frame::PROTOCOL_VERSION;

type HmacSha256 = Hmac<Sha256>;

const PROOF_DOMAIN: &[u8] = b"tunnel-v1";
pub const NONCE_LEN: usize = 32;

/// Cap on a handshake message, checked before the JSON body is read. Keeps a
/// hostile peer from making us buffer megabytes during the handshake.
pub const MAX_HANDSHAKE_LEN: usize = 8 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("protocol version mismatch: peer speaks {peer}, we speak {ours}")]
    VersionMismatch { peer: u8, ours: u8 },
    #[error("handshake rejected: {0}")]
    Rejected(String),
    #[error("limits are incompatible: {0}")]
    IncompatibleLimits(String),
}

impl From<HandshakeError> for Error {
    fn from(e: HandshakeError) -> Self {
        match e {
            HandshakeError::VersionMismatch { .. } => Error::Protocol(e.to_string()),
            HandshakeError::Rejected(m) => Error::Protocol(format!("handshake rejected: {m}")),
            HandshakeError::IncompatibleLimits(m) => Error::Config(m),
        }
    }
}

/// entry → exit, first message after the TLS handshake completes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHello {
    pub version: u8,
    /// Identity of the dialling node. Informational for the exit; also bound
    /// into the PSK proof.
    pub node_id: String,
    /// Route this tunnel serves. The exit resolves the target from it.
    pub route_id: String,
    /// Which tunnel this is within the route's pool. Diagnostics only.
    pub pool_index: u16,
    /// Hex-encoded random nonce, [`NONCE_LEN`] bytes.
    pub nonce: String,
    /// Hex-encoded HMAC proof. Empty when no PSK is configured.
    #[serde(default)]
    pub proof: String,
    /// Largest payload this side is willing to *receive*.
    pub max_frame_payload: u32,
    /// Initial per-stream receive window this side offers.
    pub stream_window: u32,
    pub agent_version: String,
}

/// exit → entry, reply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHello {
    pub version: u8,
    pub accepted: bool,
    /// Populated when `accepted == false`. Deliberately vague about *why* auth
    /// failed so it cannot be used as an oracle.
    #[serde(default)]
    pub reason: Option<String>,
    /// Negotiated values: `min` of what both sides offered. Both ends must use
    /// these, not their own proposals.
    pub max_frame_payload: u32,
    pub stream_window: u32,
    pub node_id: String,
    pub agent_version: String,
}

/// Payload of an `OPEN` frame.
///
/// The target is resolved by the exit from its own route config, *not* taken
/// from this message — an entry cannot ask an exit to dial an arbitrary host.
/// That would turn every exit into an open proxy. The optional fields here are
/// diagnostics only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamOpen {
    pub route_id: String,
    /// Client address, for the connections table. Never used for routing.
    #[serde(default)]
    pub client_addr: Option<String>,
}

/// Build the HMAC proof for a hello.
///
/// Returns `None` only if the HMAC construction rejects the key, which
/// HMAC-SHA256 never does — it accepts any key length. Propagating that instead
/// of unwrapping keeps this function total, so no handshake path can panic on a
/// hostile or malformed input.
pub fn compute_proof(
    psk: &Secret,
    node_id: &str,
    route_id: &str,
    nonce: &[u8],
) -> Option<String> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(psk.as_bytes()).ok()?;
    mac.update(PROOF_DOMAIN);
    mac.update(node_id.as_bytes());
    mac.update(route_id.as_bytes());
    mac.update(nonce);
    Some(hex_encode(&mac.finalize().into_bytes()))
}

/// Constant-time proof verification.
pub fn verify_proof(
    psk: Option<&Secret>,
    hello: &ClientHello,
) -> std::result::Result<(), HandshakeError> {
    let Some(psk) = psk else {
        // No PSK configured: TLS (ideally mTLS) is the only authentication.
        return Ok(());
    };
    if psk.is_empty() {
        return Ok(());
    }

    let nonce = hex_decode(&hello.nonce)
        .map_err(|_| HandshakeError::Rejected("authentication failed".into()))?;
    if nonce.len() != NONCE_LEN {
        return Err(HandshakeError::Rejected("authentication failed".into()));
    }

    let Some(expected) = compute_proof(psk, &hello.node_id, &hello.route_id, &nonce) else {
        return Err(HandshakeError::Rejected("authentication failed".into()));
    };
    // Length check first, then constant-time compare of the bytes.
    if expected.len() != hello.proof.len() {
        return Err(HandshakeError::Rejected("authentication failed".into()));
    }
    if expected.as_bytes().ct_eq(hello.proof.as_bytes()).into() {
        Ok(())
    } else {
        Err(HandshakeError::Rejected("authentication failed".into()))
    }
}

impl ClientHello {
    pub fn new(
        node_id: impl Into<String>,
        route_id: impl Into<String>,
        pool_index: u16,
        psk: Option<&Secret>,
        max_frame_payload: u32,
        stream_window: u32,
    ) -> Self {
        let node_id = node_id.into();
        let route_id = route_id.into();
        let nonce = random_nonce();
        let proof = match psk {
            Some(p) if !p.is_empty() => {
                compute_proof(p, &node_id, &route_id, &nonce).unwrap_or_default()
            }
            _ => String::new(),
        };
        Self {
            version: PROTOCOL_VERSION,
            node_id,
            route_id,
            pool_index,
            nonce: hex_encode(&nonce),
            proof,
            max_frame_payload,
            stream_window,
            agent_version: tunnel_common::AGENT_VERSION.to_string(),
        }
    }

    pub fn check_version(&self) -> std::result::Result<(), HandshakeError> {
        if self.version != PROTOCOL_VERSION {
            return Err(HandshakeError::VersionMismatch {
                peer: self.version,
                ours: PROTOCOL_VERSION,
            });
        }
        Ok(())
    }
}

/// Negotiate effective limits: take the smaller of the two proposals so neither
/// side can be pushed past what it is willing to buffer.
pub fn negotiate(
    ours_max_payload: u32,
    ours_window: u32,
    theirs_max_payload: u32,
    theirs_window: u32,
) -> std::result::Result<(u32, u32), HandshakeError> {
    let payload = ours_max_payload.min(theirs_max_payload);
    let window = ours_window.min(theirs_window);
    if payload < 1024 {
        return Err(HandshakeError::IncompatibleLimits(format!(
            "negotiated max_frame_payload {payload} is below the 1024 floor"
        )));
    }
    if payload as usize > crate::frame::MAX_PAYLOAD_LEN {
        return Err(HandshakeError::IncompatibleLimits(format!(
            "negotiated max_frame_payload {payload} exceeds the wire limit {}",
            crate::frame::MAX_PAYLOAD_LEN
        )));
    }
    if window < payload {
        return Err(HandshakeError::IncompatibleLimits(format!(
            "negotiated window {window} is smaller than one frame ({payload}); \
             a full-size frame could never be sent"
        )));
    }
    Ok((payload, window))
}

// --- hex helpers -----------------------------------------------------------
// Hand-rolled to keep the dependency list short; both are total functions.

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(Error::protocol("hex string has odd length"));
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = hex_val(pair[0])?;
        let lo = hex_val(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_val(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(Error::protocol("invalid hex digit")),
    }
}

fn random_nonce() -> Vec<u8> {
    use rand::RngCore;
    let mut buf = vec![0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(psk: Option<&Secret>) -> ClientHello {
        ClientHello::new("sh-01", "route-1", 0, psk, 64 * 1024, 512 * 1024)
    }

    #[test]
    fn hex_roundtrip() {
        let data = vec![0x00, 0x0f, 0xf0, 0xff, 0x42];
        assert_eq!(hex_decode(&hex_encode(&data)).unwrap(), data);
        assert!(hex_decode("abc").is_err());
        assert!(hex_decode("zz").is_err());
        assert_eq!(hex_decode("AbCd").unwrap(), vec![0xAB, 0xCD]);
    }

    #[test]
    fn valid_proof_is_accepted() {
        let psk = Secret::new("shared-secret");
        verify_proof(Some(&psk), &hello(Some(&psk))).unwrap();
    }

    #[test]
    fn wrong_psk_is_rejected() {
        let h = hello(Some(&Secret::new("right")));
        assert!(verify_proof(Some(&Secret::new("wrong")), &h).is_err());
    }

    #[test]
    fn tampered_route_invalidates_the_proof() {
        // A proof captured for route-1 must not authorise route-2.
        let psk = Secret::new("k");
        let mut h = hello(Some(&psk));
        h.route_id = "route-2".into();
        assert!(verify_proof(Some(&psk), &h).is_err());
    }

    #[test]
    fn tampered_node_id_invalidates_the_proof() {
        let psk = Secret::new("k");
        let mut h = hello(Some(&psk));
        h.node_id = "attacker".into();
        assert!(verify_proof(Some(&psk), &h).is_err());
    }

    #[test]
    fn tampered_nonce_invalidates_the_proof() {
        let psk = Secret::new("k");
        let mut h = hello(Some(&psk));
        h.nonce = hex_encode(&[0u8; NONCE_LEN]);
        assert!(verify_proof(Some(&psk), &h).is_err());
    }

    #[test]
    fn malformed_nonce_is_rejected_not_panicking() {
        let psk = Secret::new("k");
        for bad in ["", "zz", "00", &"0".repeat(63)] {
            let mut h = hello(Some(&psk));
            h.nonce = bad.to_string();
            assert!(verify_proof(Some(&psk), &h).is_err(), "accepted `{bad}`");
        }
    }

    #[test]
    fn no_psk_means_tls_only() {
        verify_proof(None, &hello(None)).unwrap();
        verify_proof(Some(&Secret::new("")), &hello(None)).unwrap();
    }

    #[test]
    fn rejection_reason_leaks_nothing() {
        let err = verify_proof(Some(&Secret::new("right")), &hello(Some(&Secret::new("wrong"))))
            .unwrap_err();
        let msg = err.to_string();
        assert!(!msg.contains("right") && !msg.contains("wrong"), "{msg}");
        assert!(!msg.contains("nonce") && !msg.contains("proof"), "{msg}");
    }

    #[test]
    fn nonces_are_unique_per_hello() {
        let psk = Secret::new("k");
        let a = hello(Some(&psk));
        let b = hello(Some(&psk));
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.proof, b.proof);
        assert_eq!(a.nonce.len(), NONCE_LEN * 2);
    }

    #[test]
    fn psk_never_appears_in_the_serialised_hello() {
        let psk = Secret::new("top-secret-psk-value");
        let json = serde_json::to_string(&hello(Some(&psk))).unwrap();
        assert!(!json.contains("top-secret-psk-value"), "PSK leaked: {json}");
    }

    #[test]
    fn version_mismatch_is_detected() {
        let mut h = hello(None);
        h.version = 99;
        assert!(matches!(
            h.check_version(),
            Err(HandshakeError::VersionMismatch { peer: 99, .. })
        ));
    }

    #[test]
    fn negotiation_takes_the_minimum() {
        let (payload, window) = negotiate(64 * 1024, 512 * 1024, 32 * 1024, 256 * 1024).unwrap();
        assert_eq!(payload, 32 * 1024);
        assert_eq!(window, 256 * 1024);
    }

    #[test]
    fn negotiation_rejects_a_window_below_one_frame() {
        assert!(negotiate(64 * 1024, 64 * 1024, 64 * 1024, 4096).is_err());
    }

    #[test]
    fn negotiation_rejects_a_tiny_payload() {
        assert!(negotiate(64 * 1024, 512 * 1024, 512, 512 * 1024).is_err());
    }

    #[test]
    fn negotiation_rejects_over_wire_limit() {
        assert!(negotiate(u32::MAX, u32::MAX, u32::MAX, u32::MAX).is_err());
    }

    #[test]
    fn hello_json_roundtrip() {
        let h = hello(Some(&Secret::new("k")));
        let back: ClientHello = serde_json::from_str(&serde_json::to_string(&h).unwrap()).unwrap();
        assert_eq!(back.nonce, h.nonce);
        assert_eq!(back.proof, h.proof);
        assert_eq!(back.route_id, h.route_id);
    }
}
