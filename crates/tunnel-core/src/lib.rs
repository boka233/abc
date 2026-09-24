//! `tunnel-core` — the data plane.
//!
//! # Structure
//!
//! ```text
//!   entry.rs                                     exit.rs
//!   ────────                                     ───────
//!   TcpListener                                  TlsAcceptor
//!       │ accept                                     │ accept
//!       ▼                                            ▼
//!   pool.rs  ── picks a tunnel ──▶  mux.rs  ◀── mux.rs
//!       │                             │              │
//!       │                        TLS 1.3 conn        │ connect(target)
//!       │                                            ▼
//!   relay.rs  ◀── stream ↔ socket copy ──▶  relay.rs
//! ```
//!
//! * [`tls`] — rustls config construction, hot-reloadable certificates
//! * [`mux`] — one TLS connection carrying N logical streams, with credit-based
//!   flow control
//! * [`relay`] — bidirectional copy between a TCP socket and a logical stream,
//!   preserving half-close
//! * [`pool`] — a set of tunnel connections per route, to bound head-of-line
//!   blocking
//! * [`health`] — endpoint failure tracking with thresholds and cooldown, so
//!   links do not flap
//! * [`metrics`] — atomic counters read by the reporting loop; never on the
//!   per-packet path
//! * [`entry`] / [`exit`] — the two roles

pub mod entry;
pub mod exit;
pub mod health;
pub mod metrics;
pub mod mux;
pub mod pool;
pub mod relay;
pub mod targets;
pub mod tls;

pub use health::{EndpointHealth, HealthPolicy, HealthVerdict};
pub use metrics::{ConnectionRegistry, Counters, RateTracker, RouteMetrics, TunnelMetrics};
pub use mux::{Multiplexer, MuxConfig, MuxRole, StreamHandle};
pub use pool::{TunnelPool, PoolConfig};
pub use targets::{TargetSelector, TargetStatus};
pub use tls::{TlsMaterial, TunnelTlsConfig};
