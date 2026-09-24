//! `tunnel-common` — shared building blocks for every crate in the workspace.
//!
//! This crate deliberately contains **no** network protocol logic and **no**
//! control-plane logic. It only holds things that both the data plane and the
//! control plane must agree on:
//!
//! * [`error`] — the single error type used across the workspace
//! * [`model`] — serialisable domain model (nodes, endpoints, routes, config bundle)
//! * [`net`] — socket tuning, source-address binding, interface discovery
//! * [`backoff`] — exponential backoff with jitter (reconnect storms are real)
//! * [`logging`] — `tracing` initialisation, plain or JSON
//! * [`time`] — monotonic/wall clock helpers used by metrics and heartbeats
//! * [`secret`] — a `Debug`/`Display`-redacted string wrapper for PSKs & tokens

pub mod backoff;
pub mod error;
pub mod logging;
pub mod model;
pub mod net;
pub mod secret;
pub mod time;

pub use error::{Error, Result};
pub use secret::Secret;

/// Wire/config compatibility version of the shared model.
///
/// The agent sends this on registration; the control plane refuses agents that
/// speak a different major model version instead of silently mis-configuring
/// them.
pub const MODEL_VERSION: u32 = 1;

/// Crate version of the running binary, surfaced in the admin panel.
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
