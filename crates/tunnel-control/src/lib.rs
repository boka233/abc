//! `tunnel-control` — the control plane.
//!
//! # The decoupling rule
//!
//! The control plane must never be in the path of user traffic. Agents fetch
//! configuration and push telemetry; they do not wait on the control plane to
//! move bytes. If this process dies, every established tunnel keeps running and
//! every agent keeps serving from its cached last-known-good configuration.
//!
//! Two consequences show up throughout the code:
//!
//! * There is no "push config and wait" path. Changing a route bumps a revision
//!   number; agents notice on their next poll. An operator action that required a
//!   live agent connection would fail whenever an agent was briefly unreachable.
//! * "Restart route" is advisory. The control plane cannot reach into an agent's
//!   process, and pretending otherwise would be a lie in the UI.
//!
//! # Layout
//!
//! * [`config`] — deployment configuration from TOML/env
//! * [`auth`] — session tokens and login throttling
//! * [`state`] — shared state and the in-memory telemetry hub
//! * [`distribute`] — assembling an agent's config bundle
//! * [`api`] — HTTP handlers, extractors, WebSocket
//! * [`tasks`] — aggregation, staleness and retention loops

pub mod api;
pub mod auth;
pub mod config;
pub mod distribute;
pub mod geo;
pub mod state;
pub mod tasks;

pub use config::ControlConfig;
pub use state::AppState;
