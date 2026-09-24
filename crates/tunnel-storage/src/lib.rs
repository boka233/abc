//! `tunnel-storage` — SQLite persistence for the control plane.
//!
//! # Position in the architecture
//!
//! This crate is reachable **only** from the control plane. The data plane never
//! links it and never blocks on it. That separation is deliberate: a database
//! write in a relay path would put disk latency between a client and its target,
//! and a locked SQLite file would stall traffic. Counters live in atomics
//! ([`tunnel_core::metrics`]) and an aggregation loop persists rolled-up rows on
//! a slow cadence.
//!
//! # Repository pattern
//!
//! Every table has a repository with a narrow, typed API. Handlers never write
//! SQL. The point is not ceremony — it is that the eventual move to PostgreSQL
//! touches these files and nothing else.
//!
//! # SQLite specifics that matter
//!
//! * **WAL mode** — readers do not block the writer. Without it, the dashboard's
//!   polling would contend with heartbeat writes.
//! * **`busy_timeout`** — SQLite returns `SQLITE_BUSY` immediately by default;
//!   under concurrent writes that surfaces as random failures. A timeout makes
//!   the writer wait instead.
//! * **One writer** — SQLite serialises writes regardless of pool size. The pool
//!   is sized for readers; write-heavy paths are batched in one transaction.
//! * **`foreign_keys = ON`** — off by default in SQLite, which silently permits
//!   orphan rows.

pub mod audit;
pub mod db;
pub mod groups;
pub mod models;
pub mod nodes;
pub mod routes;
pub mod settings;
pub mod stats;
pub mod users;

pub use db::{Database, DbError};
pub use models::*;
