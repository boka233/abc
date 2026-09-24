//! Workspace-wide error type.
//!
//! Rule that matters for this project: **network input must never panic the
//! process**. Every fallible path in the data plane returns [`Error`] so a
//! malformed frame kills exactly one connection, never the agent.

use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// Peer violated the frame protocol (bad version, bad length, unknown
    /// stream, desync). Always fatal for the offending tunnel connection.
    #[error("protocol violation: {0}")]
    Protocol(String),

    #[error("tls error: {0}")]
    Tls(String),

    #[error("configuration error: {0}")]
    Config(String),

    /// Handshake authentication failed. Never carries the secret itself.
    #[error("authentication failed: {0}")]
    Auth(&'static str),

    #[error("{0} timed out")]
    Timeout(&'static str),

    /// A resource limit was hit (max connections, max frame size, window).
    #[error("limit exceeded: {0}")]
    Limit(String),

    #[error("{0} not found")]
    NotFound(String),

    /// Local shutdown or peer-initiated close of the underlying tunnel.
    #[error("connection closed")]
    Closed,

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn protocol(msg: impl Into<String>) -> Self {
        Error::Protocol(msg.into())
    }

    pub fn config(msg: impl Into<String>) -> Self {
        Error::Config(msg.into())
    }

    pub fn tls(msg: impl Into<String>) -> Self {
        Error::Tls(msg.into())
    }

    pub fn limit(msg: impl Into<String>) -> Self {
        Error::Limit(msg.into())
    }

    pub fn other(msg: impl Into<String>) -> Self {
        Error::Other(msg.into())
    }

    /// `true` when retrying the same operation may reasonably succeed later.
    ///
    /// Used by the tunnel supervisor to decide between "reconnect with backoff"
    /// and "this endpoint is structurally broken, count a hard failure".
    pub fn is_transient(&self) -> bool {
        match self {
            Error::Io(e) => matches!(
                e.kind(),
                io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::NotConnected
                    | io::ErrorKind::AddrNotAvailable
                    | io::ErrorKind::WouldBlock
                    | io::ErrorKind::Interrupted
            ),
            Error::Timeout(_) | Error::Closed => true,
            Error::Tls(_) => true,
            Error::Protocol(_) | Error::Auth(_) | Error::Config(_) => false,
            Error::Limit(_) | Error::NotFound(_) | Error::Other(_) => false,
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Other(format!("json: {e}"))
    }
}

impl From<toml::de::Error> for Error {
    fn from(e: toml::de::Error) -> Self {
        Error::Config(format!("toml: {e}"))
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        match e {
            Error::Io(inner) => inner,
            Error::Closed => io::Error::from(io::ErrorKind::BrokenPipe),
            Error::Timeout(_) => io::Error::from(io::ErrorKind::TimedOut),
            other => io::Error::other(other.to_string()),
        }
    }
}
