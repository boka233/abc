//! `tracing` initialisation.
//!
//! Two output modes: human-readable for a terminal, JSON for shipping to
//! Loki/ELK. Level comes from config with `RUST_LOG` able to override, so an
//! operator can raise verbosity on one box without editing the config.
//!
//! Logging discipline enforced by convention across the workspace: secrets are
//! wrapped in [`crate::Secret`] (renders as `***`), payload bytes are never
//! logged, and client addresses are logged at DEBUG or redacted.

use serde::{Deserialize, Serialize};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LogConfig {
    /// `trace` | `debug` | `info` | `warn` | `error`, or a full `EnvFilter`
    /// directive such as `info,tunnel_core::mux=debug`.
    pub level: String,
    pub format: LogFormat,
    /// Include the emitting module path. Useful in dev, noisy in production.
    pub with_target: bool,
    pub with_thread_ids: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            format: LogFormat::Text,
            with_target: true,
            with_thread_ids: false,
        }
    }
}

/// Install the global subscriber. Safe to call once per process; later calls are
/// ignored rather than panicking, which keeps tests from fighting each other.
pub fn init(cfg: &LogConfig) {
    // RUST_LOG wins so an operator can override without a config edit.
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&cfg.level))
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let registry = tracing_subscriber::registry().with(filter);

    let result = match cfg.format {
        LogFormat::Json => registry
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .flatten_event(true)
                    .with_target(cfg.with_target)
                    .with_thread_ids(cfg.with_thread_ids)
                    .with_current_span(false)
                    .with_span_list(false),
            )
            .try_init(),
        LogFormat::Text => registry
            .with(
                tracing_subscriber::fmt::layer()
                    .with_target(cfg.with_target)
                    .with_thread_ids(cfg.with_thread_ids)
                    .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout())),
            )
            .try_init(),
    };

    if result.is_err() {
        tracing::debug!("tracing subscriber already installed; keeping the existing one");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_info_text() {
        let c = LogConfig::default();
        assert_eq!(c.level, "info");
        assert_eq!(c.format, LogFormat::Text);
    }

    #[test]
    fn double_init_does_not_panic() {
        init(&LogConfig::default());
        init(&LogConfig {
            format: LogFormat::Json,
            ..Default::default()
        });
    }
}
