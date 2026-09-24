//! `tunnel-agent` binary: entry, exit, or both.
//!
//! # Startup order, and why it is this way
//!
//! ```text
//! load local config
//!   └─▶ apply cached bundle   ◀── data plane is already serving here
//!         └─▶ contact control plane
//!               └─▶ apply fresh bundle (if any)
//! ```
//!
//! The cached configuration is applied *before* the control plane is contacted.
//! A node that reboots during a control-plane outage comes back carrying traffic
//! instead of waiting for an API that may be down. Registration failures are
//! retried with backoff and never block the data plane.

mod client;
mod config;
mod host;
mod supervisor;

use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use tokio::sync::watch;
use tunnel_common::backoff::Backoff;
use tunnel_common::logging;
use tunnel_common::model::AgentConfigBundle;

use crate::client::{ConfigPoll, ControlClient};
use crate::config::AgentConfig;
use crate::supervisor::Supervisor;

#[derive(Parser)]
#[command(
    name = "tunnel-agent",
    about = "TLS tunnel data plane agent (entry / exit / both)",
    version
)]
struct Cli {
    #[arg(
        short,
        long,
        env = "TUNNEL_AGENT_CONFIG",
        default_value = "/etc/tunnel-agent/config.toml"
    )]
    config: std::path::PathBuf,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the agent (default).
    Run,
    /// Print a starter configuration file.
    SampleConfig,
    /// Validate the configuration and exit.
    Check,
    /// Show the local network interfaces the agent can see.
    ///
    /// Read-only. The agent never modifies routing or sysctl settings; see
    /// `docs/networking-iepl.md` for the configuration an IEPL host needs.
    Interfaces,
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();

    if matches!(cli.command, Some(Command::SampleConfig)) {
        println!("{}", AgentConfig::sample_toml());
        return std::process::ExitCode::SUCCESS;
    }
    if matches!(cli.command, Some(Command::Interfaces)) {
        print_interfaces();
        return std::process::ExitCode::SUCCESS;
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("failed to start the async runtime: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run(cli)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("tunnel-agent: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn print_interfaces() {
    println!("{:<16} {:<40} FLAGS", "INTERFACE", "ADDRESSES");
    for iface in tunnel_common::net::interfaces() {
        let addresses = iface
            .addresses
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let flags = if iface.is_loopback { "loopback" } else { "" };
        println!("{:<16} {:<40} {}", iface.name, addresses, flags);
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let cfg = AgentConfig::load(&cli.config)
        .map_err(|e| anyhow::anyhow!("configuration error: {e}"))?;
    logging::init(&cfg.log);

    match cli.command.unwrap_or(Command::Run) {
        Command::SampleConfig | Command::Interfaces => {
            unreachable!("handled before the runtime starts")
        }
        Command::Check => {
            cfg.validate()?;
            println!("configuration at {} is valid", cli.config.display());
            Ok(())
        }
        Command::Run => serve(cfg).await,
    }
}

async fn serve(cfg: AgentConfig) -> anyhow::Result<()> {
    tracing::info!(
        version = tunnel_common::AGENT_VERSION,
        node_name = %cfg.effective_node_name(),
        standalone = cfg.standalone,
        "tunnel-agent 启动"
    );

    let supervisor = Supervisor::new(cfg.clone());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // --- standalone mode: one local bundle, no control plane at all ---
    if cfg.standalone {
        let path = cfg
            .standalone_config
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("standalone_config is required in standalone mode"))?;
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
        let bundle: AgentConfigBundle = serde_json::from_str(&text)
            .map_err(|e| anyhow::anyhow!("invalid bundle in {}: {e}", path.display()))?;
        supervisor.apply(&bundle, false).await?;
        for line in supervisor.describe().await {
            tracing::info!("{line}");
        }
    } else {
        // Serve from cache immediately; the control plane can catch up later.
        let from_cache = supervisor.start_from_cache().await;
        if !from_cache {
            tracing::info!("no usable cached configuration; waiting for the control plane");
        }
    }

    // --- background loops ---
    let mut tasks = Vec::new();

    if !cfg.standalone {
        let client = ControlClient::new(
            &cfg.control_url,
            cfg.effective_node_name(),
            cfg.enroll_token.clone(),
            cfg.control_timeout,
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .with_hostname(crate::config::hostname())
        .with_role(cfg.role.map(|r| r.as_str().to_string()));
        let client = Arc::new(client);

        tasks.push(tokio::spawn(control_loop(
            supervisor.clone(),
            client.clone(),
            shutdown_rx.clone(),
        )));
        tasks.push(tokio::spawn(heartbeat_loop(
            supervisor.clone(),
            client,
            shutdown_rx.clone(),
        )));
    }

    tasks.push(tokio::spawn(reaper_loop(
        supervisor.clone(),
        shutdown_rx.clone(),
    )));

    #[cfg(unix)]
    tasks.push(tokio::spawn(sighup_loop(
        supervisor.clone(),
        shutdown_rx.clone(),
    )));

    // --- wait for shutdown ---
    shutdown_signal().await;
    tracing::info!("shutdown requested");
    let _ = shutdown_tx.send(true);

    // Stop accepting and let in-flight streams finish before exiting, so a
    // systemd restart does not reset every user connection at once.
    supervisor.shutdown().await;

    for task in tasks {
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    tracing::info!("tunnel-agent stopped");
    Ok(())
}

/// Register, then poll for configuration changes.
async fn control_loop(
    supervisor: Arc<Supervisor>,
    client: Arc<ControlClient>,
    mut shutdown: watch::Receiver<bool>,
) {
    let poll_interval = supervisor.config().config_poll_interval;
    let mut backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(60));
    let mut registered = false;

    loop {
        if *shutdown.borrow() {
            return;
        }

        let result = if registered {
            match client.poll_config(Some(supervisor.applied_revision())).await {
                Ok(ConfigPoll::Unchanged) => Ok(None),
                Ok(ConfigPoll::Updated(bundle)) => Ok(Some(*bundle)),
                Err(e) => Err(e),
            }
        } else {
            // 注册同时拿到控制面分配的机器 id，心跳要用它标识自己。
            match client.register().await {
                Ok(reg) => {
                    tracing::info!(
                        node_id = %reg.node_id,
                        group = %reg.group_name,
                        "已加入设备组"
                    );
                    supervisor.set_node_id(reg.node_id);
                    Ok(Some(reg.bundle))
                }
                Err(e) => Err(e),
            }
        };

        match result {
            Ok(None) => {
                registered = true;
                backoff.reset();
            }
            Ok(Some(bundle)) => {
                registered = true;
                backoff.reset();
                let revision = bundle.revision;
                if revision == supervisor.applied_revision() && revision != 0 {
                    tracing::debug!(revision, "configuration unchanged");
                } else {
                    match supervisor.apply(&bundle, true).await {
                        Ok(()) => {
                            tracing::info!(revision, "applied configuration from control plane");
                            for line in supervisor.describe().await {
                                tracing::info!("{line}");
                            }
                        }
                        Err(e) => {
                            // The previous configuration is still serving; this
                            // is a report, not an outage.
                            tracing::error!(
                                revision,
                                error = %e,
                                "rejected configuration from control plane; keeping the previous one"
                            );
                        }
                    }
                }
            }
            Err(e) => {
                let fatal_auth = matches!(e, tunnel_common::Error::Auth(_));
                let delay = backoff.next_delay();
                if fatal_auth {
                    // A wrong token will not fix itself. Keep serving, keep
                    // complaining, but do not hammer the control plane.
                    tracing::error!(
                        error = %e,
                        retry_in_secs = delay.as_secs(),
                        "control plane rejected our credentials; the data plane continues \
                         on its current configuration"
                    );
                } else {
                    tracing::warn!(
                        error = %e,
                        retry_in_secs = delay.as_secs(),
                        attempt = backoff.attempt(),
                        "control plane unreachable; continuing on the cached configuration"
                    );
                }
                if sleep_or_shutdown(delay, &mut shutdown).await {
                    return;
                }
                continue;
            }
        }

        if sleep_or_shutdown(poll_interval, &mut shutdown).await {
            return;
        }
    }
}

/// Report telemetry on an interval.
async fn heartbeat_loop(
    supervisor: Arc<Supervisor>,
    client: Arc<ControlClient>,
    mut shutdown: watch::Receiver<bool>,
) {
    let interval = supervisor.config().heartbeat_interval;
    let mut consecutive_failures = 0u32;

    loop {
        if sleep_or_shutdown(interval, &mut shutdown).await {
            return;
        }

        // node_id 由控制面在注册时分配，agent 事先并不知道。注册完成前跳过心跳
        // 而不是用占位 id 上报 —— 后者会被控制面按「上报 id 不匹配」拒绝。
        let Some(node_id) = supervisor.node_id() else {
            continue;
        };
        let report = supervisor.build_report(&node_id).await;
        match client.heartbeat(&report).await {
            Ok(_) => {
                if consecutive_failures > 0 {
                    tracing::info!("control plane reachable again");
                }
                consecutive_failures = 0;
            }
            Err(e) => {
                consecutive_failures += 1;
                // Log the first failure and then back off the logging, not the
                // heartbeat: a long outage should not produce a gigabyte of logs.
                if consecutive_failures == 1 || consecutive_failures % 30 == 0 {
                    tracing::warn!(
                        error = %e,
                        failures = consecutive_failures,
                        "heartbeat failed; the data plane is unaffected"
                    );
                }
            }
        }
    }
}

/// Reap idle streams periodically.
async fn reaper_loop(supervisor: Arc<Supervisor>, mut shutdown: watch::Receiver<bool>) {
    loop {
        if sleep_or_shutdown(Duration::from_secs(60), &mut shutdown).await {
            return;
        }
        // Idle timeout comes from the applied limits; use a conservative default
        // if none has been applied yet.
        supervisor.reap_idle(Duration::from_secs(300)).await;
    }
}

/// Reload TLS material on `SIGHUP`, for certificate renewal.
#[cfg(unix)]
async fn sighup_loop(supervisor: Arc<Supervisor>, mut shutdown: watch::Receiver<bool>) {
    let mut hup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "cannot install SIGHUP handler");
            return;
        }
    };

    loop {
        tokio::select! {
            _ = hup.recv() => {
                match supervisor.reload_tls() {
                    Ok(generation) => tracing::info!(
                        generation,
                        "reloaded TLS material; established tunnels keep their current \
                         configuration and new handshakes use the new one"
                    ),
                    Err(e) => tracing::error!(
                        error = %e,
                        "TLS reload failed; the previous material stays in use"
                    ),
                }
            }
            _ = shutdown.changed() => return,
        }
    }
}

async fn sleep_or_shutdown(duration: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    if *shutdown.borrow() {
        return true;
    }
    tokio::select! {
        _ = tokio::time::sleep(duration) => false,
        _ = shutdown.changed() => true,
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => {
                tracing::error!(error = %e, "cannot install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("received SIGINT"),
        _ = terminate => tracing::info!("received SIGTERM"),
    }
}
