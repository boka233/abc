//! `tunnel-control` binary.

use clap::{Parser, Subcommand};
use tokio::sync::watch;
use tunnel_common::logging;
use tunnel_control::api;
use tunnel_control::config::ControlConfig;
use tunnel_control::state::AppState;
use tunnel_control::tasks;
use tunnel_storage::users::UserRepo;
use tunnel_storage::Database;

#[derive(Parser)]
#[command(
    name = "tunnel-control",
    about = "Control plane and admin panel for the TLS tunnel system",
    version
)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short, long, env = "TUNNEL_CONTROL_CONFIG", default_value = "/etc/tunnel-control/config.toml")]
    config: std::path::PathBuf,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the server (default).
    Run,
    /// Print a starter configuration file to stdout.
    SampleConfig,
    /// Apply pending database migrations and exit.
    Migrate,
    /// Reset a user's password. Prints the new password once.
    ResetPassword {
        username: String,
    },
    /// Validate the configuration file and exit.
    Check,
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();

    // SampleConfig needs neither a config file nor a runtime.
    if matches!(cli.command, Some(Command::SampleConfig)) {
        println!("{}", ControlConfig::sample_toml());
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
            // Startup failures happen before the logger may be installed, so
            // print as well as log.
            eprintln!("tunnel-control: {e}");
            tracing::error!(error = %e, "fatal error");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let config = ControlConfig::load(&cli.config)
        .map_err(|e| anyhow::anyhow!("configuration error: {e}"))?;
    logging::init(&config.log);

    match cli.command.unwrap_or(Command::Run) {
        Command::SampleConfig => unreachable!("handled before the runtime starts"),
        Command::Check => {
            config.validate()?;
            println!("configuration at {} is valid", cli.config.display());
            Ok(())
        }
        Command::Migrate => {
            let db = Database::connect(&config.database_path).await?;
            db.migrate().await?;
            println!("migrations applied to {}", config.database_path.display());
            db.close().await;
            Ok(())
        }
        Command::ResetPassword { username } => {
            let db = Database::connect(&config.database_path).await?;
            let repo = UserRepo::new(&db);
            let user = repo
                .find_by_username(&username)
                .await?
                .ok_or_else(|| anyhow::anyhow!("no such user: {username}"))?;
            let password = tunnel_storage::users::generate_password(24);
            repo.reset_password(&user.id, &password).await?;
            // Printed once, to stdout only. Never logged.
            println!("New password for {username}: {password}");
            println!("The user must change it at next login.");
            db.close().await;
            Ok(())
        }
        Command::Run => serve(config, cli.config).await,
    }
}

async fn serve(mut config: ControlConfig, config_path: std::path::PathBuf) -> anyhow::Result<()> {
    if config.ensure_jwt_secret() {
        tracing::warn!(
            "no auth.jwt_secret configured; generated an ephemeral one. \
             Existing sessions will be invalidated on every restart — set a \
             persistent secret in {}",
            config_path.display()
        );
    }
    if !config.production {
        tracing::warn!(
            "running in development mode; set `production = true` to enforce \
             strong secrets and a pinned CA"
        );
    }

    let listen = config.listen_addr()?;
    let db = Database::connect(&config.database_path).await?;
    tracing::info!(path = %config.database_path.display(), "database ready");

    // Create the first admin if the instance is fresh. The password is printed
    // once, to stdout, and never written to the log.
    let users = UserRepo::new(&db);
    if let Some(password) = users
        .ensure_bootstrap_admin(&config.auth.bootstrap_username)
        .await?
    {
        println!("========================================================");
        println!(" Initial administrator created");
        println!("   username: {}", config.auth.bootstrap_username);
        println!("   password: {password}");
        println!(" This is shown once. Change it at first login.");
        println!("========================================================");
        tracing::info!(
            username = %config.auth.bootstrap_username,
            "bootstrap administrator created; password printed to stdout"
        );
    }

    let state = AppState::new(db.clone(), config);
    let app = api::router(state.clone());

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let background = vec![
        tokio::spawn(tasks::aggregation_loop(state.clone(), shutdown_rx.clone())),
        tokio::spawn(tasks::staleness_loop(state.clone(), shutdown_rx.clone())),
        tokio::spawn(tasks::retention_loop(state.clone(), shutdown_rx)),
    ];

    let listener = tokio::net::TcpListener::bind(listen).await.map_err(|e| {
        anyhow::anyhow!("cannot bind {listen}: {e}")
    })?;
    tracing::info!(address = %listen, "control plane listening");

    // ConnectInfo is required for per-IP login throttling and audit source IPs.
    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal());

    if let Err(e) = server.await {
        tracing::error!(error = %e, "server error");
    }

    // Stop the background loops and let them finish their current pass, so a
    // statistics transaction is not abandoned mid-commit.
    tracing::info!("shutting down background tasks");
    let _ = shutdown_tx.send(true);
    for handle in background {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
    }

    db.close().await;
    tracing::info!("shutdown complete");
    Ok(())
}

/// Resolve on `SIGTERM` (systemd stop) or `SIGINT` (Ctrl-C).
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
