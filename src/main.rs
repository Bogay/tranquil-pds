use bspds::crawlers::{Crawlers, start_crawlers_service};
use bspds::notifications::{DiscordSender, EmailSender, NotificationService, SignalSender, TelegramSender};
use bspds::state::AppState;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use tokio::sync::watch;
use tracing::{error, info, warn};
#[tokio::main]
async fn main() -> ExitCode {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();
    bspds::metrics::init_metrics();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("Fatal error: {}", e);
            ExitCode::FAILURE
        }
    }
}
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL environment variable must be set")?;
    let max_connections: u32 = std::env::var("DATABASE_MAX_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100);
    let min_connections: u32 = std::env::var("DATABASE_MIN_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);
    let acquire_timeout_secs: u64 = std::env::var("DATABASE_ACQUIRE_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);
    info!(
        "Configuring database pool: max={}, min={}, acquire_timeout={}s",
        max_connections, min_connections, acquire_timeout_secs
    );
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(max_connections)
        .min_connections(min_connections)
        .acquire_timeout(std::time::Duration::from_secs(acquire_timeout_secs))
        .idle_timeout(std::time::Duration::from_secs(300))
        .max_lifetime(std::time::Duration::from_secs(1800))
        .connect(&database_url)
        .await
        .map_err(|e| format!("Failed to connect to Postgres: {}", e))?;
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .map_err(|e| format!("Failed to run migrations: {}", e))?;
    let state = AppState::new(pool.clone()).await;
    bspds::sync::listener::start_sequencer_listener(state.clone()).await;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut notification_service = NotificationService::new(pool);
    if let Some(email_sender) = EmailSender::from_env() {
        info!("Email notifications enabled");
        notification_service = notification_service.register_sender(email_sender);
    } else {
        warn!("Email notifications disabled (MAIL_FROM_ADDRESS not set)");
    }
    if let Some(discord_sender) = DiscordSender::from_env() {
        info!("Discord notifications enabled");
        notification_service = notification_service.register_sender(discord_sender);
    }
    if let Some(telegram_sender) = TelegramSender::from_env() {
        info!("Telegram notifications enabled");
        notification_service = notification_service.register_sender(telegram_sender);
    }
    if let Some(signal_sender) = SignalSender::from_env() {
        info!("Signal notifications enabled");
        notification_service = notification_service.register_sender(signal_sender);
    }
    let notification_handle = tokio::spawn(notification_service.run(shutdown_rx.clone()));
    let crawlers_handle = if let Some(crawlers) = Crawlers::from_env() {
        let crawlers = Arc::new(
            crawlers.with_circuit_breaker(state.circuit_breakers.relay_notification.clone())
        );
        let firehose_rx = state.firehose_tx.subscribe();
        info!("Crawlers notification service enabled");
        Some(tokio::spawn(start_crawlers_service(crawlers, firehose_rx, shutdown_rx)))
    } else {
        warn!("Crawlers notification service disabled (PDS_HOSTNAME or CRAWLERS not set)");
        None
    };
    let app = bspds::app(state);
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    info!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("Failed to bind to {}: {}", addr, e))?;
    let server_result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(shutdown_tx))
        .await;
    notification_handle.await.ok();
    if let Some(handle) = crawlers_handle {
        handle.await.ok();
    }
    if let Err(e) = server_result {
        return Err(format!("Server error: {}", e).into());
    }
    Ok(())
}
async fn shutdown_signal(shutdown_tx: watch::Sender<bool>) {
    let ctrl_c = async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {}
            Err(e) => {
                error!("Failed to install Ctrl+C handler: {}", e);
            }
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(e) => {
                error!("Failed to install SIGTERM handler: {}", e);
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("Shutdown signal received, stopping services...");
    shutdown_tx.send(true).ok();
}
