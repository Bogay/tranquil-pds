use bspds::notifications::{EmailSender, NotificationService};
use bspds::state::AppState;
use std::net::SocketAddr;
use std::process::ExitCode;
use tokio::sync::watch;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> ExitCode {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

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

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(20)
        .min_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(10))
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
    let relays = std::env::var("RELAYS")
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    bspds::sync::relay_client::start_relay_clients(state.clone(), relays, None).await;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let mut notification_service = NotificationService::new(pool);

    if let Some(email_sender) = EmailSender::from_env() {
        info!("Email notifications enabled");
        notification_service = notification_service.register_sender(email_sender);
    } else {
        warn!("Email notifications disabled (MAIL_FROM_ADDRESS not set)");
    }

    let notification_handle = tokio::spawn(notification_service.run(shutdown_rx));

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
