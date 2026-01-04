use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use tokio::sync::watch;
use tracing::{error, info, warn};
use tranquil_pds::comms::{CommsService, DiscordSender, EmailSender, SignalSender, TelegramSender};
use tranquil_pds::crawlers::{Crawlers, start_crawlers_service};
use tranquil_pds::scheduled::{
    backfill_genesis_commit_blocks, backfill_record_blobs, backfill_repo_rev, backfill_user_blocks,
    start_backup_tasks, start_scheduled_tasks,
};
use tranquil_pds::state::AppState;

#[tokio::main]
async fn main() -> ExitCode {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();
    tranquil_pds::metrics::init_metrics();

    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("Fatal error: {}", e);
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let state = AppState::new().await?;
    tranquil_pds::sync::listener::start_sequencer_listener(state.clone()).await;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let backfill_db = state.db.clone();
    let backfill_block_store = state.block_store.clone();
    tokio::spawn(async move {
        tokio::join!(
            backfill_genesis_commit_blocks(&backfill_db, backfill_block_store.clone()),
            backfill_repo_rev(&backfill_db, backfill_block_store.clone()),
            backfill_user_blocks(&backfill_db, backfill_block_store.clone()),
            backfill_record_blobs(&backfill_db, backfill_block_store),
        );
    });

    let mut comms_service = CommsService::new(state.db.clone());

    if let Some(email_sender) = EmailSender::from_env() {
        info!("Email comms enabled");
        comms_service = comms_service.register_sender(email_sender);
    } else {
        warn!("Email comms disabled (MAIL_FROM_ADDRESS not set)");
    }

    if let Some(discord_sender) = DiscordSender::from_env() {
        info!("Discord comms enabled");
        comms_service = comms_service.register_sender(discord_sender);
    }

    if let Some(telegram_sender) = TelegramSender::from_env() {
        info!("Telegram comms enabled");
        comms_service = comms_service.register_sender(telegram_sender);
    }

    if let Some(signal_sender) = SignalSender::from_env() {
        info!("Signal comms enabled");
        comms_service = comms_service.register_sender(signal_sender);
    }

    let comms_handle = tokio::spawn(comms_service.run(shutdown_rx.clone()));

    let crawlers_handle = if let Some(crawlers) = Crawlers::from_env() {
        let crawlers = Arc::new(
            crawlers.with_circuit_breaker(state.circuit_breakers.relay_notification.clone()),
        );
        let firehose_rx = state.firehose_tx.subscribe();
        info!("Crawlers notification service enabled");
        Some(tokio::spawn(start_crawlers_service(
            crawlers,
            firehose_rx,
            shutdown_rx.clone(),
        )))
    } else {
        warn!("Crawlers notification service disabled (PDS_HOSTNAME or CRAWLERS not set)");
        None
    };

    let backup_handle = if let Some(backup_storage) = state.backup_storage.clone() {
        info!("Backup service enabled");
        Some(tokio::spawn(start_backup_tasks(
            state.db.clone(),
            state.block_store.clone(),
            backup_storage,
            shutdown_rx.clone(),
        )))
    } else {
        warn!("Backup service disabled (BACKUP_S3_BUCKET not set or BACKUP_ENABLED=false)");
        None
    };

    let scheduled_handle = tokio::spawn(start_scheduled_tasks(
        state.db.clone(),
        state.blob_store.clone(),
        shutdown_rx,
    ));

    let app = tranquil_pds::app(state);

    let host = std::env::var("SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port: u16 = std::env::var("SERVER_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    let addr: SocketAddr = format!("{}:{}", host, port)
        .parse()
        .map_err(|e| format!("Invalid SERVER_HOST or SERVER_PORT: {}", e))?;

    info!("listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("Failed to bind to {}: {}", addr, e))?;

    let server_result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(shutdown_tx))
        .await;

    comms_handle.await.ok();

    if let Some(handle) = crawlers_handle {
        handle.await.ok();
    }

    if let Some(handle) = backup_handle {
        handle.await.ok();
    }

    scheduled_handle.await.ok();

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
