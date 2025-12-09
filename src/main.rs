use bspds::notifications::{EmailSender, NotificationService};
use bspds::state::AppState;
use std::net::SocketAddr;
use tokio::sync::watch;
use tracing::{info, warn};

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to connect to Postgres");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    let state = AppState::new(pool.clone()).await;

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
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    let server_result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(shutdown_tx))
        .await;

    notification_handle.await.ok();

    if let Err(e) = server_result {
        tracing::error!("Server error: {}", e);
    }
}

async fn shutdown_signal(shutdown_tx: watch::Sender<bool>) {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
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
