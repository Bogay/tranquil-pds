use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use tranquil_pds::BUILD_VERSION;
use tranquil_pds::comms::{CommsService, DiscordSender, EmailSender, SignalSender, TelegramSender};

use tranquil_pds::crawlers::{Crawlers, start_crawlers_service};
use tranquil_pds::scheduled::{
    backfill_record_blobs, backfill_repo_rev, backfill_user_blocks, start_scheduled_tasks,
};
use tranquil_pds::state::AppState;

mod http3;
mod tls;

#[derive(Parser)]
#[command(name = "tranquil-pds", version = BUILD_VERSION, about = "Tranquil AT Protocol PDS")]
struct Cli {
    #[arg(short, long, value_name = "FILE", env = "TRANQUIL_PDS_CONFIG")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    Validate {
        #[arg(long)]
        ignore_secrets: bool,
    },
    ConfigTemplate,
    Healthcheck,
}

#[tokio::main]
async fn main() -> ExitCode {
    dotenvy::dotenv().ok();

    let cli = Cli::parse();

    if let Some(command) = &cli.command {
        return match command {
            Command::Healthcheck => healthcheck(cli.config.as_ref()).await,
            Command::ConfigTemplate => {
                print!("{}", tranquil_config::template());
                ExitCode::SUCCESS
            }
            Command::Validate { ignore_secrets } => {
                let config = match tranquil_config::load(cli.config.as_ref()) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("Failed to load configuration: {e:#}");
                        return ExitCode::FAILURE;
                    }
                };
                if let Err(e) = config.validate(*ignore_secrets) {
                    eprint!("{e}");
                    return ExitCode::FAILURE;
                }
                if let Some(key) = config.secrets.plc_rotation_key.as_deref()
                    && let Err(reason) = tranquil_pds::plc::validate_rotation_did_key(key)
                {
                    eprintln!("secrets.plc_rotation_key (PLC_ROTATION_KEY) {reason}");
                    return ExitCode::FAILURE;
                }
                if !*ignore_secrets
                    && let Some((cert, key)) = config.server.tls.material()
                    && let Err(e) = tls::load_certified_key(cert, key)
                {
                    eprintln!("TLS material invalid: {e}");
                    return ExitCode::FAILURE;
                }
                println!("Configuration is valid.");
                ExitCode::SUCCESS
            }
        };
    }

    tracing_subscriber::fmt::init();

    let config = match tranquil_config::load(cli.config.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to load configuration: {e:#}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = config.validate(false) {
        error!("{e}");
        return ExitCode::FAILURE;
    }

    if let Some(key) = config.secrets.plc_rotation_key.as_deref()
        && let Err(reason) = tranquil_pds::plc::validate_rotation_did_key(key)
    {
        error!("secrets.plc_rotation_key (PLC_ROTATION_KEY) {reason}");
        return ExitCode::FAILURE;
    }

    tranquil_config::init(config);

    tranquil_pds::metrics::init_metrics();

    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("Fatal error: {}", e);
            ExitCode::FAILURE
        }
    }
}

async fn healthcheck(config: Option<&PathBuf>) -> ExitCode {
    let cfg = match tranquil_config::load(config) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Failed to load configuration: {e:#}");
            return ExitCode::FAILURE;
        }
    };
    let tls = cfg.server.tls.material().is_some();
    let scheme = if tls { "https" } else { "http" };
    let url = format!("{scheme}://localhost:{}/xrpc/_health", cfg.server.port);
    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(tls)
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Failed to build healthcheck client: {e}");
            return ExitCode::FAILURE;
        }
    };
    match client.get(&url).send().await {
        Ok(response) if response.status().is_success() => ExitCode::SUCCESS,
        Ok(response) => {
            eprintln!("Healthcheck returned {}", response.status());
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("Healthcheck request failed: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let shutdown = CancellationToken::new();

    let shutdown_for_panic = shutdown.clone();
    let default_panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        error!("PANIC: {}", info);
        shutdown_for_panic.cancel();
        default_panic_hook(info);
    }));

    spawn_signal_handler(shutdown.clone());

    let mut state = AppState::new(shutdown.clone()).await?;

    let signal_slot = Arc::new(tranquil_signal::SignalSlot::default());
    state = state.with_signal_sender(signal_slot.clone());
    if let Some(provider) = &state.signal_store_provider
        && let Some(client) = provider.load_signal_client(shutdown.clone()).await
    {
        signal_slot.set_client(client).await;
        info!("Signal device linked");
    }
    let signal_sender = SignalSender::new(signal_slot);

    tranquil_sync::listener::start_sequencer_listener(state.clone()).await;

    let backfill_repo_repo = state.repos.repo.clone();
    let backfill_block_store = state.block_store.clone();
    tokio::spawn(async move {
        tokio::join!(
            backfill_repo_rev(backfill_repo_repo.clone(), backfill_block_store.clone()),
            backfill_user_blocks(backfill_repo_repo.clone(), backfill_block_store.clone()),
            backfill_record_blobs(backfill_repo_repo, backfill_block_store),
        );
    });

    let mut comms_service = CommsService::new(state.repos.infra.clone());
    let mut deferred_discord_endpoint: Option<(DiscordSender, String, String)> = None;

    let cfg = tranquil_config::get();

    match EmailSender::from_config(cfg) {
        Ok(Some(email_sender)) => {
            info!("Email comms enabled");
            comms_service = comms_service.register_sender(email_sender);
        }
        Ok(None) => {
            warn!("Email comms disabled (MAIL_FROM_ADDRESS unset)");
        }
        Err(e) => {
            error!(error = %e, "Email configuration invalid");
            return Err(e.into());
        }
    }

    if let Some(discord_sender) = DiscordSender::from_config(cfg) {
        info!("Discord comms enabled");
        match discord_sender.resolve_bot_username().await {
            Ok(username) => {
                info!(bot_username = %username, "Resolved Discord bot username");
                tranquil_pds::util::set_discord_bot_username(username);
            }
            Err(e) => {
                warn!("Failed to resolve Discord bot username: {}", e);
            }
        }
        match discord_sender.resolve_application_info().await {
            Ok((app_id, verify_key)) => {
                info!(app_id = %app_id, "Resolved Discord application info");
                tranquil_pds::util::set_discord_app_id(app_id.clone());
                match hex::decode(&verify_key)
                    .ok()
                    .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
                    .and_then(|bytes| ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok())
                {
                    Some(public_key) => {
                        tranquil_pds::util::set_discord_public_key(public_key);
                        info!("Discord Ed25519 public key loaded");
                        let hostname = &tranquil_config::get().server.hostname;
                        let webhook_url = format!("https://{}/webhook/discord", hostname);
                        match discord_sender.register_slash_command(&app_id).await {
                            Ok(()) => info!("Discord /start slash command registered"),
                            Err(e) => warn!("Failed to register Discord slash command: {}", e),
                        }
                        deferred_discord_endpoint =
                            Some((discord_sender.clone(), app_id, webhook_url));
                    }
                    None => {
                        warn!("Failed to parse Discord verify_key as Ed25519 public key");
                    }
                }
            }
            Err(e) => {
                warn!("Failed to resolve Discord application info: {}", e);
            }
        }
        comms_service = comms_service.register_sender(discord_sender);
    }

    if let Some(telegram_sender) = TelegramSender::from_config(cfg) {
        let secret_token = tranquil_config::get()
            .telegram
            .webhook_secret
            .clone()
            .expect("telegram.webhook_secret checked during config validation");
        info!("Telegram comms enabled");
        match telegram_sender.resolve_bot_username().await {
            Ok(username) => {
                info!(bot_username = %username, "Resolved Telegram bot username");
                tranquil_pds::util::set_telegram_bot_username(username);
                let hostname = tranquil_config::get().server.hostname.clone();
                let webhook_url = format!("https://{}/webhook/telegram", hostname);
                match telegram_sender
                    .set_webhook(&webhook_url, Some(&secret_token))
                    .await
                {
                    Ok(()) => info!(url = %webhook_url, "Telegram webhook registered"),
                    Err(e) => warn!("Failed to register Telegram webhook: {}", e),
                }
            }
            Err(e) => {
                warn!("Failed to resolve Telegram bot username: {}", e);
            }
        }
        comms_service = comms_service.register_sender(telegram_sender);
    }

    comms_service = comms_service.register_sender(signal_sender);

    let comms_handle = tokio::spawn(comms_service.run(shutdown.clone()));

    let crawlers_handle = if let Some(crawlers) = Crawlers::from_config(cfg) {
        let crawlers = Arc::new(
            crawlers.with_circuit_breaker(state.circuit_breakers.relay_notification.clone()),
        );
        let firehose_rx = state.firehose_tx.subscribe();
        info!("Crawlers notification service enabled");
        Some(tokio::spawn(start_crawlers_service(
            crawlers,
            firehose_rx,
            shutdown.clone(),
        )))
    } else {
        warn!("Crawlers notification service disabled (PDS_HOSTNAME or CRAWLERS not set)");
        None
    };

    let scheduled_handle = tokio::spawn(start_scheduled_tasks(
        state.repos.user.clone(),
        state.repos.blob.clone(),
        state.blob_store.clone(),
        state.repos.sso.clone(),
        state.repos.repo.clone(),
        state.block_store.clone(),
        state.eventlog_segments_dir.clone(),
        shutdown.clone(),
    ));

    let app = http3::with_host_from_authority(tranquil_pds::app_with_routes(
        state,
        tranquil_pds::ExternalRoutes {
            xrpc: tranquil_api::api_routes().merge(tranquil_sync::sync_routes()),
            oauth: tranquil_oauth_server::oauth_routes(),
            well_known: tranquil_oauth_server::well_known_oauth_routes()
                .merge(tranquil_api::well_known_api_routes()),
            extra: tranquil_api::misc_routes()
                .merge(tranquil_api::webhook_routes())
                .merge(tranquil_oauth_server::frontend_client_metadata_route()),
        },
    ));

    let cfg = tranquil_config::get();
    let host = &cfg.server.host;
    let port = cfg.server.port;

    let addr: SocketAddr = format!("{}:{}", host, port)
        .parse()
        .map_err(|e| format!("Invalid SERVER_HOST or SERVER_PORT: {}", e))?;

    info!("tranquil-pds {} listening on {}", BUILD_VERSION, addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("Failed to bind to {}: {}", addr, e))?;

    let mut http3_handle: Option<tokio::task::JoinHandle<()>> = None;

    let server_handle = match cfg.server.tls.material() {
        Some((cert_path, key_path)) => {
            let initial = tls::load_certified_key(cert_path, key_path)
                .map_err(|e| format!("Failed to load TLS material: {e}"))?;
            let resolver = Arc::new(tls::ReloadableCertResolver::new(initial));
            let server_config = Arc::new(
                tls::build_server_config(resolver.clone())
                    .map_err(|e| format!("Failed to build TLS configuration: {e}"))?,
            );
            tls::spawn_reload_handler(
                resolver.clone(),
                cert_path.to_string(),
                key_path.to_string(),
                shutdown.clone(),
            );

            let tcp_app = if cfg.server.tls.http3 {
                let quic_config = http3::build_quic_server_config(resolver)
                    .map_err(|e| format!("Failed to build HTTP/3 configuration: {e}"))?;
                let endpoint = quinn::Endpoint::server(quic_config, addr)
                    .map_err(|e| format!("Failed to bind HTTP/3 endpoint on {addr}: {e}"))?;
                let h3_port = endpoint
                    .local_addr()
                    .map(|a| a.port())
                    .map_err(|e| format!("Failed to read HTTP/3 local address: {e}"))?;
                info!("HTTP/3 enabled on udp/{h3_port}");
                http3_handle = Some(tokio::spawn(http3::serve_http3(
                    endpoint,
                    app.clone(),
                    shutdown.clone(),
                )));
                http3::with_alt_svc(app, h3_port)
            } else {
                app
            };

            info!("TLS termination enabled (h2, http/1.1), reload with SIGHUP");
            let shutdown = shutdown.clone();
            tokio::spawn(tls::serve_tls(listener, tcp_app, server_config, shutdown))
        }
        None => {
            let make_service = app.into_make_service_with_connect_info::<SocketAddr>();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                axum::serve(listener, make_service)
                    .with_graceful_shutdown(shutdown.cancelled_owned())
                    .await
            })
        }
    };

    if let Some((sender, app_id, webhook_url)) = deferred_discord_endpoint {
        tokio::spawn(async move {
            match sender
                .set_interactions_endpoint(&app_id, &webhook_url)
                .await
            {
                Ok(()) => info!(url = %webhook_url, "Discord interactions endpoint registered"),
                Err(e) => warn!("Failed to set Discord interactions endpoint: {}", e),
            }
        });
    }

    let server_result = server_handle
        .await
        .map_err(|e| format!("Server task panicked: {}", e))?;

    if let Some(handle) = http3_handle {
        handle.await.ok();
    }

    comms_handle.await.ok();

    if let Some(handle) = crawlers_handle {
        handle.await.ok();
    }

    scheduled_handle.await.ok();

    if let Err(e) = server_result {
        return Err(format!("Server error: {}", e).into());
    }

    Ok(())
}

fn spawn_signal_handler(shutdown: CancellationToken) {
    tokio::spawn(async move {
        let ctrl_c = async {
            match tokio::signal::ctrl_c().await {
                Ok(()) => {}
                Err(e) => {
                    error!("Failed to install Ctrl+C handler: {}", e);
                    std::future::pending::<()>().await;
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
        shutdown.cancel();
    });
}
