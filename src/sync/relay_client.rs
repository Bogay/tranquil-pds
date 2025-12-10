use crate::state::AppState;
use crate::sync::util::format_event_for_sending;
use futures::{sink::SinkExt, stream::StreamExt};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{error, info, warn};

async fn run_relay_client(state: AppState, url: String, ready_tx: Option<mpsc::Sender<()>>) {
    info!("Starting firehose client for relay: {}", url);
    loop {
        match connect_async(&url).await {
            Ok((mut ws_stream, _)) => {
                info!("Connected to firehose relay: {}", url);
                if let Some(tx) = ready_tx.as_ref() {
                    tx.send(()).await.ok();
                }

                let mut rx = state.firehose_tx.subscribe();

                loop {
                    tokio::select! {
                        Ok(event) = rx.recv() => {
                            match format_event_for_sending(&state, event).await {
                                Ok(bytes) => {
                                    if let Err(e) = ws_stream.send(Message::Binary(bytes.into())).await {
                                        warn!("Failed to send event to {}: {}. Disconnecting.", url, e);
                                        break;
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to format event for relay {}: {}", url, e);
                                }
                            }
                        }
                        Some(msg) = ws_stream.next() => {
                            if let Ok(Message::Close(_)) = msg {
                                warn!("Relay {} closed connection.", url);
                                break;
                            }
                        }
                        else => break,
                    }
                }
            }
            Err(e) => {
                error!("Failed to connect to firehose relay {}: {}", url, e);
            }
        }
        warn!(
            "Disconnected from {}. Reconnecting in 5 seconds...",
            url
        );
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

pub async fn start_relay_clients(
    state: AppState,
    relays: Vec<String>,
    mut ready_rx: Option<mpsc::Receiver<()>>,
) {
    if relays.is_empty() {
        return;
    }

    let (ready_tx, mut internal_ready_rx) = mpsc::channel(1);

    for url in relays {
        let ready_tx = if ready_rx.is_some() {
            Some(ready_tx.clone())
        } else {
            None
        };
        tokio::spawn(run_relay_client(state.clone(), url, ready_tx));
    }

    if let Some(mut rx) = ready_rx.take() {
        tokio::spawn(async move {
            internal_ready_rx.recv().await;
            rx.close();
        });
    }
}
