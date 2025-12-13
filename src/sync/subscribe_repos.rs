use crate::state::AppState;
use crate::sync::firehose::SequencedEvent;
use crate::sync::util::{format_event_for_sending, format_event_with_prefetched_blocks, prefetch_blocks_for_events};
use axum::{
    extract::{ws::Message, ws::WebSocket, ws::WebSocketUpgrade, Query, State},
    response::Response,
};
use futures::{sink::SinkExt, stream::StreamExt};
use serde::Deserialize;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::broadcast::error::RecvError;
use tracing::{error, info, warn};

const BACKFILL_BATCH_SIZE: i64 = 1000;
static SUBSCRIBER_COUNT: AtomicUsize = AtomicUsize::new(0);

#[derive(Deserialize)]
pub struct SubscribeReposParams {
    pub cursor: Option<i64>,
}

#[axum::debug_handler]
pub async fn subscribe_repos(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Query(params): Query<SubscribeReposParams>,
) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, state, params))
}

async fn send_event(
    socket: &mut WebSocket,
    state: &AppState,
    event: SequencedEvent,
) -> Result<(), anyhow::Error> {
    let bytes = format_event_for_sending(state, event).await?;
    socket.send(Message::Binary(bytes.into())).await?;
    Ok(())
}

pub fn get_subscriber_count() -> usize {
    SUBSCRIBER_COUNT.load(Ordering::SeqCst)
}

async fn handle_socket(mut socket: WebSocket, state: AppState, params: SubscribeReposParams) {
    let count = SUBSCRIBER_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
    crate::metrics::set_firehose_subscribers(count);
    info!(cursor = ?params.cursor, subscribers = count, "New firehose subscriber");

    let _ = handle_socket_inner(&mut socket, &state, params).await;

    let count = SUBSCRIBER_COUNT.fetch_sub(1, Ordering::SeqCst) - 1;
    crate::metrics::set_firehose_subscribers(count);
    info!(subscribers = count, "Firehose subscriber disconnected");
}

async fn handle_socket_inner(socket: &mut WebSocket, state: &AppState, params: SubscribeReposParams) -> Result<(), ()> {
    if let Some(cursor) = params.cursor {
        let mut current_cursor = cursor;
        loop {
            let events = sqlx::query_as!(
                SequencedEvent,
                r#"
                SELECT seq, did, created_at, event_type, commit_cid, prev_cid, ops, blobs, blocks_cids
                FROM repo_seq
                WHERE seq > $1
                ORDER BY seq ASC
                LIMIT $2
                "#,
                current_cursor,
                BACKFILL_BATCH_SIZE
            )
            .fetch_all(&state.db)
            .await;

            match events {
                Ok(events) => {
                    if events.is_empty() {
                        break;
                    }

                    let events_count = events.len();

                    let prefetched = match prefetch_blocks_for_events(state, &events).await {
                        Ok(blocks) => blocks,
                        Err(e) => {
                            error!("Failed to prefetch blocks for backfill: {}", e);
                            socket.close().await.ok();
                            return Err(());
                        }
                    };

                    for event in events {
                        current_cursor = event.seq;
                        let bytes = match format_event_with_prefetched_blocks(event, &prefetched).await {
                            Ok(b) => b,
                            Err(e) => {
                                warn!("Failed to format backfill event: {}", e);
                                return Err(());
                            }
                        };
                        if let Err(e) = socket.send(Message::Binary(bytes.into())).await {
                            warn!("Failed to send backfill event: {}", e);
                            return Err(());
                        }
                        crate::metrics::record_firehose_event();
                    }
                    if (events_count as i64) < BACKFILL_BATCH_SIZE {
                        break;
                    }
                }
                Err(e) => {
                    error!("Failed to fetch backfill events: {}", e);
                    socket.close().await.ok();
                    return Err(());
                }
            }
        }
    }

    let mut rx = state.firehose_tx.subscribe();
    let max_lag_before_disconnect: u64 = std::env::var("FIREHOSE_MAX_LAG")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5000);

    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok(event) => {
                        if let Err(e) = send_event(socket, state, event).await {
                            warn!("Failed to send event: {}", e);
                            break;
                        }
                        crate::metrics::record_firehose_event();
                    }
                    Err(RecvError::Lagged(skipped)) => {
                        warn!(skipped = skipped, "Firehose subscriber lagged behind");
                        if skipped > max_lag_before_disconnect {
                            warn!(skipped = skipped, max_lag = max_lag_before_disconnect,
                                "Disconnecting slow firehose consumer");
                            break;
                        }
                    }
                    Err(RecvError::Closed) => {
                        info!("Firehose channel closed");
                        break;
                    }
                }
            }
            Some(Ok(msg)) = socket.next() => {
                if let Message::Close(_) = msg {
                    info!("Client closed connection");
                    break;
                }
            }
            else => {
                break;
            }
        }
    }
    Ok(())
}
