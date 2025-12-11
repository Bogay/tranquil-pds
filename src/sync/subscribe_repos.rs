use crate::state::AppState;
use crate::sync::firehose::SequencedEvent;
use crate::sync::util::format_event_for_sending;
use axum::{
    extract::{ws::Message, ws::WebSocket, ws::WebSocketUpgrade, Query, State},
    response::Response,
};
use futures::{sink::SinkExt, stream::StreamExt};
use serde::Deserialize;
use tracing::{error, info, warn};

const BACKFILL_BATCH_SIZE: i64 = 1000;

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

async fn handle_socket(mut socket: WebSocket, state: AppState, params: SubscribeReposParams) {
    info!(cursor = ?params.cursor, "New firehose subscriber");

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
                    for event in &events {
                        current_cursor = event.seq;
                        if let Err(e) = send_event(&mut socket, &state, event.clone()).await {
                            warn!("Failed to send backfill event: {}", e);
                            return;
                        }
                    }
                    if (events.len() as i64) < BACKFILL_BATCH_SIZE {
                        break;
                    }
                }
                Err(e) => {
                    error!("Failed to fetch backfill events: {}", e);
                    socket.close().await.ok();
                    return;
                }
            }
        }
    }

    let mut rx = state.firehose_tx.subscribe();

    loop {
        tokio::select! {
            Ok(event) = rx.recv() => {
                if let Err(e) = send_event(&mut socket, &state, event).await {
                    warn!("Failed to send event: {}", e);
                    break;
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
}
