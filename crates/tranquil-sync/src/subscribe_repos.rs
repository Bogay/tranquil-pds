use axum::{
    extract::{Query, State, ws::Message, ws::WebSocket, ws::WebSocketUpgrade},
    response::Response,
};
use futures::{sink::SinkExt, stream::StreamExt};
use serde::Deserialize;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::broadcast::error::RecvError;
use tracing::{error, info, warn};
use tranquil_db_traits::SequenceNumber;
use tranquil_pds::state::AppState;
use tranquil_pds::sync::firehose::SequencedEvent;
use tranquil_pds::sync::frame::{ErrorFrameName, InfoFrameName};
use tranquil_pds::sync::util::{
    format_error_frame, format_event_for_sending, format_event_with_prefetched_blocks,
    format_info_frame, prefetch_blocks_for_events,
};

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
    tranquil_pds::metrics::set_firehose_subscribers(count);
    info!(cursor = ?params.cursor, subscribers = count, "New firehose subscriber");
    let _ = handle_socket_inner(&mut socket, &state, params).await;
    let count = SUBSCRIBER_COUNT.fetch_sub(1, Ordering::SeqCst) - 1;
    tranquil_pds::metrics::set_firehose_subscribers(count);
    info!(subscribers = count, "Firehose subscriber disconnected");
}

fn get_backfill_hours() -> i64 {
    tranquil_config::get().firehose.backfill_hours
}

async fn handle_socket_inner(
    socket: &mut WebSocket,
    state: &AppState,
    params: SubscribeReposParams,
) -> Result<(), ()> {
    let mut rx = state.firehose_tx.subscribe();
    let mut last_seen = SequenceNumber::UNSET;

    if let Some(cursor) = params.cursor {
        let cursor_seq = SequenceNumber::from_raw(cursor);
        let current_seq = state
            .repos.repo
            .get_max_seq()
            .await
            .unwrap_or(SequenceNumber::ZERO);

        if cursor_seq > current_seq {
            if let Ok(error_bytes) =
                format_error_frame(ErrorFrameName::FutureCursor, Some("Cursor in the future."))
            {
                let _ = socket.send(Message::Binary(error_bytes.into())).await;
            }
            socket.close().await.ok();
            return Err(());
        }

        let backfill_time = chrono::Utc::now() - chrono::Duration::hours(get_backfill_hours());

        let first_event = state
            .repos.repo
            .get_events_since_cursor(cursor_seq, 1)
            .await
            .ok()
            .and_then(|events| events.into_iter().next());

        let mut current_cursor = cursor_seq;

        if let Some(ref event) = first_event
            && event.created_at < backfill_time
        {
            if let Ok(info_bytes) = format_info_frame(
                InfoFrameName::OutdatedCursor,
                Some("Requested cursor exceeded limit. Possibly missing events"),
            ) {
                let _ = socket.send(Message::Binary(info_bytes.into())).await;
            }

            let earliest = state
                .repos.repo
                .get_min_seq_since(backfill_time)
                .await
                .ok()
                .flatten();

            if let Some(earliest_seq) = earliest {
                current_cursor = SequenceNumber::from_raw(earliest_seq.as_i64() - 1);
            }
        }

        last_seen = current_cursor;

        loop {
            let events = state
                .repos.repo
                .get_events_since_cursor(current_cursor, BACKFILL_BATCH_SIZE)
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
                        last_seen = event.seq;
                        let bytes =
                            match format_event_with_prefetched_blocks(event, &prefetched).await {
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
                        tranquil_pds::metrics::record_firehose_event();
                    }
                    if i64::try_from(events_count).unwrap_or(i64::MAX) < BACKFILL_BATCH_SIZE {
                        break;
                    }
                }
                Err(e) => {
                    error!("Failed to fetch backfill events: {:?}", e);
                    socket.close().await.ok();
                    return Err(());
                }
            }
        }

        let cutover_events = state.repos.repo.get_events_since_seq(last_seen, None).await;

        if let Ok(events) = cutover_events
            && !events.is_empty()
        {
            let prefetched = match prefetch_blocks_for_events(state, &events).await {
                Ok(blocks) => blocks,
                Err(e) => {
                    error!("Failed to prefetch blocks for cutover: {}", e);
                    socket.close().await.ok();
                    return Err(());
                }
            };
            for event in events {
                last_seen = event.seq;
                let bytes = match format_event_with_prefetched_blocks(event, &prefetched).await {
                    Ok(b) => b,
                    Err(e) => {
                        warn!("Failed to format cutover event: {}", e);
                        return Err(());
                    }
                };
                if let Err(e) = socket.send(Message::Binary(bytes.into())).await {
                    warn!("Failed to send cutover event: {}", e);
                    return Err(());
                }
                tranquil_pds::metrics::record_firehose_event();
            }
        }
    }
    let max_lag_before_disconnect: u64 = tranquil_config::get().firehose.max_lag;
    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok(event) => {
                        if event.seq <= last_seen {
                            continue;
                        }
                        last_seen = event.seq;
                        if let Err(e) = send_event(socket, state, event).await {
                            warn!("Failed to send event: {}", e);
                            break;
                        }
                        tranquil_pds::metrics::record_firehose_event();
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
