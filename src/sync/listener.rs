use crate::state::AppState;
use crate::sync::firehose::SequencedEvent;
use sqlx::postgres::PgListener;
use std::sync::atomic::{AtomicI64, Ordering};
use tracing::{debug, error, info, warn};

static LAST_BROADCAST_SEQ: AtomicI64 = AtomicI64::new(0);

pub async fn start_sequencer_listener(state: AppState) {
    let initial_seq = sqlx::query_scalar!("SELECT COALESCE(MAX(seq), 0) as max FROM repo_seq")
        .fetch_one(&state.db)
        .await
        .unwrap_or(Some(0))
        .unwrap_or(0);
    LAST_BROADCAST_SEQ.store(initial_seq, Ordering::SeqCst);
    info!(initial_seq = initial_seq, "Initialized sequencer listener");
    tokio::spawn(async move {
        info!("Starting sequencer listener background task");
        loop {
            if let Err(e) = listen_loop(state.clone()).await {
                error!("Sequencer listener failed: {}. Restarting in 5s...", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        }
    });
}

async fn listen_loop(state: AppState) -> anyhow::Result<()> {
    let mut listener = PgListener::connect_with(&state.db).await?;
    listener.listen("repo_updates").await?;
    info!("Connected to Postgres and listening for 'repo_updates'");
    let catchup_start = LAST_BROADCAST_SEQ.load(Ordering::SeqCst);
    let events = sqlx::query_as!(
        SequencedEvent,
        r#"
        SELECT seq, did, created_at, event_type, commit_cid, prev_cid, prev_data_cid, ops, blobs, blocks_cids, handle, active, status, rev
        FROM repo_seq
        WHERE seq > $1
        ORDER BY seq ASC
        "#,
        catchup_start
    )
    .fetch_all(&state.db)
    .await?;
    if !events.is_empty() {
        info!(
            count = events.len(),
            from_seq = catchup_start,
            "Broadcasting catch-up events"
        );
        for event in events {
            let seq = event.seq;
            let _ = state.firehose_tx.send(event);
            LAST_BROADCAST_SEQ.store(seq, Ordering::SeqCst);
        }
    }
    loop {
        let notification = listener.recv().await?;
        let payload = notification.payload();
        debug!(payload = %payload, "Received postgres notification");
        let seq_id: i64 = match payload.parse() {
            Ok(id) => id,
            Err(e) => {
                warn!(
                    "Received invalid payload in repo_updates: '{}'. Error: {}",
                    payload, e
                );
                continue;
            }
        };
        let last_seq = LAST_BROADCAST_SEQ.load(Ordering::SeqCst);
        if seq_id <= last_seq {
            debug!(
                seq = seq_id,
                last = last_seq,
                "Skipping already-broadcast event"
            );
            continue;
        }
        if seq_id > last_seq + 1 {
            let gap_events = sqlx::query_as!(
                SequencedEvent,
                r#"
                SELECT seq, did, created_at, event_type, commit_cid, prev_cid, prev_data_cid, ops, blobs, blocks_cids, handle, active, status, rev
                FROM repo_seq
                WHERE seq > $1 AND seq < $2
                ORDER BY seq ASC
                "#,
                last_seq,
                seq_id
            )
            .fetch_all(&state.db)
            .await?;
            if !gap_events.is_empty() {
                debug!(count = gap_events.len(), "Filling sequence gap");
                for event in gap_events {
                    let seq = event.seq;
                    let _ = state.firehose_tx.send(event);
                    LAST_BROADCAST_SEQ.store(seq, Ordering::SeqCst);
                }
            }
        }
        let event = sqlx::query_as!(
            SequencedEvent,
            r#"
            SELECT seq, did, created_at, event_type, commit_cid, prev_cid, prev_data_cid, ops, blobs, blocks_cids, handle, active, status, rev
            FROM repo_seq
            WHERE seq = $1
            "#,
            seq_id
        )
        .fetch_optional(&state.db)
        .await?;
        if let Some(event) = event {
            match state.firehose_tx.send(event) {
                Ok(receiver_count) => {
                    debug!(
                        seq = seq_id,
                        receivers = receiver_count,
                        "Broadcast event to firehose"
                    );
                }
                Err(e) => {
                    warn!(seq = seq_id, error = %e, "Failed to broadcast event (no receivers?)");
                }
            }
            LAST_BROADCAST_SEQ.store(seq_id, Ordering::SeqCst);
        } else {
            warn!(
                seq = seq_id,
                "Received notification but could not find row in repo_seq"
            );
        }
    }
}
