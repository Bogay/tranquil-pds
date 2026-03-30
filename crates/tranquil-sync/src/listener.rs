use std::sync::atomic::{AtomicI64, Ordering};
use tracing::{debug, error, info, warn};
use tranquil_db_traits::SequenceNumber;
use tranquil_pds::state::AppState;
use tranquil_pds::sync::firehose::SequencedEvent;

static LAST_BROADCAST_SEQ: AtomicI64 = AtomicI64::new(0);

pub async fn start_sequencer_listener(state: AppState) {
    let initial_seq = state
        .repos
        .repo
        .get_max_seq()
        .await
        .unwrap_or(SequenceNumber::ZERO);
    LAST_BROADCAST_SEQ.store(initial_seq.as_i64(), Ordering::SeqCst);
    info!(
        initial_seq = initial_seq.as_i64(),
        "Initialized sequencer listener"
    );
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
    let mut receiver = state
        .repos
        .event_notifier
        .subscribe()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to subscribe to events: {:?}", e))?;
    info!("Connected to database and listening for repo updates");
    let catchup_start = SequenceNumber::from_raw(LAST_BROADCAST_SEQ.load(Ordering::SeqCst));
    let events = state
        .repos
        .repo
        .get_events_since_seq(catchup_start, None)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to fetch catchup events: {:?}", e))?;
    if !events.is_empty() {
        info!(
            count = events.len(),
            from_seq = catchup_start.as_i64(),
            "Broadcasting catch-up events"
        );
        events.into_iter().for_each(|event| {
            let seq = event.seq;
            let firehose_event = to_firehose_event(event);
            let _ = state.firehose_tx.send(firehose_event);
            LAST_BROADCAST_SEQ.store(seq.as_i64(), Ordering::SeqCst);
        });
    }
    loop {
        let Some(seq_id) = receiver.recv().await else {
            return Err(anyhow::anyhow!("Event receiver disconnected"));
        };
        debug!(seq = seq_id, "Received event notification");
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
            let gap_events = state
                .repos
                .repo
                .get_events_in_seq_range(
                    SequenceNumber::from_raw(last_seq),
                    SequenceNumber::from_raw(seq_id),
                )
                .await
                .unwrap_or_default();
            if !gap_events.is_empty() {
                debug!(count = gap_events.len(), "Filling sequence gap");
                gap_events.into_iter().for_each(|event| {
                    let seq = event.seq;
                    let firehose_event = to_firehose_event(event);
                    let _ = state.firehose_tx.send(firehose_event);
                    LAST_BROADCAST_SEQ.store(seq.as_i64(), Ordering::SeqCst);
                });
            }
        }
        let event = state
            .repos
            .repo
            .get_event_by_seq(SequenceNumber::from_raw(seq_id))
            .await
            .ok()
            .flatten();
        if let Some(event) = event {
            let seq = event.seq;
            let firehose_event = to_firehose_event(event);
            match state.firehose_tx.send(firehose_event) {
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
            LAST_BROADCAST_SEQ.store(seq.as_i64(), Ordering::SeqCst);
        } else {
            warn!(
                seq = seq_id,
                "Received notification but could not find row in repo_seq"
            );
        }
    }
}

fn to_firehose_event(event: tranquil_db_traits::SequencedEvent) -> SequencedEvent {
    SequencedEvent {
        seq: event.seq,
        did: event.did,
        created_at: event.created_at,
        event_type: event.event_type,
        commit_cid: event.commit_cid,
        prev_cid: event.prev_cid,
        prev_data_cid: event.prev_data_cid,
        ops: event.ops,
        blobs: event.blobs,
        blocks: event.blocks,
        handle: event.handle,
        active: event.active,
        status: event.status,
        rev: event.rev,
    }
}
