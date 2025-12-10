use crate::state::AppState;
use crate::sync::firehose::SequencedEvent;
use sqlx::postgres::PgListener;
use tracing::{error, info, warn};

pub async fn start_sequencer_listener(state: AppState) {
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

    loop {
        let notification = listener.recv().await?;
        let payload = notification.payload();

        let seq_id: i64 = match payload.parse() {
            Ok(id) => id,
            Err(e) => {
                warn!("Received invalid payload in repo_updates: '{}'. Error: {}", payload, e);
                continue;
            }
        };

        let event = sqlx::query_as!(
            SequencedEvent,
            r#"
            SELECT seq, did, created_at, event_type, commit_cid, prev_cid, ops, blobs, blocks_cids
            FROM repo_seq
            WHERE seq = $1
            "#,
            seq_id
        )
        .fetch_optional(&state.db)
        .await?;

        if let Some(event) = event {
            let _ = state.firehose_tx.send(event);
        } else {
            warn!("Received notification for seq {} but could not find row in repo_seq", seq_id);
        }
    }
}
