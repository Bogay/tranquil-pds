mod common;
use common::*;

use axum::{extract::ws::Message, routing::get, Router};
use bspds::{
    state::AppState,
    sync::{firehose::SequencedEvent, relay_client::start_relay_clients},
};
use chrono::Utc;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

async fn mock_relay_server(
    listener: TcpListener,
    event_tx: mpsc::Sender<Vec<u8>>,
    connected_tx: mpsc::Sender<()>,
) {
    let handler = |ws: axum::extract::ws::WebSocketUpgrade| async {
        ws.on_upgrade(move |mut socket| async move {
            let _ = connected_tx.send(()).await;
            while let Some(Ok(msg)) = socket.recv().await {
                if let Message::Binary(bytes) = msg {
                    let _ = event_tx.send(bytes.to_vec()).await;
                    break;
                }
            }
        })
    };
    let app = Router::new().route("/", get(handler));

    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}

#[tokio::test]
async fn test_outbound_relay_client() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (event_tx, mut event_rx) = mpsc::channel(1);
    let (connected_tx, _connected_rx) = mpsc::channel::<()>(1);
    tokio::spawn(mock_relay_server(listener, event_tx, connected_tx));
    let relay_url = format!("ws://{}", addr);

    let db_url = get_db_connection_string().await;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect(&db_url)
        .await
        .unwrap();
    let state = AppState::new(pool).await;

    let (ready_tx, ready_rx) = mpsc::channel(1);
    start_relay_clients(state.clone(), vec![relay_url], Some(ready_rx)).await;

    tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        async {
            ready_tx.closed().await;
        }
    )
    .await
    .expect("Timeout waiting for relay client to be ready");

    let dummy_event = SequencedEvent {
        seq: 1,
        did: "did:plc:test".to_string(),
        created_at: Utc::now(),
        event_type: "commit".to_string(),
        commit_cid: Some("bafyreihffx5a4o3qbv7vp6qmxpxok5mx5xvlsq6z4x3xv3zqv7vqvc7mzy".to_string()),
        prev_cid: None,
        ops: Some(serde_json::json!([])),
        blobs: Some(vec![]),
        blocks_cids: Some(vec![]),
    };
    state.firehose_tx.send(dummy_event).unwrap();

    let received_bytes = tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        event_rx.recv()
    )
    .await
    .expect("Timeout waiting for event")
    .expect("Event channel closed");

    assert!(!received_bytes.is_empty());
}
