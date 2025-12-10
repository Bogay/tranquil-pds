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
    ready_tx: mpsc::Sender<()>,
) {
    let handler = |ws: axum::extract::ws::WebSocketUpgrade| async {
        ws.on_upgrade(move |mut socket| async move {
            ready_tx.send(()).await.unwrap();
            if let Some(Ok(Message::Binary(bytes))) = socket.recv().await {
                event_tx.send(bytes.to_vec()).await.unwrap();
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
    let (ready_tx, ready_rx) = mpsc::channel(1);
    tokio::spawn(mock_relay_server(listener, event_tx, ready_tx));
    let relay_url = format!("ws://{}", addr);

    let db_url = get_db_connection_string().await;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect(&db_url)
        .await
        .unwrap();
    let state = AppState::new(pool).await;

    start_relay_clients(state.clone(), vec![relay_url], Some(ready_rx)).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let dummy_event = SequencedEvent {
        seq: 1,
        did: "did:plc:test".to_string(),
        created_at: Utc::now(),
        event_type: "commit".to_string(),
        commit_cid: None,
        prev_cid: None,
        ops: None,
        blobs: None,
        blocks_cids: None,
    };
    state.firehose_tx.send(dummy_event).unwrap();

    let received_bytes = event_rx.recv().await.expect("Did not receive event");
    assert!(!received_bytes.is_empty());
}
