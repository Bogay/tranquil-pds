mod common;
use common::*;

use bspds::sync::frame::{Frame, FrameData};
use cid::Cid;
use futures::{stream::StreamExt, SinkExt};
use iroh_car::CarReader;
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::io::Cursor;
use std::str::FromStr;
use tokio_tungstenite::{connect_async, tungstenite};

#[tokio::test]
async fn test_firehose_subscription() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    let url = format!(
        "ws://127.0.0.1:{}/xrpc/com.atproto.sync.subscribeRepos",
        app_port()
    );
    let (mut ws_stream, _) = connect_async(&url).await.expect("Failed to connect");

    let post_text = "Hello from the firehose test!";
    let post_payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": post_text,
            "createdAt": chrono::Utc::now().to_rfc3339(),
        }
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            base_url().await
        ))
        .bearer_auth(token)
        .json(&post_payload)
        .send()
        .await
        .expect("Failed to create post");
    assert_eq!(res.status(), StatusCode::OK);

    let msg = ws_stream.next().await.unwrap().unwrap();

    let frame: Frame = match msg {
        tungstenite::Message::Binary(bin) => {
            serde_ipld_dagcbor::from_slice(&bin).expect("Failed to deserialize frame")
        }
        _ => panic!("Expected binary message"),
    };

    let FrameData::Commit(commit) = frame.data;
    assert_eq!(commit.repo, did);
    assert_eq!(commit.ops.len(), 1);
    assert!(!commit.blocks.is_empty());

    let op = &commit.ops[0];
    let record_cid = Cid::from_str(&op.cid.clone().unwrap()).unwrap();

    let mut car_reader = CarReader::new(Cursor::new(&commit.blocks)).await.unwrap();
    let mut record_block: Option<Vec<u8>> = None;
    while let Ok(Some((cid, block))) = car_reader.next_block().await {
        if cid == record_cid {
            record_block = Some(block);
            break;
        }
    }
    let record_block = record_block.expect("Record block not found in CAR");

    let record: Value = serde_ipld_dagcbor::from_slice(&record_block).unwrap();
    assert_eq!(record["text"], post_text);

    ws_stream
        .send(tungstenite::Message::Close(None))
        .await
        .ok();
}