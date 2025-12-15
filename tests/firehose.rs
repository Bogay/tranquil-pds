mod common;
use common::*;
use cid::Cid;
use futures::{stream::StreamExt, SinkExt};
use iroh_car::CarReader;
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::Cursor;
use tokio_tungstenite::{connect_async, tungstenite};

#[derive(Debug, Deserialize)]
struct FrameHeader {
    op: i64,
    t: String,
}

#[derive(Debug, Deserialize)]
struct CommitFrame {
    seq: i64,
    rebase: bool,
    #[serde(rename = "tooBig")]
    too_big: bool,
    repo: String,
    commit: Cid,
    rev: String,
    since: Option<String>,
    #[serde(with = "serde_bytes")]
    blocks: Vec<u8>,
    ops: Vec<RepoOp>,
    blobs: Vec<Cid>,
    time: String,
}

#[derive(Debug, Deserialize)]
struct RepoOp {
    action: String,
    path: String,
    cid: Option<Cid>,
}

fn find_cbor_map_end(bytes: &[u8]) -> Result<usize, String> {
    let mut pos = 0;
    fn read_uint(bytes: &[u8], pos: &mut usize, additional: u8) -> Result<u64, String> {
        match additional {
            0..=23 => Ok(additional as u64),
            24 => {
                if *pos >= bytes.len() { return Err("Unexpected end".into()); }
                let val = bytes[*pos] as u64;
                *pos += 1;
                Ok(val)
            }
            25 => {
                if *pos + 2 > bytes.len() { return Err("Unexpected end".into()); }
                let val = u16::from_be_bytes([bytes[*pos], bytes[*pos + 1]]) as u64;
                *pos += 2;
                Ok(val)
            }
            26 => {
                if *pos + 4 > bytes.len() { return Err("Unexpected end".into()); }
                let val = u32::from_be_bytes([bytes[*pos], bytes[*pos + 1], bytes[*pos + 2], bytes[*pos + 3]]) as u64;
                *pos += 4;
                Ok(val)
            }
            27 => {
                if *pos + 8 > bytes.len() { return Err("Unexpected end".into()); }
                let val = u64::from_be_bytes([bytes[*pos], bytes[*pos + 1], bytes[*pos + 2], bytes[*pos + 3], bytes[*pos + 4], bytes[*pos + 5], bytes[*pos + 6], bytes[*pos + 7]]);
                *pos += 8;
                Ok(val)
            }
            _ => Err(format!("Invalid additional info: {}", additional)),
        }
    }
    fn skip_value(bytes: &[u8], pos: &mut usize) -> Result<(), String> {
        if *pos >= bytes.len() { return Err("Unexpected end".into()); }
        let initial = bytes[*pos];
        *pos += 1;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        match major {
            0 | 1 => { read_uint(bytes, pos, additional)?; Ok(()) }
            2 | 3 => {
                let len = read_uint(bytes, pos, additional)? as usize;
                *pos += len;
                Ok(())
            }
            4 => {
                let len = read_uint(bytes, pos, additional)?;
                for _ in 0..len { skip_value(bytes, pos)?; }
                Ok(())
            }
            5 => {
                let len = read_uint(bytes, pos, additional)?;
                for _ in 0..len {
                    skip_value(bytes, pos)?;
                    skip_value(bytes, pos)?;
                }
                Ok(())
            }
            6 => {
                read_uint(bytes, pos, additional)?;
                skip_value(bytes, pos)
            }
            7 => Ok(()),
            _ => Err(format!("Unknown major type: {}", major)),
        }
    }
    skip_value(bytes, &mut pos)?;
    Ok(pos)
}

fn parse_frame(bytes: &[u8]) -> Result<(FrameHeader, CommitFrame), String> {
    let header_len = find_cbor_map_end(bytes)?;
    let header: FrameHeader = serde_ipld_dagcbor::from_slice(&bytes[..header_len])
        .map_err(|e| format!("Failed to parse header: {:?}", e))?;
    let remaining = &bytes[header_len..];
    let frame: CommitFrame = serde_ipld_dagcbor::from_slice(remaining)
        .map_err(|e| format!("Failed to parse commit frame: {:?}", e))?;
    Ok((header, frame))
}

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
    let mut frame_opt: Option<(FrameHeader, CommitFrame)> = None;
    let timeout = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let msg = ws_stream.next().await.unwrap().unwrap();
            let raw_bytes = match msg {
                tungstenite::Message::Binary(bin) => bin,
                _ => continue,
            };
            if let Ok((h, f)) = parse_frame(&raw_bytes) {
                if f.repo == did {
                    frame_opt = Some((h, f));
                    break;
                }
            }
        }
    })
    .await;
    assert!(timeout.is_ok(), "Timed out waiting for event for our DID");
    let (header, commit) = frame_opt.expect("No matching frame found");
    assert_eq!(header.op, 1);
    assert_eq!(header.t, "#commit");
    assert_eq!(commit.ops.len(), 1);
    assert!(!commit.blocks.is_empty());
    let op = &commit.ops[0];
    let record_cid = op.cid.clone().expect("Op should have CID");
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
