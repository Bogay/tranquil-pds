mod common;

use cid::Cid;
use common::*;
use futures::{SinkExt, stream::StreamExt};
use iroh_car::CarReader;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::Cursor;
use tokio_tungstenite::{connect_async, tungstenite};
use tranquil_scopes::RepoAction;

#[derive(Debug, Deserialize, Serialize)]
struct FrameHeader {
    op: i64,
    t: String,
}

#[derive(Debug, Deserialize)]
struct CommitFrame {
    seq: i64,
    #[serde(default)]
    rebase: bool,
    #[serde(rename = "tooBig", default)]
    too_big: bool,
    repo: String,
    commit: Cid,
    rev: String,
    since: Option<String>,
    #[serde(with = "serde_bytes")]
    blocks: Vec<u8>,
    ops: Vec<RepoOp>,
    #[serde(default)]
    blobs: Vec<Cid>,
    time: String,
    #[serde(rename = "prevData")]
    prev_data: Option<Cid>,
}

#[derive(Debug, Deserialize)]
struct RepoOp {
    action: RepoAction,
    path: String,
    cid: Option<Cid>,
    prev: Option<Cid>,
}

fn find_cbor_map_end(bytes: &[u8]) -> Result<usize, String> {
    let mut pos = 0;

    fn read_uint(bytes: &[u8], pos: &mut usize, additional: u8) -> Result<u64, String> {
        match additional {
            0..=23 => Ok(additional as u64),
            24 => {
                if *pos >= bytes.len() {
                    return Err("Unexpected end".into());
                }
                let val = bytes[*pos] as u64;
                *pos += 1;
                Ok(val)
            }
            25 => {
                if *pos + 2 > bytes.len() {
                    return Err("Unexpected end".into());
                }
                let val = u16::from_be_bytes([bytes[*pos], bytes[*pos + 1]]) as u64;
                *pos += 2;
                Ok(val)
            }
            26 => {
                if *pos + 4 > bytes.len() {
                    return Err("Unexpected end".into());
                }
                let val = u32::from_be_bytes([
                    bytes[*pos],
                    bytes[*pos + 1],
                    bytes[*pos + 2],
                    bytes[*pos + 3],
                ]) as u64;
                *pos += 4;
                Ok(val)
            }
            27 => {
                if *pos + 8 > bytes.len() {
                    return Err("Unexpected end".into());
                }
                let val = u64::from_be_bytes([
                    bytes[*pos],
                    bytes[*pos + 1],
                    bytes[*pos + 2],
                    bytes[*pos + 3],
                    bytes[*pos + 4],
                    bytes[*pos + 5],
                    bytes[*pos + 6],
                    bytes[*pos + 7],
                ]);
                *pos += 8;
                Ok(val)
            }
            _ => Err(format!("Invalid additional info: {}", additional)),
        }
    }

    fn skip_value(bytes: &[u8], pos: &mut usize) -> Result<(), String> {
        if *pos >= bytes.len() {
            return Err("Unexpected end".into());
        }
        let initial = bytes[*pos];
        *pos += 1;
        let major = initial >> 5;
        let additional = initial & 0x1f;

        match major {
            0 | 1 => {
                read_uint(bytes, pos, additional)?;
                Ok(())
            }
            2 | 3 => {
                let len = read_uint(bytes, pos, additional)? as usize;
                *pos += len;
                Ok(())
            }
            4 => {
                let len = read_uint(bytes, pos, additional)?;
                for _ in 0..len {
                    skip_value(bytes, pos)?;
                }
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

    if header.t != "#commit" {
        return Err(format!("Not a commit frame: {}", header.t));
    }

    let remaining = &bytes[header_len..];
    let frame: CommitFrame = serde_ipld_dagcbor::from_slice(remaining)
        .map_err(|e| format!("Failed to parse commit frame: {:?}", e))?;

    Ok((header, frame))
}

fn is_valid_tid(s: &str) -> bool {
    s.len() == 13 && s.chars().all(|c| c.is_alphanumeric())
}

fn is_valid_time_format(s: &str) -> bool {
    if !s.ends_with('Z') {
        return false;
    }
    let parts: Vec<&str> = s.split('T').collect();
    if parts.len() != 2 {
        return false;
    }
    let time_part = parts[1].trim_end_matches('Z');
    let time_parts: Vec<&str> = time_part.split(':').collect();
    if time_parts.len() != 3 {
        return false;
    }
    let seconds_part = time_parts[2];
    if let Some(dot_pos) = seconds_part.find('.') {
        let millis = &seconds_part[dot_pos + 1..];
        millis.len() == 3
    } else {
        false
    }
}

#[tokio::test]
async fn test_firehose_frame_structure() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    let url = format!(
        "ws://127.0.0.1:{}/xrpc/com.atproto.sync.subscribeRepos",
        app_port()
    );
    let (mut ws_stream, _) = connect_async(&url).await.expect("Failed to connect");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let post_text = "Testing firehose validation!";
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
        .bearer_auth(&token)
        .json(&post_payload)
        .send()
        .await
        .expect("Failed to create post");
    assert_eq!(res.status(), StatusCode::OK);

    let mut frame_opt: Option<(FrameHeader, CommitFrame)> = None;
    let timeout = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let msg = ws_stream.next().await.unwrap().unwrap();
            let raw_bytes = match msg {
                tungstenite::Message::Binary(bin) => bin,
                _ => continue,
            };
            if let Ok((h, f)) = parse_frame(&raw_bytes)
                && f.repo == did
            {
                frame_opt = Some((h, f));
                break;
            }
        }
    })
    .await;
    assert!(timeout.is_ok(), "Timed out waiting for event for our DID");
    let (header, frame) = frame_opt.expect("No matching frame found");

    println!("\n=== Frame Structure Validation ===\n");

    println!("Header:");
    println!("  op: {} (expected: 1)", header.op);
    println!("  t: {} (expected: #commit)", header.t);
    assert_eq!(header.op, 1, "Header op should be 1");
    assert_eq!(header.t, "#commit", "Header t should be #commit");

    println!("\nCommitFrame fields:");
    println!("  seq: {}", frame.seq);
    println!("  rebase: {}", frame.rebase);
    println!("  tooBig: {}", frame.too_big);
    println!("  repo: {}", frame.repo);
    println!("  commit: {}", frame.commit);
    println!(
        "  rev: {} (valid TID: {})",
        frame.rev,
        is_valid_tid(&frame.rev)
    );
    println!("  since: {:?}", frame.since);
    println!("  blocks length: {} bytes", frame.blocks.len());
    println!("  ops count: {}", frame.ops.len());
    println!("  blobs count: {}", frame.blobs.len());
    println!(
        "  time: {} (valid format: {})",
        frame.time,
        is_valid_time_format(&frame.time)
    );
    println!(
        "  prevData: {:?} (IMPORTANT - should have value for updates)",
        frame.prev_data
    );

    assert_eq!(frame.repo, did, "Frame repo should match DID");
    assert!(
        is_valid_tid(&frame.rev),
        "Rev should be valid TID format, got: {}",
        frame.rev
    );
    assert!(!frame.blocks.is_empty(), "Blocks should not be empty");
    assert!(
        is_valid_time_format(&frame.time),
        "Time should be ISO 8601 with milliseconds and Z suffix"
    );

    println!("\nOps validation:");
    for (i, op) in frame.ops.iter().enumerate() {
        println!("  Op {}:", i);
        println!("    action: {:?}", op.action);
        println!("    path: {}", op.path);
        println!("    cid: {:?}", op.cid);
        println!(
            "    prev: {:?} (should be Some for updates/deletes)",
            op.prev
        );

        assert!(
            op.path.contains('/'),
            "Path should contain collection/rkey: {}",
            op.path
        );

        if op.action == RepoAction::Create {
            assert!(op.cid.is_some(), "Create op should have cid");
        }
    }

    println!("\nCAR validation:");
    let mut car_reader = CarReader::new(Cursor::new(&frame.blocks)).await.unwrap();
    let car_header = car_reader.header().clone();
    println!("  CAR roots: {:?}", car_header.roots());

    assert!(
        !car_header.roots().is_empty(),
        "CAR should have at least one root"
    );
    assert_eq!(
        car_header.roots()[0],
        frame.commit,
        "First CAR root should be commit CID"
    );

    let mut block_cids: Vec<Cid> = Vec::new();
    while let Ok(Some((cid, _))) = car_reader.next_block().await {
        block_cids.push(cid);
    }
    println!("  CAR blocks: {} total", block_cids.len());
    for cid in &block_cids {
        println!("    - {}", cid);
    }

    assert!(
        block_cids.contains(&frame.commit),
        "CAR should contain commit block"
    );

    for op in &frame.ops {
        if let Some(ref cid) = op.cid {
            assert!(
                block_cids.contains(cid),
                "CAR should contain op's record block: {}",
                cid
            );
        }
    }

    println!("\n=== Validation Complete ===\n");

    ws_stream.send(tungstenite::Message::Close(None)).await.ok();
}

#[tokio::test]
async fn test_firehose_update_has_prev_field() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    let profile_payload = json!({
        "repo": did,
        "collection": "app.bsky.actor.profile",
        "rkey": "self",
        "record": {
            "$type": "app.bsky.actor.profile",
            "displayName": "Test User v1",
        }
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&profile_payload)
        .send()
        .await
        .expect("Failed to create profile");
    assert_eq!(res.status(), StatusCode::OK);
    let first_profile: Value = res.json().await.unwrap();
    let first_cid = first_profile["cid"].as_str().unwrap();

    let url = format!(
        "ws://127.0.0.1:{}/xrpc/com.atproto.sync.subscribeRepos",
        app_port()
    );
    let (mut ws_stream, _) = connect_async(&url).await.expect("Failed to connect");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let update_payload = json!({
        "repo": did,
        "collection": "app.bsky.actor.profile",
        "rkey": "self",
        "record": {
            "$type": "app.bsky.actor.profile",
            "displayName": "Test User v2",
        }
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.putRecord",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&update_payload)
        .send()
        .await
        .expect("Failed to update profile");
    assert_eq!(res.status(), StatusCode::OK);

    let mut frame_opt: Option<CommitFrame> = None;
    let timeout = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            let msg = match ws_stream.next().await {
                Some(Ok(m)) => m,
                _ => continue,
            };
            let raw_bytes = match msg {
                tungstenite::Message::Binary(bin) => bin,
                _ => continue,
            };
            if let Ok((_, f)) = parse_frame(&raw_bytes)
                && f.repo == did
            {
                frame_opt = Some(f);
                break;
            }
        }
    })
    .await;
    assert!(timeout.is_ok(), "Timed out waiting for update commit");
    let frame = frame_opt.expect("No matching frame found");

    println!("\n=== Update Operation Validation ===\n");
    println!("First profile CID: {}", first_cid);
    println!("Frame prevData: {:?}", frame.prev_data);

    for op in &frame.ops {
        println!(
            "Op: action={:?}, path={}, cid={:?}, prev={:?}",
            op.action, op.path, op.cid, op.prev
        );

        if op.action == RepoAction::Update && op.path.contains("app.bsky.actor.profile") {
            assert!(
                op.prev.is_some(),
                "Update operation should have 'prev' field with old CID! Got: {:?}",
                op.prev
            );
            println!("  ✓ Update op has prev field: {:?}", op.prev);
        }
    }

    println!("\n=== Validation Complete ===\n");

    ws_stream.send(tungstenite::Message::Close(None)).await.ok();
}

#[tokio::test]
async fn test_firehose_commit_has_prev_data() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    let url = format!(
        "ws://127.0.0.1:{}/xrpc/com.atproto.sync.subscribeRepos",
        app_port()
    );
    let (mut ws_stream, _) = connect_async(&url).await.expect("Failed to connect");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let post_payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "First post",
            "createdAt": chrono::Utc::now().to_rfc3339(),
        }
    });
    client
        .post(format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&post_payload)
        .send()
        .await
        .expect("Failed to create first post");

    let mut first_frame_opt: Option<CommitFrame> = None;
    let timeout = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let msg = ws_stream.next().await.unwrap().unwrap();
            let raw_bytes = match msg {
                tungstenite::Message::Binary(bin) => bin,
                _ => continue,
            };
            if let Ok((_, f)) = parse_frame(&raw_bytes)
                && f.repo == did
            {
                first_frame_opt = Some(f);
                break;
            }
        }
    })
    .await;
    assert!(timeout.is_ok(), "Timed out waiting for first commit");
    let first_frame = first_frame_opt.expect("No first frame found");

    println!("\n=== First Commit ===");
    println!(
        "  prevData: {:?} (first commit may be None)",
        first_frame.prev_data
    );
    println!(
        "  since: {:?} (first commit should be None)",
        first_frame.since
    );

    let post_payload2 = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "Second post",
            "createdAt": chrono::Utc::now().to_rfc3339(),
        }
    });
    client
        .post(format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&post_payload2)
        .send()
        .await
        .expect("Failed to create second post");

    let mut second_frame_opt: Option<CommitFrame> = None;
    let timeout = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let msg = ws_stream.next().await.unwrap().unwrap();
            let raw_bytes = match msg {
                tungstenite::Message::Binary(bin) => bin,
                _ => continue,
            };
            if let Ok((_, f)) = parse_frame(&raw_bytes)
                && f.repo == did
            {
                second_frame_opt = Some(f);
                break;
            }
        }
    })
    .await;
    assert!(timeout.is_ok(), "Timed out waiting for second commit");
    let second_frame = second_frame_opt.expect("No second frame found");

    println!("\n=== Second Commit ===");
    println!(
        "  prevData: {:?} (should have value - MST root CID)",
        second_frame.prev_data
    );
    println!(
        "  since: {:?} (should have value - previous rev)",
        second_frame.since
    );

    assert!(
        second_frame.since.is_some(),
        "Second commit should have 'since' field pointing to first commit rev"
    );

    println!("\n=== Validation Complete ===\n");

    ws_stream.send(tungstenite::Message::Close(None)).await.ok();
}

#[tokio::test]
async fn test_compare_raw_cbor_encoding() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    let url = format!(
        "ws://127.0.0.1:{}/xrpc/com.atproto.sync.subscribeRepos",
        app_port()
    );
    let (mut ws_stream, _) = connect_async(&url).await.expect("Failed to connect");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let post_payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "CBOR encoding test",
            "createdAt": chrono::Utc::now().to_rfc3339(),
        }
    });
    client
        .post(format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&post_payload)
        .send()
        .await
        .expect("Failed to create post");

    let mut raw_bytes_opt: Option<Vec<u8>> = None;
    let timeout = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let msg = ws_stream.next().await.unwrap().unwrap();
            let raw = match msg {
                tungstenite::Message::Binary(bin) => bin,
                _ => continue,
            };
            if let Ok((_, f)) = parse_frame(&raw)
                && f.repo == did
            {
                raw_bytes_opt = Some(raw.to_vec());
                break;
            }
        }
    })
    .await;
    assert!(timeout.is_ok(), "Timed out waiting for event for our DID");
    let raw_bytes = raw_bytes_opt.expect("No matching frame found");

    println!("\n=== Raw CBOR Analysis ===\n");
    println!("Total frame size: {} bytes", raw_bytes.len());

    fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join("")
    }

    println!(
        "First 64 bytes (hex): {}",
        bytes_to_hex(&raw_bytes[..64.min(raw_bytes.len())])
    );

    let header_end = find_cbor_map_end(&raw_bytes).expect("Failed to find header end");

    println!("\nHeader section: {} bytes", header_end);
    println!("Header hex: {}", bytes_to_hex(&raw_bytes[..header_end]));

    println!("\nPayload section: {} bytes", raw_bytes.len() - header_end);

    println!("\n=== Analysis Complete ===\n");

    ws_stream.send(tungstenite::Message::Close(None)).await.ok();
}

#[derive(Debug, Deserialize)]
struct ErrorFrameHeader {
    op: i64,
}

#[derive(Debug, Deserialize)]
struct ErrorFrameBody {
    error: String,
    #[allow(dead_code)]
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct InfoFrameHeader {
    #[allow(dead_code)]
    op: i64,
    t: String,
}

#[derive(Debug, Deserialize)]
struct InfoFrameBody {
    name: String,
    #[allow(dead_code)]
    message: Option<String>,
}

fn parse_error_frame(bytes: &[u8]) -> Result<(ErrorFrameHeader, ErrorFrameBody), String> {
    let header_len = find_cbor_map_end(bytes)?;
    let header: ErrorFrameHeader = serde_ipld_dagcbor::from_slice(&bytes[..header_len])
        .map_err(|e| format!("Failed to parse error header: {:?}", e))?;

    if header.op != -1 {
        return Err(format!("Not an error frame, op: {}", header.op));
    }

    let remaining = &bytes[header_len..];
    let body: ErrorFrameBody = serde_ipld_dagcbor::from_slice(remaining)
        .map_err(|e| format!("Failed to parse error body: {:?}", e))?;

    Ok((header, body))
}

fn parse_info_frame(bytes: &[u8]) -> Result<(InfoFrameHeader, InfoFrameBody), String> {
    let header_len = find_cbor_map_end(bytes)?;
    let header: InfoFrameHeader = serde_ipld_dagcbor::from_slice(&bytes[..header_len])
        .map_err(|e| format!("Failed to parse info header: {:?}", e))?;

    if header.t != "#info" {
        return Err(format!("Not an info frame, t: {}", header.t));
    }

    let remaining = &bytes[header_len..];
    let body: InfoFrameBody = serde_ipld_dagcbor::from_slice(remaining)
        .map_err(|e| format!("Failed to parse info body: {:?}", e))?;

    Ok((header, body))
}

#[tokio::test]
async fn test_firehose_future_cursor_error() {
    let _ = base_url().await;

    let future_cursor = 9999999999i64;
    let url = format!(
        "ws://127.0.0.1:{}/xrpc/com.atproto.sync.subscribeRepos?cursor={}",
        app_port(),
        future_cursor
    );

    let (mut ws_stream, _) = connect_async(&url).await.expect("Failed to connect");

    let timeout = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            match ws_stream.next().await {
                Some(Ok(tungstenite::Message::Binary(bin))) => {
                    if let Ok((header, body)) = parse_error_frame(&bin) {
                        println!("Received error frame: {:?} {:?}", header, body);
                        assert_eq!(header.op, -1, "Error frame op should be -1");
                        assert_eq!(body.error, "FutureCursor", "Error should be FutureCursor");
                        return true;
                    }
                }
                Some(Ok(tungstenite::Message::Close(_))) => {
                    println!("Connection closed");
                    return false;
                }
                None => {
                    println!("Stream ended");
                    return false;
                }
                _ => continue,
            }
        }
    })
    .await;

    match timeout {
        Ok(received_error) => {
            assert!(
                received_error,
                "Should have received FutureCursor error frame before connection closed"
            );
        }
        Err(_) => {
            panic!(
                "Timed out waiting for FutureCursor error - connection should close quickly with error"
            );
        }
    }
}

#[tokio::test]
async fn test_firehose_outdated_cursor_info() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    let post_payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "Post for outdated cursor test",
            "createdAt": chrono::Utc::now().to_rfc3339(),
        }
    });
    let _ = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&post_payload)
        .send()
        .await
        .expect("Failed to create post");

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let outdated_cursor = 1i64;
    let url = format!(
        "ws://127.0.0.1:{}/xrpc/com.atproto.sync.subscribeRepos?cursor={}",
        app_port(),
        outdated_cursor
    );

    let (mut ws_stream, _) = connect_async(&url).await.expect("Failed to connect");

    let mut found_info = false;
    let mut found_commit = false;

    let timeout = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        loop {
            match ws_stream.next().await {
                Some(Ok(tungstenite::Message::Binary(bin))) => {
                    if let Ok((header, body)) = parse_info_frame(&bin) {
                        println!("Received info frame: {:?} {:?}", header, body);
                        if body.name == "OutdatedCursor" {
                            found_info = true;
                            println!("Found OutdatedCursor info frame!");
                        }
                    } else if let Ok((_, frame)) = parse_frame(&bin)
                        && frame.repo == did
                    {
                        found_commit = true;
                        println!("Found commit for our DID");
                    }
                    if found_commit {
                        break;
                    }
                }
                Some(Ok(tungstenite::Message::Close(_))) => break,
                None => break,
                _ => continue,
            }
        }
    })
    .await;

    assert!(timeout.is_ok(), "Timed out");
    assert!(
        found_commit,
        "Should have received commits even with outdated cursor"
    );
}

#[tokio::test]
async fn test_firehose_car_contains_mst_blocks() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    for i in 0..3 {
        let post_payload = json!({
            "repo": did,
            "collection": "app.bsky.feed.post",
            "record": {
                "$type": "app.bsky.feed.post",
                "text": format!("Setup post {}", i),
                "createdAt": chrono::Utc::now().to_rfc3339(),
            }
        });
        client
            .post(format!(
                "{}/xrpc/com.atproto.repo.createRecord",
                base_url().await
            ))
            .bearer_auth(&token)
            .json(&post_payload)
            .send()
            .await
            .expect("Failed to create setup post");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let url = format!(
        "ws://127.0.0.1:{}/xrpc/com.atproto.sync.subscribeRepos",
        app_port()
    );
    let (mut ws_stream, _) = connect_async(&url).await.expect("Failed to connect");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let post_payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "Test post for MST block validation",
            "createdAt": chrono::Utc::now().to_rfc3339(),
        }
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            base_url().await
        ))
        .bearer_auth(&token)
        .json(&post_payload)
        .send()
        .await
        .expect("Failed to create post");
    assert_eq!(res.status(), StatusCode::OK);
    let create_result: Value = res.json().await.unwrap();
    let record_cid_str = create_result["cid"].as_str().unwrap();
    let expected_record_cid: Cid = record_cid_str.parse().unwrap();

    let mut frame_opt: Option<CommitFrame> = None;
    let timeout = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let msg = ws_stream.next().await.unwrap().unwrap();
            let raw_bytes = match msg {
                tungstenite::Message::Binary(bin) => bin,
                _ => continue,
            };
            if let Ok((_, f)) = parse_frame(&raw_bytes)
                && f.repo == did
                && f.ops.iter().any(|op| op.cid == Some(expected_record_cid))
            {
                frame_opt = Some(f);
                break;
            }
        }
    })
    .await;
    assert!(timeout.is_ok(), "Timed out waiting for firehose event");
    let frame = frame_opt.expect("No matching frame found");

    let mut car_reader = CarReader::new(Cursor::new(&frame.blocks)).await.unwrap();

    let mut block_count = 0;
    let mut found_commit = false;
    let mut found_record = false;
    let mut mst_block_count = 0;

    while let Ok(Some((cid, data))) = car_reader.next_block().await {
        block_count += 1;

        if cid == frame.commit {
            found_commit = true;
            continue;
        }

        if cid == expected_record_cid {
            found_record = true;
            continue;
        }

        if data.len() > 10 && data.len() < 5000 {
            mst_block_count += 1;
        }
    }

    println!("CAR block analysis:");
    println!("  Total blocks: {}", block_count);
    println!("  Found commit: {}", found_commit);
    println!("  Found record: {}", found_record);
    println!("  MST/other blocks: {}", mst_block_count);

    assert!(found_commit, "CAR must contain commit block");
    assert!(found_record, "CAR must contain record block");

    assert!(
        block_count >= 3,
        "CAR should contain at least commit + record + MST node(s), got {} blocks. \
         This may indicate firehose is not including all relevant blocks.",
        block_count
    );

    assert!(
        mst_block_count >= 1,
        "CAR should contain MST node blocks for repo validation, got {} MST blocks. \
         Firehose must include relevant MST blocks, not just new ones.",
        mst_block_count
    );

    ws_stream.send(tungstenite::Message::Close(None)).await.ok();
}
