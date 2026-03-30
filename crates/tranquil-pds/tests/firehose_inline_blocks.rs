mod common;
mod firehose;
mod helpers;

use cid::Cid;
use common::*;
use firehose::FirehoseConsumer;
use helpers::build_car_with_signature;
use iroh_car::CarReader;
use k256::ecdsa::SigningKey;
use multihash::Multihash;
use reqwest::StatusCode;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::Cursor;
use std::time::Duration;
use tranquil_db_traits::{EventBlocks, RepoEventType, SequenceNumber};
use tranquil_types::{CidLink, Did};

fn synthetic_cid(payload: &[u8]) -> Cid {
    let digest = Sha256::digest(payload);
    let mh = Multihash::wrap(0x12, digest.as_slice()).expect("multihash wrap");
    Cid::new_v1(0x71, mh)
}

fn fresh_synthetic_did(label: &str) -> Did {
    Did::new(format!(
        "did:plc:test{}{}",
        label,
        uuid::Uuid::new_v4().simple()
    ))
    .expect("valid did")
}

async fn create_post(client: &reqwest::Client, token: &str, did: &str, text: &str) {
    let payload = json!({
        "repo": did,
        "collection": "app.bsky.feed.post",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": text,
            "createdAt": chrono::Utc::now().to_rfc3339(),
        }
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            base_url().await
        ))
        .bearer_auth(token)
        .json(&payload)
        .send()
        .await
        .expect("createRecord request failed");
    assert_eq!(res.status(), StatusCode::OK, "createRecord failed");
}

#[tokio::test]
async fn commit_events_carry_inline_blocks() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    create_post(&client, &token, &did, "commit A: orphans incoming").await;
    create_post(&client, &token, &did, "commit B: bye bye MST nodes from A").await;

    let repos = get_test_repos().await;
    let typed_did = tranquil_types::Did::new(did.clone()).unwrap();

    let events = repos
        .repo
        .get_events_since_seq(SequenceNumber::ZERO, None)
        .await
        .expect("get_events_since_seq failed");

    let our_commits: Vec<_> = events
        .iter()
        .filter(|e| e.did == typed_did && e.event_type == RepoEventType::Commit)
        .collect();

    assert!(
        our_commits.len() >= 2,
        "expected at least 2 commit events for our DID, got {}",
        our_commits.len()
    );

    our_commits.iter().for_each(|event| {
        let blocks = event.blocks.as_ref().unwrap_or_else(|| {
            panic!(
                "commit event seq={} has no blocks field",
                event.seq.as_i64()
            )
        });
        let inline = match blocks {
            EventBlocks::Inline(v) => v,
            EventBlocks::LegacyCids(_) => panic!(
                "commit event seq={} resolved as LegacyCids, expected Inline; \
                 new commits must inline block bytes into the eventlog",
                event.seq.as_i64()
            ),
        };
        assert!(
            !inline.is_empty(),
            "commit event seq={} has empty Inline blocks vec",
            event.seq.as_i64()
        );
        let commit_cid = event
            .commit_cid
            .as_ref()
            .and_then(|c| c.to_cid())
            .unwrap_or_else(|| {
                panic!("commit event seq={} missing commit_cid", event.seq.as_i64())
            });
        let commit_cid_bytes = commit_cid.to_bytes();
        assert!(
            inline.iter().any(|b| b.cid_bytes == commit_cid_bytes),
            "commit event seq={} inline blocks do not contain the commit block",
            event.seq.as_i64()
        );
        inline.iter().for_each(|b| {
            let parsed = Cid::read_bytes(b.cid_bytes.as_slice()).unwrap_or_else(|e| {
                panic!(
                    "commit event seq={} inline cid_bytes failed to parse as Cid: {e}",
                    event.seq.as_i64()
                )
            });
            assert_eq!(
                parsed.to_bytes(),
                b.cid_bytes,
                "commit event seq={} cid round-trip mismatch (cid={parsed})",
                event.seq.as_i64()
            );
        });
    });
}

#[tokio::test]
async fn sync_event_carries_inline_commit_block() {
    let repos = get_test_repos().await;
    let did = fresh_synthetic_did("sync");
    let commit_bytes = b"synthetic sync commit block payload".to_vec();
    let commit_cid = synthetic_cid(&commit_bytes);
    let cid_link: CidLink = (&commit_cid).into();
    let rev = "3kabcdefghij2";

    let seq = repos
        .repo
        .insert_sync_event(&did, &cid_link, Some(rev), &commit_bytes)
        .await
        .expect("insert_sync_event");

    let event = repos
        .repo
        .get_event_by_seq(seq)
        .await
        .expect("get_event_by_seq")
        .expect("event present");

    assert_eq!(event.event_type, RepoEventType::Sync);
    let blocks = event
        .blocks
        .as_ref()
        .expect("sync event must carry inline blocks");
    let inline = match blocks {
        EventBlocks::Inline(v) => v,
        EventBlocks::LegacyCids(_) => {
            panic!("sync event resolved as LegacyCids; new sync events must inline block bytes")
        }
    };
    assert_eq!(
        inline.len(),
        1,
        "sync event must carry exactly the commit block, got {}",
        inline.len()
    );
    let stored = &inline[0];
    assert_eq!(
        stored.cid_bytes,
        commit_cid.to_bytes(),
        "sync event inline cid_bytes mismatch"
    );
    assert_eq!(stored.data, commit_bytes, "sync event inline data mismatch");
}

#[tokio::test]
async fn genesis_commit_event_carries_inline_blocks() {
    let repos = get_test_repos().await;
    let did = fresh_synthetic_did("gen");
    let commit_bytes = b"synthetic genesis commit block payload".to_vec();
    let mst_root_bytes = b"synthetic genesis mst root block payload".to_vec();
    let commit_cid = synthetic_cid(&commit_bytes);
    let mst_root_cid = synthetic_cid(&mst_root_bytes);
    let commit_link: CidLink = (&commit_cid).into();
    let mst_link: CidLink = (&mst_root_cid).into();
    let rev = "3kabcdefghij3";

    let seq = repos
        .repo
        .insert_genesis_commit_event(
            &did,
            &commit_link,
            &mst_link,
            rev,
            &commit_bytes,
            &mst_root_bytes,
        )
        .await
        .expect("insert_genesis_commit_event");

    let event = repos
        .repo
        .get_event_by_seq(seq)
        .await
        .expect("get_event_by_seq")
        .expect("event present");

    assert_eq!(event.event_type, RepoEventType::Commit);
    let blocks = event
        .blocks
        .as_ref()
        .expect("genesis commit event must carry inline blocks");
    let inline = match blocks {
        EventBlocks::Inline(v) => v,
        EventBlocks::LegacyCids(_) => {
            panic!("genesis event resolved as LegacyCids; new genesis events must inline blocks")
        }
    };
    assert_eq!(
        inline.len(),
        2,
        "genesis event must carry commit + mst root blocks, got {}",
        inline.len()
    );

    let commit_cid_bytes = commit_cid.to_bytes();
    let mst_cid_bytes = mst_root_cid.to_bytes();

    let commit_block = inline
        .iter()
        .find(|b| b.cid_bytes == commit_cid_bytes)
        .expect("genesis inline blocks missing commit block");
    assert_eq!(commit_block.data, commit_bytes);

    let mst_block = inline
        .iter()
        .find(|b| b.cid_bytes == mst_cid_bytes)
        .expect("genesis inline blocks missing mst root block");
    assert_eq!(mst_block.data, mst_root_bytes);
}

#[tokio::test]
async fn backfill_succeeds_from_eventlog_alone() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    create_post(&client, &token, &did, "first").await;
    create_post(&client, &token, &did, "second").await;

    let consumer = FirehoseConsumer::connect_with_cursor(app_port(), 0).await;
    let commits = consumer
        .wait_for_commits(&did, 2, Duration::from_secs(20))
        .await;

    assert!(
        commits.len() >= 2,
        "expected at least 2 backfilled commits for {}, got {}",
        did,
        commits.len()
    );

    for commit in &commits {
        assert!(
            !commit.blocks.is_empty(),
            "backfilled commit seq={} has empty CAR blocks",
            commit.seq
        );
        let mut reader = CarReader::new(Cursor::new(&commit.blocks))
            .await
            .unwrap_or_else(|e| panic!("CAR header parse failed for seq={}: {e}", commit.seq));
        assert!(
            !reader.header().roots().is_empty(),
            "CAR for seq={} has no roots",
            commit.seq
        );
        assert_eq!(
            reader.header().roots()[0],
            commit.commit,
            "CAR root mismatch for seq={}",
            commit.seq
        );
        let mut found_commit_block = false;
        while let Ok(Some((cid, _))) = reader.next_block().await {
            if cid == commit.commit {
                found_commit_block = true;
            }
        }
        assert!(
            found_commit_block,
            "backfilled commit seq={} CAR missing the commit block",
            commit.seq
        );
    }
}

#[tokio::test]
async fn import_event_carries_inline_commit_block() {
    let client = client();
    let (token, did) = create_account_and_login(&client).await;

    let signing_key = SigningKey::random(&mut rand::thread_rng());
    let (car_bytes, _car_root_cid) = build_car_with_signature(&did, &signing_key);

    let import_res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.importRepo",
            base_url().await
        ))
        .bearer_auth(&token)
        .header("Content-Type", "application/vnd.ipld.car")
        .body(car_bytes)
        .send()
        .await
        .expect("import request failed");
    assert_eq!(
        import_res.status(),
        StatusCode::OK,
        "import should succeed: body={:?}",
        import_res.text().await.unwrap_or_default()
    );

    let repos = get_test_repos().await;
    let typed_did = tranquil_types::Did::new(did.clone()).unwrap();
    let events = repos
        .repo
        .get_events_since_seq(SequenceNumber::ZERO, None)
        .await
        .expect("get_events_since_seq failed");

    let our_commits: Vec<_> = events
        .iter()
        .filter(|e| e.did == typed_did && e.event_type == RepoEventType::Commit)
        .collect();
    assert!(
        !our_commits.is_empty(),
        "expected at least one commit event for {} after import",
        did
    );

    let import_event = our_commits
        .last()
        .expect("at least one commit event after import");
    let blocks = import_event.blocks.as_ref().unwrap_or_else(|| {
        panic!(
            "import commit event seq={} missing blocks field",
            import_event.seq.as_i64()
        )
    });
    let inline = match blocks {
        EventBlocks::Inline(v) => v,
        EventBlocks::LegacyCids(_) => panic!(
            "import event seq={} resolved as LegacyCids; new commits must inline blocks",
            import_event.seq.as_i64()
        ),
    };
    assert!(
        !inline.is_empty(),
        "import event seq={} has empty Inline blocks vec — this is the bug from \
         sequence_import_event using `blocks: Some(vec![])`",
        import_event.seq.as_i64()
    );
    let commit_cid = import_event
        .commit_cid
        .as_ref()
        .and_then(|c| c.to_cid())
        .unwrap_or_else(|| {
            panic!(
                "import event seq={} missing commit_cid",
                import_event.seq.as_i64()
            )
        });
    let commit_cid_bytes = commit_cid.to_bytes();
    assert!(
        inline.iter().any(|b| b.cid_bytes == commit_cid_bytes),
        "import event seq={} inline blocks do not contain the freshly-created commit block",
        import_event.seq.as_i64()
    );

    let consumer = FirehoseConsumer::connect_with_cursor(app_port(), 0).await;
    let commits = consumer
        .wait_for_commits(&did, 1, Duration::from_secs(20))
        .await;
    assert!(
        !commits.is_empty(),
        "expected at least one backfilled commit after import for {}",
        did
    );
    for commit in &commits {
        assert!(
            !commit.blocks.is_empty(),
            "backfilled import commit seq={} has empty CAR blocks",
            commit.seq
        );
        let mut reader = CarReader::new(Cursor::new(&commit.blocks))
            .await
            .unwrap_or_else(|e| panic!("CAR header parse failed for seq={}: {e}", commit.seq));
        assert_eq!(
            reader.header().roots()[0],
            commit.commit,
            "CAR root mismatch for import commit seq={}",
            commit.seq
        );
        let mut found_commit_block = false;
        while let Ok(Some((cid, _))) = reader.next_block().await {
            if cid == commit.commit {
                found_commit_block = true;
            }
        }
        assert!(
            found_commit_block,
            "backfilled import commit seq={} CAR missing the commit block",
            commit.seq
        );
    }
}
