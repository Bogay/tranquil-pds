use crate::state::AppState;
use crate::types::{Did, Handle, Nsid, Rkey};
use bytes::Bytes;
use cid::Cid;
use jacquard::types::{integer::LimitedU32, string::Tid};
use jacquard_repo::commit::Commit;
use jacquard_repo::storage::BlockStore;
use k256::ecdsa::SigningKey;
use serde_json::{Value, json};
use std::str::FromStr;
use uuid::Uuid;

pub fn extract_blob_cids(record: &Value) -> Vec<String> {
    let mut blobs = Vec::new();
    extract_blob_cids_recursive(record, &mut blobs);
    blobs
}

fn extract_blob_cids_recursive(value: &Value, blobs: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            if map.get("$type").and_then(|v| v.as_str()) == Some("blob")
                && let Some(ref_obj) = map.get("ref")
                && let Some(link) = ref_obj.get("$link").and_then(|v| v.as_str())
            {
                blobs.push(link.to_string());
            }
            map.values()
                .for_each(|v| extract_blob_cids_recursive(v, blobs));
        }
        Value::Array(arr) => {
            arr.iter()
                .for_each(|v| extract_blob_cids_recursive(v, blobs));
        }
        _ => {}
    }
}

use tranquil_db_traits::Backlink;
use crate::types::AtUri;

pub fn extract_backlinks(uri: &AtUri, record: &Value) -> Vec<Backlink> {
    let record_type = record
        .get("$type")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    match record_type {
        "app.bsky.graph.follow" | "app.bsky.graph.block" => record
            .get("subject")
            .and_then(|v| v.as_str())
            .filter(|s| s.starts_with("did:"))
            .map(|subject| vec![Backlink {
                uri: uri.clone(),
                path: "subject".to_string(),
                link_to: subject.to_string(),
            }])
            .unwrap_or_default(),
        "app.bsky.feed.like" | "app.bsky.feed.repost" => record
            .get("subject")
            .and_then(|v| v.get("uri"))
            .and_then(|v| v.as_str())
            .filter(|s| s.starts_with("at://"))
            .map(|subject_uri| vec![Backlink {
                uri: uri.clone(),
                path: "subject.uri".to_string(),
                link_to: subject_uri.to_string(),
            }])
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

pub fn create_signed_commit(
    did: &Did,
    data: Cid,
    rev: &str,
    prev: Option<Cid>,
    signing_key: &SigningKey,
) -> Result<(Vec<u8>, Bytes), String> {
    let did = jacquard::types::string::Did::new(did.as_str())
        .map_err(|e| format!("Invalid DID: {:?}", e))?;
    let rev =
        jacquard::types::string::Tid::from_str(rev).map_err(|e| format!("Invalid TID: {:?}", e))?;
    let unsigned = Commit::new_unsigned(did, data, rev, prev);
    let signed = unsigned
        .sign(signing_key)
        .map_err(|e| format!("Failed to sign commit: {:?}", e))?;
    let sig_bytes = signed.sig().clone();
    let signed_bytes = signed
        .to_cbor()
        .map_err(|e| format!("Failed to serialize signed commit: {:?}", e))?;
    Ok((signed_bytes, sig_bytes))
}

pub enum RecordOp {
    Create {
        collection: Nsid,
        rkey: Rkey,
        cid: Cid,
    },
    Update {
        collection: Nsid,
        rkey: Rkey,
        cid: Cid,
        prev: Option<Cid>,
    },
    Delete {
        collection: Nsid,
        rkey: Rkey,
        prev: Option<Cid>,
    },
}

pub struct CommitResult {
    pub commit_cid: Cid,
    pub rev: String,
}

pub struct CommitParams<'a> {
    pub did: &'a Did,
    pub user_id: Uuid,
    pub current_root_cid: Option<Cid>,
    pub prev_data_cid: Option<Cid>,
    pub new_mst_root: Cid,
    pub ops: Vec<RecordOp>,
    pub blocks_cids: &'a [String],
    pub blobs: &'a [String],
    pub obsolete_cids: Vec<Cid>,
}

pub async fn commit_and_log(
    state: &AppState,
    params: CommitParams<'_>,
) -> Result<CommitResult, String> {
    use tranquil_db_traits::{ApplyCommitError, ApplyCommitInput, CommitEventData, RecordDelete, RecordUpsert};

    let CommitParams {
        did,
        user_id,
        current_root_cid,
        prev_data_cid,
        new_mst_root,
        ops,
        blocks_cids,
        blobs,
        obsolete_cids,
    } = params;
    let key_row = state
        .user_repo
        .get_user_key_by_id(user_id)
        .await
        .map_err(|e| format!("Failed to fetch signing key: {}", e))?
        .ok_or_else(|| "Signing key not found".to_string())?;
    let key_bytes = crate::config::decrypt_key(&key_row.key_bytes, key_row.encryption_version)
        .map_err(|e| format!("Failed to decrypt signing key: {}", e))?;
    let signing_key =
        SigningKey::from_slice(&key_bytes).map_err(|e| format!("Invalid signing key: {}", e))?;
    let rev = Tid::now(LimitedU32::MIN);
    let rev_str = rev.to_string();
    let (new_commit_bytes, _sig) =
        create_signed_commit(did, new_mst_root, &rev_str, current_root_cid, &signing_key)?;
    let new_root_cid = state
        .block_store
        .put(&new_commit_bytes)
        .await
        .map_err(|e| format!("Failed to save commit block: {:?}", e))?;

    let mut all_block_cids: Vec<Vec<u8>> = blocks_cids
        .iter()
        .filter_map(|s| Cid::from_str(s).ok())
        .map(|c| c.to_bytes())
        .collect();
    all_block_cids.push(new_root_cid.to_bytes());

    let obsolete_bytes: Vec<Vec<u8>> = obsolete_cids.iter().map(|c| c.to_bytes()).collect();

    let (record_upserts, record_deletes): (Vec<RecordUpsert>, Vec<RecordDelete>) = ops.iter().fold(
        (Vec::new(), Vec::new()),
        |(mut upserts, mut deletes), op| {
            match op {
                RecordOp::Create { collection, rkey, cid }
                | RecordOp::Update { collection, rkey, cid, .. } => {
                    upserts.push(RecordUpsert {
                        collection: collection.clone(),
                        rkey: rkey.clone(),
                        cid: crate::types::CidLink::new_unchecked(&cid.to_string()),
                    });
                }
                RecordOp::Delete { collection, rkey, .. } => {
                    deletes.push(RecordDelete {
                        collection: collection.clone(),
                        rkey: rkey.clone(),
                    });
                }
            }
            (upserts, deletes)
        },
    );

    let ops_json: Vec<serde_json::Value> = ops
        .iter()
        .map(|op| match op {
            RecordOp::Create { collection, rkey, cid } => json!({
                "action": "create",
                "path": format!("{}/{}", collection, rkey),
                "cid": cid.to_string()
            }),
            RecordOp::Update { collection, rkey, cid, prev } => {
                let mut obj = json!({
                    "action": "update",
                    "path": format!("{}/{}", collection, rkey),
                    "cid": cid.to_string()
                });
                if let Some(prev_cid) = prev {
                    obj["prev"] = json!(prev_cid.to_string());
                }
                obj
            }
            RecordOp::Delete { collection, rkey, prev } => {
                let mut obj = json!({
                    "action": "delete",
                    "path": format!("{}/{}", collection, rkey),
                    "cid": null
                });
                if let Some(prev_cid) = prev {
                    obj["prev"] = json!(prev_cid.to_string());
                }
                obj
            }
        })
        .collect();

    let commit_event = CommitEventData {
        did: did.clone(),
        event_type: "commit".to_string(),
        commit_cid: Some(crate::types::CidLink::new_unchecked(&new_root_cid.to_string())),
        prev_cid: current_root_cid.map(|c| crate::types::CidLink::new_unchecked(&c.to_string())),
        ops: Some(json!(ops_json)),
        blobs: Some(blobs.to_vec()),
        blocks_cids: Some(blocks_cids.to_vec()),
        prev_data_cid: prev_data_cid.map(|c| crate::types::CidLink::new_unchecked(&c.to_string())),
        rev: Some(rev_str.clone()),
    };

    let input = ApplyCommitInput {
        user_id,
        did: did.clone(),
        expected_root_cid: current_root_cid.map(|c| crate::types::CidLink::new_unchecked(&c.to_string())),
        new_root_cid: crate::types::CidLink::new_unchecked(&new_root_cid.to_string()),
        new_rev: rev_str.clone(),
        new_block_cids: all_block_cids,
        obsolete_block_cids: obsolete_bytes,
        record_upserts,
        record_deletes,
        commit_event,
    };

    let result = state
        .repo_repo
        .apply_commit(input)
        .await
        .map_err(|e| match e {
            ApplyCommitError::RepoNotFound => "Repo not found".to_string(),
            ApplyCommitError::ConcurrentModification => {
                "ConcurrentModification: Repo has been modified since last read".to_string()
            }
            ApplyCommitError::Database(msg) => format!("DB Error: {}", msg),
        })?;

    if result.is_account_active {
        let _ = sequence_sync_event(state, did, &new_root_cid.to_string(), Some(&rev_str)).await;
    }

    Ok(CommitResult {
        commit_cid: new_root_cid,
        rev: rev_str,
    })
}
pub async fn create_record_internal(
    state: &AppState,
    did: &Did,
    collection: &Nsid,
    rkey: &Rkey,
    record: &serde_json::Value,
) -> Result<(String, Cid), String> {
    use crate::repo::tracking::TrackingBlockStore;
    use jacquard_repo::mst::Mst;
    use std::sync::Arc;
    let user_id: Uuid = state
        .user_repo
        .get_id_by_did(did)
        .await
        .map_err(|e| format!("DB error: {}", e))?
        .ok_or_else(|| "User not found".to_string())?;
    let root_cid_link = state
        .repo_repo
        .get_repo_root_cid_by_user_id(user_id)
        .await
        .map_err(|e| format!("DB error: {}", e))?
        .ok_or_else(|| "Repo not found".to_string())?;
    let current_root_cid =
        Cid::from_str(root_cid_link.as_str()).map_err(|_| "Invalid repo root CID".to_string())?;
    let tracking_store = TrackingBlockStore::new(state.block_store.clone());
    let commit_bytes = tracking_store
        .get(&current_root_cid)
        .await
        .map_err(|e| format!("Failed to fetch commit: {:?}", e))?
        .ok_or_else(|| "Commit block not found".to_string())?;
    let commit = jacquard_repo::commit::Commit::from_cbor(&commit_bytes)
        .map_err(|e| format!("Failed to parse commit: {:?}", e))?;
    let mst = Mst::load(Arc::new(tracking_store.clone()), commit.data, None);
    let record_ipld = crate::util::json_to_ipld(record);
    let mut record_bytes = Vec::new();
    serde_ipld_dagcbor::to_writer(&mut record_bytes, &record_ipld)
        .map_err(|e| format!("Failed to serialize record: {:?}", e))?;
    let record_cid = tracking_store
        .put(&record_bytes)
        .await
        .map_err(|e| format!("Failed to save record block: {:?}", e))?;
    let key = format!("{}/{}", collection, rkey);
    let new_mst = mst
        .add(&key, record_cid)
        .await
        .map_err(|e| format!("Failed to add to MST: {:?}", e))?;
    let new_mst_root = new_mst
        .persist()
        .await
        .map_err(|e| format!("Failed to persist MST: {:?}", e))?;
    let op = RecordOp::Create {
        collection: collection.clone(),
        rkey: rkey.clone(),
        cid: record_cid,
    };
    let mut new_mst_blocks = std::collections::BTreeMap::new();
    let mut old_mst_blocks = std::collections::BTreeMap::new();
    new_mst
        .blocks_for_path(&key, &mut new_mst_blocks)
        .await
        .map_err(|e| format!("Failed to get new MST blocks for path: {:?}", e))?;
    mst.blocks_for_path(&key, &mut old_mst_blocks)
        .await
        .map_err(|e| format!("Failed to get old MST blocks for path: {:?}", e))?;
    let obsolete_cids: Vec<Cid> = std::iter::once(current_root_cid)
        .chain(
            old_mst_blocks
                .keys()
                .filter(|cid| !new_mst_blocks.contains_key(*cid))
                .copied(),
        )
        .collect();
    let mut relevant_blocks = new_mst_blocks;
    relevant_blocks.extend(old_mst_blocks);
    relevant_blocks.insert(record_cid, bytes::Bytes::from(record_bytes));
    let written_cids: Vec<Cid> = tracking_store
        .get_all_relevant_cids()
        .into_iter()
        .chain(relevant_blocks.keys().copied())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    let written_cids_str: Vec<String> = written_cids.iter().map(|c| c.to_string()).collect();
    let blob_cids = extract_blob_cids(record);
    let result = commit_and_log(
        state,
        CommitParams {
            did,
            user_id,
            current_root_cid: Some(current_root_cid),
            prev_data_cid: Some(commit.data),
            new_mst_root,
            ops: vec![op],
            blocks_cids: &written_cids_str,
            blobs: &blob_cids,
            obsolete_cids,
        },
    )
    .await?;
    let uri = format!("at://{}/{}/{}", did, collection, rkey);
    Ok((uri, result.commit_cid))
}

pub async fn sequence_identity_event(
    state: &AppState,
    did: &Did,
    handle: Option<&Handle>,
) -> Result<i64, String> {
    state
        .repo_repo
        .insert_identity_event(did, handle)
        .await
        .map_err(|e| format!("DB Error (identity event): {}", e))
}
pub async fn sequence_account_event(
    state: &AppState,
    did: &Did,
    active: bool,
    status: Option<&str>,
) -> Result<i64, String> {
    state
        .repo_repo
        .insert_account_event(did, active, status)
        .await
        .map_err(|e| format!("DB Error (account event): {}", e))
}
pub async fn sequence_sync_event(
    state: &AppState,
    did: &Did,
    commit_cid: &str,
    rev: Option<&str>,
) -> Result<i64, String> {
    let cid_link = crate::types::CidLink::new_unchecked(commit_cid);
    state
        .repo_repo
        .insert_sync_event(did, &cid_link, rev)
        .await
        .map_err(|e| format!("DB Error (sync event): {}", e))
}

pub async fn sequence_genesis_commit(
    state: &AppState,
    did: &Did,
    commit_cid: &Cid,
    mst_root_cid: &Cid,
    rev: &str,
) -> Result<i64, String> {
    let commit_cid_link = crate::types::CidLink::new_unchecked(&commit_cid.to_string());
    let mst_root_cid_link = crate::types::CidLink::new_unchecked(&mst_root_cid.to_string());
    state
        .repo_repo
        .insert_genesis_commit_event(did, &commit_cid_link, &mst_root_cid_link, rev)
        .await
        .map_err(|e| format!("DB Error (genesis commit event): {}", e))
}
