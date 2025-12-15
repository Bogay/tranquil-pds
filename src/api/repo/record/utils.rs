use crate::state::AppState;
use bytes::Bytes;
use cid::Cid;
use jacquard::types::{integer::LimitedU32, string::Tid};
use jacquard_repo::storage::BlockStore;
use k256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;
/*
 * Why am I making custom commit objects instead of jacquard's Commit::sign(), you ask?
 *
 * At time of writing, jacquard has a bug in how it creates unsigned bytes for signing.
 * Jacquard sets sig to empty bytes and serializes (6-field CBOR map)
 * Indigo/ATProto creates a struct *without* the sig field (5-field CBOR map)
 *
 * These produce different CBOR bytes, so signatures created with jacquard
 * don't verify with the relay's algorithm. The relay silently rejects commits
 * with invalid signatures.
 *
 * If you have it downloaded, see: reference-relay-indigo/atproto/repo/commit.go UnsignedBytes()
 */
#[derive(Serialize)]
struct UnsignedCommit<'a> {
    data: Cid,
    did: &'a str,
    prev: Option<Cid>,
    rev: &'a str,
    version: i64,
}

fn create_signed_commit(
    did: &str,
    data: Cid,
    rev: &str,
    prev: Option<Cid>,
    signing_key: &SigningKey,
) -> Result<(Vec<u8>, Bytes), String> {
    let unsigned = UnsignedCommit {
        data,
        did,
        prev,
        rev,
        version: 3,
    };
    let unsigned_bytes = serde_ipld_dagcbor::to_vec(&unsigned)
        .map_err(|e| format!("Failed to serialize unsigned commit: {:?}", e))?;
    let sig: Signature = signing_key.sign(&unsigned_bytes);
    let sig_bytes = Bytes::copy_from_slice(&sig.to_bytes());
    #[derive(Serialize)]
    struct SignedCommit<'a> {
        data: Cid,
        did: &'a str,
        prev: Option<Cid>,
        rev: &'a str,
        #[serde(with = "serde_bytes")]
        sig: &'a [u8],
        version: i64,
    }
    let signed = SignedCommit {
        data,
        did,
        prev,
        rev,
        sig: &sig_bytes,
        version: 3,
    };
    let signed_bytes = serde_ipld_dagcbor::to_vec(&signed)
        .map_err(|e| format!("Failed to serialize signed commit: {:?}", e))?;
    Ok((signed_bytes, sig_bytes))
}

pub enum RecordOp {
    Create { collection: String, rkey: String, cid: Cid },
    Update { collection: String, rkey: String, cid: Cid, prev: Option<Cid> },
    Delete { collection: String, rkey: String, prev: Option<Cid> },
}

pub struct CommitResult {
    pub commit_cid: Cid,
    pub rev: String,
}

pub async fn commit_and_log(
    state: &AppState,
    did: &str,
    user_id: Uuid,
    current_root_cid: Option<Cid>,
    prev_data_cid: Option<Cid>,
    new_mst_root: Cid,
    ops: Vec<RecordOp>,
    blocks_cids: &[String],
) -> Result<CommitResult, String> {
    let key_row = sqlx::query!(
        "SELECT key_bytes, encryption_version FROM user_keys WHERE user_id = $1",
        user_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| format!("Failed to fetch signing key: {}", e))?;
    let key_bytes = crate::config::decrypt_key(&key_row.key_bytes, key_row.encryption_version)
        .map_err(|e| format!("Failed to decrypt signing key: {}", e))?;
    let signing_key = SigningKey::from_slice(&key_bytes)
        .map_err(|e| format!("Invalid signing key: {}", e))?;
    let rev = Tid::now(LimitedU32::MIN);
    let rev_str = rev.to_string();
    let (new_commit_bytes, _sig) = create_signed_commit(
        did,
        new_mst_root,
        &rev_str,
        current_root_cid,
        &signing_key,
    )?;
    let new_root_cid = state.block_store.put(&new_commit_bytes).await
        .map_err(|e| format!("Failed to save commit block: {:?}", e))?;
    let mut tx = state.db.begin().await
        .map_err(|e| format!("Failed to begin transaction: {}", e))?;
    let lock_result = sqlx::query!(
        "SELECT repo_root_cid FROM repos WHERE user_id = $1 FOR UPDATE NOWAIT",
        user_id
    )
    .fetch_optional(&mut *tx)
    .await;
    match lock_result {
        Err(e) => {
            if let Some(db_err) = e.as_database_error() {
                if db_err.code().as_deref() == Some("55P03") {
                    return Err("ConcurrentModification: Another request is modifying this repo".to_string());
                }
            }
            return Err(format!("Failed to acquire repo lock: {}", e));
        }
        Ok(Some(row)) => {
            if let Some(expected_root) = &current_root_cid {
                if row.repo_root_cid != expected_root.to_string() {
                    return Err("ConcurrentModification: Repo has been modified since last read".to_string());
                }
            }
        }
        Ok(None) => {
            return Err("Repo not found".to_string());
        }
    }
    sqlx::query!("UPDATE repos SET repo_root_cid = $1 WHERE user_id = $2", new_root_cid.to_string(), user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("DB Error (repos): {}", e))?;
    let mut upsert_collections: Vec<String> = Vec::new();
    let mut upsert_rkeys: Vec<String> = Vec::new();
    let mut upsert_cids: Vec<String> = Vec::new();
    let mut delete_collections: Vec<String> = Vec::new();
    let mut delete_rkeys: Vec<String> = Vec::new();
    for op in &ops {
        match op {
            RecordOp::Create { collection, rkey, cid } | RecordOp::Update { collection, rkey, cid, .. } => {
                upsert_collections.push(collection.clone());
                upsert_rkeys.push(rkey.clone());
                upsert_cids.push(cid.to_string());
            }
            RecordOp::Delete { collection, rkey, .. } => {
                delete_collections.push(collection.clone());
                delete_rkeys.push(rkey.clone());
            }
        }
    }
    if !upsert_collections.is_empty() {
        sqlx::query!(
            r#"
            INSERT INTO records (repo_id, collection, rkey, record_cid, repo_rev)
            SELECT $1, collection, rkey, record_cid, $5
            FROM UNNEST($2::text[], $3::text[], $4::text[]) AS t(collection, rkey, record_cid)
            ON CONFLICT (repo_id, collection, rkey) DO UPDATE
            SET record_cid = EXCLUDED.record_cid, repo_rev = EXCLUDED.repo_rev, created_at = NOW()
            "#,
            user_id,
            &upsert_collections,
            &upsert_rkeys,
            &upsert_cids,
            rev_str
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("DB Error (records batch upsert): {}", e))?;
    }
    if !delete_collections.is_empty() {
        sqlx::query!(
            r#"
            DELETE FROM records
            WHERE repo_id = $1
            AND (collection, rkey) IN (SELECT * FROM UNNEST($2::text[], $3::text[]))
            "#,
            user_id,
            &delete_collections,
            &delete_rkeys
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("DB Error (records batch delete): {}", e))?;
    }
    let ops_json = ops.iter().map(|op| {
        match op {
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
            },
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
            },
        }
    }).collect::<Vec<_>>();
    let event_type = "commit";
    let prev_cid_str = current_root_cid.map(|c| c.to_string());
    let prev_data_cid_str = prev_data_cid.map(|c| c.to_string());
    let seq_row = sqlx::query!(
        r#"
        INSERT INTO repo_seq (did, event_type, commit_cid, prev_cid, ops, blobs, blocks_cids, prev_data_cid)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING seq
        "#,
        did,
        event_type,
        new_root_cid.to_string(),
        prev_cid_str,
        json!(ops_json),
        &[] as &[String],
        blocks_cids,
        prev_data_cid_str,
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| format!("DB Error (repo_seq): {}", e))?;
    sqlx::query(
        &format!("NOTIFY repo_updates, '{}'", seq_row.seq)
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("DB Error (notify): {}", e))?;
    tx.commit().await
        .map_err(|e| format!("Failed to commit transaction: {}", e))?;
    let _ = sequence_sync_event(state, did, &new_root_cid.to_string()).await;
    Ok(CommitResult {
        commit_cid: new_root_cid,
        rev: rev_str,
    })
}
pub async fn create_record_internal(
    state: &AppState,
    did: &str,
    collection: &str,
    rkey: &str,
    record: &serde_json::Value,
) -> Result<(String, Cid), String> {
    use crate::repo::tracking::TrackingBlockStore;
    use jacquard_repo::mst::Mst;
    use std::sync::Arc;
    let user_id: Uuid = sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| format!("DB error: {}", e))?
        .ok_or_else(|| "User not found".to_string())?;
    let root_cid_str: String =
        sqlx::query_scalar!("SELECT repo_root_cid FROM repos WHERE user_id = $1", user_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| format!("DB error: {}", e))?
            .ok_or_else(|| "Repo not found".to_string())?;
    let current_root_cid = Cid::from_str(&root_cid_str)
        .map_err(|_| "Invalid repo root CID".to_string())?;
    let tracking_store = TrackingBlockStore::new(state.block_store.clone());
    let commit_bytes = tracking_store.get(&current_root_cid).await
        .map_err(|e| format!("Failed to fetch commit: {:?}", e))?
        .ok_or_else(|| "Commit block not found".to_string())?;
    let commit = jacquard_repo::commit::Commit::from_cbor(&commit_bytes)
        .map_err(|e| format!("Failed to parse commit: {:?}", e))?;
    let mst = Mst::load(Arc::new(tracking_store.clone()), commit.data, None);
    let mut record_bytes = Vec::new();
    serde_ipld_dagcbor::to_writer(&mut record_bytes, record)
        .map_err(|e| format!("Failed to serialize record: {:?}", e))?;
    let record_cid = tracking_store.put(&record_bytes).await
        .map_err(|e| format!("Failed to save record block: {:?}", e))?;
    let key = format!("{}/{}", collection, rkey);
    let new_mst = mst.add(&key, record_cid).await
        .map_err(|e| format!("Failed to add to MST: {:?}", e))?;
    let new_mst_root = new_mst.persist().await
        .map_err(|e| format!("Failed to persist MST: {:?}", e))?;
    let op = RecordOp::Create {
        collection: collection.to_string(),
        rkey: rkey.to_string(),
        cid: record_cid,
    };
    let mut relevant_blocks = std::collections::BTreeMap::new();
    new_mst.blocks_for_path(&key, &mut relevant_blocks).await
        .map_err(|e| format!("Failed to get new MST blocks for path: {:?}", e))?;
    mst.blocks_for_path(&key, &mut relevant_blocks).await
        .map_err(|e| format!("Failed to get old MST blocks for path: {:?}", e))?;
    relevant_blocks.insert(record_cid, bytes::Bytes::from(record_bytes));
    let mut written_cids = tracking_store.get_all_relevant_cids();
    for cid in relevant_blocks.keys() {
        if !written_cids.contains(cid) {
            written_cids.push(*cid);
        }
    }
    let written_cids_str: Vec<String> = written_cids.iter().map(|c| c.to_string()).collect();
    let result = commit_and_log(
        state,
        did,
        user_id,
        Some(current_root_cid),
        Some(commit.data),
        new_mst_root,
        vec![op],
        &written_cids_str,
    ).await?;
    let uri = format!("at://{}/{}/{}", did, collection, rkey);
    Ok((uri, result.commit_cid))
}
use std::str::FromStr;
pub async fn sequence_identity_event(
    state: &AppState,
    did: &str,
    handle: Option<&str>,
) -> Result<i64, String> {
    let seq_row = sqlx::query!(
        r#"
        INSERT INTO repo_seq (did, event_type, handle)
        VALUES ($1, 'identity', $2)
        RETURNING seq
        "#,
        did,
        handle,
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| format!("DB Error (repo_seq identity): {}", e))?;
    sqlx::query(&format!("NOTIFY repo_updates, '{}'", seq_row.seq))
        .execute(&state.db)
        .await
        .map_err(|e| format!("DB Error (notify): {}", e))?;
    Ok(seq_row.seq)
}
pub async fn sequence_account_event(
    state: &AppState,
    did: &str,
    active: bool,
    status: Option<&str>,
) -> Result<i64, String> {
    let seq_row = sqlx::query!(
        r#"
        INSERT INTO repo_seq (did, event_type, active, status)
        VALUES ($1, 'account', $2, $3)
        RETURNING seq
        "#,
        did,
        active,
        status,
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| format!("DB Error (repo_seq account): {}", e))?;
    sqlx::query(&format!("NOTIFY repo_updates, '{}'", seq_row.seq))
        .execute(&state.db)
        .await
        .map_err(|e| format!("DB Error (notify): {}", e))?;
    Ok(seq_row.seq)
}
pub async fn sequence_sync_event(
    state: &AppState,
    did: &str,
    commit_cid: &str,
) -> Result<i64, String> {
    let seq_row = sqlx::query!(
        r#"
        INSERT INTO repo_seq (did, event_type, commit_cid)
        VALUES ($1, 'sync', $2)
        RETURNING seq
        "#,
        did,
        commit_cid,
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| format!("DB Error (repo_seq sync): {}", e))?;
    sqlx::query(&format!("NOTIFY repo_updates, '{}'", seq_row.seq))
        .execute(&state.db)
        .await
        .map_err(|e| format!("DB Error (notify): {}", e))?;
    Ok(seq_row.seq)
}
