use crate::state::AppState;
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
            for v in map.values() {
                extract_blob_cids_recursive(v, blobs);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                extract_blob_cids_recursive(v, blobs);
            }
        }
        _ => {}
    }
}

pub fn create_signed_commit(
    did: &str,
    data: Cid,
    rev: &str,
    prev: Option<Cid>,
    signing_key: &SigningKey,
) -> Result<(Vec<u8>, Bytes), String> {
    let did =
        jacquard::types::string::Did::new(did).map_err(|e| format!("Invalid DID: {:?}", e))?;
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
        collection: String,
        rkey: String,
        cid: Cid,
    },
    Update {
        collection: String,
        rkey: String,
        cid: Cid,
        prev: Option<Cid>,
    },
    Delete {
        collection: String,
        rkey: String,
        prev: Option<Cid>,
    },
}

pub struct CommitResult {
    pub commit_cid: Cid,
    pub rev: String,
}

pub struct CommitParams<'a> {
    pub did: &'a str,
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
    let key_row = sqlx::query!(
        "SELECT key_bytes, encryption_version FROM user_keys WHERE user_id = $1",
        user_id
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| format!("Failed to fetch signing key: {}", e))?;
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
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| format!("Failed to begin transaction: {}", e))?;
    let lock_result = sqlx::query!(
        "SELECT repo_root_cid FROM repos WHERE user_id = $1 FOR UPDATE NOWAIT",
        user_id
    )
    .fetch_optional(&mut *tx)
    .await;
    match lock_result {
        Err(e) => {
            if let Some(db_err) = e.as_database_error()
                && db_err.code().as_deref() == Some("55P03")
            {
                return Err(
                    "ConcurrentModification: Another request is modifying this repo".to_string(),
                );
            }
            return Err(format!("Failed to acquire repo lock: {}", e));
        }
        Ok(Some(row)) => {
            if let Some(expected_root) = &current_root_cid
                && row.repo_root_cid != expected_root.to_string()
            {
                return Err(
                    "ConcurrentModification: Repo has been modified since last read".to_string(),
                );
            }
        }
        Ok(None) => {
            return Err("Repo not found".to_string());
        }
    }
    let is_account_active = sqlx::query_scalar!(
        "SELECT deactivated_at IS NULL FROM users WHERE id = $1",
        user_id
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| format!("Failed to check account status: {}", e))?
    .flatten()
    .unwrap_or(false);
    sqlx::query!(
        "UPDATE repos SET repo_root_cid = $1, repo_rev = $2 WHERE user_id = $3",
        new_root_cid.to_string(),
        &rev_str,
        user_id
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("DB Error (repos): {}", e))?;
    let mut all_block_cids: Vec<Vec<u8>> = blocks_cids
        .iter()
        .filter_map(|s| Cid::from_str(s).ok())
        .map(|c| c.to_bytes())
        .collect();
    all_block_cids.push(new_root_cid.to_bytes());
    if !all_block_cids.is_empty() {
        sqlx::query!(
            r#"
            INSERT INTO user_blocks (user_id, block_cid)
            SELECT $1, block_cid FROM UNNEST($2::bytea[]) AS t(block_cid)
            ON CONFLICT (user_id, block_cid) DO NOTHING
            "#,
            user_id,
            &all_block_cids
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("DB Error (user_blocks): {}", e))?;
    }
    if !obsolete_cids.is_empty() {
        let obsolete_bytes: Vec<Vec<u8>> = obsolete_cids.iter().map(|c| c.to_bytes()).collect();
        sqlx::query!(
            r#"
            DELETE FROM user_blocks
            WHERE user_id = $1
            AND block_cid = ANY($2)
            "#,
            user_id,
            &obsolete_bytes as &[Vec<u8>]
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("DB Error (user_blocks delete obsolete): {}", e))?;
    }
    let mut upsert_collections: Vec<String> = Vec::new();
    let mut upsert_rkeys: Vec<String> = Vec::new();
    let mut upsert_cids: Vec<String> = Vec::new();
    let mut delete_collections: Vec<String> = Vec::new();
    let mut delete_rkeys: Vec<String> = Vec::new();
    for op in &ops {
        match op {
            RecordOp::Create {
                collection,
                rkey,
                cid,
            }
            | RecordOp::Update {
                collection,
                rkey,
                cid,
                ..
            } => {
                upsert_collections.push(collection.clone());
                upsert_rkeys.push(rkey.clone());
                upsert_cids.push(cid.to_string());
            }
            RecordOp::Delete {
                collection, rkey, ..
            } => {
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
    let ops_json = ops
        .iter()
        .map(|op| match op {
            RecordOp::Create {
                collection,
                rkey,
                cid,
            } => json!({
                "action": "create",
                "path": format!("{}/{}", collection, rkey),
                "cid": cid.to_string()
            }),
            RecordOp::Update {
                collection,
                rkey,
                cid,
                prev,
            } => {
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
            RecordOp::Delete {
                collection,
                rkey,
                prev,
            } => {
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
        .collect::<Vec<_>>();
    if is_account_active {
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
            blobs,
            blocks_cids,
            prev_data_cid_str,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| format!("DB Error (repo_seq): {}", e))?;
        sqlx::query(&format!("NOTIFY repo_updates, '{}'", seq_row.seq))
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("DB Error (notify): {}", e))?;
    }
    tx.commit()
        .await
        .map_err(|e| format!("Failed to commit transaction: {}", e))?;
    if is_account_active {
        let _ = sequence_sync_event(state, did, &new_root_cid.to_string(), Some(&rev_str)).await;
    }
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
    let root_cid_str: String = sqlx::query_scalar!(
        "SELECT repo_root_cid FROM repos WHERE user_id = $1",
        user_id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| format!("DB error: {}", e))?
    .ok_or_else(|| "Repo not found".to_string())?;
    let current_root_cid =
        Cid::from_str(&root_cid_str).map_err(|_| "Invalid repo root CID".to_string())?;
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
        collection: collection.to_string(),
        rkey: rkey.to_string(),
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
    rev: Option<&str>,
) -> Result<i64, String> {
    let seq_row = sqlx::query!(
        r#"
        INSERT INTO repo_seq (did, event_type, commit_cid, rev)
        VALUES ($1, 'sync', $2, $3)
        RETURNING seq
        "#,
        did,
        commit_cid,
        rev,
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

pub async fn sequence_genesis_commit(
    state: &AppState,
    did: &str,
    commit_cid: &Cid,
    mst_root_cid: &Cid,
    rev: &str,
) -> Result<i64, String> {
    let ops = serde_json::json!([]);
    let blobs: Vec<String> = vec![];
    let blocks_cids: Vec<String> = vec![mst_root_cid.to_string(), commit_cid.to_string()];
    let prev_cid: Option<&str> = None;
    let commit_cid_str = commit_cid.to_string();
    let seq_row = sqlx::query!(
        r#"
        INSERT INTO repo_seq (did, event_type, commit_cid, prev_cid, ops, blobs, blocks_cids, rev)
        VALUES ($1, 'commit', $2, $3::TEXT, $4, $5, $6, $7)
        RETURNING seq
        "#,
        did,
        commit_cid_str,
        prev_cid,
        ops,
        &blobs,
        &blocks_cids,
        rev
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| format!("DB Error (repo_seq genesis commit): {}", e))?;
    sqlx::query(&format!("NOTIFY repo_updates, '{}'", seq_row.seq))
        .execute(&state.db)
        .await
        .map_err(|e| format!("DB Error (notify): {}", e))?;
    Ok(seq_row.seq)
}
