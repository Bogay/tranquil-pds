use crate::state::AppState;
use cid::Cid;
use jacquard::types::{did::Did, integer::LimitedU32, string::Tid};
use jacquard_repo::commit::Commit;
use jacquard_repo::storage::BlockStore;
use k256::ecdsa::SigningKey;
use serde_json::json;
use uuid::Uuid;

pub enum RecordOp {
    Create { collection: String, rkey: String, cid: Cid },
    Update { collection: String, rkey: String, cid: Cid },
    Delete { collection: String, rkey: String },
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

    let did_obj = Did::new(did).map_err(|e| format!("Invalid DID: {}", e))?;
    let rev = Tid::now(LimitedU32::MIN);

    let unsigned_commit = Commit::new_unsigned(did_obj, new_mst_root, rev.clone(), current_root_cid);

    let signed_commit = unsigned_commit
        .sign(&signing_key)
        .map_err(|e| format!("Failed to sign commit: {:?}", e))?;

    let new_commit_bytes = signed_commit.to_cbor().map_err(|e| format!("Failed to serialize commit: {:?}", e))?;

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

    let rev_str = rev.to_string();

    let mut upsert_collections: Vec<String> = Vec::new();
    let mut upsert_rkeys: Vec<String> = Vec::new();
    let mut upsert_cids: Vec<String> = Vec::new();

    let mut delete_collections: Vec<String> = Vec::new();
    let mut delete_rkeys: Vec<String> = Vec::new();

    for op in &ops {
        match op {
            RecordOp::Create { collection, rkey, cid } | RecordOp::Update { collection, rkey, cid } => {
                upsert_collections.push(collection.clone());
                upsert_rkeys.push(rkey.clone());
                upsert_cids.push(cid.to_string());
            }
            RecordOp::Delete { collection, rkey } => {
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
            RecordOp::Update { collection, rkey, cid } => json!({
                "action": "update",
                "path": format!("{}/{}", collection, rkey),
                "cid": cid.to_string()
            }),
            RecordOp::Delete { collection, rkey } => json!({
                "action": "delete",
                "path": format!("{}/{}", collection, rkey),
                "cid": null
            }),
        }
    }).collect::<Vec<_>>();

    let event_type = "commit";
    let prev_cid_str = current_root_cid.map(|c| c.to_string());

    let seq_row = sqlx::query!(
        r#"
        INSERT INTO repo_seq (did, event_type, commit_cid, prev_cid, ops, blobs, blocks_cids)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING seq
        "#,
        did,
        event_type,
        new_root_cid.to_string(),
        prev_cid_str,
        json!(ops_json),
        &[] as &[String],
        blocks_cids,
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

    Ok(CommitResult {
        commit_cid: new_root_cid,
        rev: rev.to_string(),
    })
}
