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
    blocks_cids: &Vec<String>,
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

    sqlx::query!("UPDATE repos SET repo_root_cid = $1 WHERE user_id = $2", new_root_cid.to_string(), user_id)
        .execute(&state.db)
        .await
        .map_err(|e| format!("DB Error (repos): {}", e))?;

    for op in &ops {
        match op {
            RecordOp::Create { collection, rkey, cid } | RecordOp::Update { collection, rkey, cid } => {
                sqlx::query!(
                    "INSERT INTO records (repo_id, collection, rkey, record_cid) VALUES ($1, $2, $3, $4)
                     ON CONFLICT (repo_id, collection, rkey) DO UPDATE SET record_cid = $4, created_at = NOW()",
                    user_id,
                    collection,
                    rkey,
                    cid.to_string()
                )
                .execute(&state.db)
                .await
                .map_err(|e| format!("DB Error (records): {}", e))?;
            }
            RecordOp::Delete { collection, rkey } => {
                sqlx::query!(
                    "DELETE FROM records WHERE repo_id = $1 AND collection = $2 AND rkey = $3",
                    user_id,
                    collection,
                    rkey
                )
                .execute(&state.db)
                .await
                .map_err(|e| format!("DB Error (records): {}", e))?;
            }
        }
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
    .fetch_one(&state.db)
    .await
    .map_err(|e| format!("DB Error (repo_seq): {}", e))?;

    sqlx::query(
        &format!("NOTIFY repo_updates, '{}'", seq_row.seq)
    )
    .execute(&state.db)
    .await
    .map_err(|e| format!("DB Error (notify): {}", e))?;

    Ok(CommitResult {
        commit_cid: new_root_cid,
        rev: rev.to_string(),
    })
}
