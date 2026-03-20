use super::validation::validate_record_with_status;
use super::validation_mode::{ValidationMode, deserialize_validation_mode};
use axum::{Json, extract::State};
use cid::Cid;
use jacquard_repo::storage::BlockStore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::str::FromStr;
use tracing::error;
use tranquil_pds::api::error::{ApiError, DbResultExt};
use tranquil_pds::auth::{
    Active, Auth, AuthSource, RepoScopeAction, ScopeVerified, VerifyScope, require_not_migrated,
    require_verified_or_delegated,
};
use tranquil_pds::repo_ops::{
    FinalizeParams, RecordOp, begin_repo_write, extract_backlinks, extract_blob_cids,
    finalize_repo_write,
};
use tranquil_pds::state::AppState;
use tranquil_pds::types::{AtIdentifier, AtUri, Did, Nsid, Rkey};
use tranquil_pds::validation::ValidationStatus;
use uuid::Uuid;

pub struct RepoWriteAuth {
    pub did: Did,
    pub user_id: Uuid,
    pub auth_source: AuthSource,
    pub scope: Option<String>,
    pub controller_did: Option<Did>,
}

pub async fn prepare_repo_write<A: RepoScopeAction>(
    state: &AppState,
    scope_proof: &ScopeVerified<'_, A>,
    repo: &AtIdentifier,
) -> Result<RepoWriteAuth, ApiError> {
    let user = scope_proof.user();
    let principal_did = scope_proof.principal_did();
    if repo.as_str() != principal_did.as_str() {
        return Err(ApiError::InvalidRepo(
            "Repo does not match authenticated user".into(),
        ));
    }

    require_not_migrated(state, principal_did.as_did()).await?;
    let _account_verified = require_verified_or_delegated(state, user).await?;

    let user_id = state
        .repos.user
        .get_id_by_did(principal_did.as_did())
        .await
        .log_db_err("fetching user for repo write")?
        .ok_or(ApiError::InternalError(Some("User not found".into())))?;

    Ok(RepoWriteAuth {
        did: principal_did.into_did(),
        user_id,
        auth_source: user.auth_source.clone(),
        scope: user.scope.clone(),
        controller_did: scope_proof.controller_did().map(|c| c.into_did()),
    })
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct CreateRecordInput {
    pub repo: AtIdentifier,
    pub collection: Nsid,
    pub rkey: Option<Rkey>,
    #[serde(default, deserialize_with = "deserialize_validation_mode")]
    pub validate: ValidationMode,
    pub record: serde_json::Value,
    #[serde(rename = "swapCommit")]
    pub swap_commit: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommitInfo {
    pub cid: String,
    pub rev: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRecordOutput {
    pub uri: AtUri,
    pub cid: String,
    pub commit: CommitInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_status: Option<ValidationStatus>,
}

pub async fn create_record(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<CreateRecordInput>,
) -> Result<Json<CreateRecordOutput>, ApiError> {
    let scope_proof = auth.verify_repo_create(&input.collection)?;
    let repo_auth = prepare_repo_write(&state, &scope_proof, &input.repo).await?;
    let did = repo_auth.did;
    let user_id = repo_auth.user_id;
    let controller_did = repo_auth.controller_did;

    let (ctx, mut mst) = begin_repo_write(&state, user_id, input.swap_commit.as_deref()).await?;

    let validation_status = if input.validate.should_skip() {
        None
    } else {
        Some(
            validate_record_with_status(
                &input.record,
                &input.collection,
                input.rkey.as_ref(),
                input.validate.requires_lexicon(),
            )
            .await?,
        )
    };

    let rkey = input.rkey.unwrap_or_else(Rkey::generate);
    let mut ops: Vec<RecordOp> = Vec::new();
    let mut conflict_uris_to_cleanup: Vec<AtUri> = Vec::new();

    if !input.validate.should_skip() {
        let record_uri = AtUri::from_parts(&did, &input.collection, &rkey);
        let backlinks = extract_backlinks(&record_uri, &input.record);

        if !backlinks.is_empty() {
            let conflicts = state
                .repos.backlink
                .get_backlink_conflicts(user_id, &input.collection, &backlinks)
                .await
                .log_db_err("checking backlink conflicts")?;

            for conflict_uri in conflicts {
                let (Some(conflict_rkey_str), Some(conflict_col_str)) =
                    (conflict_uri.rkey(), conflict_uri.collection())
                else {
                    continue;
                };
                let conflict_rkey = Rkey::from(conflict_rkey_str.to_string());
                let conflict_collection = Nsid::from(conflict_col_str.to_string());
                let conflict_key = format!("{}/{}", conflict_collection, conflict_rkey);

                let prev_cid = match mst.get(&conflict_key).await {
                    Ok(Some(cid)) => cid,
                    _ => continue,
                };

                mst = match mst.delete(&conflict_key).await {
                    Ok(m) => m,
                    Err(e) => {
                        error!(
                            "Failed to delete conflict from MST {}: {:?}",
                            conflict_uri, e
                        );
                        continue;
                    }
                };

                ops.push(RecordOp::Delete {
                    collection: conflict_collection,
                    rkey: conflict_rkey,
                    prev: Some(prev_cid),
                });
                conflict_uris_to_cleanup.push(conflict_uri);
            }
        }
    }

    let record_ipld = tranquil_pds::util::json_to_ipld(&input.record);
    let record_bytes = serde_ipld_dagcbor::to_vec(&record_ipld)
        .map_err(|_| ApiError::InvalidRecord("Failed to serialize record".into()))?;
    let record_cid = ctx
        .tracking_store
        .put(&record_bytes)
        .await
        .map_err(|_| ApiError::InternalError(Some("Failed to save record block".into())))?;

    let key = format!("{}/{}", input.collection, rkey);
    mst = mst
        .add(&key, record_cid)
        .await
        .map_err(|_| ApiError::InternalError(Some("Failed to add to MST".into())))?;

    ops.push(RecordOp::Create {
        collection: input.collection.clone(),
        rkey: rkey.clone(),
        cid: record_cid,
    });

    let modified_keys: Vec<String> = ops
        .iter()
        .map(|op| match op {
            RecordOp::Create {
                collection, rkey, ..
            }
            | RecordOp::Update {
                collection, rkey, ..
            }
            | RecordOp::Delete {
                collection, rkey, ..
            } => format!("{}/{}", collection, rkey),
        })
        .collect();
    let blob_cids = extract_blob_cids(&input.record);

    let commit_result = finalize_repo_write(
        &state,
        ctx,
        mst,
        FinalizeParams {
            did: &did,
            user_id,
            controller_did: controller_did.as_ref(),
            delegation_detail: controller_did.as_ref().map(|_| {
                json!({
                    "action": "create",
                    "collection": input.collection,
                    "rkey": rkey
                })
            }),
            ops,
            modified_keys: &modified_keys,
            blob_cids: &blob_cids,
        },
    )
    .await?;

    {
        let backlink_repo = state.repos.backlink.clone();
        futures::future::join_all(conflict_uris_to_cleanup.iter().map(|uri| {
            let backlink_repo = backlink_repo.clone();
            async move {
                if let Err(e) = backlink_repo.remove_backlinks_by_uri(uri).await {
                    error!("Failed to remove backlinks for {}: {}", uri, e);
                }
            }
        }))
        .await;
    }

    let created_uri = AtUri::from_parts(&did, &input.collection, &rkey);
    let backlinks = extract_backlinks(&created_uri, &input.record);
    if !backlinks.is_empty()
        && let Err(e) = state.repos.backlink.add_backlinks(user_id, &backlinks).await
    {
        error!("Failed to add backlinks for {}: {}", created_uri, e);
    }

    Ok(Json(CreateRecordOutput {
        uri: created_uri,
        cid: record_cid.to_string(),
        commit: CommitInfo {
            cid: commit_result.commit_cid.to_string(),
            rev: commit_result.rev,
        },
        validation_status,
    }))
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct PutRecordInput {
    pub repo: AtIdentifier,
    pub collection: Nsid,
    pub rkey: Rkey,
    #[serde(default, deserialize_with = "deserialize_validation_mode")]
    pub validate: ValidationMode,
    pub record: serde_json::Value,
    #[serde(rename = "swapCommit")]
    pub swap_commit: Option<String>,
    #[serde(rename = "swapRecord")]
    pub swap_record: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PutRecordOutput {
    pub uri: AtUri,
    pub cid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<CommitInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_status: Option<ValidationStatus>,
}

pub async fn put_record(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<PutRecordInput>,
) -> Result<Json<PutRecordOutput>, ApiError> {
    let upsert_proof = auth.verify_repo_upsert(&input.collection)?;
    let repo_auth = prepare_repo_write(&state, &upsert_proof, &input.repo).await?;
    let did = repo_auth.did;
    let user_id = repo_auth.user_id;
    let controller_did = repo_auth.controller_did;

    let (ctx, mst) = begin_repo_write(&state, user_id, input.swap_commit.as_deref()).await?;

    let validation_status = if input.validate.should_skip() {
        None
    } else {
        Some(
            validate_record_with_status(
                &input.record,
                &input.collection,
                Some(&input.rkey),
                input.validate.requires_lexicon(),
            )
            .await?,
        )
    };

    let key = format!("{}/{}", input.collection, input.rkey);

    if let Some(swap_record_str) = &input.swap_record {
        let expected_cid = Cid::from_str(swap_record_str).ok();
        let actual_cid = mst.get(&key).await.ok().flatten();
        if expected_cid != actual_cid {
            return Err(ApiError::InvalidSwap(Some(
                "Record has been modified or does not exist".into(),
            )));
        }
    }

    let existing_cid = mst.get(&key).await.ok().flatten();
    let record_ipld = tranquil_pds::util::json_to_ipld(&input.record);
    let record_bytes = serde_ipld_dagcbor::to_vec(&record_ipld)
        .map_err(|_| ApiError::InvalidRecord("Failed to serialize record".into()))?;
    let record_cid = ctx
        .tracking_store
        .put(&record_bytes)
        .await
        .map_err(|_| ApiError::InternalError(Some("Failed to save record block".into())))?;

    if existing_cid == Some(record_cid) {
        return Ok(Json(PutRecordOutput {
            uri: AtUri::from_parts(&did, &input.collection, &input.rkey),
            cid: record_cid.to_string(),
            commit: None,
            validation_status,
        }));
    }

    let is_update = existing_cid.is_some();
    let new_mst = if is_update {
        mst.update(&key, record_cid)
            .await
            .map_err(|_| ApiError::InternalError(Some("Failed to update MST".into())))?
    } else {
        mst.add(&key, record_cid)
            .await
            .map_err(|_| ApiError::InternalError(Some("Failed to add to MST".into())))?
    };

    let op = if is_update {
        RecordOp::Update {
            collection: input.collection.clone(),
            rkey: input.rkey.clone(),
            cid: record_cid,
            prev: existing_cid,
        }
    } else {
        RecordOp::Create {
            collection: input.collection.clone(),
            rkey: input.rkey.clone(),
            cid: record_cid,
        }
    };

    let modified_keys = [key];
    let blob_cids = extract_blob_cids(&input.record);

    let commit_result = finalize_repo_write(
        &state,
        ctx,
        new_mst,
        FinalizeParams {
            did: &did,
            user_id,
            controller_did: controller_did.as_ref(),
            delegation_detail: controller_did.as_ref().map(|_| {
                json!({
                    "action": if is_update { "update" } else { "create" },
                    "collection": input.collection,
                    "rkey": input.rkey
                })
            }),
            ops: vec![op],
            modified_keys: &modified_keys,
            blob_cids: &blob_cids,
        },
    )
    .await?;

    Ok(Json(PutRecordOutput {
        uri: AtUri::from_parts(&did, &input.collection, &input.rkey),
        cid: record_cid.to_string(),
        commit: Some(CommitInfo {
            cid: commit_result.commit_cid.to_string(),
            rev: commit_result.rev,
        }),
        validation_status,
    }))
}
