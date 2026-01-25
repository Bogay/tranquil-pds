use super::validation::validate_record_with_status;
use super::validation_mode::{ValidationMode, deserialize_validation_mode};
use crate::api::error::ApiError;
use crate::api::repo::record::utils::{
    CommitParams, RecordOp, commit_and_log, extract_backlinks, extract_blob_cids,
};
use crate::auth::{
    Active, Auth, RepoScopeAction, ScopeVerified, VerifyScope, require_not_migrated,
    require_verified_or_delegated,
};
use crate::cid_types::CommitCid;
use crate::delegation::DelegationActionType;
use crate::repo::tracking::TrackingBlockStore;
use crate::state::AppState;
use crate::types::{AtIdentifier, AtUri, Did, Nsid, Rkey};
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use cid::Cid;
use jacquard_repo::{commit::Commit, mst::Mst, storage::BlockStore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::str::FromStr;
use std::sync::Arc;
use tracing::error;
use uuid::Uuid;

pub struct RepoWriteAuth {
    pub did: Did,
    pub user_id: Uuid,
    pub current_root_cid: CommitCid,
    pub is_oauth: bool,
    pub scope: Option<String>,
    pub controller_did: Option<Did>,
}

pub async fn prepare_repo_write<A: RepoScopeAction>(
    state: &AppState,
    scope_proof: &ScopeVerified<'_, A>,
    repo: &AtIdentifier,
) -> Result<RepoWriteAuth, Response> {
    let user = scope_proof.user();
    let principal_did = scope_proof.principal_did();
    if repo.as_str() != principal_did.as_str() {
        return Err(
            ApiError::InvalidRepo("Repo does not match authenticated user".into()).into_response(),
        );
    }

    require_not_migrated(state, principal_did.as_did()).await?;
    let _account_verified = require_verified_or_delegated(state, user).await?;

    let user_id = state
        .user_repo
        .get_id_by_did(principal_did.as_did())
        .await
        .map_err(|e| {
            error!("DB error fetching user: {}", e);
            ApiError::InternalError(None).into_response()
        })?
        .ok_or_else(|| ApiError::InternalError(Some("User not found".into())).into_response())?;
    let root_cid_str = state
        .repo_repo
        .get_repo_root_cid_by_user_id(user_id)
        .await
        .map_err(|e| {
            error!("DB error fetching repo root: {}", e);
            ApiError::InternalError(None).into_response()
        })?
        .ok_or_else(|| {
            ApiError::InternalError(Some("Repo root not found".into())).into_response()
        })?;
    let current_root_cid = CommitCid::from_str(&root_cid_str).map_err(|_| {
        ApiError::InternalError(Some("Invalid repo root CID".into())).into_response()
    })?;
    Ok(RepoWriteAuth {
        did: principal_did.into_did(),
        user_id,
        current_root_cid,
        is_oauth: user.is_oauth(),
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
    pub validation_status: Option<String>,
}
pub async fn create_record(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<CreateRecordInput>,
) -> Result<Response, crate::api::error::ApiError> {
    let scope_proof = match auth.verify_repo_create(&input.collection) {
        Ok(proof) => proof,
        Err(e) => return Ok(e.into_response()),
    };

    let repo_auth = match prepare_repo_write(&state, &scope_proof, &input.repo).await {
        Ok(res) => res,
        Err(err_res) => return Ok(err_res),
    };

    let did = repo_auth.did;
    let user_id = repo_auth.user_id;
    let current_root_cid = repo_auth.current_root_cid;
    let controller_did = repo_auth.controller_did;

    if let Some(swap_commit) = &input.swap_commit
        && CommitCid::from_str(swap_commit).ok().as_ref() != Some(&current_root_cid)
    {
        return Ok(ApiError::InvalidSwap(Some("Repo has been modified".into())).into_response());
    }

    let validation_status = if input.validate.should_skip() {
        None
    } else {
        match validate_record_with_status(
            &input.record,
            &input.collection,
            input.rkey.as_ref(),
            input.validate.requires_lexicon(),
        ) {
            Ok(status) => Some(status),
            Err(err_response) => return Ok(*err_response),
        }
    };
    let rkey = input.rkey.unwrap_or_else(Rkey::generate);

    let tracking_store = TrackingBlockStore::new(state.block_store.clone());
    let commit_bytes = match tracking_store.get(current_root_cid.as_cid()).await {
        Ok(Some(b)) => b,
        _ => {
            return Ok(
                ApiError::InternalError(Some("Commit block not found".into())).into_response(),
            );
        }
    };
    let commit = match Commit::from_cbor(&commit_bytes) {
        Ok(c) => c,
        _ => {
            return Ok(
                ApiError::InternalError(Some("Failed to parse commit".into())).into_response(),
            );
        }
    };
    let mut mst = Mst::load(Arc::new(tracking_store.clone()), commit.data, None);
    let initial_mst_root = commit.data;

    let mut ops: Vec<RecordOp> = Vec::new();
    let mut conflict_uris_to_cleanup: Vec<AtUri> = Vec::new();
    let mut all_old_mst_blocks = std::collections::BTreeMap::new();

    if !input.validate.should_skip() {
        let record_uri = AtUri::from_parts(&did, &input.collection, &rkey);
        let backlinks = extract_backlinks(&record_uri, &input.record);

        if !backlinks.is_empty() {
            let conflicts = match state
                .backlink_repo
                .get_backlink_conflicts(user_id, &input.collection, &backlinks)
                .await
            {
                Ok(c) => c,
                Err(e) => {
                    error!("Failed to check backlink conflicts: {}", e);
                    return Ok(ApiError::InternalError(None).into_response());
                }
            };

            for conflict_uri in conflicts {
                let conflict_rkey = match conflict_uri.rkey() {
                    Some(r) => Rkey::from(r.to_string()),
                    None => continue,
                };
                let conflict_collection = match conflict_uri.collection() {
                    Some(c) => Nsid::from(c.to_string()),
                    None => continue,
                };
                let conflict_key = format!("{}/{}", conflict_collection, conflict_rkey);

                let prev_cid = match mst.get(&conflict_key).await {
                    Ok(Some(cid)) => cid,
                    Ok(None) => continue,
                    Err(_) => continue,
                };

                if mst
                    .blocks_for_path(&conflict_key, &mut all_old_mst_blocks)
                    .await
                    .is_err()
                {
                    error!("Failed to get old MST blocks for conflict {}", conflict_uri);
                }

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

    let record_ipld = crate::util::json_to_ipld(&input.record);
    let mut record_bytes = Vec::new();
    if serde_ipld_dagcbor::to_writer(&mut record_bytes, &record_ipld).is_err() {
        return Ok(ApiError::InvalidRecord("Failed to serialize record".into()).into_response());
    }
    let record_cid = match tracking_store.put(&record_bytes).await {
        Ok(c) => c,
        _ => {
            return Ok(
                ApiError::InternalError(Some("Failed to save record block".into())).into_response(),
            );
        }
    };
    let key = format!("{}/{}", input.collection, rkey);

    if mst
        .blocks_for_path(&key, &mut all_old_mst_blocks)
        .await
        .is_err()
    {
        error!("Failed to get old MST blocks for new record path");
    }

    let new_mst = match mst.add(&key, record_cid).await {
        Ok(m) => m,
        _ => {
            return Ok(ApiError::InternalError(Some("Failed to add to MST".into())).into_response());
        }
    };
    let new_mst_root = match new_mst.persist().await {
        Ok(c) => c,
        _ => {
            return Ok(
                ApiError::InternalError(Some("Failed to persist MST".into())).into_response(),
            );
        }
    };

    ops.push(RecordOp::Create {
        collection: input.collection.clone(),
        rkey: rkey.clone(),
        cid: record_cid,
    });

    let mut new_mst_blocks = std::collections::BTreeMap::new();
    if new_mst
        .blocks_for_path(&key, &mut new_mst_blocks)
        .await
        .is_err()
    {
        return Ok(
            ApiError::InternalError(Some("Failed to get new MST blocks for path".into()))
                .into_response(),
        );
    }

    let mut relevant_blocks = new_mst_blocks.clone();
    relevant_blocks.extend(all_old_mst_blocks.iter().map(|(k, v)| (*k, v.clone())));
    relevant_blocks.insert(record_cid, bytes::Bytes::new());
    let written_cids: Vec<Cid> = tracking_store
        .get_all_relevant_cids()
        .into_iter()
        .chain(relevant_blocks.keys().copied())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    let written_cids_str: Vec<String> = written_cids.iter().map(|c| c.to_string()).collect();
    let blob_cids = extract_blob_cids(&input.record);
    let obsolete_cids: Vec<Cid> = std::iter::once(current_root_cid.into_cid())
        .chain(
            all_old_mst_blocks
                .keys()
                .filter(|cid| !new_mst_blocks.contains_key(*cid))
                .copied(),
        )
        .collect();

    let commit_result = match commit_and_log(
        &state,
        CommitParams {
            did: &did,
            user_id,
            current_root_cid: Some(current_root_cid.into_cid()),
            prev_data_cid: Some(initial_mst_root),
            new_mst_root,
            ops,
            blocks_cids: &written_cids_str,
            blobs: &blob_cids,
            obsolete_cids,
        },
    )
    .await
    {
        Ok(res) => res,
        Err(e) if e.contains("ConcurrentModification") => {
            return Ok(ApiError::InvalidSwap(Some("Repo has been modified".into())).into_response());
        }
        Err(e) => return Ok(ApiError::InternalError(Some(e)).into_response()),
    };

    for conflict_uri in conflict_uris_to_cleanup {
        if let Err(e) = state
            .backlink_repo
            .remove_backlinks_by_uri(&conflict_uri)
            .await
        {
            error!("Failed to remove backlinks for {}: {}", conflict_uri, e);
        }
    }

    if let Some(ref controller) = controller_did {
        let _ = state
            .delegation_repo
            .log_delegation_action(
                &did,
                controller,
                Some(controller),
                DelegationActionType::RepoWrite,
                Some(json!({
                    "action": "create",
                    "collection": input.collection,
                    "rkey": rkey
                })),
                None,
                None,
            )
            .await;
    }

    let created_uri = AtUri::from_parts(&did, &input.collection, &rkey);
    let backlinks = extract_backlinks(&created_uri, &input.record);
    if !backlinks.is_empty()
        && let Err(e) = state.backlink_repo.add_backlinks(user_id, &backlinks).await
    {
        error!("Failed to add backlinks for {}: {}", created_uri, e);
    }

    Ok((
        StatusCode::OK,
        Json(CreateRecordOutput {
            uri: created_uri,
            cid: record_cid.to_string(),
            commit: CommitInfo {
                cid: commit_result.commit_cid.to_string(),
                rev: commit_result.rev,
            },
            validation_status: validation_status.map(|s| s.to_string()),
        }),
    )
        .into_response())
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
    pub validation_status: Option<String>,
}
pub async fn put_record(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<PutRecordInput>,
) -> Result<Response, crate::api::error::ApiError> {
    let upsert_proof = match auth.verify_repo_upsert(&input.collection) {
        Ok(proof) => proof,
        Err(e) => return Ok(e.into_response()),
    };

    let repo_auth = match prepare_repo_write(&state, &upsert_proof, &input.repo).await {
        Ok(res) => res,
        Err(err_res) => return Ok(err_res),
    };

    let did = repo_auth.did;
    let user_id = repo_auth.user_id;
    let current_root_cid = repo_auth.current_root_cid;
    let controller_did = repo_auth.controller_did;

    if let Some(swap_commit) = &input.swap_commit
        && CommitCid::from_str(swap_commit).ok().as_ref() != Some(&current_root_cid)
    {
        return Ok(ApiError::InvalidSwap(Some("Repo has been modified".into())).into_response());
    }
    let tracking_store = TrackingBlockStore::new(state.block_store.clone());
    let commit_bytes = match tracking_store.get(current_root_cid.as_cid()).await {
        Ok(Some(b)) => b,
        _ => {
            return Ok(
                ApiError::InternalError(Some("Commit block not found".into())).into_response(),
            );
        }
    };
    let commit = match Commit::from_cbor(&commit_bytes) {
        Ok(c) => c,
        _ => {
            return Ok(
                ApiError::InternalError(Some("Failed to parse commit".into())).into_response(),
            );
        }
    };
    let mst = Mst::load(Arc::new(tracking_store.clone()), commit.data, None);
    let key = format!("{}/{}", input.collection, input.rkey);
    let validation_status = if input.validate.should_skip() {
        None
    } else {
        match validate_record_with_status(
            &input.record,
            &input.collection,
            Some(&input.rkey),
            input.validate.requires_lexicon(),
        ) {
            Ok(status) => Some(status),
            Err(err_response) => return Ok(*err_response),
        }
    };
    if let Some(swap_record_str) = &input.swap_record {
        let expected_cid = Cid::from_str(swap_record_str).ok();
        let actual_cid = mst.get(&key).await.ok().flatten();
        if expected_cid != actual_cid {
            return Ok(ApiError::InvalidSwap(Some(
                "Record has been modified or does not exist".into(),
            ))
            .into_response());
        }
    }
    let existing_cid = mst.get(&key).await.ok().flatten();
    let record_ipld = crate::util::json_to_ipld(&input.record);
    let mut record_bytes = Vec::new();
    if serde_ipld_dagcbor::to_writer(&mut record_bytes, &record_ipld).is_err() {
        return Ok(ApiError::InvalidRecord("Failed to serialize record".into()).into_response());
    }
    let record_cid = match tracking_store.put(&record_bytes).await {
        Ok(c) => c,
        _ => {
            return Ok(
                ApiError::InternalError(Some("Failed to save record block".into())).into_response(),
            );
        }
    };
    if existing_cid == Some(record_cid) {
        return Ok((
            StatusCode::OK,
            Json(PutRecordOutput {
                uri: AtUri::from_parts(&did, &input.collection, &input.rkey),
                cid: record_cid.to_string(),
                commit: None,
                validation_status: validation_status.map(|s| s.to_string()),
            }),
        )
            .into_response());
    }
    let new_mst =
        if existing_cid.is_some() {
            match mst.update(&key, record_cid).await {
                Ok(m) => m,
                Err(_) => {
                    return Ok(ApiError::InternalError(Some("Failed to update MST".into()))
                        .into_response());
                }
            }
        } else {
            match mst.add(&key, record_cid).await {
                Ok(m) => m,
                Err(_) => {
                    return Ok(ApiError::InternalError(Some("Failed to add to MST".into()))
                        .into_response());
                }
            }
        };
    let new_mst_root = match new_mst.persist().await {
        Ok(c) => c,
        Err(_) => {
            return Ok(
                ApiError::InternalError(Some("Failed to persist MST".into())).into_response(),
            );
        }
    };
    let op = if existing_cid.is_some() {
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
    let mut new_mst_blocks = std::collections::BTreeMap::new();
    let mut old_mst_blocks = std::collections::BTreeMap::new();
    if new_mst
        .blocks_for_path(&key, &mut new_mst_blocks)
        .await
        .is_err()
    {
        return Ok(
            ApiError::InternalError(Some("Failed to get new MST blocks for path".into()))
                .into_response(),
        );
    }
    if mst
        .blocks_for_path(&key, &mut old_mst_blocks)
        .await
        .is_err()
    {
        return Ok(
            ApiError::InternalError(Some("Failed to get old MST blocks for path".into()))
                .into_response(),
        );
    }
    let mut relevant_blocks = new_mst_blocks.clone();
    relevant_blocks.extend(old_mst_blocks.iter().map(|(k, v)| (*k, v.clone())));
    relevant_blocks.insert(record_cid, bytes::Bytes::from(record_bytes));
    let written_cids: Vec<Cid> = tracking_store
        .get_all_relevant_cids()
        .into_iter()
        .chain(relevant_blocks.keys().copied())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    let written_cids_str: Vec<String> = written_cids.iter().map(|c| c.to_string()).collect();
    let is_update = existing_cid.is_some();
    let blob_cids = extract_blob_cids(&input.record);
    let obsolete_cids: Vec<Cid> = std::iter::once(current_root_cid.into_cid())
        .chain(
            old_mst_blocks
                .keys()
                .filter(|cid| !new_mst_blocks.contains_key(*cid))
                .copied(),
        )
        .chain(existing_cid)
        .collect();
    let commit_result = match commit_and_log(
        &state,
        CommitParams {
            did: &did,
            user_id,
            current_root_cid: Some(current_root_cid.into_cid()),
            prev_data_cid: Some(commit.data),
            new_mst_root,
            ops: vec![op],
            blocks_cids: &written_cids_str,
            blobs: &blob_cids,
            obsolete_cids,
        },
    )
    .await
    {
        Ok(res) => res,
        Err(e) if e.contains("ConcurrentModification") => {
            return Ok(ApiError::InvalidSwap(Some("Repo has been modified".into())).into_response());
        }
        Err(e) => return Ok(ApiError::InternalError(Some(e)).into_response()),
    };

    if let Some(ref controller) = controller_did {
        let _ = state
            .delegation_repo
            .log_delegation_action(
                &did,
                controller,
                Some(controller),
                DelegationActionType::RepoWrite,
                Some(json!({
                    "action": if is_update { "update" } else { "create" },
                    "collection": input.collection,
                    "rkey": input.rkey
                })),
                None,
                None,
            )
            .await;
    }

    Ok((
        StatusCode::OK,
        Json(PutRecordOutput {
            uri: AtUri::from_parts(&did, &input.collection, &input.rkey),
            cid: record_cid.to_string(),
            commit: Some(CommitInfo {
                cid: commit_result.commit_cid.to_string(),
                rev: commit_result.rev,
            }),
            validation_status: validation_status.map(|s| s.to_string()),
        }),
    )
        .into_response())
}
