use super::validation::validate_record_with_status;
use crate::api::error::ApiError;
use crate::api::repo::record::utils::{CommitParams, RecordOp, commit_and_log, extract_backlinks, extract_blob_cids};
use crate::delegation::DelegationActionType;
use crate::repo::tracking::TrackingBlockStore;
use crate::state::AppState;
use crate::types::{AtIdentifier, AtUri, Did, Nsid, Rkey};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
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
    pub current_root_cid: Cid,
    pub is_oauth: bool,
    pub scope: Option<String>,
    pub controller_did: Option<Did>,
}

pub async fn prepare_repo_write(
    state: &AppState,
    headers: &HeaderMap,
    repo: &AtIdentifier,
    http_method: &str,
    http_uri: &str,
) -> Result<RepoWriteAuth, Response> {
    let extracted = crate::auth::extract_auth_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    )
    .ok_or_else(|| ApiError::AuthenticationRequired.into_response())?;
    let dpop_proof = headers.get("DPoP").and_then(|h| h.to_str().ok());
    let auth_user = crate::auth::validate_token_with_dpop(
        state.user_repo.as_ref(),
        state.oauth_repo.as_ref(),
        &extracted.token,
        extracted.is_dpop,
        dpop_proof,
        http_method,
        http_uri,
        false,
        false,
    )
    .await
    .map_err(|e| {
        tracing::warn!(error = ?e, is_dpop = extracted.is_dpop, "Token validation failed in prepare_repo_write");
        ApiError::from(e).into_response()
    })?;
    if repo.as_str() != auth_user.did.as_str() {
        return Err(
            ApiError::InvalidRepo("Repo does not match authenticated user".into()).into_response(),
        );
    }
    if state
        .user_repo
        .is_account_migrated(&auth_user.did)
        .await
        .unwrap_or(false)
    {
        return Err(ApiError::AccountMigrated.into_response());
    }
    let is_verified = state
        .user_repo
        .has_verified_comms_channel(&auth_user.did)
        .await
        .unwrap_or(false);
    let is_delegated = state
        .delegation_repo
        .is_delegated_account(&auth_user.did)
        .await
        .unwrap_or(false);
    if !is_verified && !is_delegated {
        return Err(ApiError::AccountNotVerified.into_response());
    }
    let user_id = state
        .user_repo
        .get_id_by_did(&auth_user.did)
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
        .ok_or_else(|| ApiError::InternalError(Some("Repo root not found".into())).into_response())?;
    let current_root_cid = Cid::from_str(&root_cid_str).map_err(|_| {
        ApiError::InternalError(Some("Invalid repo root CID".into())).into_response()
    })?;
    Ok(RepoWriteAuth {
        did: auth_user.did.clone(),
        user_id,
        current_root_cid,
        is_oauth: auth_user.is_oauth,
        scope: auth_user.scope,
        controller_did: auth_user.controller_did.clone(),
    })
}
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct CreateRecordInput {
    pub repo: AtIdentifier,
    pub collection: Nsid,
    pub rkey: Option<Rkey>,
    pub validate: Option<bool>,
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
    headers: HeaderMap,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    Json(input): Json<CreateRecordInput>,
) -> Response {
    let auth = match prepare_repo_write(
        &state,
        &headers,
        &input.repo,
        "POST",
        &crate::util::build_full_url(&uri.to_string()),
    )
    .await
    {
        Ok(res) => res,
        Err(err_res) => return err_res,
    };

    if let Err(e) = crate::auth::scope_check::check_repo_scope(
        auth.is_oauth,
        auth.scope.as_deref(),
        crate::oauth::RepoAction::Create,
        &input.collection,
    ) {
        return e;
    }

    let did = auth.did;
    let user_id = auth.user_id;
    let current_root_cid = auth.current_root_cid;
    let controller_did = auth.controller_did;

    if let Some(swap_commit) = &input.swap_commit
        && Cid::from_str(swap_commit).ok() != Some(current_root_cid)
    {
        return ApiError::InvalidSwap(Some("Repo has been modified".into())).into_response();
    }

    let validation_status = if input.validate == Some(false) {
        None
    } else {
        let require_lexicon = input.validate == Some(true);
        match validate_record_with_status(
            &input.record,
            &input.collection,
            input.rkey.as_ref(),
            require_lexicon,
        ) {
            Ok(status) => Some(status),
            Err(err_response) => return *err_response,
        }
    };
    let rkey = input.rkey.unwrap_or_else(Rkey::generate);

    let tracking_store = TrackingBlockStore::new(state.block_store.clone());
    let commit_bytes = match tracking_store.get(&current_root_cid).await {
        Ok(Some(b)) => b,
        _ => return ApiError::InternalError(Some("Commit block not found".into())).into_response(),
    };
    let commit = match Commit::from_cbor(&commit_bytes) {
        Ok(c) => c,
        _ => return ApiError::InternalError(Some("Failed to parse commit".into())).into_response(),
    };
    let mut mst = Mst::load(Arc::new(tracking_store.clone()), commit.data, None);
    let initial_mst_root = commit.data;

    let mut ops: Vec<RecordOp> = Vec::new();
    let mut conflict_uris_to_cleanup: Vec<AtUri> = Vec::new();
    let mut all_old_mst_blocks = std::collections::BTreeMap::new();

    if input.validate != Some(false) {
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
                    return ApiError::InternalError(None).into_response();
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

                if mst.blocks_for_path(&conflict_key, &mut all_old_mst_blocks).await.is_err() {
                    error!("Failed to get old MST blocks for conflict {}", conflict_uri);
                }

                mst = match mst.delete(&conflict_key).await {
                    Ok(m) => m,
                    Err(e) => {
                        error!("Failed to delete conflict from MST {}: {:?}", conflict_uri, e);
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
        return ApiError::InvalidRecord("Failed to serialize record".into()).into_response();
    }
    let record_cid = match tracking_store.put(&record_bytes).await {
        Ok(c) => c,
        _ => {
            return ApiError::InternalError(Some("Failed to save record block".into()))
                .into_response();
        }
    };
    let key = format!("{}/{}", input.collection, rkey);

    if mst.blocks_for_path(&key, &mut all_old_mst_blocks).await.is_err() {
        error!("Failed to get old MST blocks for new record path");
    }

    let new_mst = match mst.add(&key, record_cid).await {
        Ok(m) => m,
        _ => return ApiError::InternalError(Some("Failed to add to MST".into())).into_response(),
    };
    let new_mst_root = match new_mst.persist().await {
        Ok(c) => c,
        _ => return ApiError::InternalError(Some("Failed to persist MST".into())).into_response(),
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
        return ApiError::InternalError(Some("Failed to get new MST blocks for path".into()))
            .into_response();
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
    let obsolete_cids: Vec<Cid> = std::iter::once(current_root_cid)
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
            current_root_cid: Some(current_root_cid),
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
            return ApiError::InvalidSwap(Some("Repo has been modified".into())).into_response();
        }
        Err(e) => return ApiError::InternalError(Some(e)).into_response(),
    };

    for conflict_uri in conflict_uris_to_cleanup {
        if let Err(e) = state.backlink_repo.remove_backlinks_by_uri(&conflict_uri).await {
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
    if !backlinks.is_empty() {
        if let Err(e) = state
            .backlink_repo
            .add_backlinks(user_id, &backlinks)
            .await
        {
            error!("Failed to add backlinks for {}: {}", created_uri, e);
        }
    }

    (
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
        .into_response()
}
#[derive(Deserialize)]
#[allow(dead_code)]
pub struct PutRecordInput {
    pub repo: AtIdentifier,
    pub collection: Nsid,
    pub rkey: Rkey,
    pub validate: Option<bool>,
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
    headers: HeaderMap,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    Json(input): Json<PutRecordInput>,
) -> Response {
    let auth = match prepare_repo_write(
        &state,
        &headers,
        &input.repo,
        "POST",
        &crate::util::build_full_url(&uri.to_string()),
    )
    .await
    {
        Ok(res) => res,
        Err(err_res) => return err_res,
    };

    if let Err(e) = crate::auth::scope_check::check_repo_scope(
        auth.is_oauth,
        auth.scope.as_deref(),
        crate::oauth::RepoAction::Create,
        &input.collection,
    ) {
        return e;
    }
    if let Err(e) = crate::auth::scope_check::check_repo_scope(
        auth.is_oauth,
        auth.scope.as_deref(),
        crate::oauth::RepoAction::Update,
        &input.collection,
    ) {
        return e;
    }

    let did = auth.did;
    let user_id = auth.user_id;
    let current_root_cid = auth.current_root_cid;
    let controller_did = auth.controller_did;

    if let Some(swap_commit) = &input.swap_commit
        && Cid::from_str(swap_commit).ok() != Some(current_root_cid)
    {
        return ApiError::InvalidSwap(Some("Repo has been modified".into())).into_response();
    }
    let tracking_store = TrackingBlockStore::new(state.block_store.clone());
    let commit_bytes = match tracking_store.get(&current_root_cid).await {
        Ok(Some(b)) => b,
        _ => return ApiError::InternalError(Some("Commit block not found".into())).into_response(),
    };
    let commit = match Commit::from_cbor(&commit_bytes) {
        Ok(c) => c,
        _ => return ApiError::InternalError(Some("Failed to parse commit".into())).into_response(),
    };
    let mst = Mst::load(Arc::new(tracking_store.clone()), commit.data, None);
    let key = format!("{}/{}", input.collection, input.rkey);
    let validation_status = if input.validate == Some(false) {
        None
    } else {
        let require_lexicon = input.validate == Some(true);
        match validate_record_with_status(
            &input.record,
            &input.collection,
            Some(&input.rkey),
            require_lexicon,
        ) {
            Ok(status) => Some(status),
            Err(err_response) => return *err_response,
        }
    };
    if let Some(swap_record_str) = &input.swap_record {
        let expected_cid = Cid::from_str(swap_record_str).ok();
        let actual_cid = mst.get(&key).await.ok().flatten();
        if expected_cid != actual_cid {
            return ApiError::InvalidSwap(Some(
                "Record has been modified or does not exist".into(),
            ))
            .into_response();
        }
    }
    let existing_cid = mst.get(&key).await.ok().flatten();
    let record_ipld = crate::util::json_to_ipld(&input.record);
    let mut record_bytes = Vec::new();
    if serde_ipld_dagcbor::to_writer(&mut record_bytes, &record_ipld).is_err() {
        return ApiError::InvalidRecord("Failed to serialize record".into()).into_response();
    }
    let record_cid = match tracking_store.put(&record_bytes).await {
        Ok(c) => c,
        _ => {
            return ApiError::InternalError(Some("Failed to save record block".into()))
                .into_response();
        }
    };
    if existing_cid == Some(record_cid) {
        return (
            StatusCode::OK,
            Json(PutRecordOutput {
                uri: AtUri::from_parts(&did, &input.collection, &input.rkey),
                cid: record_cid.to_string(),
                commit: None,
                validation_status: validation_status.map(|s| s.to_string()),
            }),
        )
            .into_response();
    }
    let new_mst = if existing_cid.is_some() {
        match mst.update(&key, record_cid).await {
            Ok(m) => m,
            Err(_) => {
                return ApiError::InternalError(Some("Failed to update MST".into()))
                    .into_response();
            }
        }
    } else {
        match mst.add(&key, record_cid).await {
            Ok(m) => m,
            Err(_) => {
                return ApiError::InternalError(Some("Failed to add to MST".into()))
                    .into_response();
            }
        }
    };
    let new_mst_root = match new_mst.persist().await {
        Ok(c) => c,
        Err(_) => {
            return ApiError::InternalError(Some("Failed to persist MST".into())).into_response();
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
        return ApiError::InternalError(Some("Failed to get new MST blocks for path".into()))
            .into_response();
    }
    if mst
        .blocks_for_path(&key, &mut old_mst_blocks)
        .await
        .is_err()
    {
        return ApiError::InternalError(Some("Failed to get old MST blocks for path".into()))
            .into_response();
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
    let obsolete_cids: Vec<Cid> = std::iter::once(current_root_cid)
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
            current_root_cid: Some(current_root_cid),
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
            return ApiError::InvalidSwap(Some("Repo has been modified".into())).into_response();
        }
        Err(e) => return ApiError::InternalError(Some(e)).into_response(),
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

    (
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
        .into_response()
}
