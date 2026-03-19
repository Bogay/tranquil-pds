use axum::{Json, body::Bytes, extract::State};
use jacquard_common::types::{integer::LimitedU32, string::Tid};
use jacquard_repo::storage::BlockStore;
use k256::ecdsa::SigningKey;
use serde_json::json;
use tracing::{debug, error, info, warn};
use tranquil_pds::api::EmptyResponse;
use tranquil_pds::api::error::{ApiError, DbResultExt};
use tranquil_pds::auth::{Auth, NotTakendown};
use tranquil_pds::repo_ops::create_signed_commit;
use tranquil_pds::state::AppState;
use tranquil_pds::sync::import::{ImportError, apply_import, parse_car};
use tranquil_pds::sync::verify::CarVerifier;
use tranquil_pds::types::Did;
use tranquil_types::{AtUri, CidLink};

pub async fn import_repo(
    State(state): State<AppState>,
    auth: Auth<NotTakendown>,
    body: Bytes,
) -> Result<Json<EmptyResponse>, ApiError> {
    let accepting_imports = tranquil_config::get().import.accepting;
    if !accepting_imports {
        return Err(ApiError::InvalidRequest(
            "Service is not accepting repo imports".into(),
        ));
    }
    let max_size = tranquil_config::get().import.max_size as usize;
    if body.len() > max_size {
        return Err(ApiError::PayloadTooLarge(format!(
            "Import size exceeds limit of {} bytes",
            max_size
        )));
    }
    let did = &auth.did;
    let user = state
        .user_repo
        .get_by_did(did)
        .await
        .log_db_err("fetching user")?
        .ok_or(ApiError::AccountNotFound)?;
    if user.takedown_ref.is_some() {
        return Err(ApiError::AccountTakedown);
    }
    let user_id = user.id;
    let expected_root_cid = state
        .repo_repo
        .get_repo_root_cid_by_user_id(user_id)
        .await
        .map_err(|e| {
            error!("DB error fetching repo root: {:?}", e);
            ApiError::InternalError(None)
        })?;
    let (root, blocks) = match parse_car(&body).await {
        Ok((r, b)) => (r, b),
        Err(ImportError::InvalidRootCount) => {
            return Err(ApiError::InvalidRequest(
                "Expected exactly one root in CAR file".into(),
            ));
        }
        Err(ImportError::CarParse(msg)) => {
            return Err(ApiError::InvalidRequest(format!(
                "Failed to parse CAR file: {}",
                msg
            )));
        }
        Err(e) => {
            error!("CAR parsing error: {:?}", e);
            return Err(ApiError::InvalidRequest(format!("Invalid CAR file: {}", e)));
        }
    };
    info!(
        "Importing repo for user {}: {} blocks, root {}",
        did,
        blocks.len(),
        root
    );
    let Some(root_block) = blocks.get(&root) else {
        return Err(ApiError::InvalidRequest(
            "Root block not found in CAR file".into(),
        ));
    };
    let commit_did: Did = match jacquard_repo::commit::Commit::from_cbor(root_block) {
        Ok(commit) => commit
            .did()
            .as_str()
            .parse()
            .map_err(|_| ApiError::InvalidRequest("Commit contains invalid DID".into()))?,
        Err(e) => {
            return Err(ApiError::InvalidRequest(format!("Invalid commit: {}", e)));
        }
    };
    if commit_did != *did {
        return Err(ApiError::InvalidRepo(format!(
            "CAR file is for DID {} but you are authenticated as {}",
            commit_did, did
        )));
    }
    let skip_verification = std::env::var("SKIP_IMPORT_VERIFICATION")
        .ok()
        .map(|v| v == "true" || v == "1")
        .unwrap_or_else(|| {
            tranquil_config::try_get()
                .map(|c| c.import.skip_verification)
                .unwrap_or(false)
        });
    let is_migration = user.deactivated_at.is_some();
    if skip_verification {
        warn!("Skipping all CAR verification for import (SKIP_IMPORT_VERIFICATION=true)");
    } else if is_migration {
        debug!("Verifying CAR file structure for migration (skipping signature verification)");
        let verifier = CarVerifier::new();
        match verifier.verify_car_structure_only(did, &root, &blocks) {
            Ok(verified) => {
                debug!(
                    "CAR structure verification successful: rev={}, data_cid={}",
                    verified.rev, verified.data_cid
                );
            }
            Err(tranquil_pds::sync::verify::VerifyError::DidMismatch {
                commit_did,
                expected_did,
            }) => {
                return Err(ApiError::InvalidRepo(format!(
                    "CAR file is for DID {} but you are authenticated as {}",
                    commit_did, expected_did
                )));
            }
            Err(tranquil_pds::sync::verify::VerifyError::MstValidationFailed(msg)) => {
                return Err(ApiError::InvalidRequest(format!(
                    "MST validation failed: {}",
                    msg
                )));
            }
            Err(e) => {
                error!("CAR structure verification error: {:?}", e);
                return Err(ApiError::InvalidRequest(format!(
                    "CAR verification failed: {}",
                    e
                )));
            }
        }
    } else {
        debug!("Verifying CAR file signature and structure for DID {}", did);
        let verifier = CarVerifier::new();
        match verifier.verify_car(did, &root, &blocks).await {
            Ok(verified) => {
                debug!(
                    "CAR verification successful: rev={}, data_cid={}",
                    verified.rev, verified.data_cid
                );
            }
            Err(tranquil_pds::sync::verify::VerifyError::DidMismatch {
                commit_did,
                expected_did,
            }) => {
                return Err(ApiError::InvalidRepo(format!(
                    "CAR file is for DID {} but you are authenticated as {}",
                    commit_did, expected_did
                )));
            }
            Err(tranquil_pds::sync::verify::VerifyError::InvalidSignature) => {
                return Err(ApiError::InvalidRequest(
                    "CAR file commit signature verification failed".into(),
                ));
            }
            Err(tranquil_pds::sync::verify::VerifyError::DidResolutionFailed(msg)) => {
                warn!("DID resolution failed during import verification: {}", msg);
                return Err(ApiError::InvalidRequest(format!(
                    "Failed to verify DID: {}",
                    msg
                )));
            }
            Err(tranquil_pds::sync::verify::VerifyError::NoSigningKey) => {
                return Err(ApiError::InvalidRequest(
                    "DID document does not contain a signing key".into(),
                ));
            }
            Err(tranquil_pds::sync::verify::VerifyError::MstValidationFailed(msg)) => {
                return Err(ApiError::InvalidRequest(format!(
                    "MST validation failed: {}",
                    msg
                )));
            }
            Err(e) => {
                error!("CAR verification error: {:?}", e);
                return Err(ApiError::InvalidRequest(format!(
                    "CAR verification failed: {}",
                    e
                )));
            }
        }
    }
    let max_blocks = tranquil_config::get().import.max_blocks as usize;
    let _write_lock = state.repo_write_locks.lock(user_id).await;
    match apply_import(
        &state.repo_repo,
        user_id,
        root,
        blocks.clone(),
        max_blocks,
        expected_root_cid.as_ref(),
    )
    .await
    {
        Ok(import_result) => {
            info!(
                "Successfully imported {} records for user {}",
                import_result.records.len(),
                did
            );
            let blob_refs: Vec<(AtUri, CidLink)> = import_result
                .records
                .iter()
                .flat_map(|record| {
                    let record_uri =
                        AtUri::from_parts(did.as_str(), &record.collection, &record.rkey);
                    record.blob_refs.iter().filter_map(move |blob_ref| {
                        match CidLink::new(&blob_ref.cid) {
                            Ok(cid_link) => Some((record_uri.clone(), cid_link)),
                            Err(_) => {
                                tracing::warn!(cid = %blob_ref.cid, "skipping unparseable blob CID reference during import");
                                None
                            }
                        }
                    })
                })
                .collect();

            if !blob_refs.is_empty() {
                let (record_uris, blob_cids): (Vec<AtUri>, Vec<CidLink>) =
                    blob_refs.into_iter().unzip();

                match state
                    .blob_repo
                    .insert_record_blobs(user_id, &record_uris, &blob_cids)
                    .await
                {
                    Ok(()) => {
                        info!(
                            "Recorded {} blob references for imported repo",
                            blob_cids.len()
                        );
                    }
                    Err(e) => {
                        warn!("Failed to insert record_blobs: {:?}", e);
                    }
                }
            }
            let key_row = state
                .user_repo
                .get_user_with_key_by_did(did)
                .await
                .map_err(|e| {
                    error!("DB error fetching signing key: {:?}", e);
                    ApiError::InternalError(None)
                })?
                .ok_or_else(|| {
                    error!("No signing key found for user {}", did);
                    ApiError::InternalError(Some("Signing key not found".into()))
                })?;
            let key_bytes =
                tranquil_pds::config::decrypt_key(&key_row.key_bytes, key_row.encryption_version)
                    .map_err(|e| {
                    error!("Failed to decrypt signing key: {}", e);
                    ApiError::InternalError(None)
                })?;
            let signing_key = SigningKey::from_slice(&key_bytes).map_err(|e| {
                error!("Invalid signing key: {:?}", e);
                ApiError::InternalError(None)
            })?;
            let new_rev = Tid::now(LimitedU32::MIN);
            let new_rev_str = new_rev.to_string();
            let (commit_bytes, _sig) = create_signed_commit(
                did,
                import_result.data_cid,
                &new_rev_str,
                None,
                &signing_key,
            )
            .map_err(|e| {
                error!("Failed to create new commit: {}", e);
                ApiError::InternalError(None)
            })?;
            let new_root_cid: cid::Cid =
                state.block_store.put(&commit_bytes).await.map_err(|e| {
                    error!("Failed to store new commit block: {:?}", e);
                    ApiError::InternalError(None)
                })?;
            let new_root_cid_link = CidLink::from(&new_root_cid);
            state
                .repo_repo
                .update_repo_root(user_id, &new_root_cid_link, &new_rev_str)
                .await
                .map_err(|e| {
                    error!("Failed to update repo root: {:?}", e);
                    ApiError::InternalError(None)
                })?;
            let mut all_block_cids: Vec<Vec<u8>> = blocks.keys().map(|c| c.to_bytes()).collect();
            all_block_cids.push(new_root_cid.to_bytes());
            state
                .repo_repo
                .insert_user_blocks(user_id, &all_block_cids, &new_rev_str)
                .await
                .map_err(|e| {
                    error!("Failed to insert user_blocks: {:?}", e);
                    ApiError::InternalError(None)
                })?;
            let new_root_str = new_root_cid.to_string();
            info!(
                "Created new commit for imported repo: cid={}, rev={}",
                new_root_str, new_rev_str
            );
            if !is_migration
                && let Err(e) = sequence_import_event(&state, did, &new_root_cid_link).await
            {
                warn!("Failed to sequence import event: {:?}", e);
            }
            if tranquil_config::get().server.age_assurance_override {
                let birthdate_pref = json!({
                    "$type": "app.bsky.actor.defs#personalDetailsPref",
                    "birthDate": "1998-05-06T00:00:00.000Z"
                });
                if let Err(e) = state
                    .infra_repo
                    .insert_account_preference_if_not_exists(
                        user_id,
                        "app.bsky.actor.defs#personalDetailsPref",
                        birthdate_pref,
                    )
                    .await
                {
                    warn!(
                        "Failed to set default birthdate preference for migrated user: {:?}",
                        e
                    );
                }
            }
            Ok(Json(EmptyResponse {}))
        }
        Err(ImportError::SizeLimitExceeded) => Err(ApiError::PayloadTooLarge(format!(
            "Import exceeds block limit of {}",
            max_blocks
        ))),
        Err(ImportError::RepoNotFound) => Err(ApiError::RepoNotFound(Some(
            "Repository not initialized for this account".into(),
        ))),
        Err(ImportError::InvalidCbor(msg)) => Err(ApiError::InvalidRequest(format!(
            "Invalid CBOR data: {}",
            msg
        ))),
        Err(ImportError::InvalidCommit(msg)) => Err(ApiError::InvalidRequest(format!(
            "Invalid commit structure: {}",
            msg
        ))),
        Err(ImportError::BlockNotFound(cid)) => Err(ApiError::InvalidRequest(format!(
            "Referenced block not found in CAR: {}",
            cid
        ))),
        Err(ImportError::ConcurrentModification) => Err(ApiError::InvalidSwap(Some(
            "Repository is being modified by another operation, please retry".into(),
        ))),
        Err(ImportError::VerificationFailed(ve)) => Err(ApiError::InvalidRequest(format!(
            "CAR verification failed: {}",
            ve
        ))),
        Err(ImportError::DidMismatch { car_did, auth_did }) => Err(ApiError::InvalidRequest(
            format!("CAR is for {} but authenticated as {}", car_did, auth_did),
        )),
        Err(e) => {
            error!("Import error: {:?}", e);
            Err(ApiError::InternalError(None))
        }
    }
}

async fn sequence_import_event(
    state: &AppState,
    did: &Did,
    commit_cid: &CidLink,
) -> Result<(), tranquil_db::DbError> {
    let data = tranquil_db::CommitEventData {
        did: did.clone(),
        event_type: tranquil_db::RepoEventType::Commit,
        commit_cid: Some(commit_cid.clone()),
        prev_cid: None,
        ops: Some(serde_json::json!([])),
        blobs: Some(vec![]),
        blocks_cids: Some(vec![]),
        prev_data_cid: None,
        rev: None,
    };

    let seq = state.repo_repo.insert_commit_event(&data).await?;
    state.repo_repo.notify_update(seq).await?;
    Ok(())
}
