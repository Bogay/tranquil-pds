use crate::api::EmptyResponse;
use crate::api::error::ApiError;
use crate::api::repo::record::create_signed_commit;
use crate::state::AppState;
use crate::sync::import::{ImportError, apply_import, parse_car};
use crate::sync::verify::CarVerifier;
use axum::{
    body::Bytes,
    extract::State,
    response::{IntoResponse, Response},
};
use jacquard::types::{integer::LimitedU32, string::Tid};
use jacquard_repo::storage::BlockStore;
use k256::ecdsa::SigningKey;
use serde_json::json;
use tracing::{debug, error, info, warn};

const DEFAULT_MAX_IMPORT_SIZE: usize = 1024 * 1024 * 1024;
const DEFAULT_MAX_BLOCKS: usize = 500000;

pub async fn import_repo(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    let accepting_imports = std::env::var("ACCEPTING_REPO_IMPORTS")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true);
    if !accepting_imports {
        return ApiError::InvalidRequest("Service is not accepting repo imports".into())
            .into_response();
    }
    let max_size: usize = std::env::var("MAX_IMPORT_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_IMPORT_SIZE);
    if body.len() > max_size {
        return ApiError::PayloadTooLarge(format!(
            "Import size exceeds limit of {} bytes",
            max_size
        ))
        .into_response();
    }
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => return ApiError::AuthenticationRequired.into_response(),
    };
    let auth_user =
        match crate::auth::validate_bearer_token_allow_deactivated(&state.db, &token).await {
            Ok(user) => user,
            Err(e) => return ApiError::from(e).into_response(),
        };
    let did = &auth_user.did;
    let user = match sqlx::query!(
        "SELECT id, handle, deactivated_at, takedown_ref FROM users WHERE did = $1",
        did
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return ApiError::AccountNotFound.into_response();
        }
        Err(e) => {
            error!("DB error fetching user: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    if user.takedown_ref.is_some() {
        return ApiError::AccountTakedown.into_response();
    }
    let user_id = user.id;
    let (root, blocks) = match parse_car(&body).await {
        Ok((r, b)) => (r, b),
        Err(ImportError::InvalidRootCount) => {
            return ApiError::InvalidRequest("Expected exactly one root in CAR file".into())
                .into_response();
        }
        Err(ImportError::CarParse(msg)) => {
            return ApiError::InvalidRequest(format!("Failed to parse CAR file: {}", msg))
                .into_response();
        }
        Err(e) => {
            error!("CAR parsing error: {:?}", e);
            return ApiError::InvalidRequest(format!("Invalid CAR file: {}", e)).into_response();
        }
    };
    info!(
        "Importing repo for user {}: {} blocks, root {}",
        did,
        blocks.len(),
        root
    );
    let Some(root_block) = blocks.get(&root) else {
        return ApiError::InvalidRequest("Root block not found in CAR file".into()).into_response();
    };
    let commit_did = match jacquard_repo::commit::Commit::from_cbor(root_block) {
        Ok(commit) => commit.did().to_string(),
        Err(e) => {
            return ApiError::InvalidRequest(format!("Invalid commit: {}", e)).into_response();
        }
    };
    if commit_did != *did {
        return ApiError::InvalidRepo(format!(
            "CAR file is for DID {} but you are authenticated as {}",
            commit_did, did
        ))
        .into_response();
    }
    let skip_verification = std::env::var("SKIP_IMPORT_VERIFICATION")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
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
            Err(crate::sync::verify::VerifyError::DidMismatch {
                commit_did,
                expected_did,
            }) => {
                return ApiError::InvalidRepo(format!(
                    "CAR file is for DID {} but you are authenticated as {}",
                    commit_did, expected_did
                ))
                .into_response();
            }
            Err(crate::sync::verify::VerifyError::MstValidationFailed(msg)) => {
                return ApiError::InvalidRequest(format!("MST validation failed: {}", msg))
                    .into_response();
            }
            Err(e) => {
                error!("CAR structure verification error: {:?}", e);
                return ApiError::InvalidRequest(format!("CAR verification failed: {}", e))
                    .into_response();
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
            Err(crate::sync::verify::VerifyError::DidMismatch {
                commit_did,
                expected_did,
            }) => {
                return ApiError::InvalidRepo(format!(
                    "CAR file is for DID {} but you are authenticated as {}",
                    commit_did, expected_did
                ))
                .into_response();
            }
            Err(crate::sync::verify::VerifyError::InvalidSignature) => {
                return ApiError::InvalidRequest(
                    "CAR file commit signature verification failed".into(),
                )
                .into_response();
            }
            Err(crate::sync::verify::VerifyError::DidResolutionFailed(msg)) => {
                warn!("DID resolution failed during import verification: {}", msg);
                return ApiError::InvalidRequest(format!("Failed to verify DID: {}", msg))
                    .into_response();
            }
            Err(crate::sync::verify::VerifyError::NoSigningKey) => {
                return ApiError::InvalidRequest(
                    "DID document does not contain a signing key".into(),
                )
                .into_response();
            }
            Err(crate::sync::verify::VerifyError::MstValidationFailed(msg)) => {
                return ApiError::InvalidRequest(format!("MST validation failed: {}", msg))
                    .into_response();
            }
            Err(e) => {
                error!("CAR verification error: {:?}", e);
                return ApiError::InvalidRequest(format!("CAR verification failed: {}", e))
                    .into_response();
            }
        }
    }
    let max_blocks: usize = std::env::var("MAX_IMPORT_BLOCKS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_BLOCKS);
    match apply_import(&state.db, user_id, root, blocks.clone(), max_blocks).await {
        Ok(import_result) => {
            info!(
                "Successfully imported {} records for user {}",
                import_result.records.len(),
                did
            );
            let mut blob_ref_count = 0;
            for record in &import_result.records {
                for blob_ref in &record.blob_refs {
                    let record_uri = format!("at://{}/{}/{}", did, record.collection, record.rkey);
                    if let Err(e) = sqlx::query!(
                        r#"
                        INSERT INTO record_blobs (repo_id, record_uri, blob_cid)
                        VALUES ($1, $2, $3)
                        ON CONFLICT (repo_id, record_uri, blob_cid) DO NOTHING
                        "#,
                        user_id,
                        record_uri,
                        blob_ref.cid
                    )
                    .execute(&state.db)
                    .await
                    {
                        warn!("Failed to insert record_blob for {}: {:?}", record_uri, e);
                    } else {
                        blob_ref_count += 1;
                    }
                }
            }
            if blob_ref_count > 0 {
                info!(
                    "Recorded {} blob references for imported repo",
                    blob_ref_count
                );
            }
            let key_row = match sqlx::query!(
                r#"SELECT uk.key_bytes, uk.encryption_version
                   FROM user_keys uk
                   JOIN users u ON uk.user_id = u.id
                   WHERE u.did = $1"#,
                did
            )
            .fetch_optional(&state.db)
            .await
            {
                Ok(Some(row)) => row,
                Ok(None) => {
                    error!("No signing key found for user {}", did);
                    return ApiError::InternalError(Some("Signing key not found".into()))
                        .into_response();
                }
                Err(e) => {
                    error!("DB error fetching signing key: {:?}", e);
                    return ApiError::InternalError(None).into_response();
                }
            };
            let key_bytes =
                match crate::config::decrypt_key(&key_row.key_bytes, key_row.encryption_version) {
                    Ok(k) => k,
                    Err(e) => {
                        error!("Failed to decrypt signing key: {}", e);
                        return ApiError::InternalError(None).into_response();
                    }
                };
            let signing_key = match SigningKey::from_slice(&key_bytes) {
                Ok(k) => k,
                Err(e) => {
                    error!("Invalid signing key: {:?}", e);
                    return ApiError::InternalError(None).into_response();
                }
            };
            let new_rev = Tid::now(LimitedU32::MIN);
            let new_rev_str = new_rev.to_string();
            let (commit_bytes, _sig) = match create_signed_commit(
                did,
                import_result.data_cid,
                &new_rev_str,
                None,
                &signing_key,
            ) {
                Ok(result) => result,
                Err(e) => {
                    error!("Failed to create new commit: {}", e);
                    return ApiError::InternalError(None).into_response();
                }
            };
            let new_root_cid: cid::Cid = match state.block_store.put(&commit_bytes).await {
                Ok(cid) => cid,
                Err(e) => {
                    error!("Failed to store new commit block: {:?}", e);
                    return ApiError::InternalError(None).into_response();
                }
            };
            let new_root_str = new_root_cid.to_string();
            if let Err(e) = sqlx::query!(
                "UPDATE repos SET repo_root_cid = $1, repo_rev = $2, updated_at = NOW() WHERE user_id = $3",
                new_root_str,
                &new_rev_str,
                user_id
            )
            .execute(&state.db)
            .await
            {
                error!("Failed to update repo root: {:?}", e);
                return ApiError::InternalError(None).into_response();
            }
            let mut all_block_cids: Vec<Vec<u8>> = blocks.keys().map(|c| c.to_bytes()).collect();
            all_block_cids.push(new_root_cid.to_bytes());
            if let Err(e) = sqlx::query!(
                r#"
                INSERT INTO user_blocks (user_id, block_cid)
                SELECT $1, block_cid FROM UNNEST($2::bytea[]) AS t(block_cid)
                ON CONFLICT (user_id, block_cid) DO NOTHING
                "#,
                user_id,
                &all_block_cids
            )
            .execute(&state.db)
            .await
            {
                error!("Failed to insert user_blocks: {:?}", e);
                return ApiError::InternalError(None).into_response();
            }
            info!(
                "Created new commit for imported repo: cid={}, rev={}",
                new_root_str, new_rev_str
            );
            if !is_migration && let Err(e) = sequence_import_event(&state, did, &new_root_str).await
            {
                warn!("Failed to sequence import event: {:?}", e);
            }
            if std::env::var("PDS_AGE_ASSURANCE_OVERRIDE").is_ok() {
                let birthdate_pref = json!({
                    "$type": "app.bsky.actor.defs#personalDetailsPref",
                    "birthDate": "1998-05-06T00:00:00.000Z"
                });
                if let Err(e) = sqlx::query!(
                    "INSERT INTO account_preferences (user_id, name, value_json) VALUES ($1, $2, $3)
                     ON CONFLICT (user_id, name) DO NOTHING",
                    user_id,
                    "app.bsky.actor.defs#personalDetailsPref",
                    birthdate_pref
                )
                .execute(&state.db)
                .await
                {
                    warn!(
                        "Failed to set default birthdate preference for migrated user: {:?}",
                        e
                    );
                }
            }
            EmptyResponse::ok().into_response()
        }
        Err(ImportError::SizeLimitExceeded) => {
            ApiError::PayloadTooLarge(format!("Import exceeds block limit of {}", max_blocks))
                .into_response()
        }
        Err(ImportError::RepoNotFound) => {
            ApiError::RepoNotFound(Some("Repository not initialized for this account".into()))
                .into_response()
        }
        Err(ImportError::InvalidCbor(msg)) => {
            ApiError::InvalidRequest(format!("Invalid CBOR data: {}", msg)).into_response()
        }
        Err(ImportError::InvalidCommit(msg)) => {
            ApiError::InvalidRequest(format!("Invalid commit structure: {}", msg)).into_response()
        }
        Err(ImportError::BlockNotFound(cid)) => {
            ApiError::InvalidRequest(format!("Referenced block not found in CAR: {}", cid))
                .into_response()
        }
        Err(ImportError::ConcurrentModification) => ApiError::InvalidSwap(Some(
            "Repository is being modified by another operation, please retry".into(),
        ))
        .into_response(),
        Err(ImportError::VerificationFailed(ve)) => {
            ApiError::InvalidRequest(format!("CAR verification failed: {}", ve)).into_response()
        }
        Err(ImportError::DidMismatch { car_did, auth_did }) => ApiError::InvalidRequest(format!(
            "CAR is for {} but authenticated as {}",
            car_did, auth_did
        ))
        .into_response(),
        Err(e) => {
            error!("Import error: {:?}", e);
            ApiError::InternalError(None).into_response()
        }
    }
}

async fn sequence_import_event(
    state: &AppState,
    did: &str,
    commit_cid: &str,
) -> Result<(), sqlx::Error> {
    let prev_cid: Option<String> = None;
    let prev_data_cid: Option<String> = None;
    let ops = serde_json::json!([]);
    let blobs: Vec<String> = vec![];
    let blocks_cids: Vec<String> = vec![];
    let seq_row = sqlx::query!(
        r#"
        INSERT INTO repo_seq (did, event_type, commit_cid, prev_cid, prev_data_cid, ops, blobs, blocks_cids)
        VALUES ($1, 'commit', $2, $3, $4, $5, $6, $7)
        RETURNING seq
        "#,
        did,
        commit_cid,
        prev_cid,
        prev_data_cid,
        ops,
        &blobs,
        &blocks_cids
    )
    .fetch_one(&state.db)
    .await?;
    sqlx::query(&format!("NOTIFY repo_updates, '{}'", seq_row.seq))
        .execute(&state.db)
        .await?;
    Ok(())
}
