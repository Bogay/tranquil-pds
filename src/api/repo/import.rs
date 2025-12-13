use crate::api::ApiError;
use crate::state::AppState;
use crate::sync::import::{apply_import, parse_car, ImportError};
use crate::sync::verify::CarVerifier;
use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use tracing::{debug, error, info, warn};

const DEFAULT_MAX_IMPORT_SIZE: usize = 100 * 1024 * 1024;
const DEFAULT_MAX_BLOCKS: usize = 50000;

pub async fn import_repo(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    let accepting_imports = std::env::var("ACCEPTING_REPO_IMPORTS")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true);

    if !accepting_imports {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "InvalidRequest",
                "message": "Service is not accepting repo imports"
            })),
        )
            .into_response();
    }

    let max_size: usize = std::env::var("MAX_IMPORT_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_IMPORT_SIZE);

    if body.len() > max_size {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({
                "error": "InvalidRequest",
                "message": format!("Import size exceeds limit of {} bytes", max_size)
            })),
        )
            .into_response();
    }

    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => return ApiError::AuthenticationRequired.into_response(),
    };

    let auth_user = match crate::auth::validate_bearer_token(&state.db, &token).await {
        Ok(user) => user,
        Err(e) => return ApiError::from(e).into_response(),
    };

    let did = &auth_user.did;

    let user = match sqlx::query!(
        "SELECT id, deactivated_at, takedown_ref FROM users WHERE did = $1",
        did
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "AccountNotFound"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error fetching user: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    if user.deactivated_at.is_some() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "AccountDeactivated",
                "message": "Account is deactivated"
            })),
        )
            .into_response();
    }

    if user.takedown_ref.is_some() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "AccountTakenDown",
                "message": "Account has been taken down"
            })),
        )
            .into_response();
    }

    let user_id = user.id;

    let (root, blocks) = match parse_car(&body).await {
        Ok((r, b)) => (r, b),
        Err(ImportError::InvalidRootCount) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "InvalidRequest",
                    "message": "Expected exactly one root in CAR file"
                })),
            )
                .into_response();
        }
        Err(ImportError::CarParse(msg)) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "InvalidRequest",
                    "message": format!("Failed to parse CAR file: {}", msg)
                })),
            )
                .into_response();
        }
        Err(e) => {
            error!("CAR parsing error: {:?}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "InvalidRequest",
                    "message": format!("Invalid CAR file: {}", e)
                })),
            )
                .into_response();
        }
    };

    info!(
        "Importing repo for user {}: {} blocks, root {}",
        did,
        blocks.len(),
        root
    );

    let root_block = match blocks.get(&root) {
        Some(b) => b,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "InvalidRequest",
                    "message": "Root block not found in CAR file"
                })),
            )
                .into_response();
        }
    };

    let commit_did = match jacquard_repo::commit::Commit::from_cbor(root_block) {
        Ok(commit) => commit.did().to_string(),
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "InvalidRequest",
                    "message": format!("Invalid commit: {}", e)
                })),
            )
                .into_response();
        }
    };

    if commit_did != *did {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "InvalidRequest",
                "message": format!(
                    "CAR file is for DID {} but you are authenticated as {}",
                    commit_did, did
                )
            })),
        )
            .into_response();
    }

    let skip_verification = std::env::var("SKIP_IMPORT_VERIFICATION")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    if !skip_verification {
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
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "error": "InvalidRequest",
                        "message": format!(
                            "CAR file is for DID {} but you are authenticated as {}",
                            commit_did, expected_did
                        )
                    })),
                )
                    .into_response();
            }
            Err(crate::sync::verify::VerifyError::InvalidSignature) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "InvalidSignature",
                        "message": "CAR file commit signature verification failed"
                    })),
                )
                    .into_response();
            }
            Err(crate::sync::verify::VerifyError::DidResolutionFailed(msg)) => {
                warn!("DID resolution failed during import verification: {}", msg);
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "InvalidRequest",
                        "message": format!("Failed to verify DID: {}", msg)
                    })),
                )
                    .into_response();
            }
            Err(crate::sync::verify::VerifyError::NoSigningKey) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "InvalidRequest",
                        "message": "DID document does not contain a signing key"
                    })),
                )
                    .into_response();
            }
            Err(crate::sync::verify::VerifyError::MstValidationFailed(msg)) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "InvalidRequest",
                        "message": format!("MST validation failed: {}", msg)
                    })),
                )
                    .into_response();
            }
            Err(e) => {
                error!("CAR verification error: {:?}", e);
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "InvalidRequest",
                        "message": format!("CAR verification failed: {}", e)
                    })),
                )
                    .into_response();
            }
        }
    } else {
        warn!("Skipping CAR signature verification for import (SKIP_IMPORT_VERIFICATION=true)");
    }

    let max_blocks: usize = std::env::var("MAX_IMPORT_BLOCKS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_BLOCKS);

    match apply_import(&state.db, user_id, root, blocks, max_blocks).await {
        Ok(records) => {
            info!(
                "Successfully imported {} records for user {}",
                records.len(),
                did
            );

            if let Err(e) = sequence_import_event(&state, did, &root.to_string()).await {
                warn!("Failed to sequence import event: {:?}", e);
            }

            (StatusCode::OK, Json(json!({}))).into_response()
        }
        Err(ImportError::SizeLimitExceeded) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "InvalidRequest",
                "message": format!("Import exceeds block limit of {}", max_blocks)
            })),
        )
            .into_response(),
        Err(ImportError::RepoNotFound) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "RepoNotFound",
                "message": "Repository not initialized for this account"
            })),
        )
            .into_response(),
        Err(ImportError::InvalidCbor(msg)) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "InvalidRequest",
                "message": format!("Invalid CBOR data: {}", msg)
            })),
        )
            .into_response(),
        Err(ImportError::InvalidCommit(msg)) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "InvalidRequest",
                "message": format!("Invalid commit structure: {}", msg)
            })),
        )
            .into_response(),
        Err(ImportError::BlockNotFound(cid)) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "InvalidRequest",
                "message": format!("Referenced block not found in CAR: {}", cid)
            })),
        )
            .into_response(),
        Err(ImportError::ConcurrentModification) => (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "ConcurrentModification",
                "message": "Repository is being modified by another operation, please retry"
            })),
        )
            .into_response(),
        Err(ImportError::VerificationFailed(ve)) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "VerificationFailed",
                "message": format!("CAR verification failed: {}", ve)
            })),
        )
            .into_response(),
        Err(ImportError::DidMismatch { car_did, auth_did }) => (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "DidMismatch",
                "message": format!("CAR is for {} but authenticated as {}", car_did, auth_did)
            })),
        )
            .into_response(),
        Err(e) => {
            error!("Import error: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

async fn sequence_import_event(
    state: &AppState,
    did: &str,
    commit_cid: &str,
) -> Result<(), sqlx::Error> {
    let prev_cid: Option<String> = None;
    let ops = serde_json::json!([]);
    let blobs: Vec<String> = vec![];
    let blocks_cids: Vec<String> = vec![];

    let seq_row = sqlx::query!(
        r#"
        INSERT INTO repo_seq (did, event_type, commit_cid, prev_cid, ops, blobs, blocks_cids)
        VALUES ($1, 'commit', $2, $3, $4, $5, $6)
        RETURNING seq
        "#,
        did,
        commit_cid,
        prev_cid,
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
