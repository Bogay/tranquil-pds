use crate::auth::{ServiceTokenVerifier, is_service_token};
use crate::delegation::{self, DelegationActionType};
use crate::state::AppState;
use crate::util::get_max_blob_size;
use axum::body::Bytes;
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use cid::Cid;
use multihash::Multihash;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{debug, error};

pub async fn upload_blob(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationRequired"})),
            )
                .into_response();
        }
    };

    let is_service_auth = is_service_token(&token);

    let (did, _is_migration, controller_did) = if is_service_auth {
        debug!("Verifying service token for blob upload");
        let verifier = ServiceTokenVerifier::new();
        match verifier
            .verify_service_token(&token, Some("com.atproto.repo.uploadBlob"))
            .await
        {
            Ok(claims) => {
                debug!("Service token verified for DID: {}", claims.iss);
                (claims.iss, false, None)
            }
            Err(e) => {
                error!("Service token verification failed: {:?}", e);
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "AuthenticationFailed", "message": format!("Service token verification failed: {}", e)})),
                )
                    .into_response();
            }
        }
    } else {
        match crate::auth::validate_bearer_token_allow_deactivated(&state.db, &token).await {
            Ok(user) => {
                let mime_type_for_check = headers
                    .get("content-type")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("application/octet-stream");
                if let Err(e) = crate::auth::scope_check::check_blob_scope(
                    user.is_oauth,
                    user.scope.as_deref(),
                    mime_type_for_check,
                ) {
                    return e;
                }
                let deactivated = sqlx::query_scalar!(
                    "SELECT deactivated_at FROM users WHERE did = $1",
                    user.did
                )
                .fetch_optional(&state.db)
                .await
                .ok()
                .flatten()
                .flatten();
                let ctrl_did = user.controller_did.clone();
                (user.did, deactivated.is_some(), ctrl_did)
            }
            Err(_) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "AuthenticationFailed"})),
                )
                    .into_response();
            }
        }
    };

    if crate::util::is_account_migrated(&state.db, &did)
        .await
        .unwrap_or(false)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "AccountMigrated",
                "message": "Account has been migrated to another PDS. Blob operations are not allowed."
            })),
        )
            .into_response();
    }

    let max_size = get_max_blob_size();

    if body.len() > max_size {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({"error": "BlobTooLarge", "message": format!("Blob size {} exceeds maximum of {} bytes", body.len(), max_size)})),
        )
            .into_response();
    }
    let mime_type = headers
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let size = body.len() as i64;
    let data = body.to_vec();
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let hash = hasher.finalize();
    let multihash = match Multihash::wrap(0x12, &hash) {
        Ok(mh) => mh,
        Err(e) => {
            error!("Failed to create multihash for blob: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Failed to hash blob"})),
            )
                .into_response();
        }
    };
    let cid = Cid::new_v1(0x55, multihash);
    let cid_str = cid.to_string();
    let storage_key = format!("blobs/{}", cid_str);
    let user_query = sqlx::query!("SELECT id FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await;
    let user_id = match user_query {
        Ok(Some(row)) => row.id,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            error!("Failed to begin transaction: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let insert = sqlx::query!(
        "INSERT INTO blobs (cid, mime_type, size_bytes, created_by_user, storage_key) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (cid) DO NOTHING RETURNING cid",
        cid_str,
        mime_type,
        size,
        user_id,
        storage_key
    )
    .fetch_optional(&mut *tx)
    .await;
    let was_inserted = match insert {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(e) => {
            error!("Failed to insert blob record: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    if was_inserted
        && let Err(e) = state
            .blob_store
            .put_bytes(&storage_key, bytes::Bytes::from(data))
            .await
    {
        error!("Failed to upload blob to storage: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError", "message": "Failed to store blob"})),
        )
            .into_response();
    }
    if let Err(e) = tx.commit().await {
        error!("Failed to commit blob transaction: {:?}", e);
        if was_inserted && let Err(cleanup_err) = state.blob_store.delete(&storage_key).await {
            error!(
                "Failed to cleanup orphaned blob {}: {:?}",
                storage_key, cleanup_err
            );
        }
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    if let Some(ref controller) = controller_did {
        let _ = delegation::log_delegation_action(
            &state.db,
            &did,
            controller,
            Some(controller),
            DelegationActionType::BlobUpload,
            Some(json!({
                "cid": cid_str,
                "mime_type": mime_type,
                "size": size
            })),
            None,
            None,
        )
        .await;
    }

    Json(json!({
        "blob": {
            "$type": "blob",
            "ref": {
                "$link": cid_str
            },
            "mimeType": mime_type,
            "size": size
        }
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct ListMissingBlobsParams {
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordBlob {
    pub cid: String,
    pub record_uri: String,
}

#[derive(Serialize)]
pub struct ListMissingBlobsOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    pub blobs: Vec<RecordBlob>,
}

pub async fn list_missing_blobs(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<ListMissingBlobsParams>,
) -> Response {
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationRequired"})),
            )
                .into_response();
        }
    };
    let auth_user =
        match crate::auth::validate_bearer_token_allow_deactivated(&state.db, &token).await {
            Ok(user) => user,
            Err(_) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "AuthenticationFailed"})),
                )
                    .into_response();
            }
        };
    let did = auth_user.did;
    let user_query = sqlx::query!("SELECT id FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await;
    let user_id = match user_query {
        Ok(Some(row)) => row.id,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let limit = params.limit.unwrap_or(500).clamp(1, 1000);
    let cursor_cid = params.cursor.as_deref().unwrap_or("");
    let missing_query = sqlx::query!(
        r#"
        SELECT rb.blob_cid, rb.record_uri
        FROM record_blobs rb
        LEFT JOIN blobs b ON rb.blob_cid = b.cid AND b.created_by_user = rb.repo_id
        WHERE rb.repo_id = $1 AND b.cid IS NULL AND rb.blob_cid > $2
        ORDER BY rb.blob_cid
        LIMIT $3
        "#,
        user_id,
        cursor_cid,
        limit + 1
    )
    .fetch_all(&state.db)
    .await;
    let rows = match missing_query {
        Ok(r) => r,
        Err(e) => {
            error!("DB error fetching missing blobs: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let has_more = rows.len() > limit as usize;
    let blobs: Vec<RecordBlob> = rows
        .into_iter()
        .take(limit as usize)
        .map(|row| RecordBlob {
            cid: row.blob_cid,
            record_uri: row.record_uri,
        })
        .collect();
    let next_cursor = if has_more {
        blobs.last().map(|b| b.cid.clone())
    } else {
        None
    };
    (
        StatusCode::OK,
        Json(ListMissingBlobsOutput {
            cursor: next_cursor,
            blobs,
        }),
    )
        .into_response()
}
