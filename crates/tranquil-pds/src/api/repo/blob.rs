use crate::api::error::ApiError;
use crate::auth::{BearerAuthAllowDeactivated, ServiceTokenVerifier, is_service_token};
use crate::delegation::DelegationActionType;
use crate::state::AppState;
use crate::types::{CidLink, Did};
use crate::util::get_max_blob_size;
use axum::body::Body;
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use cid::Cid;
use futures::StreamExt;
use multihash::Multihash;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::pin::Pin;
use tracing::{debug, error, info, warn};

fn detect_mime_type(data: &[u8], client_hint: &str) -> String {
    if let Some(kind) = infer::get(data) {
        let detected = kind.mime_type().to_string();
        if detected != client_hint {
            debug!(
                "MIME type detection: client sent '{}', detected '{}'",
                client_hint, detected
            );
        }
        detected
    } else if client_hint == "*/*" || client_hint.is_empty() {
        warn!(
            "Could not detect MIME type and client sent invalid hint: '{}'",
            client_hint
        );
        "application/octet-stream".to_string()
    } else {
        client_hint.to_string()
    }
}

pub async fn upload_blob(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: Body,
) -> Response {
    let extracted = match crate::auth::extract_auth_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => return ApiError::AuthenticationRequired.into_response(),
    };
    let token = extracted.token;

    let is_service_auth = is_service_token(&token);

    let (did, _is_migration, controller_did): (Did, bool, Option<Did>) = if is_service_auth {
        debug!("Verifying service token for blob upload");
        let verifier = ServiceTokenVerifier::new();
        match verifier
            .verify_service_token(&token, Some("com.atproto.repo.uploadBlob"))
            .await
        {
            Ok(claims) => {
                debug!("Service token verified for DID: {}", claims.iss);
                let did: Did = match claims.iss.parse() {
                    Ok(d) => d,
                    Err(_) => {
                        return ApiError::InvalidDid("Invalid DID format".into()).into_response();
                    }
                };
                (did, false, None)
            }
            Err(e) => {
                error!("Service token verification failed: {:?}", e);
                return ApiError::AuthenticationFailed(Some(format!(
                    "Service token verification failed: {}",
                    e
                )))
                .into_response();
            }
        }
    } else {
        let dpop_proof = headers.get("DPoP").and_then(|h| h.to_str().ok());
        let http_uri = format!(
            "https://{}/xrpc/com.atproto.repo.uploadBlob",
            std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string())
        );
        match crate::auth::validate_token_with_dpop(
            state.user_repo.as_ref(),
            state.oauth_repo.as_ref(),
            &token,
            extracted.is_dpop,
            dpop_proof,
            "POST",
            &http_uri,
            true,
            false,
        )
        .await
        {
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
                let deactivated = state
                    .user_repo
                    .get_status_by_did(&user.did)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|s| s.deactivated_at);
                let ctrl_did = user.controller_did.clone();
                (user.did, deactivated.is_some(), ctrl_did)
            }
            Err(_) => {
                return ApiError::AuthenticationFailed(None).into_response();
            }
        }
    };

    if state
        .user_repo
        .is_account_migrated(&did)
        .await
        .unwrap_or(false)
    {
        return ApiError::Forbidden.into_response();
    }

    let client_mime_hint = headers
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("application/octet-stream");

    let user_id = match state.user_repo.get_id_by_did(&did).await {
        Ok(Some(id)) => id,
        _ => {
            return ApiError::InternalError(None).into_response();
        }
    };

    let temp_key = format!("temp/{}", uuid::Uuid::new_v4());
    let max_size = get_max_blob_size() as u64;

    let body_stream = body.into_data_stream();
    let mapped_stream =
        body_stream.map(|result| result.map_err(|e| std::io::Error::other(e.to_string())));
    let pinned_stream: Pin<Box<dyn futures::Stream<Item = Result<Bytes, std::io::Error>> + Send>> =
        Box::pin(mapped_stream);

    info!("Starting streaming blob upload to temp key: {}", temp_key);

    let upload_result = match state.blob_store.put_stream(&temp_key, pinned_stream).await {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to stream blob to storage: {:?}", e);
            return ApiError::InternalError(Some("Failed to store blob".into())).into_response();
        }
    };

    let size = upload_result.size;
    if size > max_size {
        let _ = state.blob_store.delete(&temp_key).await;
        return ApiError::InvalidRequest(format!(
            "Blob size {} exceeds maximum of {} bytes",
            size, max_size
        ))
        .into_response();
    }

    let mime_type = match state.blob_store.get_head(&temp_key, 8192).await {
        Ok(head_bytes) => detect_mime_type(&head_bytes, client_mime_hint),
        Err(e) => {
            warn!("Failed to read blob head for MIME detection: {:?}", e);
            client_mime_hint.to_string()
        }
    };

    let multihash = match Multihash::wrap(0x12, &upload_result.sha256_hash) {
        Ok(mh) => mh,
        Err(e) => {
            let _ = state.blob_store.delete(&temp_key).await;
            error!("Failed to create multihash for blob: {:?}", e);
            return ApiError::InternalError(Some("Failed to hash blob".into())).into_response();
        }
    };
    let cid = Cid::new_v1(0x55, multihash);
    let cid_str = cid.to_string();
    let cid_link: CidLink = CidLink::new_unchecked(&cid_str);
    let storage_key = format!("blobs/{}", cid_str);

    info!(
        "Blob upload complete: size={}, cid={}, copying to final location",
        size, cid_str
    );

    let was_inserted = match state
        .blob_repo
        .insert_blob(&cid_link, &mime_type, size as i64, user_id, &storage_key)
        .await
    {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(e) => {
            let _ = state.blob_store.delete(&temp_key).await;
            error!("Failed to insert blob record: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    if was_inserted && let Err(e) = state.blob_store.copy(&temp_key, &storage_key).await {
        let _ = state.blob_store.delete(&temp_key).await;
        error!("Failed to copy blob to final location: {:?}", e);
        return ApiError::InternalError(Some("Failed to store blob".into())).into_response();
    }

    let _ = state.blob_store.delete(&temp_key).await;

    if let Some(ref controller) = controller_did {
        let _ = state
            .delegation_repo
            .log_delegation_action(
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
    auth: BearerAuthAllowDeactivated,
    Query(params): Query<ListMissingBlobsParams>,
) -> Response {
    let auth_user = auth.0;
    let did = &auth_user.did;
    let user = match state.user_repo.get_by_did(did).await {
        Ok(Some(u)) => u,
        Ok(None) => return ApiError::InternalError(None).into_response(),
        Err(e) => {
            error!("DB error fetching user: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let limit = params.limit.unwrap_or(500).clamp(1, 1000);
    let cursor = params.cursor.as_deref();
    let missing = match state
        .blob_repo
        .list_missing_blobs(user.id, cursor, limit + 1)
        .await
    {
        Ok(m) => m,
        Err(e) => {
            error!("DB error fetching missing blobs: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let has_more = missing.len() > limit as usize;
    let blobs: Vec<RecordBlob> = missing
        .into_iter()
        .take(limit as usize)
        .map(|m| RecordBlob {
            cid: m.blob_cid.to_string(),
            record_uri: m.record_uri.to_string(),
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
