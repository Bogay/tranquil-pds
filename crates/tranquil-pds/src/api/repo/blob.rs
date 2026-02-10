use crate::api::error::{ApiError, DbResultExt};
use crate::auth::{Auth, AuthAny, NotTakendown, Permissive, VerifyScope};
use crate::delegation::DelegationActionType;
use crate::state::AppState;
use crate::types::{CidLink, Did};
use crate::util::{get_header_str, get_max_blob_size};
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
    } else {
        match client_hint {
            "" | "*/*" => "application/octet-stream".to_string(),
            hint if hint.starts_with("text/html") || hint.starts_with("application/xhtml") => {
                "application/octet-stream".to_string()
            }
            hint => hint.to_string(),
        }
    }
}

pub async fn upload_blob(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    auth: AuthAny<Permissive>,
    body: Body,
) -> Result<Response, ApiError> {
    let (did, controller_did): (Did, Option<Did>) = match &auth {
        AuthAny::Service(service) => {
            service.require_lxm("com.atproto.repo.uploadBlob")?;
            (service.did.clone(), None)
        }
        AuthAny::User(user) => {
            if user.status.is_takendown() {
                return Err(ApiError::AccountTakedown);
            }
            let mime_type_for_check = get_header_str(&headers, http::header::CONTENT_TYPE)
                .unwrap_or("application/octet-stream");
            let scope_proof = match user.verify_blob_upload(mime_type_for_check) {
                Ok(proof) => proof,
                Err(e) => return Ok(e.into_response()),
            };
            (
                scope_proof.principal_did().into_did(),
                scope_proof.controller_did().map(|c| c.into_did()),
            )
        }
    };

    if state
        .user_repo
        .is_account_migrated(&did)
        .await
        .unwrap_or(false)
    {
        return Err(ApiError::Forbidden);
    }

    let client_mime_hint =
        get_header_str(&headers, http::header::CONTENT_TYPE).unwrap_or("application/octet-stream");

    let user_id = state
        .user_repo
        .get_id_by_did(&did)
        .await
        .log_db_err("fetching user id for blob upload")?
        .ok_or(ApiError::InternalError(None))?;

    let temp_key = format!("temp/{}", uuid::Uuid::new_v4());
    let max_size = u64::try_from(get_max_blob_size()).unwrap_or(u64::MAX);

    let body_stream = body.into_data_stream();
    let mapped_stream =
        body_stream.map(|result| result.map_err(|e| std::io::Error::other(e.to_string())));
    let pinned_stream: Pin<Box<dyn futures::Stream<Item = Result<Bytes, std::io::Error>> + Send>> =
        Box::pin(mapped_stream);

    info!("Starting streaming blob upload to temp key: {}", temp_key);

    let upload_result = state
        .blob_store
        .put_stream(&temp_key, pinned_stream)
        .await
        .map_err(|e| {
            error!("Failed to stream blob to storage: {:?}", e);
            ApiError::InternalError(Some("Failed to store blob".into()))
        })?;

    let size = upload_result.size;
    if size > max_size {
        let _ = state.blob_store.delete(&temp_key).await;
        return Err(ApiError::InvalidRequest(format!(
            "Blob size {} exceeds maximum of {} bytes",
            size, max_size
        )));
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
            return Err(ApiError::InternalError(Some("Failed to hash blob".into())));
        }
    };
    let cid = Cid::new_v1(0x55, multihash);
    let cid_str = cid.to_string();
    let cid_link: CidLink = CidLink::new(&cid_str).map_err(|e| {
        error!("Failed to construct CidLink from computed CID: {:?}", e);
        ApiError::InternalError(Some("Failed to construct CID".into()))
    })?;
    let storage_key = cid_str.clone();

    info!(
        "Blob upload complete: size={}, cid={}, copying to final location",
        size, cid_str
    );

    match state
        .blob_repo
        .insert_blob(
            &cid_link,
            &mime_type,
            i64::try_from(size).unwrap_or(i64::MAX),
            user_id,
            &storage_key,
        )
        .await
    {
        Ok(_) => {}
        Err(e) => {
            let _ = state.blob_store.delete(&temp_key).await;
            error!("Failed to insert blob record: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    };

    if let Err(e) = state.blob_store.copy(&temp_key, &storage_key).await {
        let _ = state.blob_store.delete(&temp_key).await;
        if let Err(db_err) = state.blob_repo.delete_blob_by_cid(&cid_link).await {
            error!(
                "Failed to clean up orphaned blob record after copy failure: {:?}",
                db_err
            );
        }
        error!("Failed to copy blob to final location: {:?}", e);
        return Err(ApiError::InternalError(Some("Failed to store blob".into())));
    }

    let _ = state.blob_store.delete(&temp_key).await;

    if let Some(ref controller) = controller_did
        && let Err(e) = state
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
            .await
    {
        warn!("Failed to log delegation action for blob upload: {:?}", e);
    }

    Ok(Json(json!({
        "blob": {
            "$type": "blob",
            "ref": {
                "$link": cid_str
            },
            "mimeType": mime_type,
            "size": size
        }
    }))
    .into_response())
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
    auth: Auth<NotTakendown>,
    Query(params): Query<ListMissingBlobsParams>,
) -> Result<Response, ApiError> {
    let did = &auth.did;
    let user = state
        .user_repo
        .get_by_did(did)
        .await
        .log_db_err("fetching user")?
        .ok_or(ApiError::InternalError(None))?;

    let limit = params.limit.unwrap_or(500).clamp(1, 1000);
    let cursor = params.cursor.as_deref();
    let missing = state
        .blob_repo
        .list_missing_blobs(user.id, cursor, limit + 1)
        .await
        .log_db_err("fetching missing blobs")?;

    let limit_usize = usize::try_from(limit).unwrap_or(0);
    let has_more = missing.len() > limit_usize;
    let blobs: Vec<RecordBlob> = missing
        .into_iter()
        .take(limit_usize)
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
    Ok((
        StatusCode::OK,
        Json(ListMissingBlobsOutput {
            cursor: next_cursor,
            blobs,
        }),
    )
        .into_response())
}
