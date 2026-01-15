use crate::api::error::ApiError;
use crate::auth::BearerAuthAdmin;
use crate::state::AppState;
use crate::types::{CidLink, Did};
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{error, warn};

#[derive(Deserialize)]
pub struct GetSubjectStatusParams {
    pub did: Option<String>,
    pub uri: Option<String>,
    pub blob: Option<String>,
}

#[derive(Serialize)]
pub struct SubjectStatus {
    pub subject: serde_json::Value,
    pub takedown: Option<StatusAttr>,
    pub deactivated: Option<StatusAttr>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusAttr {
    pub applied: bool,
    pub r#ref: Option<String>,
}

pub async fn get_subject_status(
    State(state): State<AppState>,
    _auth: BearerAuthAdmin,
    Query(params): Query<GetSubjectStatusParams>,
) -> Response {
    if params.did.is_none() && params.uri.is_none() && params.blob.is_none() {
        return ApiError::InvalidRequest("Must provide did, uri, or blob".into()).into_response();
    }
    if let Some(did_str) = &params.did {
        let did: Did = match did_str.parse() {
            Ok(d) => d,
            Err(_) => return ApiError::InvalidDid("Invalid DID format".into()).into_response(),
        };
        match state.user_repo.get_status_by_did(&did).await {
            Ok(Some(status)) => {
                let deactivated = status.deactivated_at.map(|_| StatusAttr {
                    applied: true,
                    r#ref: None,
                });
                let takedown = status.takedown_ref.as_ref().map(|r| StatusAttr {
                    applied: true,
                    r#ref: Some(r.clone()),
                });
                return (
                    StatusCode::OK,
                    Json(SubjectStatus {
                        subject: json!({
                            "$type": "com.atproto.admin.defs#repoRef",
                            "did": did_str
                        }),
                        takedown,
                        deactivated,
                    }),
                )
                    .into_response();
            }
            Ok(None) => {
                return ApiError::SubjectNotFound.into_response();
            }
            Err(e) => {
                error!("DB error in get_subject_status: {:?}", e);
                return ApiError::InternalError(None).into_response();
            }
        }
    }
    if let Some(uri_str) = &params.uri {
        let cid: CidLink = match uri_str.parse() {
            Ok(c) => c,
            Err(_) => return ApiError::InvalidRequest("Invalid CID format".into()).into_response(),
        };
        match state.repo_repo.get_record_by_cid(&cid).await {
            Ok(Some(record)) => {
                let takedown = record.takedown_ref.as_ref().map(|r| StatusAttr {
                    applied: true,
                    r#ref: Some(r.clone()),
                });
                return (
                    StatusCode::OK,
                    Json(SubjectStatus {
                        subject: json!({
                            "$type": "com.atproto.repo.strongRef",
                            "uri": uri_str,
                            "cid": uri_str
                        }),
                        takedown,
                        deactivated: None,
                    }),
                )
                    .into_response();
            }
            Ok(None) => {
                return ApiError::RecordNotFound.into_response();
            }
            Err(e) => {
                error!("DB error in get_subject_status: {:?}", e);
                return ApiError::InternalError(None).into_response();
            }
        }
    }
    if let Some(blob_cid_str) = &params.blob {
        let blob_cid: CidLink = match blob_cid_str.parse() {
            Ok(c) => c,
            Err(_) => return ApiError::InvalidRequest("Invalid CID format".into()).into_response(),
        };
        let did = match &params.did {
            Some(d) => d,
            None => {
                return ApiError::InvalidRequest("Must provide a did to request blob state".into())
                    .into_response();
            }
        };
        match state.blob_repo.get_blob_with_takedown(&blob_cid).await {
            Ok(Some(blob)) => {
                let takedown = blob.takedown_ref.as_ref().map(|r| StatusAttr {
                    applied: true,
                    r#ref: Some(r.clone()),
                });
                return (
                    StatusCode::OK,
                    Json(SubjectStatus {
                        subject: json!({
                            "$type": "com.atproto.admin.defs#repoBlobRef",
                            "did": did,
                            "cid": blob.cid
                        }),
                        takedown,
                        deactivated: None,
                    }),
                )
                    .into_response();
            }
            Ok(None) => {
                return ApiError::BlobNotFound(None).into_response();
            }
            Err(e) => {
                error!("DB error in get_subject_status: {:?}", e);
                return ApiError::InternalError(None).into_response();
            }
        }
    }
    ApiError::InvalidRequest("Invalid subject type".into()).into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateSubjectStatusInput {
    pub subject: serde_json::Value,
    pub takedown: Option<StatusAttrInput>,
    pub deactivated: Option<StatusAttrInput>,
}

#[derive(Deserialize)]
pub struct StatusAttrInput {
    pub applied: bool,
    pub r#ref: Option<String>,
}

pub async fn update_subject_status(
    State(state): State<AppState>,
    _auth: BearerAuthAdmin,
    Json(input): Json<UpdateSubjectStatusInput>,
) -> Response {
    let subject_type = input.subject.get("$type").and_then(|t| t.as_str());
    match subject_type {
        Some("com.atproto.admin.defs#repoRef") => {
            let did_str = input.subject.get("did").and_then(|d| d.as_str());
            if let Some(did_str) = did_str {
                let did = Did::new_unchecked(did_str);
                if let Some(takedown) = &input.takedown {
                    let takedown_ref = if takedown.applied {
                        takedown.r#ref.as_deref()
                    } else {
                        None
                    };
                    if let Err(e) = state.user_repo.set_user_takedown(&did, takedown_ref).await {
                        error!("Failed to update user takedown status for {}: {:?}", did, e);
                        return ApiError::InternalError(Some(
                            "Failed to update takedown status".into(),
                        ))
                        .into_response();
                    }
                }
                if let Some(deactivated) = &input.deactivated {
                    let result = if deactivated.applied {
                        state.user_repo.deactivate_account(&did, None).await
                    } else {
                        state.user_repo.activate_account(&did).await
                    };
                    if let Err(e) = result {
                        error!(
                            "Failed to update user deactivation status for {}: {:?}",
                            did, e
                        );
                        return ApiError::InternalError(Some(
                            "Failed to update deactivation status".into(),
                        ))
                        .into_response();
                    }
                }
                if let Some(takedown) = &input.takedown {
                    let status = if takedown.applied {
                        Some("takendown")
                    } else {
                        None
                    };
                    if let Err(e) = crate::api::repo::record::sequence_account_event(
                        &state,
                        &did,
                        !takedown.applied,
                        status,
                    )
                    .await
                    {
                        warn!("Failed to sequence account event for takedown: {}", e);
                    }
                }
                if let Some(deactivated) = &input.deactivated {
                    let status = if deactivated.applied {
                        Some("deactivated")
                    } else {
                        None
                    };
                    if let Err(e) = crate::api::repo::record::sequence_account_event(
                        &state,
                        &did,
                        !deactivated.applied,
                        status,
                    )
                    .await
                    {
                        warn!("Failed to sequence account event for deactivation: {}", e);
                    }
                }
                if let Ok(Some(handle)) = state.user_repo.get_handle_by_did(&did).await {
                    let _ = state.cache.delete(&format!("handle:{}", handle)).await;
                }
                return (
                    StatusCode::OK,
                    Json(json!({
                        "subject": input.subject,
                        "takedown": input.takedown.as_ref().map(|t| json!({
                            "applied": t.applied,
                            "ref": t.r#ref
                        })),
                        "deactivated": input.deactivated.as_ref().map(|d| json!({
                            "applied": d.applied
                        }))
                    })),
                )
                    .into_response();
            }
        }
        Some("com.atproto.repo.strongRef") => {
            let uri_str = input.subject.get("uri").and_then(|u| u.as_str());
            if let Some(uri_str) = uri_str {
                let cid: CidLink = match uri_str.parse() {
                    Ok(c) => c,
                    Err(_) => {
                        return ApiError::InvalidRequest("Invalid CID format".into())
                            .into_response();
                    }
                };
                if let Some(takedown) = &input.takedown {
                    let takedown_ref = if takedown.applied {
                        takedown.r#ref.as_deref()
                    } else {
                        None
                    };
                    if let Err(e) = state
                        .repo_repo
                        .set_record_takedown(&cid, takedown_ref)
                        .await
                    {
                        error!(
                            "Failed to update record takedown status for {}: {:?}",
                            uri_str, e
                        );
                        return ApiError::InternalError(Some(
                            "Failed to update takedown status".into(),
                        ))
                        .into_response();
                    }
                }
                return (
                    StatusCode::OK,
                    Json(json!({
                        "subject": input.subject,
                        "takedown": input.takedown.as_ref().map(|t| json!({
                            "applied": t.applied,
                            "ref": t.r#ref
                        }))
                    })),
                )
                    .into_response();
            }
        }
        Some("com.atproto.admin.defs#repoBlobRef") => {
            let cid_str = input.subject.get("cid").and_then(|c| c.as_str());
            if let Some(cid_str) = cid_str {
                let cid: CidLink = match cid_str.parse() {
                    Ok(c) => c,
                    Err(_) => {
                        return ApiError::InvalidRequest("Invalid CID format".into())
                            .into_response();
                    }
                };
                if let Some(takedown) = &input.takedown {
                    let takedown_ref = if takedown.applied {
                        takedown.r#ref.as_deref()
                    } else {
                        None
                    };
                    if let Err(e) = state
                        .blob_repo
                        .update_blob_takedown(&cid, takedown_ref)
                        .await
                    {
                        error!(
                            "Failed to update blob takedown status for {}: {:?}",
                            cid_str, e
                        );
                        return ApiError::InternalError(Some(
                            "Failed to update takedown status".into(),
                        ))
                        .into_response();
                    }
                }
                return (
                    StatusCode::OK,
                    Json(json!({
                        "subject": input.subject,
                        "takedown": input.takedown.as_ref().map(|t| json!({
                            "applied": t.applied,
                            "ref": t.r#ref
                        }))
                    })),
                )
                    .into_response();
            }
        }
        _ => {}
    }
    ApiError::InvalidRequest("Invalid subject type".into()).into_response()
}
