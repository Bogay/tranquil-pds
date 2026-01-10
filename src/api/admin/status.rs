use crate::api::error::ApiError;
use crate::auth::BearerAuthAdmin;
use crate::state::AppState;
use crate::types::Did;
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
    if let Some(did) = &params.did {
        let user = sqlx::query!(
            "SELECT did, deactivated_at, takedown_ref FROM users WHERE did = $1",
            did
        )
        .fetch_optional(&state.db)
        .await;
        match user {
            Ok(Some(row)) => {
                let deactivated = row.deactivated_at.map(|_| StatusAttr {
                    applied: true,
                    r#ref: None,
                });
                let takedown = row.takedown_ref.as_ref().map(|r| StatusAttr {
                    applied: true,
                    r#ref: Some(r.clone()),
                });
                return (
                    StatusCode::OK,
                    Json(SubjectStatus {
                        subject: json!({
                            "$type": "com.atproto.admin.defs#repoRef",
                            "did": row.did
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
    if let Some(uri) = &params.uri {
        let record = sqlx::query!(
            "SELECT r.id, r.takedown_ref FROM records r WHERE r.record_cid = $1",
            uri
        )
        .fetch_optional(&state.db)
        .await;
        match record {
            Ok(Some(row)) => {
                let takedown = row.takedown_ref.as_ref().map(|r| StatusAttr {
                    applied: true,
                    r#ref: Some(r.clone()),
                });
                return (
                    StatusCode::OK,
                    Json(SubjectStatus {
                        subject: json!({
                            "$type": "com.atproto.repo.strongRef",
                            "uri": uri,
                            "cid": uri
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
    if let Some(blob_cid) = &params.blob {
        let did = match &params.did {
            Some(d) => d,
            None => {
                return ApiError::InvalidRequest("Must provide a did to request blob state".into())
                    .into_response();
            }
        };
        let blob = sqlx::query!(
            "SELECT cid, takedown_ref FROM blobs WHERE cid = $1",
            blob_cid
        )
        .fetch_optional(&state.db)
        .await;
        match blob {
            Ok(Some(row)) => {
                let takedown = row.takedown_ref.as_ref().map(|r| StatusAttr {
                    applied: true,
                    r#ref: Some(r.clone()),
                });
                return (
                    StatusCode::OK,
                    Json(SubjectStatus {
                        subject: json!({
                            "$type": "com.atproto.admin.defs#repoBlobRef",
                            "did": did,
                            "cid": row.cid
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
                let mut tx = match state.db.begin().await {
                    Ok(tx) => tx,
                    Err(e) => {
                        error!("Failed to begin transaction: {:?}", e);
                        return ApiError::InternalError(None).into_response();
                    }
                };
                if let Some(takedown) = &input.takedown {
                    let takedown_ref = if takedown.applied {
                        takedown.r#ref.clone()
                    } else {
                        None
                    };
                    if let Err(e) = sqlx::query!(
                        "UPDATE users SET takedown_ref = $1 WHERE did = $2",
                        takedown_ref,
                        did.as_str()
                    )
                    .execute(&mut *tx)
                    .await
                    {
                        error!("Failed to update user takedown status for {}: {:?}", did, e);
                        return ApiError::InternalError(Some(
                            "Failed to update takedown status".into(),
                        ))
                        .into_response();
                    }
                }
                if let Some(deactivated) = &input.deactivated {
                    let result = if deactivated.applied {
                        sqlx::query!(
                            "UPDATE users SET deactivated_at = NOW() WHERE did = $1",
                            did.as_str()
                        )
                        .execute(&mut *tx)
                        .await
                    } else {
                        sqlx::query!("UPDATE users SET deactivated_at = NULL WHERE did = $1", did.as_str())
                            .execute(&mut *tx)
                            .await
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
                if let Err(e) = tx.commit().await {
                    error!("Failed to commit transaction: {:?}", e);
                    return ApiError::InternalError(None).into_response();
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
                if let Ok(Some(handle)) =
                    sqlx::query_scalar!("SELECT handle FROM users WHERE did = $1", did.as_str())
                        .fetch_optional(&state.db)
                        .await
                {
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
            let uri = input.subject.get("uri").and_then(|u| u.as_str());
            if let Some(uri) = uri {
                if let Some(takedown) = &input.takedown {
                    let takedown_ref = if takedown.applied {
                        takedown.r#ref.clone()
                    } else {
                        None
                    };
                    if let Err(e) = sqlx::query!(
                        "UPDATE records SET takedown_ref = $1 WHERE record_cid = $2",
                        takedown_ref,
                        uri
                    )
                    .execute(&state.db)
                    .await
                    {
                        error!(
                            "Failed to update record takedown status for {}: {:?}",
                            uri, e
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
            let cid = input.subject.get("cid").and_then(|c| c.as_str());
            if let Some(cid) = cid {
                if let Some(takedown) = &input.takedown {
                    let takedown_ref = if takedown.applied {
                        takedown.r#ref.clone()
                    } else {
                        None
                    };
                    if let Err(e) = sqlx::query!(
                        "UPDATE blobs SET takedown_ref = $1 WHERE cid = $2",
                        takedown_ref,
                        cid
                    )
                    .execute(&state.db)
                    .await
                    {
                        error!("Failed to update blob takedown status for {}: {:?}", cid, e);
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
