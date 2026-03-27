use axum::{
    Json,
    extract::{Query, State},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::{error, warn};
use tranquil_pds::api::error::ApiError;
use tranquil_pds::auth::{Admin, Auth};
use tranquil_pds::state::AppState;
use tranquil_pds::types::{CidLink, Did};

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
    _auth: Auth<Admin>,
    Query(params): Query<GetSubjectStatusParams>,
) -> Result<Json<SubjectStatus>, ApiError> {
    if params.did.is_none() && params.uri.is_none() && params.blob.is_none() {
        return Err(ApiError::InvalidRequest(
            "Must provide did, uri, or blob".into(),
        ));
    }
    if let Some(did_str) = &params.did {
        let did: Did = did_str
            .parse()
            .map_err(|_| ApiError::InvalidDid("Invalid DID format".into()))?;
        match state.repos.user.get_status_by_did(&did).await {
            Ok(Some(status)) => {
                let deactivated = status.deactivated_at.map(|_| StatusAttr {
                    applied: true,
                    r#ref: None,
                });
                let takedown = status.takedown_ref.as_ref().map(|r| StatusAttr {
                    applied: true,
                    r#ref: Some(r.clone()),
                });
                return Ok(Json(SubjectStatus {
                    subject: json!({
                        "$type": "com.atproto.admin.defs#repoRef",
                        "did": did_str
                    }),
                    takedown,
                    deactivated,
                }));
            }
            Ok(None) => {
                return Err(ApiError::SubjectNotFound);
            }
            Err(e) => {
                error!("DB error in get_subject_status: {:?}", e);
                return Err(ApiError::InternalError(None));
            }
        }
    }
    if let Some(uri_str) = &params.uri {
        let cid: CidLink = uri_str
            .parse()
            .map_err(|_| ApiError::InvalidRequest("Invalid CID format".into()))?;
        match state.repos.repo.get_record_by_cid(&cid).await {
            Ok(Some(record)) => {
                let takedown = record.takedown_ref.as_ref().map(|r| StatusAttr {
                    applied: true,
                    r#ref: Some(r.clone()),
                });
                return Ok(Json(SubjectStatus {
                    subject: json!({
                        "$type": "com.atproto.repo.strongRef",
                        "uri": uri_str,
                        "cid": uri_str
                    }),
                    takedown,
                    deactivated: None,
                }));
            }
            Ok(None) => {
                return Err(ApiError::RecordNotFound);
            }
            Err(e) => {
                error!("DB error in get_subject_status: {:?}", e);
                return Err(ApiError::InternalError(None));
            }
        }
    }
    if let Some(blob_cid_str) = &params.blob {
        let blob_cid: CidLink = blob_cid_str
            .parse()
            .map_err(|_| ApiError::InvalidRequest("Invalid CID format".into()))?;
        let did = params.did.as_ref().ok_or_else(|| {
            ApiError::InvalidRequest("Must provide a did to request blob state".into())
        })?;
        match state.repos.blob.get_blob_with_takedown(&blob_cid).await {
            Ok(Some(blob)) => {
                let takedown = blob.takedown_ref.as_ref().map(|r| StatusAttr {
                    applied: true,
                    r#ref: Some(r.clone()),
                });
                return Ok(Json(SubjectStatus {
                    subject: json!({
                        "$type": "com.atproto.admin.defs#repoBlobRef",
                        "did": did,
                        "cid": blob.cid
                    }),
                    takedown,
                    deactivated: None,
                }));
            }
            Ok(None) => {
                return Err(ApiError::BlobNotFound(None));
            }
            Err(e) => {
                error!("DB error in get_subject_status: {:?}", e);
                return Err(ApiError::InternalError(None));
            }
        }
    }
    Err(ApiError::InvalidRequest("Invalid subject type".into()))
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
    _auth: Auth<Admin>,
    Json(input): Json<UpdateSubjectStatusInput>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let subject_type = input.subject.get("$type").and_then(Value::as_str);
    match subject_type {
        Some("com.atproto.admin.defs#repoRef") => {
            let did_str = input.subject.get("did").and_then(Value::as_str);
            if let Some(did_str) = did_str {
                let did: Did = match did_str.parse() {
                    Ok(d) => d,
                    Err(_) => return Err(ApiError::InvalidDid("Invalid DID format".into())),
                };
                if let Some(takedown) = &input.takedown {
                    let takedown_ref = if takedown.applied {
                        takedown.r#ref.as_deref()
                    } else {
                        None
                    };
                    state
                        .repos
                        .user
                        .set_user_takedown(&did, takedown_ref)
                        .await
                        .map_err(|e| {
                            error!("Failed to update user takedown status for {}: {:?}", did, e);
                            ApiError::InternalError(Some("Failed to update takedown status".into()))
                        })?;
                }
                if let Some(deactivated) = &input.deactivated {
                    let result = if deactivated.applied {
                        state.repos.user.deactivate_account(&did, None).await
                    } else {
                        state.repos.user.activate_account(&did).await
                    };
                    result.map_err(|e| {
                        error!(
                            "Failed to update user deactivation status for {}: {:?}",
                            did, e
                        );
                        ApiError::InternalError(Some("Failed to update deactivation status".into()))
                    })?;
                }
                let takedown_update = input.takedown.as_ref().map(|t| t.applied);
                let takedown_ref = input.takedown.as_ref().and_then(|t| t.r#ref.as_deref());
                let deactivated_update = input.deactivated.as_ref().map(|d| d.applied);
                if (takedown_update.is_some() || deactivated_update.is_some())
                    && let Err(e) = state
                        .repos
                        .repo
                        .update_repo_status(&did, takedown_update, takedown_ref, deactivated_update)
                        .await
                {
                    warn!("failed to sync status to repo backend: {e:?}");
                }
                if let Some(takedown) = &input.takedown {
                    let status = match takedown.applied {
                        true => tranquil_db_traits::AccountStatus::Takendown,
                        false => tranquil_db_traits::AccountStatus::Active,
                    };
                    if let Err(e) =
                        tranquil_pds::repo_ops::sequence_account_event(&state, &did, status).await
                    {
                        warn!("Failed to sequence account event for takedown: {}", e);
                    }
                }
                if let Some(deactivated) = &input.deactivated {
                    let status = match deactivated.applied {
                        true => tranquil_db_traits::AccountStatus::Deactivated,
                        false => tranquil_db_traits::AccountStatus::Active,
                    };
                    if let Err(e) =
                        tranquil_pds::repo_ops::sequence_account_event(&state, &did, status).await
                    {
                        warn!("Failed to sequence account event for deactivation: {}", e);
                    }
                }
                if let Ok(Some(handle)) = state.repos.user.get_handle_by_did(&did).await {
                    let _ = state
                        .cache
                        .delete(&tranquil_pds::cache_keys::handle_key(&handle))
                        .await;
                }
                return Ok(Json(json!({
                    "subject": input.subject,
                    "takedown": input.takedown.as_ref().map(|t| json!({
                        "applied": t.applied,
                        "ref": t.r#ref
                    })),
                    "deactivated": input.deactivated.as_ref().map(|d| json!({
                        "applied": d.applied
                    }))
                })));
            }
        }
        Some("com.atproto.repo.strongRef") => {
            let uri_str = input.subject.get("uri").and_then(Value::as_str);
            if let Some(uri_str) = uri_str {
                let cid: CidLink = uri_str
                    .parse()
                    .map_err(|_| ApiError::InvalidRequest("Invalid CID format".into()))?;
                if let Some(takedown) = &input.takedown {
                    let takedown_ref = if takedown.applied {
                        takedown.r#ref.as_deref()
                    } else {
                        None
                    };
                    state
                        .repos
                        .repo
                        .set_record_takedown(&cid, takedown_ref)
                        .await
                        .map_err(|e| {
                            error!(
                                "Failed to update record takedown status for {}: {:?}",
                                uri_str, e
                            );
                            ApiError::InternalError(Some("Failed to update takedown status".into()))
                        })?;
                }
                return Ok(Json(json!({
                    "subject": input.subject,
                    "takedown": input.takedown.as_ref().map(|t| json!({
                        "applied": t.applied,
                        "ref": t.r#ref
                    }))
                })));
            }
        }
        Some("com.atproto.admin.defs#repoBlobRef") => {
            let cid_str = input.subject.get("cid").and_then(Value::as_str);
            if let Some(cid_str) = cid_str {
                let cid: CidLink = cid_str
                    .parse()
                    .map_err(|_| ApiError::InvalidRequest("Invalid CID format".into()))?;
                if let Some(takedown) = &input.takedown {
                    let takedown_ref = if takedown.applied {
                        takedown.r#ref.as_deref()
                    } else {
                        None
                    };
                    state
                        .repos
                        .blob
                        .update_blob_takedown(&cid, takedown_ref)
                        .await
                        .map_err(|e| {
                            error!(
                                "Failed to update blob takedown status for {}: {:?}",
                                cid_str, e
                            );
                            ApiError::InternalError(Some("Failed to update takedown status".into()))
                        })?;
                }
                return Ok(Json(json!({
                    "subject": input.subject,
                    "takedown": input.takedown.as_ref().map(|t| json!({
                        "applied": t.applied,
                        "ref": t.r#ref
                    }))
                })));
            }
        }
        _ => {}
    }
    Err(ApiError::InvalidRequest("Invalid subject type".into()))
}
