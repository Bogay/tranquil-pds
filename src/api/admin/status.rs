use crate::state::AppState;
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::error;

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
    headers: axum::http::HeaderMap,
    Query(params): Query<GetSubjectStatusParams>,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }

    if params.did.is_none() && params.uri.is_none() && params.blob.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "Must provide did, uri, or blob"})),
        )
            .into_response();
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
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "SubjectNotFound", "message": "Subject not found"})),
                )
                    .into_response();
            }
            Err(e) => {
                error!("DB error in get_subject_status: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError"})),
                )
                    .into_response();
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
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "SubjectNotFound", "message": "Subject not found"})),
                )
                    .into_response();
            }
            Err(e) => {
                error!("DB error in get_subject_status: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError"})),
                )
                    .into_response();
            }
        }
    }

    if let Some(blob_cid) = &params.blob {
        let blob = sqlx::query!("SELECT cid, takedown_ref FROM blobs WHERE cid = $1", blob_cid)
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
                            "did": "",
                            "cid": row.cid
                        }),
                        takedown,
                        deactivated: None,
                    }),
                )
                    .into_response();
            }
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "SubjectNotFound", "message": "Subject not found"})),
                )
                    .into_response();
            }
            Err(e) => {
                error!("DB error in get_subject_status: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError"})),
                )
                    .into_response();
            }
        }
    }

    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": "InvalidRequest", "message": "Invalid subject type"})),
    )
        .into_response()
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
    pub apply: bool,
    pub r#ref: Option<String>,
}

pub async fn update_subject_status(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<UpdateSubjectStatusInput>,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }

    let subject_type = input.subject.get("$type").and_then(|t| t.as_str());

    match subject_type {
        Some("com.atproto.admin.defs#repoRef") => {
            let did = input.subject.get("did").and_then(|d| d.as_str());
            if let Some(did) = did {
                if let Some(takedown) = &input.takedown {
                    let takedown_ref = if takedown.apply {
                        takedown.r#ref.clone()
                    } else {
                        None
                    };
                    let _ = sqlx::query!(
                        "UPDATE users SET takedown_ref = $1 WHERE did = $2",
                        takedown_ref,
                        did
                    )
                    .execute(&state.db)
                    .await;
                }

                if let Some(deactivated) = &input.deactivated {
                    if deactivated.apply {
                        let _ = sqlx::query!(
                            "UPDATE users SET deactivated_at = NOW() WHERE did = $1",
                            did
                        )
                        .execute(&state.db)
                        .await;
                    } else {
                        let _ = sqlx::query!(
                            "UPDATE users SET deactivated_at = NULL WHERE did = $1",
                            did
                        )
                        .execute(&state.db)
                        .await;
                    }
                }

                return (
                    StatusCode::OK,
                    Json(json!({
                        "subject": input.subject,
                        "takedown": input.takedown.as_ref().map(|t| json!({
                            "applied": t.apply,
                            "ref": t.r#ref
                        })),
                        "deactivated": input.deactivated.as_ref().map(|d| json!({
                            "applied": d.apply
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
                    let takedown_ref = if takedown.apply {
                        takedown.r#ref.clone()
                    } else {
                        None
                    };
                    let _ = sqlx::query!(
                        "UPDATE records SET takedown_ref = $1 WHERE record_cid = $2",
                        takedown_ref,
                        uri
                    )
                    .execute(&state.db)
                    .await;
                }

                return (
                    StatusCode::OK,
                    Json(json!({
                        "subject": input.subject,
                        "takedown": input.takedown.as_ref().map(|t| json!({
                            "applied": t.apply,
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
                    let takedown_ref = if takedown.apply {
                        takedown.r#ref.clone()
                    } else {
                        None
                    };
                    let _ = sqlx::query!(
                        "UPDATE blobs SET takedown_ref = $1 WHERE cid = $2",
                        takedown_ref,
                        cid
                    )
                    .execute(&state.db)
                    .await;
                }

                return (
                    StatusCode::OK,
                    Json(json!({
                        "subject": input.subject,
                        "takedown": input.takedown.as_ref().map(|t| json!({
                            "applied": t.apply,
                            "ref": t.r#ref
                        }))
                    })),
                )
                    .into_response();
            }
        }
        _ => {}
    }

    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": "InvalidRequest", "message": "Invalid subject type"})),
    )
        .into_response()
}
