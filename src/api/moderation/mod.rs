use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::error;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateReportInput {
    pub reason_type: String,
    pub reason: Option<String>,
    pub subject: Value,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateReportOutput {
    pub id: i64,
    pub reason_type: String,
    pub reason: Option<String>,
    pub subject: Value,
    pub reported_by: String,
    pub created_at: String,
}

pub async fn create_report(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<CreateReportInput>,
) -> Response {
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok())
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

    let auth_result = crate::auth::validate_bearer_token(&state.db, &token).await;
    let did = match auth_result {
        Ok(user) => user.did,
        Err(e) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": e})),
            )
                .into_response();
        }
    };

    let valid_reason_types = [
        "com.atproto.moderation.defs#reasonSpam",
        "com.atproto.moderation.defs#reasonViolation",
        "com.atproto.moderation.defs#reasonMisleading",
        "com.atproto.moderation.defs#reasonSexual",
        "com.atproto.moderation.defs#reasonRude",
        "com.atproto.moderation.defs#reasonOther",
        "com.atproto.moderation.defs#reasonAppeal",
    ];

    if !valid_reason_types.contains(&input.reason_type.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "Invalid reasonType"})),
        )
            .into_response();
    }

    let created_at = chrono::Utc::now();
    let report_id = created_at.timestamp_millis();

    let subject_json = json!(input.subject);
    let insert = sqlx::query!(
        "INSERT INTO reports (id, reason_type, reason, subject_json, reported_by_did, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
        report_id,
        input.reason_type,
        input.reason,
        subject_json,
        did,
        created_at
    )
    .execute(&state.db)
    .await;

    if let Err(e) = insert {
        error!("Failed to insert report: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        Json(CreateReportOutput {
            id: report_id,
            reason_type: input.reason_type,
            reason: input.reason,
            subject: input.subject,
            reported_by: did,
            created_at: created_at.to_rfc3339(),
        }),
    )
        .into_response()
}
