use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Row;
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
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }

    let token = auth_header
        .unwrap()
        .to_str()
        .unwrap_or("")
        .replace("Bearer ", "");

    let session = sqlx::query(
        r#"
        SELECT s.did, k.key_bytes
        FROM sessions s
        JOIN users u ON s.did = u.did
        JOIN user_keys k ON u.id = k.user_id
        WHERE s.access_jwt = $1
        "#,
    )
    .bind(&token)
    .fetch_optional(&state.db)
    .await;

    let (did, key_bytes) = match session {
        Ok(Some(row)) => (
            row.get::<String, _>("did"),
            row.get::<Vec<u8>, _>("key_bytes"),
        ),
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationFailed"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error in create_report: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    if let Err(_) = crate::auth::verify_token(&token, &key_bytes) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationFailed", "message": "Invalid token signature"})),
        )
            .into_response();
    }

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

    let created_at = chrono::Utc::now().to_rfc3339();
    let report_id = chrono::Utc::now().timestamp_millis();

    (
        StatusCode::OK,
        Json(CreateReportOutput {
            id: report_id,
            reason_type: input.reason_type,
            reason: input.reason,
            subject: input.subject,
            reported_by: did,
            created_at,
        }),
    )
        .into_response()
}
