use crate::api::ApiError;
use crate::api::proxy_client::{is_ssrf_safe, proxy_client};
use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::{error, info};

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

fn get_report_service_config() -> Option<(String, String)> {
    let url = std::env::var("REPORT_SERVICE_URL").ok()?;
    let did = std::env::var("REPORT_SERVICE_DID").ok()?;
    if url.is_empty() || did.is_empty() {
        return None;
    }
    Some((url, did))
}

pub async fn create_report(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<CreateReportInput>,
) -> Response {
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => return ApiError::AuthenticationRequired.into_response(),
    };

    let auth_user =
        match crate::auth::validate_bearer_token_allow_takendown(&state.db, &token).await {
            Ok(user) => user,
            Err(e) => return ApiError::from(e).into_response(),
        };

    let did = &auth_user.did;

    if let Some((service_url, service_did)) = get_report_service_config() {
        return proxy_to_report_service(&state, &auth_user, &service_url, &service_did, &input)
            .await;
    }

    create_report_locally(&state, did, auth_user.is_takendown, input).await
}

async fn proxy_to_report_service(
    state: &AppState,
    auth_user: &crate::auth::AuthenticatedUser,
    service_url: &str,
    service_did: &str,
    input: &CreateReportInput,
) -> Response {
    if let Err(e) = is_ssrf_safe(service_url) {
        error!("Report service URL failed SSRF check: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError", "message": "Invalid report service configuration"})),
        )
            .into_response();
    }

    let key_bytes = match &auth_user.key_bytes {
        Some(kb) => kb.clone(),
        None => {
            match sqlx::query_as::<_, (Vec<u8>, Option<i32>)>(
                "SELECT k.key_bytes, k.encryption_version
                 FROM users u
                 JOIN user_keys k ON u.id = k.user_id
                 WHERE u.did = $1",
            )
            .bind(&auth_user.did)
            .fetch_optional(&state.db)
            .await
            {
                Ok(Some((key_bytes_enc, encryption_version))) => {
                    match crate::config::decrypt_key(&key_bytes_enc, encryption_version) {
                        Ok(key) => key,
                        Err(e) => {
                            error!(error = ?e, "Failed to decrypt user key for report service auth");
                            return ApiError::AuthenticationFailedMsg(
                                "Failed to get signing key".into(),
                            )
                            .into_response();
                        }
                    }
                }
                Ok(None) => {
                    return ApiError::AuthenticationFailedMsg("User has no signing key".into())
                        .into_response();
                }
                Err(e) => {
                    error!(error = ?e, "DB error fetching user key for report");
                    return ApiError::AuthenticationFailedMsg("Failed to get signing key".into())
                        .into_response();
                }
            }
        }
    };

    let service_token = match crate::auth::create_service_token(
        &auth_user.did,
        service_did,
        "com.atproto.moderation.createReport",
        &key_bytes,
    ) {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to create service token for report: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let target_url = format!("{}/xrpc/com.atproto.moderation.createReport", service_url);
    info!(
        did = %auth_user.did,
        service_did = %service_did,
        "Proxying createReport to report service"
    );

    let request_body = json!({
        "reasonType": input.reason_type,
        "reason": input.reason,
        "subject": input.subject
    });

    let client = proxy_client();
    let result = client
        .post(&target_url)
        .header("Authorization", format!("Bearer {}", service_token))
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await;

    match result {
        Ok(resp) => {
            let status = resp.status();
            let headers = resp.headers().clone();

            let body = match resp.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    error!("Error reading report service response: {:?}", e);
                    return (StatusCode::BAD_GATEWAY, "Error reading upstream response")
                        .into_response();
                }
            };

            let mut response_builder = Response::builder().status(status);

            if let Some(ct) = headers.get("content-type") {
                response_builder = response_builder.header("content-type", ct);
            }

            match response_builder.body(axum::body::Body::from(body)) {
                Ok(r) => r,
                Err(e) => {
                    error!("Error building proxy response: {:?}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
                }
            }
        }
        Err(e) => {
            error!("Error sending report to service: {:?}", e);
            if e.is_timeout() {
                (StatusCode::GATEWAY_TIMEOUT, "Report service timeout").into_response()
            } else {
                (StatusCode::BAD_GATEWAY, "Report service error").into_response()
            }
        }
    }
}

async fn create_report_locally(
    state: &AppState,
    did: &str,
    is_takendown: bool,
    input: CreateReportInput,
) -> Response {
    const REASON_APPEAL: &str = "com.atproto.moderation.defs#reasonAppeal";

    if is_takendown && input.reason_type != REASON_APPEAL {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "Report not accepted from takendown account"})),
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
        REASON_APPEAL,
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

    info!(
        report_id = %report_id,
        reported_by = %did,
        reason_type = %input.reason_type,
        "Report created locally (no report service configured)"
    );

    (
        StatusCode::OK,
        Json(CreateReportOutput {
            id: report_id,
            reason_type: input.reason_type,
            reason: input.reason,
            subject: input.subject,
            reported_by: did.to_string(),
            created_at: created_at.to_rfc3339(),
        }),
    )
        .into_response()
}
