use axum::{
    Json,
    extract::State,
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;
use tranquil_pds::auth::{
    AccountRequirement, extract_auth_token_from_header, validate_token_with_dpop,
};
use tranquil_pds::state::AppState;

pub async fn get_state(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let created_at = get_account_created_at(&state, &headers).await;
    let now = chrono::Utc::now().to_rfc3339();

    (
        StatusCode::OK,
        Json(json!({
            "state": {
                "status": "assured",
                "access": "full",
                "lastInitiatedAt": now
            },
            "metadata": {
                "accountCreatedAt": created_at
            }
        })),
    )
        .into_response()
}

pub async fn get_age_assurance_state() -> Response {
    (StatusCode::OK, Json(json!({"status": "assured"}))).into_response()
}

async fn get_account_created_at(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let auth_header = tranquil_pds::util::get_header_str(headers, http::header::AUTHORIZATION);
    tracing::debug!(?auth_header, "age assurance: extracting token");

    let extracted = extract_auth_token_from_header(auth_header)?;
    tracing::debug!("age assurance: got token, validating");

    let dpop_proof = tranquil_pds::util::get_header_str(headers, tranquil_pds::util::HEADER_DPOP);
    let http_uri = "/";

    let auth_user = match validate_token_with_dpop(
        state.user_repo.as_ref(),
        state.oauth_repo.as_ref(),
        &extracted.token,
        extracted.scheme,
        dpop_proof,
        Method::GET.as_str(),
        http_uri,
        AccountRequirement::Active,
    )
    .await
    {
        Ok(user) => {
            tracing::debug!(did = %user.did, "age assurance: validated user");
            user
        }
        Err(e) => {
            tracing::warn!(?e, "age assurance: token validation failed");
            return None;
        }
    };

    match state.user_repo.get_by_did(&auth_user.did).await {
        Ok(Some(user)) => {
            tracing::debug!(created_at = ?user.created_at, "age assurance: got user");
            Some(user.created_at.to_rfc3339())
        }
        Ok(None) => {
            tracing::debug!("age assurance: user not found");
            None
        }
        Err(e) => {
            tracing::warn!(?e, "age assurance: query failed");
            None
        }
    }
}
