use crate::api::EmptyResponse;
use crate::api::error::ApiError;
use crate::auth::{Auth, NotTakendown};
use crate::state::AppState;
use axum::{
    extract::State,
    response::{IntoResponse, Response},
};
use chrono::{Duration, Utc};
use tracing::{error, info, warn};

fn generate_plc_token() -> String {
    crate::util::generate_token_code()
}

pub async fn request_plc_operation_signature(
    State(state): State<AppState>,
    auth: Auth<NotTakendown>,
) -> Result<Response, ApiError> {
    if let Err(e) = crate::auth::scope_check::check_identity_scope(
        auth.is_oauth(),
        auth.scope.as_deref(),
        crate::oauth::scopes::IdentityAttr::Wildcard,
    ) {
        return Ok(e);
    }
    let user_id = state
        .user_repo
        .get_id_by_did(&auth.did)
        .await
        .map_err(|e| {
            error!("DB error: {:?}", e);
            ApiError::InternalError(None)
        })?
        .ok_or(ApiError::AccountNotFound)?;

    let _ = state.infra_repo.delete_plc_tokens_for_user(user_id).await;
    let plc_token = generate_plc_token();
    let expires_at = Utc::now() + Duration::minutes(10);
    state
        .infra_repo
        .insert_plc_token(user_id, &plc_token, expires_at)
        .await
        .map_err(|e| {
            error!("Failed to create PLC token: {:?}", e);
            ApiError::InternalError(None)
        })?;

    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    if let Err(e) = crate::comms::comms_repo::enqueue_plc_operation(
        state.user_repo.as_ref(),
        state.infra_repo.as_ref(),
        user_id,
        &plc_token,
        &hostname,
    )
    .await
    {
        warn!("Failed to enqueue PLC operation notification: {:?}", e);
    }
    info!("PLC operation signature requested for user {}", auth.did);
    Ok(EmptyResponse::ok().into_response())
}
