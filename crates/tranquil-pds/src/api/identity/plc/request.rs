use crate::api::EmptyResponse;
use crate::api::error::ApiError;
use crate::auth::BearerAuthAllowDeactivated;
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
    auth: BearerAuthAllowDeactivated,
) -> Response {
    let auth_user = auth.0;
    if let Err(e) = crate::auth::scope_check::check_identity_scope(
        auth_user.is_oauth,
        auth_user.scope.as_deref(),
        crate::oauth::scopes::IdentityAttr::Wildcard,
    ) {
        return e;
    }
    let user_id = match state.user_repo.get_id_by_did(&auth_user.did).await {
        Ok(Some(id)) => id,
        Ok(None) => return ApiError::AccountNotFound.into_response(),
        Err(e) => {
            error!("DB error: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let _ = state.infra_repo.delete_plc_tokens_for_user(user_id).await;
    let plc_token = generate_plc_token();
    let expires_at = Utc::now() + Duration::minutes(10);
    if let Err(e) = state
        .infra_repo
        .insert_plc_token(user_id, &plc_token, expires_at)
        .await
    {
        error!("Failed to create PLC token: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }
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
    info!(
        "PLC operation signature requested for user {}",
        auth_user.did
    );
    EmptyResponse::ok().into_response()
}
