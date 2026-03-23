use axum::{Json, extract::State};
use chrono::{Duration, Utc};
use tracing::{info, warn};
use tranquil_pds::api::EmptyResponse;
use tranquil_pds::api::error::{ApiError, DbResultExt};
use tranquil_pds::auth::{Auth, Permissive};
use tranquil_pds::state::AppState;

fn generate_plc_token() -> String {
    tranquil_pds::util::generate_token_code()
}

pub async fn request_plc_operation_signature(
    State(state): State<AppState>,
    auth: Auth<Permissive>,
) -> Result<Json<EmptyResponse>, ApiError> {
    tranquil_pds::auth::scope_check::check_identity_scope(
        &auth.auth_source,
        auth.scope.as_deref(),
        tranquil_pds::oauth::scopes::IdentityAttr::Wildcard,
    )?;
    let user_id = state
        .repos
        .user
        .get_id_by_did(&auth.did)
        .await
        .log_db_err("fetching user id")?
        .ok_or(ApiError::AccountNotFound)?;

    let _ = state.repos.infra.delete_plc_tokens_for_user(user_id).await;
    let plc_token = generate_plc_token();
    let expires_at = Utc::now() + Duration::minutes(10);
    state
        .repos
        .infra
        .insert_plc_token(user_id, &plc_token, expires_at)
        .await
        .log_db_err("creating PLC token")?;

    let hostname = &tranquil_config::get().server.hostname;
    if let Err(e) = tranquil_pds::comms::comms_repo::enqueue_plc_operation(
        state.repos.user.as_ref(),
        state.repos.infra.as_ref(),
        user_id,
        &plc_token,
        hostname,
    )
    .await
    {
        warn!("Failed to enqueue PLC operation notification: {:?}", e);
    }
    info!("PLC operation signature requested for user {}", auth.did);
    Ok(Json(EmptyResponse {}))
}
