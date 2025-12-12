use crate::api::ApiError;
use crate::auth::BearerAuth;
use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use bcrypt::verify;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{error, info, warn};

fn extract_client_ip(headers: &HeaderMap) -> String {
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(value) = forwarded.to_str() {
            if let Some(first_ip) = value.split(',').next() {
                return first_ip.trim().to_string();
            }
        }
    }
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(value) = real_ip.to_str() {
            return value.trim().to_string();
        }
    }
    "unknown".to_string()
}

#[derive(Deserialize)]
pub struct CreateSessionInput {
    pub identifier: String,
    pub password: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSessionOutput {
    pub access_jwt: String,
    pub refresh_jwt: String,
    pub handle: String,
    pub did: String,
}

pub async fn create_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateSessionInput>,
) -> Response {
    info!("create_session called");

    let client_ip = extract_client_ip(&headers);
    if state.rate_limiters.login.check_key(&client_ip).is_err() {
        warn!(ip = %client_ip, "Login rate limit exceeded");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "RateLimitExceeded",
                "message": "Too many login attempts. Please try again later."
            })),
        )
            .into_response();
    }

    let row = match sqlx::query!(
        "SELECT u.id, u.did, u.handle, u.password_hash, k.key_bytes, k.encryption_version FROM users u JOIN user_keys k ON u.id = k.user_id WHERE u.handle = $1 OR u.email = $1",
        input.identifier
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            warn!("User not found for login attempt");
            return ApiError::AuthenticationFailedMsg("Invalid identifier or password".into()).into_response();
        }
        Err(e) => {
            error!("Database error fetching user: {:?}", e);
            return ApiError::InternalError.into_response();
        }
    };

    let key_bytes = match crate::config::decrypt_key(&row.key_bytes, row.encryption_version) {
        Ok(k) => k,
        Err(e) => {
            error!("Failed to decrypt user key: {:?}", e);
            return ApiError::InternalError.into_response();
        }
    };

    let password_valid = verify(&input.password, &row.password_hash).unwrap_or(false)
        || sqlx::query!("SELECT password_hash FROM app_passwords WHERE user_id = $1", row.id)
            .fetch_all(&state.db)
            .await
            .unwrap_or_default()
            .iter()
            .any(|app| verify(&input.password, &app.password_hash).unwrap_or(false));

    if !password_valid {
        warn!("Password verification failed for login attempt");
        return ApiError::AuthenticationFailedMsg("Invalid identifier or password".into()).into_response();
    }

    let access_meta = match crate::auth::create_access_token_with_metadata(&row.did, &key_bytes) {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to create access token: {:?}", e);
            return ApiError::InternalError.into_response();
        }
    };

    let refresh_meta = match crate::auth::create_refresh_token_with_metadata(&row.did, &key_bytes) {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to create refresh token: {:?}", e);
            return ApiError::InternalError.into_response();
        }
    };

    if let Err(e) = sqlx::query!(
        "INSERT INTO session_tokens (did, access_jti, refresh_jti, access_expires_at, refresh_expires_at) VALUES ($1, $2, $3, $4, $5)",
        row.did,
        access_meta.jti,
        refresh_meta.jti,
        access_meta.expires_at,
        refresh_meta.expires_at
    )
    .execute(&state.db)
    .await
    {
        error!("Failed to insert session: {:?}", e);
        return ApiError::InternalError.into_response();
    }

    Json(CreateSessionOutput {
        access_jwt: access_meta.token,
        refresh_jwt: refresh_meta.token,
        handle: row.handle,
        did: row.did,
    }).into_response()
}

pub async fn get_session(
    State(state): State<AppState>,
    BearerAuth(auth_user): BearerAuth,
) -> Response {
    match sqlx::query!("SELECT handle, email FROM users WHERE did = $1", auth_user.did)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(row)) => Json(json!({
            "handle": row.handle,
            "did": auth_user.did,
            "email": row.email,
            "didDoc": {}
        })).into_response(),
        Ok(None) => ApiError::AuthenticationFailed.into_response(),
        Err(e) => {
            error!("Database error in get_session: {:?}", e);
            ApiError::InternalError.into_response()
        }
    }
}

pub async fn delete_session(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok())
    ) {
        Some(t) => t,
        None => return ApiError::AuthenticationRequired.into_response(),
    };

    let jti = match crate::auth::get_jti_from_token(&token) {
        Ok(jti) => jti,
        Err(_) => return ApiError::AuthenticationFailed.into_response(),
    };

    match sqlx::query!("DELETE FROM session_tokens WHERE access_jti = $1", jti)
        .execute(&state.db)
        .await
    {
        Ok(res) if res.rows_affected() > 0 => Json(json!({})).into_response(),
        Ok(_) => ApiError::AuthenticationFailed.into_response(),
        Err(e) => {
            error!("Database error in delete_session: {:?}", e);
            ApiError::AuthenticationFailed.into_response()
        }
    }
}

pub async fn refresh_session(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let refresh_token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok())
    ) {
        Some(t) => t,
        None => return ApiError::AuthenticationRequired.into_response(),
    };

    let refresh_jti = match crate::auth::get_jti_from_token(&refresh_token) {
        Ok(jti) => jti,
        Err(_) => return ApiError::AuthenticationFailedMsg("Invalid token format".into()).into_response(),
    };

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            error!("Failed to begin transaction: {:?}", e);
            return ApiError::InternalError.into_response();
        }
    };

    if let Ok(Some(session_id)) = sqlx::query_scalar!(
        "SELECT session_id FROM used_refresh_tokens WHERE refresh_jti = $1 FOR UPDATE",
        refresh_jti
    )
    .fetch_optional(&mut *tx)
    .await
    {
        warn!("Refresh token reuse detected! Revoking token family for session_id: {}", session_id);
        let _ = sqlx::query!("DELETE FROM session_tokens WHERE id = $1", session_id)
            .execute(&mut *tx)
            .await;
        let _ = tx.commit().await;
        return ApiError::ExpiredTokenMsg("Refresh token has been revoked due to suspected compromise".into()).into_response();
    }

    let session_row = match sqlx::query!(
        r#"SELECT st.id, st.did, k.key_bytes, k.encryption_version
           FROM session_tokens st
           JOIN users u ON st.did = u.did
           JOIN user_keys k ON u.id = k.user_id
           WHERE st.refresh_jti = $1 AND st.refresh_expires_at > NOW()
           FOR UPDATE OF st"#,
        refresh_jti
    )
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return ApiError::AuthenticationFailedMsg("Invalid refresh token".into()).into_response(),
        Err(e) => {
            error!("Database error fetching session: {:?}", e);
            return ApiError::InternalError.into_response();
        }
    };

    let key_bytes = match crate::config::decrypt_key(&session_row.key_bytes, session_row.encryption_version) {
        Ok(k) => k,
        Err(e) => {
            error!("Failed to decrypt user key: {:?}", e);
            return ApiError::InternalError.into_response();
        }
    };

    if crate::auth::verify_refresh_token(&refresh_token, &key_bytes).is_err() {
        return ApiError::AuthenticationFailedMsg("Invalid refresh token".into()).into_response();
    }

    let new_access_meta = match crate::auth::create_access_token_with_metadata(&session_row.did, &key_bytes) {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to create access token: {:?}", e);
            return ApiError::InternalError.into_response();
        }
    };

    let new_refresh_meta = match crate::auth::create_refresh_token_with_metadata(&session_row.did, &key_bytes) {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to create refresh token: {:?}", e);
            return ApiError::InternalError.into_response();
        }
    };

    match sqlx::query!(
        "INSERT INTO used_refresh_tokens (refresh_jti, session_id) VALUES ($1, $2) ON CONFLICT (refresh_jti) DO NOTHING",
        refresh_jti,
        session_row.id
    )
    .execute(&mut *tx)
    .await
    {
        Ok(result) if result.rows_affected() == 0 => {
            warn!("Concurrent refresh token reuse detected for session_id: {}", session_row.id);
            let _ = sqlx::query!("DELETE FROM session_tokens WHERE id = $1", session_row.id)
                .execute(&mut *tx)
                .await;
            let _ = tx.commit().await;
            return ApiError::ExpiredTokenMsg("Refresh token has been revoked due to suspected compromise".into()).into_response();
        }
        Err(e) => {
            error!("Failed to record used refresh token: {:?}", e);
            return ApiError::InternalError.into_response();
        }
        Ok(_) => {}
    }

    if let Err(e) = sqlx::query!(
        "UPDATE session_tokens SET access_jti = $1, refresh_jti = $2, access_expires_at = $3, refresh_expires_at = $4, updated_at = NOW() WHERE id = $5",
        new_access_meta.jti,
        new_refresh_meta.jti,
        new_access_meta.expires_at,
        new_refresh_meta.expires_at,
        session_row.id
    )
    .execute(&mut *tx)
    .await
    {
        error!("Database error updating session: {:?}", e);
        return ApiError::InternalError.into_response();
    }

    if let Err(e) = tx.commit().await {
        error!("Failed to commit transaction: {:?}", e);
        return ApiError::InternalError.into_response();
    }

    match sqlx::query!("SELECT handle FROM users WHERE did = $1", session_row.did)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(u)) => Json(json!({
            "accessJwt": new_access_meta.token,
            "refreshJwt": new_refresh_meta.token,
            "handle": u.handle,
            "did": session_row.did
        })).into_response(),
        Ok(None) => {
            error!("User not found for existing session: {}", session_row.did);
            ApiError::InternalError.into_response()
        }
        Err(e) => {
            error!("Database error fetching user: {:?}", e);
            ApiError::InternalError.into_response()
        }
    }
}
