use crate::state::AppState;
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use bcrypt::verify;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{error, info, warn};

#[derive(Deserialize)]
pub struct GetServiceAuthParams {
    pub aud: String,
    pub lxm: Option<String>,
    pub exp: Option<i64>,
}

#[derive(Serialize)]
pub struct GetServiceAuthOutput {
    pub token: String,
}

pub async fn get_service_auth(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(params): Query<GetServiceAuthParams>,
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
    let (did, key_bytes) = match auth_result {
        Ok(user) => {
            let kb = match user.key_bytes {
                Some(kb) => kb,
                None => {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({"error": "AuthenticationFailed", "message": "OAuth tokens cannot create service auth"})),
                    )
                        .into_response();
                }
            };
            (user.did, kb)
        }
        Err(e) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": e})),
            )
                .into_response();
        }
    };

    let lxm = params.lxm.as_deref().unwrap_or("*");

    let service_token = match crate::auth::create_service_token(&did, &params.aud, lxm, &key_bytes)
    {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to create service token: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    (StatusCode::OK, Json(GetServiceAuthOutput { token: service_token })).into_response()
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
    Json(input): Json<CreateSessionInput>,
) -> Response {
    info!("create_session: identifier='{}'", input.identifier);

    let user_row = sqlx::query!(
        "SELECT u.id, u.did, u.handle, u.password_hash, k.key_bytes, k.encryption_version FROM users u JOIN user_keys k ON u.id = k.user_id WHERE u.handle = $1 OR u.email = $1",
        input.identifier
    )
        .fetch_optional(&state.db)
        .await;

    match user_row {
        Ok(Some(row)) => {
            let user_id = row.id;
            let stored_hash = &row.password_hash;
            let did = &row.did;
            let handle = &row.handle;
            let key_bytes = match crate::config::decrypt_key(&row.key_bytes, row.encryption_version) {
                Ok(k) => k,
                Err(e) => {
                    error!("Failed to decrypt user key: {:?}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "InternalError"})),
                    )
                        .into_response();
                }
            };

            let password_valid = if verify(&input.password, stored_hash).unwrap_or(false) {
                true
            } else {
                let app_pass_rows = sqlx::query!("SELECT password_hash FROM app_passwords WHERE user_id = $1", user_id)
                    .fetch_all(&state.db)
                    .await
                    .unwrap_or_default();

                app_pass_rows.iter().any(|row| {
                    verify(&input.password, &row.password_hash).unwrap_or(false)
                })
            };

            if password_valid {
                let access_meta = match crate::auth::create_access_token_with_metadata(did, &key_bytes) {
                    Ok(m) => m,
                    Err(e) => {
                        error!("Failed to create access token: {:?}", e);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"error": "InternalError"})),
                        )
                            .into_response();
                    }
                };

                let refresh_meta = match crate::auth::create_refresh_token_with_metadata(did, &key_bytes) {
                    Ok(m) => m,
                    Err(e) => {
                        error!("Failed to create refresh token: {:?}", e);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"error": "InternalError"})),
                        )
                            .into_response();
                    }
                };

                let session_insert = sqlx::query!(
                    "INSERT INTO session_tokens (did, access_jti, refresh_jti, access_expires_at, refresh_expires_at) VALUES ($1, $2, $3, $4, $5)",
                    did,
                    access_meta.jti,
                    refresh_meta.jti,
                    access_meta.expires_at,
                    refresh_meta.expires_at
                )
                .execute(&state.db)
                .await;

                match session_insert {
                    Ok(_) => {
                        return (
                            StatusCode::OK,
                            Json(CreateSessionOutput {
                                access_jwt: access_meta.token,
                                refresh_jwt: refresh_meta.token,
                                handle: handle.clone(),
                                did: did.clone(),
                            }),
                        )
                            .into_response();
                    }
                    Err(e) => {
                        error!("Failed to insert session: {:?}", e);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"error": "InternalError"})),
                        )
                            .into_response();
                    }
                }
            } else {
                warn!(
                    "Password verification failed for identifier: {}",
                    input.identifier
                );
            }
        }
        Ok(None) => {
            warn!("User not found for identifier: {}", input.identifier);
        }
        Err(e) => {
            error!("Database error fetching user: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "AuthenticationFailed", "message": "Invalid identifier or password"})),
    )
        .into_response()
}

pub async fn get_session(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok())
    ) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationRequired", "message": "Invalid Authorization header format"})),
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

    let user = sqlx::query!(
        "SELECT handle, email FROM users WHERE did = $1",
        did
    )
    .fetch_optional(&state.db)
    .await;

    match user {
        Ok(Some(row)) => {
            return (
                StatusCode::OK,
                Json(json!({
                    "handle": row.handle,
                    "did": did,
                    "email": row.email,
                    "didDoc": {}
                })),
            )
                .into_response();
        }
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationFailed"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("Database error in get_session: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
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
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationRequired"})),
            )
                .into_response();
        }
    };

    let jti = match crate::auth::get_did_from_token(&token) {
        Ok(_) => {
            let parts: Vec<&str> = token.split('.').collect();
            if parts.len() != 3 {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "AuthenticationFailed"})),
                )
                    .into_response();
            }
            use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
            let claims_json = match URL_SAFE_NO_PAD.decode(parts[1]) {
                Ok(bytes) => bytes,
                Err(_) => {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({"error": "AuthenticationFailed"})),
                    )
                        .into_response();
                }
            };
            let claims: serde_json::Value = match serde_json::from_slice(&claims_json) {
                Ok(c) => c,
                Err(_) => {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({"error": "AuthenticationFailed"})),
                    )
                        .into_response();
                }
            };
            match claims.get("jti").and_then(|j| j.as_str()) {
                Some(jti) => jti.to_string(),
                None => {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({"error": "AuthenticationFailed"})),
                    )
                        .into_response();
                }
            }
        }
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationFailed"})),
            )
                .into_response();
        }
    };

    let result = sqlx::query!("DELETE FROM session_tokens WHERE access_jti = $1", jti)
        .execute(&state.db)
        .await;

    match result {
        Ok(res) => {
            if res.rows_affected() > 0 {
                return (StatusCode::OK, Json(json!({}))).into_response();
            }
        }
        Err(e) => {
            error!("Database error in delete_session: {:?}", e);
        }
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "AuthenticationFailed"})),
    )
        .into_response()
}

pub async fn refresh_session(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    let refresh_token = match crate::auth::extract_bearer_token_from_header(
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

    let refresh_jti = {
        let parts: Vec<&str> = refresh_token.split('.').collect();
        if parts.len() != 3 {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationFailed", "message": "Invalid token format"})),
            )
                .into_response();
        }
        let claims_bytes = match URL_SAFE_NO_PAD.decode(parts[1]) {
            Ok(b) => b,
            Err(_) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "AuthenticationFailed"})),
                )
                    .into_response();
            }
        };
        let claims: serde_json::Value = match serde_json::from_slice(&claims_bytes) {
            Ok(c) => c,
            Err(_) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "AuthenticationFailed"})),
                )
                    .into_response();
            }
        };
        match claims.get("jti").and_then(|j| j.as_str()) {
            Some(jti) => jti.to_string(),
            None => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "AuthenticationFailed"})),
                )
                    .into_response();
            }
        }
    };

    let reuse_check = sqlx::query_scalar!(
        "SELECT session_id FROM used_refresh_tokens WHERE refresh_jti = $1",
        refresh_jti
    )
    .fetch_optional(&state.db)
    .await;

    if let Ok(Some(session_id)) = reuse_check {
        warn!("Refresh token reuse detected! Revoking token family for session_id: {}", session_id);
        let _ = sqlx::query!("DELETE FROM session_tokens WHERE id = $1", session_id)
            .execute(&state.db)
            .await;
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "ExpiredToken", "message": "Refresh token has been revoked due to suspected compromise"})),
        )
            .into_response();
    }

    let session = sqlx::query!(
        r#"SELECT st.id, st.did, k.key_bytes, k.encryption_version
           FROM session_tokens st
           JOIN users u ON st.did = u.did
           JOIN user_keys k ON u.id = k.user_id
           WHERE st.refresh_jti = $1 AND st.refresh_expires_at > NOW()"#,
        refresh_jti
    )
    .fetch_optional(&state.db)
    .await;

    match session {
        Ok(Some(session_row)) => {
            let session_id = session_row.id;
            let did = &session_row.did;
            let key_bytes = match crate::config::decrypt_key(&session_row.key_bytes, session_row.encryption_version) {
                Ok(k) => k,
                Err(e) => {
                    error!("Failed to decrypt user key: {:?}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "InternalError"})),
                    )
                        .into_response();
                }
            };

            if let Err(_) = crate::auth::verify_refresh_token(&refresh_token, &key_bytes) {
                return (StatusCode::UNAUTHORIZED, Json(json!({"error": "AuthenticationFailed", "message": "Invalid refresh token"}))).into_response();
            }

            let new_access_meta = match crate::auth::create_access_token_with_metadata(did, &key_bytes) {
                Ok(m) => m,
                Err(e) => {
                    error!("Failed to create access token: {:?}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "InternalError"})),
                    )
                        .into_response();
                }
            };
            let new_refresh_meta = match crate::auth::create_refresh_token_with_metadata(did, &key_bytes) {
                Ok(m) => m,
                Err(e) => {
                    error!("Failed to create refresh token: {:?}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "InternalError"})),
                    )
                        .into_response();
                }
            };

            let mut tx = match state.db.begin().await {
                Ok(tx) => tx,
                Err(e) => {
                    error!("Failed to begin transaction: {:?}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "InternalError"})),
                    )
                        .into_response();
                }
            };

            if let Err(e) = sqlx::query!(
                "INSERT INTO used_refresh_tokens (refresh_jti, session_id) VALUES ($1, $2)",
                refresh_jti,
                session_id
            )
            .execute(&mut *tx)
            .await
            {
                error!("Failed to record used refresh token: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError"})),
                )
                    .into_response();
            }

            if let Err(e) = sqlx::query!(
                "UPDATE session_tokens SET access_jti = $1, refresh_jti = $2, access_expires_at = $3, refresh_expires_at = $4, updated_at = NOW() WHERE id = $5",
                new_access_meta.jti,
                new_refresh_meta.jti,
                new_access_meta.expires_at,
                new_refresh_meta.expires_at,
                session_id
            )
            .execute(&mut *tx)
            .await
            {
                error!("Database error updating session: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError"})),
                )
                    .into_response();
            }

            if let Err(e) = tx.commit().await {
                error!("Failed to commit transaction: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError"})),
                )
                    .into_response();
            }

            let user = sqlx::query!("SELECT handle FROM users WHERE did = $1", did)
                .fetch_optional(&state.db)
                .await;

            match user {
                Ok(Some(u)) => {
                    return (
                        StatusCode::OK,
                        Json(json!({
                            "accessJwt": new_access_meta.token,
                            "refreshJwt": new_refresh_meta.token,
                            "handle": u.handle,
                            "did": did
                        })),
                    )
                        .into_response();
                }
                Ok(None) => {
                    error!("User not found for existing session: {}", did);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "InternalError"})),
                    )
                        .into_response();
                }
                Err(e) => {
                    error!("Database error fetching user: {:?}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "InternalError"})),
                    )
                        .into_response();
                }
            }
        }
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationFailed", "message": "Invalid refresh token"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("Database error fetching session: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    }
}
