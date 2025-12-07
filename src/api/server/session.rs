use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use bcrypt::verify;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;
use tracing::{error, info, warn};

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

    let user_row = sqlx::query("SELECT u.did, u.handle, u.password_hash, k.key_bytes FROM users u JOIN user_keys k ON u.id = k.user_id WHERE u.handle = $1 OR u.email = $1")
        .bind(&input.identifier)
        .fetch_optional(&state.db)
        .await;

    match user_row {
        Ok(Some(row)) => {
            let stored_hash: String = row.get("password_hash");

            if verify(&input.password, &stored_hash).unwrap_or(false) {
                let did: String = row.get("did");
                let handle: String = row.get("handle");
                let key_bytes: Vec<u8> = row.get("key_bytes");

                let access_jwt = match crate::auth::create_access_token(&did, &key_bytes) {
                    Ok(t) => t,
                    Err(e) => {
                        error!("Failed to create access token: {:?}", e);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"error": "InternalError"})),
                        )
                            .into_response();
                    }
                };

                let refresh_jwt = match crate::auth::create_refresh_token(&did, &key_bytes) {
                    Ok(t) => t,
                    Err(e) => {
                        error!("Failed to create refresh token: {:?}", e);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"error": "InternalError"})),
                        )
                            .into_response();
                    }
                };

                let session_insert = sqlx::query(
                    "INSERT INTO sessions (access_jwt, refresh_jwt, did) VALUES ($1, $2, $3)",
                )
                .bind(&access_jwt)
                .bind(&refresh_jwt)
                .bind(&did)
                .execute(&state.db)
                .await;

                match session_insert {
                    Ok(_) => {
                        return (
                            StatusCode::OK,
                            Json(CreateSessionOutput {
                                access_jwt,
                                refresh_jwt,
                                handle,
                                did,
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

    let result = sqlx::query(
        r#"
        SELECT u.handle, u.did, u.email, k.key_bytes
        FROM sessions s
        JOIN users u ON s.did = u.did
        JOIN user_keys k ON u.id = k.user_id
        WHERE s.access_jwt = $1
        "#,
    )
    .bind(&token)
    .fetch_optional(&state.db)
    .await;

    match result {
        Ok(Some(row)) => {
            let handle: String = row.get("handle");
            let did: String = row.get("did");
            let email: String = row.get("email");
            let key_bytes: Vec<u8> = row.get("key_bytes");

            if let Err(_) = crate::auth::verify_token(&token, &key_bytes) {
                return (StatusCode::UNAUTHORIZED, Json(json!({"error": "AuthenticationFailed", "message": "Invalid token signature"}))).into_response();
            }

            return (
                StatusCode::OK,
                Json(json!({
                    "handle": handle,
                    "did": did,
                    "email": email,
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

    let result = sqlx::query("DELETE FROM sessions WHERE access_jwt = $1")
        .bind(token)
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
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }

    let refresh_token = auth_header
        .unwrap()
        .to_str()
        .unwrap_or("")
        .replace("Bearer ", "");

    let session = sqlx::query(
            "SELECT s.did, k.key_bytes FROM sessions s JOIN users u ON s.did = u.did JOIN user_keys k ON u.id = k.user_id WHERE s.refresh_jwt = $1"
        )
        .bind(&refresh_token)
        .fetch_optional(&state.db)
        .await;

    match session {
        Ok(Some(session_row)) => {
            let did: String = session_row.get("did");
            let key_bytes: Vec<u8> = session_row.get("key_bytes");

            if let Err(_) = crate::auth::verify_token(&refresh_token, &key_bytes) {
                return (StatusCode::UNAUTHORIZED, Json(json!({"error": "AuthenticationFailed", "message": "Invalid refresh token signature"}))).into_response();
            }

            let new_access_jwt = match crate::auth::create_access_token(&did, &key_bytes) {
                Ok(t) => t,
                Err(e) => {
                    error!("Failed to create access token: {:?}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "InternalError"})),
                    )
                        .into_response();
                }
            };
            let new_refresh_jwt = match crate::auth::create_refresh_token(&did, &key_bytes) {
                Ok(t) => t,
                Err(e) => {
                    error!("Failed to create refresh token: {:?}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "InternalError"})),
                    )
                        .into_response();
                }
            };

            let update = sqlx::query(
                "UPDATE sessions SET access_jwt = $1, refresh_jwt = $2 WHERE refresh_jwt = $3",
            )
            .bind(&new_access_jwt)
            .bind(&new_refresh_jwt)
            .bind(&refresh_token)
            .execute(&state.db)
            .await;

            match update {
                Ok(_) => {
                    let user = sqlx::query("SELECT handle FROM users WHERE did = $1")
                        .bind(&did)
                        .fetch_optional(&state.db)
                        .await;

                    match user {
                        Ok(Some(u)) => {
                            let handle: String = u.get("handle");
                            return (
                                StatusCode::OK,
                                Json(json!({
                                    "accessJwt": new_access_jwt,
                                    "refreshJwt": new_refresh_jwt,
                                    "handle": handle,
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
                Err(e) => {
                    error!("Database error updating session: {:?}", e);
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
