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
use sqlx::Row;
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
            error!("DB error in get_service_auth: {:?}", e);
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

    let user_row = sqlx::query("SELECT u.id, u.did, u.handle, u.password_hash, k.key_bytes FROM users u JOIN user_keys k ON u.id = k.user_id WHERE u.handle = $1 OR u.email = $1")
        .bind(&input.identifier)
        .fetch_optional(&state.db)
        .await;

    match user_row {
        Ok(Some(row)) => {
            let user_id: uuid::Uuid = row.get("id");
            let stored_hash: String = row.get("password_hash");
            let did: String = row.get("did");
            let handle: String = row.get("handle");
            let key_bytes: Vec<u8> = row.get("key_bytes");

            let password_valid = if verify(&input.password, &stored_hash).unwrap_or(false) {
                true
            } else {
                let app_pass_rows = sqlx::query("SELECT password_hash FROM app_passwords WHERE user_id = $1")
                    .bind(user_id)
                    .fetch_all(&state.db)
                    .await
                    .unwrap_or_default();

                app_pass_rows.iter().any(|row| {
                    let hash: String = row.get("password_hash");
                    verify(&input.password, &hash).unwrap_or(false)
                })
            };

            if password_valid {
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckAccountStatusOutput {
    pub activated: bool,
    pub valid_did: bool,
    pub repo_commit: String,
    pub repo_rev: String,
    pub repo_blocks: i64,
    pub indexed_records: i64,
    pub private_state_values: i64,
    pub expected_blobs: i64,
    pub imported_blobs: i64,
}

pub async fn check_account_status(
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

    let session = sqlx::query(
        r#"
        SELECT s.did, k.key_bytes, u.id as user_id
        FROM sessions s
        JOIN users u ON s.did = u.did
        JOIN user_keys k ON u.id = k.user_id
        WHERE s.access_jwt = $1
        "#,
    )
    .bind(&token)
    .fetch_optional(&state.db)
    .await;

    let (did, key_bytes, user_id) = match session {
        Ok(Some(row)) => (
            row.get::<String, _>("did"),
            row.get::<Vec<u8>, _>("key_bytes"),
            row.get::<uuid::Uuid, _>("user_id"),
        ),
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationFailed"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error in check_account_status: {:?}", e);
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

    let repo_result = sqlx::query("SELECT repo_root_cid FROM repos WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await;

    let repo_commit = match repo_result {
        Ok(Some(row)) => row.get::<String, _>("repo_root_cid"),
        _ => String::new(),
    };

    let record_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE repo_id = $1")
        .bind(user_id)
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    let blob_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM blobs WHERE created_by_user = $1")
            .bind(user_id)
            .fetch_one(&state.db)
            .await
            .unwrap_or(0);

    let valid_did = did.starts_with("did:");

    (
        StatusCode::OK,
        Json(CheckAccountStatusOutput {
            activated: true,
            valid_did,
            repo_commit: repo_commit.clone(),
            repo_rev: chrono::Utc::now().timestamp_millis().to_string(),
            repo_blocks: 0,
            indexed_records: record_count,
            private_state_values: 0,
            expected_blobs: blob_count,
            imported_blobs: blob_count,
        }),
    )
        .into_response()
}

pub async fn activate_account(
    State(_state): State<AppState>,
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

    (StatusCode::OK, Json(json!({}))).into_response()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeactivateAccountInput {
    pub delete_after: Option<String>,
}

pub async fn deactivate_account(
    State(_state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(_input): Json<DeactivateAccountInput>,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }

    (StatusCode::OK, Json(json!({}))).into_response()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppPassword {
    pub name: String,
    pub created_at: String,
    pub privileged: bool,
}

#[derive(Serialize)]
pub struct ListAppPasswordsOutput {
    pub passwords: Vec<AppPassword>,
}

pub async fn list_app_passwords(
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

    let session = sqlx::query(
        r#"
        SELECT s.did, k.key_bytes, u.id as user_id
        FROM sessions s
        JOIN users u ON s.did = u.did
        JOIN user_keys k ON u.id = k.user_id
        WHERE s.access_jwt = $1
        "#,
    )
    .bind(&token)
    .fetch_optional(&state.db)
    .await;

    let (_did, key_bytes, user_id) = match session {
        Ok(Some(row)) => (
            row.get::<String, _>("did"),
            row.get::<Vec<u8>, _>("key_bytes"),
            row.get::<uuid::Uuid, _>("user_id"),
        ),
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationFailed"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error in list_app_passwords: {:?}", e);
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

    let result = sqlx::query("SELECT name, created_at, privileged FROM app_passwords WHERE user_id = $1 ORDER BY created_at DESC")
        .bind(user_id)
        .fetch_all(&state.db)
        .await;

    match result {
        Ok(rows) => {
            let passwords: Vec<AppPassword> = rows
                .iter()
                .map(|row| {
                    let name: String = row.get("name");
                    let created_at: chrono::DateTime<chrono::Utc> = row.get("created_at");
                    let privileged: bool = row.get("privileged");
                    AppPassword {
                        name,
                        created_at: created_at.to_rfc3339(),
                        privileged,
                    }
                })
                .collect();

            (StatusCode::OK, Json(ListAppPasswordsOutput { passwords })).into_response()
        }
        Err(e) => {
            error!("DB error listing app passwords: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct CreateAppPasswordInput {
    pub name: String,
    pub privileged: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAppPasswordOutput {
    pub name: String,
    pub password: String,
    pub created_at: String,
    pub privileged: bool,
}

pub async fn create_app_password(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<CreateAppPasswordInput>,
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
        SELECT s.did, k.key_bytes, u.id as user_id
        FROM sessions s
        JOIN users u ON s.did = u.did
        JOIN user_keys k ON u.id = k.user_id
        WHERE s.access_jwt = $1
        "#,
    )
    .bind(&token)
    .fetch_optional(&state.db)
    .await;

    let (_did, key_bytes, user_id) = match session {
        Ok(Some(row)) => (
            row.get::<String, _>("did"),
            row.get::<Vec<u8>, _>("key_bytes"),
            row.get::<uuid::Uuid, _>("user_id"),
        ),
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationFailed"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error in create_app_password: {:?}", e);
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

    let name = input.name.trim();
    if name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "name is required"})),
        )
            .into_response();
    }

    let existing = sqlx::query("SELECT id FROM app_passwords WHERE user_id = $1 AND name = $2")
        .bind(user_id)
        .bind(name)
        .fetch_optional(&state.db)
        .await;

    if let Ok(Some(_)) = existing {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "DuplicateAppPassword", "message": "App password with this name already exists"})),
        )
            .into_response();
    }

    let password: String = (0..4)
        .map(|_| {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyz234567".chars().collect();
            (0..4).map(|_| chars[rng.gen_range(0..chars.len())]).collect::<String>()
        })
        .collect::<Vec<String>>()
        .join("-");

    let password_hash = match bcrypt::hash(&password, bcrypt::DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            error!("Failed to hash password: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let privileged = input.privileged.unwrap_or(false);
    let created_at = chrono::Utc::now();

    let result = sqlx::query(
        "INSERT INTO app_passwords (user_id, name, password_hash, created_at, privileged) VALUES ($1, $2, $3, $4, $5)"
    )
    .bind(user_id)
    .bind(name)
    .bind(&password_hash)
    .bind(created_at)
    .bind(privileged)
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => (
            StatusCode::OK,
            Json(CreateAppPasswordOutput {
                name: name.to_string(),
                password,
                created_at: created_at.to_rfc3339(),
                privileged,
            }),
        )
            .into_response(),
        Err(e) => {
            error!("DB error creating app password: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct RevokeAppPasswordInput {
    pub name: String,
}

pub async fn revoke_app_password(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<RevokeAppPasswordInput>,
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
        SELECT s.did, k.key_bytes, u.id as user_id
        FROM sessions s
        JOIN users u ON s.did = u.did
        JOIN user_keys k ON u.id = k.user_id
        WHERE s.access_jwt = $1
        "#,
    )
    .bind(&token)
    .fetch_optional(&state.db)
    .await;

    let (_did, key_bytes, user_id) = match session {
        Ok(Some(row)) => (
            row.get::<String, _>("did"),
            row.get::<Vec<u8>, _>("key_bytes"),
            row.get::<uuid::Uuid, _>("user_id"),
        ),
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationFailed"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error in revoke_app_password: {:?}", e);
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

    let name = input.name.trim();
    if name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "name is required"})),
        )
            .into_response();
    }

    let result = sqlx::query("DELETE FROM app_passwords WHERE user_id = $1 AND name = $2")
        .bind(user_id)
        .bind(name)
        .execute(&state.db)
        .await;

    match result {
        Ok(r) => {
            if r.rows_affected() == 0 {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "AppPasswordNotFound", "message": "App password not found"})),
                )
                    .into_response();
            }
            (StatusCode::OK, Json(json!({}))).into_response()
        }
        Err(e) => {
            error!("DB error revoking app password: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}
