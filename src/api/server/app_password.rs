use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::error;

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

    let session = sqlx::query!(
        r#"
        SELECT s.did, k.key_bytes, u.id as user_id
        FROM sessions s
        JOIN users u ON s.did = u.did
        JOIN user_keys k ON u.id = k.user_id
        WHERE s.access_jwt = $1
        "#,
        token
    )
    .fetch_optional(&state.db)
    .await;

    let (_did, key_bytes, user_id) = match session {
        Ok(Some(row)) => (row.did, row.key_bytes, row.user_id),
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

    let result = sqlx::query!("SELECT name, created_at, privileged FROM app_passwords WHERE user_id = $1 ORDER BY created_at DESC", user_id)
        .fetch_all(&state.db)
        .await;

    match result {
        Ok(rows) => {
            let passwords: Vec<AppPassword> = rows
                .iter()
                .map(|row| {
                    AppPassword {
                        name: row.name.clone(),
                        created_at: row.created_at.to_rfc3339(),
                        privileged: row.privileged,
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

    let session = sqlx::query!(
        r#"
        SELECT s.did, k.key_bytes, u.id as user_id
        FROM sessions s
        JOIN users u ON s.did = u.did
        JOIN user_keys k ON u.id = k.user_id
        WHERE s.access_jwt = $1
        "#,
        token
    )
    .fetch_optional(&state.db)
    .await;

    let (_did, key_bytes, user_id) = match session {
        Ok(Some(row)) => (row.did, row.key_bytes, row.user_id),
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

    let existing = sqlx::query!("SELECT id FROM app_passwords WHERE user_id = $1 AND name = $2", user_id, name)
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

    let result = sqlx::query!(
        "INSERT INTO app_passwords (user_id, name, password_hash, created_at, privileged) VALUES ($1, $2, $3, $4, $5)",
        user_id,
        name,
        password_hash,
        created_at,
        privileged
    )
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

    let session = sqlx::query!(
        r#"
        SELECT s.did, k.key_bytes, u.id as user_id
        FROM sessions s
        JOIN users u ON s.did = u.did
        JOIN user_keys k ON u.id = k.user_id
        WHERE s.access_jwt = $1
        "#,
        token
    )
    .fetch_optional(&state.db)
    .await;

    let (_did, key_bytes, user_id) = match session {
        Ok(Some(row)) => (row.did, row.key_bytes, row.user_id),
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

    let result = sqlx::query!("DELETE FROM app_passwords WHERE user_id = $1 AND name = $2", user_id, name)
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
