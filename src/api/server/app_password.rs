use crate::api::ApiError;
use crate::auth::BearerAuth;
use crate::state::{AppState, RateLimitKind};
use crate::util::get_user_id_by_did;
use axum::{
    Json,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{error, warn};
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
    BearerAuth(auth_user): BearerAuth,
) -> Response {
    let user_id = match get_user_id_by_did(&state.db, &auth_user.did).await {
        Ok(id) => id,
        Err(e) => return ApiError::from(e).into_response(),
    };
    match sqlx::query!(
        "SELECT name, created_at, privileged FROM app_passwords WHERE user_id = $1 ORDER BY created_at DESC",
        user_id
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(rows) => {
            let passwords: Vec<AppPassword> = rows
                .iter()
                .map(|row| AppPassword {
                    name: row.name.clone(),
                    created_at: row.created_at.to_rfc3339(),
                    privileged: row.privileged,
                })
                .collect();
            Json(ListAppPasswordsOutput { passwords }).into_response()
        }
        Err(e) => {
            error!("DB error listing app passwords: {:?}", e);
            ApiError::InternalError.into_response()
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
    headers: HeaderMap,
    BearerAuth(auth_user): BearerAuth,
    Json(input): Json<CreateAppPasswordInput>,
) -> Response {
    let client_ip = crate::rate_limit::extract_client_ip(&headers, None);
    if !state.check_rate_limit(RateLimitKind::AppPassword, &client_ip).await {
        warn!(ip = %client_ip, "App password creation rate limit exceeded");
        return (
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "RateLimitExceeded",
                "message": "Too many requests. Please try again later."
            })),
        ).into_response();
    }
    let user_id = match get_user_id_by_did(&state.db, &auth_user.did).await {
        Ok(id) => id,
        Err(e) => return ApiError::from(e).into_response(),
    };
    let name = input.name.trim();
    if name.is_empty() {
        return ApiError::InvalidRequest("name is required".into()).into_response();
    }
    let existing = sqlx::query!(
        "SELECT id FROM app_passwords WHERE user_id = $1 AND name = $2",
        user_id,
        name
    )
    .fetch_optional(&state.db)
    .await;
    if let Ok(Some(_)) = existing {
        return ApiError::DuplicateAppPassword.into_response();
    }
    let password: String = (0..4)
        .map(|_| {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyz234567".chars().collect();
            (0..4)
                .map(|_| chars[rng.gen_range(0..chars.len())])
                .collect::<String>()
        })
        .collect::<Vec<String>>()
        .join("-");
    let password_hash = match bcrypt::hash(&password, bcrypt::DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            error!("Failed to hash password: {:?}", e);
            return ApiError::InternalError.into_response();
        }
    };
    let privileged = input.privileged.unwrap_or(false);
    let created_at = chrono::Utc::now();
    match sqlx::query!(
        "INSERT INTO app_passwords (user_id, name, password_hash, created_at, privileged) VALUES ($1, $2, $3, $4, $5)",
        user_id,
        name,
        password_hash,
        created_at,
        privileged
    )
    .execute(&state.db)
    .await
    {
        Ok(_) => Json(CreateAppPasswordOutput {
            name: name.to_string(),
            password,
            created_at: created_at.to_rfc3339(),
            privileged,
        })
        .into_response(),
        Err(e) => {
            error!("DB error creating app password: {:?}", e);
            ApiError::InternalError.into_response()
        }
    }
}
#[derive(Deserialize)]
pub struct RevokeAppPasswordInput {
    pub name: String,
}
pub async fn revoke_app_password(
    State(state): State<AppState>,
    BearerAuth(auth_user): BearerAuth,
    Json(input): Json<RevokeAppPasswordInput>,
) -> Response {
    let user_id = match get_user_id_by_did(&state.db, &auth_user.did).await {
        Ok(id) => id,
        Err(e) => return ApiError::from(e).into_response(),
    };
    let name = input.name.trim();
    if name.is_empty() {
        return ApiError::InvalidRequest("name is required".into()).into_response();
    }
    match sqlx::query!(
        "DELETE FROM app_passwords WHERE user_id = $1 AND name = $2",
        user_id,
        name
    )
    .execute(&state.db)
    .await
    {
        Ok(r) => {
            if r.rows_affected() == 0 {
                return ApiError::AppPasswordNotFound.into_response();
            }
            Json(json!({})).into_response()
        }
        Err(e) => {
            error!("DB error revoking app password: {:?}", e);
            ApiError::InternalError.into_response()
        }
    }
}
