use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const APP_BSKY_NAMESPACE: &str = "app.bsky";
const MAX_PREFERENCES_COUNT: usize = 100;
const MAX_PREFERENCE_SIZE: usize = 10_000;

#[derive(Serialize)]
pub struct GetPreferencesOutput {
    pub preferences: Vec<Value>,
}
pub async fn get_preferences(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
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
    let auth_user =
        match crate::auth::validate_bearer_token_allow_deactivated(&state.db, &token).await {
            Ok(user) => user,
            Err(_) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "AuthenticationFailed"})),
                )
                    .into_response();
            }
        };
    let user_id: uuid::Uuid =
        match sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", auth_user.did)
            .fetch_optional(&state.db)
            .await
        {
            Ok(Some(id)) => id,
            _ => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError", "message": "User not found"})),
                )
                    .into_response();
            }
        };
    let prefs_result = sqlx::query!(
        "SELECT name, value_json FROM account_preferences WHERE user_id = $1",
        user_id
    )
    .fetch_all(&state.db)
    .await;
    let prefs = match prefs_result {
        Ok(rows) => rows,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Failed to fetch preferences"})),
            )
                .into_response();
        }
    };
    let preferences: Vec<Value> = prefs
        .into_iter()
        .filter(|row| {
            row.name == APP_BSKY_NAMESPACE
                || row.name.starts_with(&format!("{}.", APP_BSKY_NAMESPACE))
        })
        .filter_map(|row| {
            if row.name == "app.bsky.actor.defs#declaredAgePref" {
                return None;
            }
            serde_json::from_value(row.value_json).ok()
        })
        .collect();
    (StatusCode::OK, Json(GetPreferencesOutput { preferences })).into_response()
}

#[derive(Deserialize)]
pub struct PutPreferencesInput {
    pub preferences: Vec<Value>,
}
pub async fn put_preferences(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<PutPreferencesInput>,
) -> Response {
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
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
    let auth_user =
        match crate::auth::validate_bearer_token_allow_deactivated(&state.db, &token).await {
            Ok(user) => user,
            Err(_) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "AuthenticationFailed"})),
                )
                    .into_response();
            }
        };
    let (user_id, is_migration): (uuid::Uuid, bool) = match sqlx::query!(
        "SELECT id, deactivated_at FROM users WHERE did = $1",
        auth_user.did
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(row)) => (row.id, row.deactivated_at.is_some()),
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "User not found"})),
            )
                .into_response();
        }
    };
    if input.preferences.len() > MAX_PREFERENCES_COUNT {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": format!("Too many preferences: {} exceeds limit of {}", input.preferences.len(), MAX_PREFERENCES_COUNT)})),
        )
            .into_response();
    }
    for pref in &input.preferences {
        let pref_str = serde_json::to_string(pref).unwrap_or_default();
        if pref_str.len() > MAX_PREFERENCE_SIZE {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidRequest", "message": format!("Preference too large: {} bytes exceeds limit of {}", pref_str.len(), MAX_PREFERENCE_SIZE)})),
            )
                .into_response();
        }
        let pref_type = match pref.get("$type").and_then(|t| t.as_str()) {
            Some(t) => t,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "InvalidRequest", "message": "Preference missing $type field"})),
                )
                    .into_response();
            }
        };
        if !pref_type.starts_with(APP_BSKY_NAMESPACE) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidRequest", "message": format!("Invalid preference namespace: {}", pref_type)})),
            )
                .into_response();
        }
        if pref_type == "app.bsky.actor.defs#declaredAgePref" && !is_migration {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidRequest", "message": "declaredAgePref is read-only"})),
            )
                .into_response();
        }
    }
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Failed to start transaction"})),
            )
                .into_response();
        }
    };
    let delete_result = sqlx::query!(
        "DELETE FROM account_preferences WHERE user_id = $1 AND (name = $2 OR name LIKE $3)",
        user_id,
        APP_BSKY_NAMESPACE,
        format!("{}.%", APP_BSKY_NAMESPACE)
    )
    .execute(&mut *tx)
    .await;
    if delete_result.is_err() {
        let _ = tx.rollback().await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError", "message": "Failed to clear preferences"})),
        )
            .into_response();
    }
    for pref in input.preferences {
        let pref_type = match pref.get("$type").and_then(|t| t.as_str()) {
            Some(t) => t,
            None => continue,
        };
        let insert_result = sqlx::query!(
            "INSERT INTO account_preferences (user_id, name, value_json) VALUES ($1, $2, $3)",
            user_id,
            pref_type,
            pref
        )
        .execute(&mut *tx)
        .await;
        if insert_result.is_err() {
            let _ = tx.rollback().await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Failed to save preference"})),
            )
                .into_response();
        }
    }
    if tx.commit().await.is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError", "message": "Failed to commit transaction"})),
        )
            .into_response();
    }
    StatusCode::OK.into_response()
}
