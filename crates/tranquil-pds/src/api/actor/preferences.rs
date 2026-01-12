use crate::api::error::ApiError;
use crate::auth::BearerAuthAllowDeactivated;
use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{Datelike, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const APP_BSKY_NAMESPACE: &str = "app.bsky";
const MAX_PREFERENCES_COUNT: usize = 100;
const MAX_PREFERENCE_SIZE: usize = 10_000;
const PERSONAL_DETAILS_PREF: &str = "app.bsky.actor.defs#personalDetailsPref";
const DECLARED_AGE_PREF: &str = "app.bsky.actor.defs#declaredAgePref";

fn get_age_from_datestring(birth_date: &str) -> Option<i32> {
    let bday = NaiveDate::parse_from_str(birth_date, "%Y-%m-%d").ok()?;
    let today = Utc::now().date_naive();
    let mut age = today.year() - bday.year();
    let m = today.month() as i32 - bday.month() as i32;
    if m < 0 || (m == 0 && today.day() < bday.day()) {
        age -= 1;
    }
    Some(age)
}

#[derive(Serialize)]
pub struct GetPreferencesOutput {
    pub preferences: Vec<Value>,
}
pub async fn get_preferences(
    State(state): State<AppState>,
    auth: BearerAuthAllowDeactivated,
) -> Response {
    let auth_user = auth.0;
    let has_full_access = auth_user.permissions().has_full_access();
    let user_id: uuid::Uuid =
        match sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", &*auth_user.did)
            .fetch_optional(&state.db)
            .await
        {
            Ok(Some(id)) => id,
            _ => {
                return ApiError::InternalError(Some("User not found".into())).into_response();
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
            return ApiError::InternalError(Some("Failed to fetch preferences".into()))
                .into_response();
        }
    };
    let mut personal_details_pref: Option<Value> = None;
    let mut preferences: Vec<Value> = prefs
        .into_iter()
        .filter(|row| {
            row.name == APP_BSKY_NAMESPACE
                || row.name.starts_with(&format!("{}.", APP_BSKY_NAMESPACE))
        })
        .filter_map(|row| {
            if row.name == DECLARED_AGE_PREF {
                return None;
            }
            if row.name == PERSONAL_DETAILS_PREF {
                if !has_full_access {
                    return None;
                }
                personal_details_pref = serde_json::from_value(row.value_json.clone()).ok();
            }
            serde_json::from_value(row.value_json).ok()
        })
        .collect();
    if let Some(age) = personal_details_pref
        .as_ref()
        .and_then(|pref| pref.get("birthDate"))
        .and_then(|v| v.as_str())
        .and_then(get_age_from_datestring)
    {
        let declared_age_pref = serde_json::json!({
            "$type": DECLARED_AGE_PREF,
            "isOverAge13": age >= 13,
            "isOverAge16": age >= 16,
            "isOverAge18": age >= 18,
        });
        preferences.push(declared_age_pref);
    }
    (StatusCode::OK, Json(GetPreferencesOutput { preferences })).into_response()
}

#[derive(Deserialize)]
pub struct PutPreferencesInput {
    pub preferences: Vec<Value>,
}
pub async fn put_preferences(
    State(state): State<AppState>,
    auth: BearerAuthAllowDeactivated,
    Json(input): Json<PutPreferencesInput>,
) -> Response {
    let auth_user = auth.0;
    let has_full_access = auth_user.permissions().has_full_access();
    let user_id: uuid::Uuid =
        match sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", &*auth_user.did)
            .fetch_optional(&state.db)
            .await
        {
            Ok(Some(id)) => id,
            _ => {
                return ApiError::InternalError(Some("User not found".into())).into_response();
            }
        };
    if input.preferences.len() > MAX_PREFERENCES_COUNT {
        return ApiError::InvalidRequest(format!(
            "Too many preferences: {} exceeds limit of {}",
            input.preferences.len(),
            MAX_PREFERENCES_COUNT
        ))
        .into_response();
    }
    enum PrefValidation {
        Ok(Option<String>),
        TooLarge(usize),
        MissingType,
        WrongNamespace,
    }

    let validation_results: Vec<PrefValidation> = input
        .preferences
        .iter()
        .map(|pref| {
            let pref_str = serde_json::to_string(pref).unwrap_or_default();
            if pref_str.len() > MAX_PREFERENCE_SIZE {
                return PrefValidation::TooLarge(pref_str.len());
            }
            let pref_type = match pref.get("$type").and_then(|t| t.as_str()) {
                Some(t) => t,
                None => return PrefValidation::MissingType,
            };
            if !pref_type.starts_with(APP_BSKY_NAMESPACE) {
                return PrefValidation::WrongNamespace;
            }
            if pref_type == PERSONAL_DETAILS_PREF && !has_full_access {
                PrefValidation::Ok(Some(pref_type.to_string()))
            } else {
                PrefValidation::Ok(None)
            }
        })
        .collect();

    if let Some(err) = validation_results.iter().find_map(|v| match v {
        PrefValidation::TooLarge(size) => Some(
            ApiError::InvalidRequest(format!(
                "Preference too large: {} bytes exceeds limit of {}",
                size, MAX_PREFERENCE_SIZE
            ))
            .into_response(),
        ),
        PrefValidation::MissingType => Some(
            ApiError::InvalidRequest("Preference is missing a $type".into()).into_response(),
        ),
        PrefValidation::WrongNamespace => Some(
            ApiError::InvalidRequest(format!(
                "Some preferences are not in the {} namespace",
                APP_BSKY_NAMESPACE
            ))
            .into_response(),
        ),
        PrefValidation::Ok(_) => None,
    }) {
        return err;
    }

    let forbidden_prefs: Vec<String> = validation_results
        .into_iter()
        .filter_map(|v| match v {
            PrefValidation::Ok(Some(s)) => Some(s),
            _ => None,
        })
        .collect();

    if !forbidden_prefs.is_empty() {
        return ApiError::InvalidRequest(format!(
            "Do not have authorization to set preferences: {}",
            forbidden_prefs.join(", ")
        ))
        .into_response();
    }
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(_) => {
            return ApiError::InternalError(Some("Failed to start transaction".into()))
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
        return ApiError::InternalError(Some("Failed to clear preferences".into())).into_response();
    }
    for pref in input.preferences {
        let pref_type = match pref.get("$type").and_then(|t| t.as_str()) {
            Some(t) => t,
            None => continue,
        };
        if pref_type == DECLARED_AGE_PREF {
            continue;
        }
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
            return ApiError::InternalError(Some("Failed to save preference".into()))
                .into_response();
        }
    }
    if tx.commit().await.is_err() {
        return ApiError::InternalError(Some("Failed to commit transaction".into()))
            .into_response();
    }
    StatusCode::OK.into_response()
}
