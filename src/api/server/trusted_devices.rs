use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;
use tracing::{error, info};

use crate::auth::BearerAuth;
use crate::state::AppState;

const TRUST_DURATION_DAYS: i64 = 30;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedDevice {
    pub id: String,
    pub user_agent: Option<String>,
    pub friendly_name: Option<String>,
    pub trusted_at: Option<DateTime<Utc>>,
    pub trusted_until: Option<DateTime<Utc>>,
    pub last_seen_at: DateTime<Utc>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListTrustedDevicesResponse {
    pub devices: Vec<TrustedDevice>,
}

pub async fn list_trusted_devices(State(state): State<AppState>, auth: BearerAuth) -> Response {
    let devices = sqlx::query!(
        r#"SELECT od.id, od.user_agent, od.friendly_name, od.trusted_at, od.trusted_until, od.last_seen_at
           FROM oauth_device od
           JOIN oauth_account_device oad ON od.id = oad.device_id
           WHERE oad.did = $1 AND od.trusted_until IS NOT NULL AND od.trusted_until > NOW()
           ORDER BY od.last_seen_at DESC"#,
        auth.0.did
    )
    .fetch_all(&state.db)
    .await;

    match devices {
        Ok(rows) => {
            let devices = rows
                .into_iter()
                .map(|row| TrustedDevice {
                    id: row.id,
                    user_agent: row.user_agent,
                    friendly_name: row.friendly_name,
                    trusted_at: row.trusted_at,
                    trusted_until: row.trusted_until,
                    last_seen_at: row.last_seen_at,
                })
                .collect();
            Json(ListTrustedDevicesResponse { devices }).into_response()
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeTrustedDeviceInput {
    pub device_id: String,
}

pub async fn revoke_trusted_device(
    State(state): State<AppState>,
    auth: BearerAuth,
    Json(input): Json<RevokeTrustedDeviceInput>,
) -> Response {
    let device_exists = sqlx::query_scalar!(
        r#"SELECT 1 as one FROM oauth_device od
           JOIN oauth_account_device oad ON od.id = oad.device_id
           WHERE oad.did = $1 AND od.id = $2"#,
        auth.0.did,
        input.device_id
    )
    .fetch_optional(&state.db)
    .await;

    match device_exists {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "DeviceNotFound", "message": "Device not found or not owned by this account"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    }

    let result = sqlx::query!(
        "UPDATE oauth_device SET trusted_at = NULL, trusted_until = NULL WHERE id = $1",
        input.device_id
    )
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => {
            info!(did = %auth.0.did, device_id = %input.device_id, "Trusted device revoked");
            Json(json!({"success": true})).into_response()
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateTrustedDeviceInput {
    pub device_id: String,
    pub friendly_name: Option<String>,
}

pub async fn update_trusted_device(
    State(state): State<AppState>,
    auth: BearerAuth,
    Json(input): Json<UpdateTrustedDeviceInput>,
) -> Response {
    let device_exists = sqlx::query_scalar!(
        r#"SELECT 1 as one FROM oauth_device od
           JOIN oauth_account_device oad ON od.id = oad.device_id
           WHERE oad.did = $1 AND od.id = $2"#,
        auth.0.did,
        input.device_id
    )
    .fetch_optional(&state.db)
    .await;

    match device_exists {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "DeviceNotFound", "message": "Device not found or not owned by this account"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    }

    let result = sqlx::query!(
        "UPDATE oauth_device SET friendly_name = $1 WHERE id = $2",
        input.friendly_name,
        input.device_id
    )
    .execute(&state.db)
    .await;

    match result {
        Ok(_) => {
            info!(did = %auth.0.did, device_id = %input.device_id, "Trusted device updated");
            Json(json!({"success": true})).into_response()
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

pub async fn is_device_trusted(db: &PgPool, device_id: &str, did: &str) -> bool {
    let result = sqlx::query_scalar!(
        r#"SELECT trusted_until FROM oauth_device od
           JOIN oauth_account_device oad ON od.id = oad.device_id
           WHERE od.id = $1 AND oad.did = $2"#,
        device_id,
        did
    )
    .fetch_optional(db)
    .await;

    match result {
        Ok(Some(Some(trusted_until))) => trusted_until > Utc::now(),
        _ => false,
    }
}

pub async fn trust_device(db: &PgPool, device_id: &str) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    let trusted_until = now + Duration::days(TRUST_DURATION_DAYS);

    sqlx::query!(
        "UPDATE oauth_device SET trusted_at = $1, trusted_until = $2 WHERE id = $3",
        now,
        trusted_until,
        device_id
    )
    .execute(db)
    .await?;

    Ok(())
}

pub async fn extend_device_trust(db: &PgPool, device_id: &str) -> Result<(), sqlx::Error> {
    let trusted_until = Utc::now() + Duration::days(TRUST_DURATION_DAYS);

    sqlx::query!(
        "UPDATE oauth_device SET trusted_until = $1 WHERE id = $2 AND trusted_until IS NOT NULL",
        trusted_until,
        device_id
    )
    .execute(db)
    .await?;

    Ok(())
}
