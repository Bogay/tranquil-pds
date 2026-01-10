use crate::api::SuccessResponse;
use crate::api::error::ApiError;
use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{error, info};

use crate::auth::BearerAuth;
use crate::state::AppState;

const TRUST_DURATION_DAYS: i64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceTrustState {
    Untrusted,
    Trusted,
    Expired,
}

impl DeviceTrustState {
    pub fn from_timestamps(
        trusted_at: Option<DateTime<Utc>>,
        trusted_until: Option<DateTime<Utc>>,
    ) -> Self {
        match (trusted_at, trusted_until) {
            (Some(_), Some(until)) if until > Utc::now() => Self::Trusted,
            (Some(_), Some(_)) => Self::Expired,
            _ => Self::Untrusted,
        }
    }

    pub fn is_trusted(&self) -> bool {
        matches!(self, Self::Trusted)
    }

    pub fn is_expired(&self) -> bool {
        matches!(self, Self::Expired)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Untrusted => "untrusted",
            Self::Trusted => "trusted",
            Self::Expired => "expired",
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedDevice {
    pub id: String,
    pub user_agent: Option<String>,
    pub friendly_name: Option<String>,
    pub trusted_at: Option<DateTime<Utc>>,
    pub trusted_until: Option<DateTime<Utc>>,
    pub last_seen_at: DateTime<Utc>,
    pub trust_state: DeviceTrustState,
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
        &auth.0.did
    )
    .fetch_all(&state.db)
    .await;

    match devices {
        Ok(rows) => {
            let devices = rows
                .into_iter()
                .map(|row| {
                    let trust_state =
                        DeviceTrustState::from_timestamps(row.trusted_at, row.trusted_until);
                    TrustedDevice {
                        id: row.id,
                        user_agent: row.user_agent,
                        friendly_name: row.friendly_name,
                        trusted_at: row.trusted_at,
                        trusted_until: row.trusted_until,
                        last_seen_at: row.last_seen_at,
                        trust_state,
                    }
                })
                .collect();
            Json(ListTrustedDevicesResponse { devices }).into_response()
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            ApiError::InternalError(None).into_response()
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
        &auth.0.did,
        input.device_id
    )
    .fetch_optional(&state.db)
    .await;

    match device_exists {
        Ok(Some(_)) => {}
        Ok(None) => {
            return ApiError::DeviceNotFound.into_response();
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            return ApiError::InternalError(None).into_response();
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
            info!(did = %&auth.0.did, device_id = %input.device_id, "Trusted device revoked");
            SuccessResponse::ok().into_response()
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            ApiError::InternalError(None).into_response()
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
        &auth.0.did,
        input.device_id
    )
    .fetch_optional(&state.db)
    .await;

    match device_exists {
        Ok(Some(_)) => {}
        Ok(None) => {
            return ApiError::DeviceNotFound.into_response();
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            return ApiError::InternalError(None).into_response();
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
            SuccessResponse::ok().into_response()
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            ApiError::InternalError(None).into_response()
        }
    }
}

pub async fn get_device_trust_state(db: &PgPool, device_id: &str, did: &str) -> DeviceTrustState {
    let result = sqlx::query!(
        r#"SELECT trusted_at, trusted_until FROM oauth_device od
           JOIN oauth_account_device oad ON od.id = oad.device_id
           WHERE od.id = $1 AND oad.did = $2"#,
        device_id,
        did
    )
    .fetch_optional(db)
    .await;

    match result {
        Ok(Some(row)) => DeviceTrustState::from_timestamps(row.trusted_at, row.trusted_until),
        _ => DeviceTrustState::Untrusted,
    }
}

pub async fn is_device_trusted(db: &PgPool, device_id: &str, did: &str) -> bool {
    get_device_trust_state(db, device_id, did)
        .await
        .is_trusted()
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
