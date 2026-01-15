use crate::api::SuccessResponse;
use crate::api::error::ApiError;
use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tracing::{error, info};
use tranquil_db_traits::OAuthRepository;
use tranquil_types::DeviceId;

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
    match state.oauth_repo.list_trusted_devices(&auth.0.did).await {
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
    let device_id = DeviceId::from(input.device_id.clone());
    match state
        .oauth_repo
        .device_belongs_to_user(&device_id, &auth.0.did)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return ApiError::DeviceNotFound.into_response();
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    }

    match state.oauth_repo.revoke_device_trust(&device_id).await {
        Ok(()) => {
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
    let device_id = DeviceId::from(input.device_id.clone());
    match state
        .oauth_repo
        .device_belongs_to_user(&device_id, &auth.0.did)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return ApiError::DeviceNotFound.into_response();
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    }

    match state
        .oauth_repo
        .update_device_friendly_name(&device_id, input.friendly_name.as_deref())
        .await
    {
        Ok(()) => {
            info!(did = %auth.0.did, device_id = %input.device_id, "Trusted device updated");
            SuccessResponse::ok().into_response()
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            ApiError::InternalError(None).into_response()
        }
    }
}

pub async fn get_device_trust_state(
    oauth_repo: &dyn OAuthRepository,
    device_id: &str,
    did: &tranquil_types::Did,
) -> DeviceTrustState {
    let device_id_typed = DeviceId::from(device_id.to_string());
    match oauth_repo
        .get_device_trust_info(&device_id_typed, did)
        .await
    {
        Ok(Some(info)) => DeviceTrustState::from_timestamps(info.trusted_at, info.trusted_until),
        _ => DeviceTrustState::Untrusted,
    }
}

pub async fn is_device_trusted(
    oauth_repo: &dyn OAuthRepository,
    device_id: &str,
    did: &tranquil_types::Did,
) -> bool {
    get_device_trust_state(oauth_repo, device_id, did)
        .await
        .is_trusted()
}

pub async fn trust_device(
    oauth_repo: &dyn OAuthRepository,
    device_id: &str,
) -> Result<(), tranquil_db_traits::DbError> {
    let now = Utc::now();
    let trusted_until = now + Duration::days(TRUST_DURATION_DAYS);
    let device_id_typed = DeviceId::from(device_id.to_string());
    oauth_repo
        .trust_device(&device_id_typed, now, trusted_until)
        .await
}

pub async fn extend_device_trust(
    oauth_repo: &dyn OAuthRepository,
    device_id: &str,
) -> Result<(), tranquil_db_traits::DbError> {
    let trusted_until = Utc::now() + Duration::days(TRUST_DURATION_DAYS);
    let device_id_typed = DeviceId::from(device_id.to_string());
    oauth_repo
        .extend_device_trust(&device_id_typed, trusted_until)
        .await
}
