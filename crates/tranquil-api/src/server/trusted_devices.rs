use axum::{Json, extract::State};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tracing::{error, info};
use tranquil_db_traits::OAuthRepository;
use tranquil_pds::api::SuccessResponse;
use tranquil_pds::api::error::{ApiError, DbResultExt};
use tranquil_types::DeviceId;

use tranquil_pds::auth::{Active, Auth};
use tranquil_pds::state::AppState;

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
pub struct ListTrustedDevicesOutput {
    pub devices: Vec<TrustedDevice>,
}

pub async fn list_trusted_devices(
    State(state): State<AppState>,
    auth: Auth<Active>,
) -> Result<Json<ListTrustedDevicesOutput>, ApiError> {
    let rows = state
        .oauth_repo
        .list_trusted_devices(&auth.did)
        .await
        .log_db_err("listing trusted devices")?;

    let devices = rows
        .into_iter()
        .map(|row| {
            let trust_state = DeviceTrustState::from_timestamps(row.trusted_at, row.trusted_until);
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

    Ok(Json(ListTrustedDevicesOutput { devices }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeTrustedDeviceInput {
    pub device_id: DeviceId,
}

pub async fn revoke_trusted_device(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<RevokeTrustedDeviceInput>,
) -> Result<Json<SuccessResponse>, ApiError> {
    match state
        .oauth_repo
        .device_belongs_to_user(&input.device_id, &auth.did)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return Err(ApiError::DeviceNotFound);
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    }

    state
        .oauth_repo
        .revoke_device_trust(&input.device_id)
        .await
        .log_db_err("revoking device trust")?;

    info!(did = %&auth.did, device_id = %input.device_id, "Trusted device revoked");
    Ok(Json(SuccessResponse { success: true }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateTrustedDeviceInput {
    pub device_id: DeviceId,
    pub friendly_name: Option<String>,
}

pub async fn update_trusted_device(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<UpdateTrustedDeviceInput>,
) -> Result<Json<SuccessResponse>, ApiError> {
    match state
        .oauth_repo
        .device_belongs_to_user(&input.device_id, &auth.did)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return Err(ApiError::DeviceNotFound);
        }
        Err(e) => {
            error!("DB error: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    }

    state
        .oauth_repo
        .update_device_friendly_name(&input.device_id, input.friendly_name.as_deref())
        .await
        .log_db_err("updating device friendly name")?;

    info!(did = %auth.did, device_id = %input.device_id, "Trusted device updated");
    Ok(Json(SuccessResponse { success: true }))
}

pub async fn get_device_trust_state(
    oauth_repo: &dyn OAuthRepository,
    device_id: &DeviceId,
    did: &tranquil_types::Did,
) -> DeviceTrustState {
    match oauth_repo.get_device_trust_info(device_id, did).await {
        Ok(Some(info)) => DeviceTrustState::from_timestamps(info.trusted_at, info.trusted_until),
        _ => DeviceTrustState::Untrusted,
    }
}

pub async fn is_device_trusted(
    oauth_repo: &dyn OAuthRepository,
    device_id: &DeviceId,
    did: &tranquil_types::Did,
) -> bool {
    get_device_trust_state(oauth_repo, device_id, did)
        .await
        .is_trusted()
}

pub async fn trust_device(
    oauth_repo: &dyn OAuthRepository,
    device_id: &DeviceId,
) -> Result<(), tranquil_db_traits::DbError> {
    let now = Utc::now();
    let trusted_until = now + Duration::days(TRUST_DURATION_DAYS);
    oauth_repo.trust_device(device_id, now, trusted_until).await
}

pub async fn extend_device_trust(
    oauth_repo: &dyn OAuthRepository,
    device_id: &DeviceId,
) -> Result<(), tranquil_db_traits::DbError> {
    let trusted_until = Utc::now() + Duration::days(TRUST_DURATION_DAYS);
    oauth_repo
        .extend_device_trust(device_id, trusted_until)
        .await
}
