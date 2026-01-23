use crate::api::error::ApiError;
use crate::auth::{Admin, Auth};
use crate::state::AppState;
use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use tracing::error;
use tranquil_types::CidLink;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerConfigResponse {
    pub server_name: String,
    pub primary_color: Option<String>,
    pub primary_color_dark: Option<String>,
    pub secondary_color: Option<String>,
    pub secondary_color_dark: Option<String>,
    pub logo_cid: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateServerConfigRequest {
    pub server_name: Option<String>,
    pub primary_color: Option<String>,
    pub primary_color_dark: Option<String>,
    pub secondary_color: Option<String>,
    pub secondary_color_dark: Option<String>,
    pub logo_cid: Option<String>,
}

#[derive(Serialize)]
pub struct UpdateServerConfigResponse {
    pub success: bool,
}

fn is_valid_hex_color(s: &str) -> bool {
    if s.len() != 7 || !s.starts_with('#') {
        return false;
    }
    s[1..].chars().all(|c| c.is_ascii_hexdigit())
}

pub async fn get_server_config(
    State(state): State<AppState>,
) -> Result<Json<ServerConfigResponse>, ApiError> {
    let keys = &[
        "server_name",
        "primary_color",
        "primary_color_dark",
        "secondary_color",
        "secondary_color_dark",
        "logo_cid",
    ];

    let rows = state
        .infra_repo
        .get_server_configs(keys)
        .await
        .map_err(|e| {
            error!("DB error fetching server config: {:?}", e);
            ApiError::InternalError(None)
        })?;

    let config_map: std::collections::HashMap<String, String> = rows.into_iter().collect();

    Ok(Json(ServerConfigResponse {
        server_name: config_map
            .get("server_name")
            .cloned()
            .unwrap_or_else(|| "Tranquil PDS".to_string()),
        primary_color: config_map.get("primary_color").cloned(),
        primary_color_dark: config_map.get("primary_color_dark").cloned(),
        secondary_color: config_map.get("secondary_color").cloned(),
        secondary_color_dark: config_map.get("secondary_color_dark").cloned(),
        logo_cid: config_map.get("logo_cid").cloned(),
    }))
}

pub async fn update_server_config(
    State(state): State<AppState>,
    _auth: Auth<Admin>,
    Json(req): Json<UpdateServerConfigRequest>,
) -> Result<Json<UpdateServerConfigResponse>, ApiError> {
    if let Some(server_name) = req.server_name {
        let trimmed = server_name.trim();
        if trimmed.is_empty() || trimmed.len() > 100 {
            return Err(ApiError::InvalidRequest(
                "Server name must be 1-100 characters".into(),
            ));
        }
        state
            .infra_repo
            .upsert_server_config("server_name", trimmed)
            .await
            .map_err(|e| {
                error!("DB error upserting server_name: {:?}", e);
                ApiError::InternalError(None)
            })?;
    }

    if let Some(ref color) = req.primary_color {
        if color.is_empty() {
            state
                .infra_repo
                .delete_server_config("primary_color")
                .await
                .map_err(|e| {
                    error!("DB error deleting primary_color: {:?}", e);
                    ApiError::InternalError(None)
                })?;
        } else if is_valid_hex_color(color) {
            state
                .infra_repo
                .upsert_server_config("primary_color", color)
                .await
                .map_err(|e| {
                    error!("DB error upserting primary_color: {:?}", e);
                    ApiError::InternalError(None)
                })?;
        } else {
            return Err(ApiError::InvalidRequest(
                "Invalid primary color format (expected #RRGGBB)".into(),
            ));
        }
    }

    if let Some(ref color) = req.primary_color_dark {
        if color.is_empty() {
            state
                .infra_repo
                .delete_server_config("primary_color_dark")
                .await
                .map_err(|e| {
                    error!("DB error deleting primary_color_dark: {:?}", e);
                    ApiError::InternalError(None)
                })?;
        } else if is_valid_hex_color(color) {
            state
                .infra_repo
                .upsert_server_config("primary_color_dark", color)
                .await
                .map_err(|e| {
                    error!("DB error upserting primary_color_dark: {:?}", e);
                    ApiError::InternalError(None)
                })?;
        } else {
            return Err(ApiError::InvalidRequest(
                "Invalid primary dark color format (expected #RRGGBB)".into(),
            ));
        }
    }

    if let Some(ref color) = req.secondary_color {
        if color.is_empty() {
            state
                .infra_repo
                .delete_server_config("secondary_color")
                .await
                .map_err(|e| {
                    error!("DB error deleting secondary_color: {:?}", e);
                    ApiError::InternalError(None)
                })?;
        } else if is_valid_hex_color(color) {
            state
                .infra_repo
                .upsert_server_config("secondary_color", color)
                .await
                .map_err(|e| {
                    error!("DB error upserting secondary_color: {:?}", e);
                    ApiError::InternalError(None)
                })?;
        } else {
            return Err(ApiError::InvalidRequest(
                "Invalid secondary color format (expected #RRGGBB)".into(),
            ));
        }
    }

    if let Some(ref color) = req.secondary_color_dark {
        if color.is_empty() {
            state
                .infra_repo
                .delete_server_config("secondary_color_dark")
                .await
                .map_err(|e| {
                    error!("DB error deleting secondary_color_dark: {:?}", e);
                    ApiError::InternalError(None)
                })?;
        } else if is_valid_hex_color(color) {
            state
                .infra_repo
                .upsert_server_config("secondary_color_dark", color)
                .await
                .map_err(|e| {
                    error!("DB error upserting secondary_color_dark: {:?}", e);
                    ApiError::InternalError(None)
                })?;
        } else {
            return Err(ApiError::InvalidRequest(
                "Invalid secondary dark color format (expected #RRGGBB)".into(),
            ));
        }
    }

    if let Some(ref logo_cid) = req.logo_cid {
        let old_logo_cid = state
            .infra_repo
            .get_server_config("logo_cid")
            .await
            .ok()
            .flatten();

        let should_delete_old = match (&old_logo_cid, logo_cid.is_empty()) {
            (Some(old), true) => Some(old.clone()),
            (Some(old), false) if old != logo_cid => Some(old.clone()),
            _ => None,
        };

        if let Some(old_cid_str) = should_delete_old {
            let old_cid = CidLink::new_unchecked(old_cid_str);
            if let Ok(Some(storage_key)) =
                state.infra_repo.get_blob_storage_key_by_cid(&old_cid).await
            {
                if let Err(e) = state.blob_store.delete(&storage_key).await {
                    error!("Failed to delete old logo blob from storage: {:?}", e);
                }
                if let Err(e) = state.infra_repo.delete_blob_by_cid(&old_cid).await {
                    error!("Failed to delete old logo blob record: {:?}", e);
                }
            }
        }

        if logo_cid.is_empty() {
            state
                .infra_repo
                .delete_server_config("logo_cid")
                .await
                .map_err(|e| {
                    error!("DB error deleting logo_cid: {:?}", e);
                    ApiError::InternalError(None)
                })?;
        } else {
            state
                .infra_repo
                .upsert_server_config("logo_cid", logo_cid)
                .await
                .map_err(|e| {
                    error!("DB error upserting logo_cid: {:?}", e);
                    ApiError::InternalError(None)
                })?;
        }
    }

    Ok(Json(UpdateServerConfigResponse { success: true }))
}
