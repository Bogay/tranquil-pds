use crate::api::error::ApiError;
use crate::auth::BearerAuthAdmin;
use crate::state::AppState;
use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use tracing::error;

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
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT key, value FROM server_config WHERE key IN ('server_name', 'primary_color', 'primary_color_dark', 'secondary_color', 'secondary_color_dark', 'logo_cid')"
    )
    .fetch_all(&state.db)
    .await?;

    let mut server_name = "Tranquil PDS".to_string();
    let mut primary_color = None;
    let mut primary_color_dark = None;
    let mut secondary_color = None;
    let mut secondary_color_dark = None;
    let mut logo_cid = None;

    for (key, value) in rows {
        match key.as_str() {
            "server_name" => server_name = value,
            "primary_color" => primary_color = Some(value),
            "primary_color_dark" => primary_color_dark = Some(value),
            "secondary_color" => secondary_color = Some(value),
            "secondary_color_dark" => secondary_color_dark = Some(value),
            "logo_cid" => logo_cid = Some(value),
            _ => {}
        }
    }

    Ok(Json(ServerConfigResponse {
        server_name,
        primary_color,
        primary_color_dark,
        secondary_color,
        secondary_color_dark,
        logo_cid,
    }))
}

async fn upsert_config(db: &sqlx::PgPool, key: &str, value: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO server_config (key, value, updated_at) VALUES ($1, $2, NOW())
         ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()",
    )
    .bind(key)
    .bind(value)
    .execute(db)
    .await?;
    Ok(())
}

async fn delete_config(db: &sqlx::PgPool, key: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM server_config WHERE key = $1")
        .bind(key)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn update_server_config(
    State(state): State<AppState>,
    _admin: BearerAuthAdmin,
    Json(req): Json<UpdateServerConfigRequest>,
) -> Result<Json<UpdateServerConfigResponse>, ApiError> {
    if let Some(server_name) = req.server_name {
        let trimmed = server_name.trim();
        if trimmed.is_empty() || trimmed.len() > 100 {
            return Err(ApiError::InvalidRequest(
                "Server name must be 1-100 characters".into(),
            ));
        }
        upsert_config(&state.db, "server_name", trimmed).await?;
    }

    if let Some(ref color) = req.primary_color {
        if color.is_empty() {
            delete_config(&state.db, "primary_color").await?;
        } else if is_valid_hex_color(color) {
            upsert_config(&state.db, "primary_color", color).await?;
        } else {
            return Err(ApiError::InvalidRequest(
                "Invalid primary color format (expected #RRGGBB)".into(),
            ));
        }
    }

    if let Some(ref color) = req.primary_color_dark {
        if color.is_empty() {
            delete_config(&state.db, "primary_color_dark").await?;
        } else if is_valid_hex_color(color) {
            upsert_config(&state.db, "primary_color_dark", color).await?;
        } else {
            return Err(ApiError::InvalidRequest(
                "Invalid primary dark color format (expected #RRGGBB)".into(),
            ));
        }
    }

    if let Some(ref color) = req.secondary_color {
        if color.is_empty() {
            delete_config(&state.db, "secondary_color").await?;
        } else if is_valid_hex_color(color) {
            upsert_config(&state.db, "secondary_color", color).await?;
        } else {
            return Err(ApiError::InvalidRequest(
                "Invalid secondary color format (expected #RRGGBB)".into(),
            ));
        }
    }

    if let Some(ref color) = req.secondary_color_dark {
        if color.is_empty() {
            delete_config(&state.db, "secondary_color_dark").await?;
        } else if is_valid_hex_color(color) {
            upsert_config(&state.db, "secondary_color_dark", color).await?;
        } else {
            return Err(ApiError::InvalidRequest(
                "Invalid secondary dark color format (expected #RRGGBB)".into(),
            ));
        }
    }

    if let Some(ref logo_cid) = req.logo_cid {
        let old_logo_cid: Option<String> =
            sqlx::query_scalar("SELECT value FROM server_config WHERE key = 'logo_cid'")
                .fetch_optional(&state.db)
                .await?;

        let should_delete_old = match (&old_logo_cid, logo_cid.is_empty()) {
            (Some(old), true) => Some(old.clone()),
            (Some(old), false) if old != logo_cid => Some(old.clone()),
            _ => None,
        };

        if let Some(old_cid) = should_delete_old
            && let Ok(Some(blob)) =
                sqlx::query!("SELECT storage_key FROM blobs WHERE cid = $1", old_cid)
                    .fetch_optional(&state.db)
                    .await
        {
            if let Err(e) = state.blob_store.delete(&blob.storage_key).await {
                error!("Failed to delete old logo blob from storage: {:?}", e);
            }
            if let Err(e) = sqlx::query!("DELETE FROM blobs WHERE cid = $1", old_cid)
                .execute(&state.db)
                .await
            {
                error!("Failed to delete old logo blob record: {:?}", e);
            }
        }

        if logo_cid.is_empty() {
            delete_config(&state.db, "logo_cid").await?;
        } else {
            upsert_config(&state.db, "logo_cid", logo_cid).await?;
        }
    }

    Ok(Json(UpdateServerConfigResponse { success: true }))
}
