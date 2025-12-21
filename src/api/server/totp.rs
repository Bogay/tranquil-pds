use crate::auth::BearerAuth;
use crate::auth::totp::{
    decrypt_totp_secret, encrypt_totp_secret, generate_backup_codes, generate_qr_png_base64,
    generate_totp_secret, generate_totp_uri, hash_backup_code, is_backup_code_format,
    verify_backup_code, verify_totp_code,
};
use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{error, info, warn};

const ENCRYPTION_VERSION: i32 = 1;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTotpSecretResponse {
    pub secret: String,
    pub uri: String,
    pub qr_base64: String,
}

pub async fn create_totp_secret(State(state): State<AppState>, auth: BearerAuth) -> Response {
    let existing = sqlx::query_scalar!("SELECT verified FROM user_totp WHERE did = $1", auth.0.did)
        .fetch_optional(&state.db)
        .await;

    if let Ok(Some(true)) = existing {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "TotpAlreadyEnabled",
                "message": "TOTP is already enabled for this account"
            })),
        )
            .into_response();
    }

    let secret = generate_totp_secret();

    let handle = sqlx::query_scalar!("SELECT handle FROM users WHERE did = $1", auth.0.did)
        .fetch_optional(&state.db)
        .await;

    let handle = match handle {
        Ok(Some(h)) => h,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "AccountNotFound", "message": "Account not found"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error fetching handle: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let uri = generate_totp_uri(&secret, &handle, &hostname);

    let qr_code = match generate_qr_png_base64(&secret, &handle, &hostname) {
        Ok(qr) => qr,
        Err(e) => {
            error!("Failed to generate QR code: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Failed to generate QR code"})),
            )
                .into_response();
        }
    };

    let encrypted_secret = match encrypt_totp_secret(&secret) {
        Ok(enc) => enc,
        Err(e) => {
            error!("Failed to encrypt TOTP secret: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let result = sqlx::query!(
        r#"
        INSERT INTO user_totp (did, secret_encrypted, encryption_version, verified, created_at)
        VALUES ($1, $2, $3, false, NOW())
        ON CONFLICT (did) DO UPDATE SET
            secret_encrypted = $2,
            encryption_version = $3,
            verified = false,
            created_at = NOW(),
            last_used = NULL
        "#,
        auth.0.did,
        encrypted_secret,
        ENCRYPTION_VERSION
    )
    .execute(&state.db)
    .await;

    if let Err(e) = result {
        error!("Failed to store TOTP secret: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    let secret_base32 = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &secret);

    info!(did = %auth.0.did, "TOTP secret created (pending verification)");

    Json(CreateTotpSecretResponse {
        secret: secret_base32,
        uri,
        qr_base64: qr_code,
    })
    .into_response()
}

#[derive(Deserialize)]
pub struct EnableTotpInput {
    pub code: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnableTotpResponse {
    pub backup_codes: Vec<String>,
}

pub async fn enable_totp(
    State(state): State<AppState>,
    auth: BearerAuth,
    Json(input): Json<EnableTotpInput>,
) -> Response {
    let totp_row = sqlx::query!(
        "SELECT secret_encrypted, encryption_version, verified FROM user_totp WHERE did = $1",
        auth.0.did
    )
    .fetch_optional(&state.db)
    .await;

    let totp_row = match totp_row {
        Ok(Some(row)) => row,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "TotpNotSetup",
                    "message": "Please call createTotpSecret first"
                })),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error fetching TOTP: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    if totp_row.verified {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "TotpAlreadyEnabled",
                "message": "TOTP is already enabled"
            })),
        )
            .into_response();
    }

    let secret = match decrypt_totp_secret(&totp_row.secret_encrypted, totp_row.encryption_version)
    {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to decrypt TOTP secret: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let code = input.code.trim();
    if !verify_totp_code(&secret, code) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "InvalidCode",
                "message": "Invalid verification code"
            })),
        )
            .into_response();
    }

    let backup_codes = generate_backup_codes();
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            error!("Failed to begin transaction: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    if let Err(e) = sqlx::query!(
        "UPDATE user_totp SET verified = true, last_used = NOW() WHERE did = $1",
        auth.0.did
    )
    .execute(&mut *tx)
    .await
    {
        error!("Failed to enable TOTP: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    if let Err(e) = sqlx::query!("DELETE FROM backup_codes WHERE did = $1", auth.0.did)
        .execute(&mut *tx)
        .await
    {
        error!("Failed to clear old backup codes: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    for code in &backup_codes {
        let hash = match hash_backup_code(code) {
            Ok(h) => h,
            Err(e) => {
                error!("Failed to hash backup code: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError"})),
                )
                    .into_response();
            }
        };

        if let Err(e) = sqlx::query!(
            "INSERT INTO backup_codes (did, code_hash, created_at) VALUES ($1, $2, NOW())",
            auth.0.did,
            hash
        )
        .execute(&mut *tx)
        .await
        {
            error!("Failed to store backup code: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    }

    if let Err(e) = tx.commit().await {
        error!("Failed to commit transaction: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    info!(did = %auth.0.did, "TOTP enabled with {} backup codes", backup_codes.len());

    Json(EnableTotpResponse { backup_codes }).into_response()
}

#[derive(Deserialize)]
pub struct DisableTotpInput {
    pub password: String,
    pub code: String,
}

pub async fn disable_totp(
    State(state): State<AppState>,
    auth: BearerAuth,
    Json(input): Json<DisableTotpInput>,
) -> Response {
    let user = sqlx::query!("SELECT password_hash FROM users WHERE did = $1", auth.0.did)
        .fetch_optional(&state.db)
        .await;

    let password_hash = match user {
        Ok(Some(row)) => row.password_hash,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "AccountNotFound", "message": "Account not found"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error fetching user: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let password_valid = password_hash
        .as_ref()
        .map(|h| bcrypt::verify(&input.password, h).unwrap_or(false))
        .unwrap_or(false);
    if !password_valid {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "InvalidPassword",
                "message": "Password is incorrect"
            })),
        )
            .into_response();
    }

    let totp_row = sqlx::query!(
        "SELECT secret_encrypted, encryption_version, verified FROM user_totp WHERE did = $1",
        auth.0.did
    )
    .fetch_optional(&state.db)
    .await;

    let totp_row = match totp_row {
        Ok(Some(row)) if row.verified => row,
        Ok(Some(_)) | Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "TotpNotEnabled",
                    "message": "TOTP is not enabled for this account"
                })),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error fetching TOTP: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let code = input.code.trim();
    let code_valid = if is_backup_code_format(code) {
        verify_backup_code_for_user(&state, &auth.0.did, code).await
    } else {
        let secret =
            match decrypt_totp_secret(&totp_row.secret_encrypted, totp_row.encryption_version) {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to decrypt TOTP secret: {:?}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "InternalError"})),
                    )
                        .into_response();
                }
            };
        verify_totp_code(&secret, code)
    };

    if !code_valid {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "InvalidCode",
                "message": "Invalid verification code"
            })),
        )
            .into_response();
    }

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            error!("Failed to begin transaction: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    if let Err(e) = sqlx::query!("DELETE FROM user_totp WHERE did = $1", auth.0.did)
        .execute(&mut *tx)
        .await
    {
        error!("Failed to delete TOTP: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    if let Err(e) = sqlx::query!("DELETE FROM backup_codes WHERE did = $1", auth.0.did)
        .execute(&mut *tx)
        .await
    {
        error!("Failed to delete backup codes: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    if let Err(e) = tx.commit().await {
        error!("Failed to commit transaction: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    info!(did = %auth.0.did, "TOTP disabled");

    (StatusCode::OK, Json(json!({}))).into_response()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTotpStatusResponse {
    pub enabled: bool,
    pub has_backup_codes: bool,
    pub backup_codes_remaining: i64,
}

pub async fn get_totp_status(State(state): State<AppState>, auth: BearerAuth) -> Response {
    let totp_row = sqlx::query!("SELECT verified FROM user_totp WHERE did = $1", auth.0.did)
        .fetch_optional(&state.db)
        .await;

    let enabled = match totp_row {
        Ok(Some(row)) => row.verified,
        Ok(None) => false,
        Err(e) => {
            error!("DB error fetching TOTP status: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let backup_count_row = sqlx::query!(
        "SELECT COUNT(*) as count FROM backup_codes WHERE did = $1 AND used_at IS NULL",
        auth.0.did
    )
    .fetch_one(&state.db)
    .await;

    let backup_count = backup_count_row.map(|r| r.count.unwrap_or(0)).unwrap_or(0);

    Json(GetTotpStatusResponse {
        enabled,
        has_backup_codes: backup_count > 0,
        backup_codes_remaining: backup_count,
    })
    .into_response()
}

#[derive(Deserialize)]
pub struct RegenerateBackupCodesInput {
    pub password: String,
    pub code: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegenerateBackupCodesResponse {
    pub backup_codes: Vec<String>,
}

pub async fn regenerate_backup_codes(
    State(state): State<AppState>,
    auth: BearerAuth,
    Json(input): Json<RegenerateBackupCodesInput>,
) -> Response {
    let user = sqlx::query!("SELECT password_hash FROM users WHERE did = $1", auth.0.did)
        .fetch_optional(&state.db)
        .await;

    let password_hash = match user {
        Ok(Some(row)) => row.password_hash,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "AccountNotFound", "message": "Account not found"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error fetching user: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let password_valid = password_hash
        .as_ref()
        .map(|h| bcrypt::verify(&input.password, h).unwrap_or(false))
        .unwrap_or(false);
    if !password_valid {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "InvalidPassword",
                "message": "Password is incorrect"
            })),
        )
            .into_response();
    }

    let totp_row = sqlx::query!(
        "SELECT secret_encrypted, encryption_version, verified FROM user_totp WHERE did = $1",
        auth.0.did
    )
    .fetch_optional(&state.db)
    .await;

    let totp_row = match totp_row {
        Ok(Some(row)) if row.verified => row,
        Ok(Some(_)) | Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "TotpNotEnabled",
                    "message": "TOTP must be enabled to regenerate backup codes"
                })),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error fetching TOTP: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let secret = match decrypt_totp_secret(&totp_row.secret_encrypted, totp_row.encryption_version)
    {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to decrypt TOTP secret: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let code = input.code.trim();
    if !verify_totp_code(&secret, code) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "InvalidCode",
                "message": "Invalid verification code"
            })),
        )
            .into_response();
    }

    let backup_codes = generate_backup_codes();
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            error!("Failed to begin transaction: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    if let Err(e) = sqlx::query!("DELETE FROM backup_codes WHERE did = $1", auth.0.did)
        .execute(&mut *tx)
        .await
    {
        error!("Failed to clear old backup codes: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    for code in &backup_codes {
        let hash = match hash_backup_code(code) {
            Ok(h) => h,
            Err(e) => {
                error!("Failed to hash backup code: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError"})),
                )
                    .into_response();
            }
        };

        if let Err(e) = sqlx::query!(
            "INSERT INTO backup_codes (did, code_hash, created_at) VALUES ($1, $2, NOW())",
            auth.0.did,
            hash
        )
        .execute(&mut *tx)
        .await
        {
            error!("Failed to store backup code: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    }

    if let Err(e) = tx.commit().await {
        error!("Failed to commit transaction: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    info!(did = %auth.0.did, "Backup codes regenerated");

    Json(RegenerateBackupCodesResponse { backup_codes }).into_response()
}

async fn verify_backup_code_for_user(state: &AppState, did: &str, code: &str) -> bool {
    let code = code.trim().to_uppercase();

    let backup_codes = sqlx::query!(
        "SELECT id, code_hash FROM backup_codes WHERE did = $1 AND used_at IS NULL",
        did
    )
    .fetch_all(&state.db)
    .await;

    let backup_codes = match backup_codes {
        Ok(codes) => codes,
        Err(e) => {
            warn!("Failed to fetch backup codes: {:?}", e);
            return false;
        }
    };

    for row in backup_codes {
        if verify_backup_code(&code, &row.code_hash) {
            let _ = sqlx::query!(
                "UPDATE backup_codes SET used_at = $1 WHERE id = $2",
                Utc::now(),
                row.id
            )
            .execute(&state.db)
            .await;
            return true;
        }
    }

    false
}

pub async fn verify_totp_or_backup_for_user(state: &AppState, did: &str, code: &str) -> bool {
    let code = code.trim();

    if is_backup_code_format(code) {
        return verify_backup_code_for_user(state, did, code).await;
    }

    let totp_row = sqlx::query!(
        "SELECT secret_encrypted, encryption_version, verified FROM user_totp WHERE did = $1",
        did
    )
    .fetch_optional(&state.db)
    .await;

    let totp_row = match totp_row {
        Ok(Some(row)) if row.verified => row,
        _ => return false,
    };

    let secret = match decrypt_totp_secret(&totp_row.secret_encrypted, totp_row.encryption_version)
    {
        Ok(s) => s,
        Err(_) => return false,
    };

    if verify_totp_code(&secret, code) {
        let _ = sqlx::query!("UPDATE user_totp SET last_used = NOW() WHERE did = $1", did)
            .execute(&state.db)
            .await;
        return true;
    }

    false
}

pub async fn has_totp_enabled(state: &AppState, did: &str) -> bool {
    has_totp_enabled_db(&state.db, did).await
}

pub async fn has_totp_enabled_db(db: &sqlx::PgPool, did: &str) -> bool {
    let result = sqlx::query_scalar!("SELECT verified FROM user_totp WHERE did = $1", did)
        .fetch_optional(db)
        .await;

    matches!(result, Ok(Some(true)))
}
