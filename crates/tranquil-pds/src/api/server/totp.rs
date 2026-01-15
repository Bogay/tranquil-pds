use crate::api::EmptyResponse;
use crate::api::error::ApiError;
use crate::auth::BearerAuth;
use crate::auth::{
    decrypt_totp_secret, encrypt_totp_secret, generate_backup_codes, generate_qr_png_base64,
    generate_totp_secret, generate_totp_uri, hash_backup_code, is_backup_code_format,
    verify_backup_code, verify_totp_code,
};
use crate::state::{AppState, RateLimitKind};
use crate::types::PlainPassword;
use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
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
    match state.user_repo.get_totp_record(&auth.0.did).await {
        Ok(Some(record)) if record.verified => return ApiError::TotpAlreadyEnabled.into_response(),
        Ok(_) => {}
        Err(e) => {
            error!("DB error checking TOTP: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    }

    let secret = generate_totp_secret();

    let handle = match state.user_repo.get_handle_by_did(&auth.0.did).await {
        Ok(Some(h)) => h,
        Ok(None) => return ApiError::AccountNotFound.into_response(),
        Err(e) => {
            error!("DB error fetching handle: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let uri = generate_totp_uri(&secret, &handle, &hostname);

    let qr_code = match generate_qr_png_base64(&secret, &handle, &hostname) {
        Ok(qr) => qr,
        Err(e) => {
            error!("Failed to generate QR code: {:?}", e);
            return ApiError::InternalError(Some("Failed to generate QR code".into()))
                .into_response();
        }
    };

    let encrypted_secret = match encrypt_totp_secret(&secret) {
        Ok(enc) => enc,
        Err(e) => {
            error!("Failed to encrypt TOTP secret: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    if let Err(e) = state
        .user_repo
        .upsert_totp_secret(&auth.0.did, &encrypted_secret, ENCRYPTION_VERSION)
        .await
    {
        error!("Failed to store TOTP secret: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }

    let secret_base32 = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &secret);

    info!(did = %&auth.0.did, "TOTP secret created (pending verification)");

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
    if !state
        .check_rate_limit(RateLimitKind::TotpVerify, &auth.0.did)
        .await
    {
        warn!(did = %&auth.0.did, "TOTP verification rate limit exceeded");
        return ApiError::RateLimitExceeded(None).into_response();
    }

    let totp_record = match state.user_repo.get_totp_record(&auth.0.did).await {
        Ok(Some(row)) => row,
        Ok(None) => return ApiError::TotpNotEnabled.into_response(),
        Err(e) => {
            error!("DB error fetching TOTP: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    if totp_record.verified {
        return ApiError::TotpAlreadyEnabled.into_response();
    }

    let secret = match decrypt_totp_secret(
        &totp_record.secret_encrypted,
        totp_record.encryption_version,
    ) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to decrypt TOTP secret: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let code = input.code.trim();
    if !verify_totp_code(&secret, code) {
        return ApiError::InvalidCode(Some("Invalid verification code".into())).into_response();
    }

    let backup_codes = generate_backup_codes();
    let backup_hashes: Result<Vec<_>, _> =
        backup_codes.iter().map(|c| hash_backup_code(c)).collect();
    let backup_hashes = match backup_hashes {
        Ok(hashes) => hashes,
        Err(e) => {
            error!("Failed to hash backup code: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    if let Err(e) = state
        .user_repo
        .enable_totp_with_backup_codes(&auth.0.did, &backup_hashes)
        .await
    {
        error!("Failed to enable TOTP: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }

    info!(did = %&auth.0.did, "TOTP enabled with {} backup codes", backup_codes.len());

    Json(EnableTotpResponse { backup_codes }).into_response()
}

#[derive(Deserialize)]
pub struct DisableTotpInput {
    pub password: PlainPassword,
    pub code: String,
}

pub async fn disable_totp(
    State(state): State<AppState>,
    auth: BearerAuth,
    Json(input): Json<DisableTotpInput>,
) -> Response {
    if !crate::api::server::reauth::check_legacy_session_mfa(&*state.session_repo, &auth.0.did)
        .await
    {
        return crate::api::server::reauth::legacy_mfa_required_response(
            &*state.user_repo,
            &*state.session_repo,
            &auth.0.did,
        )
        .await;
    }

    if !state
        .check_rate_limit(RateLimitKind::TotpVerify, &auth.0.did)
        .await
    {
        warn!(did = %&auth.0.did, "TOTP verification rate limit exceeded");
        return ApiError::RateLimitExceeded(None).into_response();
    }

    let password_hash = match state.user_repo.get_password_hash_by_did(&auth.0.did).await {
        Ok(Some(hash)) => hash,
        Ok(None) => return ApiError::AccountNotFound.into_response(),
        Err(e) => {
            error!("DB error fetching user: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let password_valid = bcrypt::verify(&input.password, &password_hash).unwrap_or(false);
    if !password_valid {
        return ApiError::InvalidPassword("Password is incorrect".into()).into_response();
    }

    let totp_record = match state.user_repo.get_totp_record(&auth.0.did).await {
        Ok(Some(row)) if row.verified => row,
        Ok(Some(_)) | Ok(None) => return ApiError::TotpNotEnabled.into_response(),
        Err(e) => {
            error!("DB error fetching TOTP: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let code = input.code.trim();
    let code_valid = if is_backup_code_format(code) {
        verify_backup_code_for_user(&state, &auth.0.did, code).await
    } else {
        let secret = match decrypt_totp_secret(
            &totp_record.secret_encrypted,
            totp_record.encryption_version,
        ) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to decrypt TOTP secret: {:?}", e);
                return ApiError::InternalError(None).into_response();
            }
        };
        verify_totp_code(&secret, code)
    };

    if !code_valid {
        return ApiError::InvalidCode(Some("Invalid verification code".into())).into_response();
    }

    if let Err(e) = state
        .user_repo
        .delete_totp_and_backup_codes(&auth.0.did)
        .await
    {
        error!("Failed to delete TOTP: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }

    info!(did = %&auth.0.did, "TOTP disabled");

    EmptyResponse::ok().into_response()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTotpStatusResponse {
    pub enabled: bool,
    pub has_backup_codes: bool,
    pub backup_codes_remaining: i64,
}

pub async fn get_totp_status(State(state): State<AppState>, auth: BearerAuth) -> Response {
    let enabled = match state.user_repo.get_totp_record(&auth.0.did).await {
        Ok(Some(row)) => row.verified,
        Ok(None) => false,
        Err(e) => {
            error!("DB error fetching TOTP status: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let backup_count = match state.user_repo.count_unused_backup_codes(&auth.0.did).await {
        Ok(count) => count,
        Err(e) => {
            error!("DB error counting backup codes: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    Json(GetTotpStatusResponse {
        enabled,
        has_backup_codes: backup_count > 0,
        backup_codes_remaining: backup_count,
    })
    .into_response()
}

#[derive(Deserialize)]
pub struct RegenerateBackupCodesInput {
    pub password: PlainPassword,
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
    if !state
        .check_rate_limit(RateLimitKind::TotpVerify, &auth.0.did)
        .await
    {
        warn!(did = %&auth.0.did, "TOTP verification rate limit exceeded");
        return ApiError::RateLimitExceeded(None).into_response();
    }

    let password_hash = match state.user_repo.get_password_hash_by_did(&auth.0.did).await {
        Ok(Some(hash)) => hash,
        Ok(None) => return ApiError::AccountNotFound.into_response(),
        Err(e) => {
            error!("DB error fetching user: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let password_valid = bcrypt::verify(&input.password, &password_hash).unwrap_or(false);
    if !password_valid {
        return ApiError::InvalidPassword("Password is incorrect".into()).into_response();
    }

    let totp_record = match state.user_repo.get_totp_record(&auth.0.did).await {
        Ok(Some(row)) if row.verified => row,
        Ok(Some(_)) | Ok(None) => return ApiError::TotpNotEnabled.into_response(),
        Err(e) => {
            error!("DB error fetching TOTP: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let secret = match decrypt_totp_secret(
        &totp_record.secret_encrypted,
        totp_record.encryption_version,
    ) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to decrypt TOTP secret: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let code = input.code.trim();
    if !verify_totp_code(&secret, code) {
        return ApiError::InvalidCode(Some("Invalid verification code".into())).into_response();
    }

    let backup_codes = generate_backup_codes();
    let backup_hashes: Result<Vec<_>, _> =
        backup_codes.iter().map(|c| hash_backup_code(c)).collect();
    let backup_hashes = match backup_hashes {
        Ok(hashes) => hashes,
        Err(e) => {
            error!("Failed to hash backup code: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    if let Err(e) = state
        .user_repo
        .replace_backup_codes(&auth.0.did, &backup_hashes)
        .await
    {
        error!("Failed to regenerate backup codes: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }

    info!(did = %&auth.0.did, "Backup codes regenerated");

    Json(RegenerateBackupCodesResponse { backup_codes }).into_response()
}

async fn verify_backup_code_for_user(
    state: &AppState,
    did: &crate::types::Did,
    code: &str,
) -> bool {
    let code = code.trim().to_uppercase();

    let backup_codes = match state.user_repo.get_unused_backup_codes(did).await {
        Ok(codes) => codes,
        Err(e) => {
            warn!("Failed to fetch backup codes: {:?}", e);
            return false;
        }
    };

    let matched = backup_codes
        .iter()
        .find(|row| verify_backup_code(&code, &row.code_hash));

    match matched {
        Some(row) => {
            let _ = state.user_repo.mark_backup_code_used(row.id).await;
            true
        }
        None => false,
    }
}

pub async fn verify_totp_or_backup_for_user(
    state: &AppState,
    did: &crate::types::Did,
    code: &str,
) -> bool {
    let code = code.trim();

    if is_backup_code_format(code) {
        return verify_backup_code_for_user(state, did, code).await;
    }

    let totp_record = match state.user_repo.get_totp_record(did).await {
        Ok(Some(row)) if row.verified => row,
        _ => return false,
    };

    let secret = match decrypt_totp_secret(
        &totp_record.secret_encrypted,
        totp_record.encryption_version,
    ) {
        Ok(s) => s,
        Err(_) => return false,
    };

    if verify_totp_code(&secret, code) {
        let _ = state.user_repo.update_totp_last_used(did).await;
        return true;
    }

    false
}

pub async fn has_totp_enabled(state: &AppState, did: &crate::types::Did) -> bool {
    state.user_repo.has_totp_enabled(did).await.unwrap_or(false)
}
