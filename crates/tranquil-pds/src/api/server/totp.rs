use crate::api::EmptyResponse;
use crate::api::error::{ApiError, DbResultExt};
use crate::auth::{
    Active, Auth, decrypt_totp_secret, encrypt_totp_secret, generate_backup_codes,
    generate_qr_png_base64, generate_totp_secret, generate_totp_uri, hash_backup_code,
    is_backup_code_format, require_legacy_session_mfa, verify_backup_code, verify_password_mfa,
    verify_totp_code, verify_totp_mfa,
};
use crate::rate_limit::{TotpVerifyLimit, check_user_rate_limit_with_message};
use crate::state::AppState;
use crate::types::PlainPassword;
use crate::util::pds_hostname;
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

pub async fn create_totp_secret(
    State(state): State<AppState>,
    auth: Auth<Active>,
) -> Result<Response, ApiError> {
    use tranquil_db_traits::TotpRecordState;

    match state.user_repo.get_totp_record_state(&auth.did).await {
        Ok(Some(TotpRecordState::Verified(_))) => return Err(ApiError::TotpAlreadyEnabled),
        Ok(Some(TotpRecordState::Unverified(_))) | Ok(None) => {}
        Err(e) => {
            error!("DB error checking TOTP: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    }

    let secret = generate_totp_secret();

    let handle = state
        .user_repo
        .get_handle_by_did(&auth.did)
        .await
        .log_db_err("fetching handle")?
        .ok_or(ApiError::AccountNotFound)?;

    let hostname = pds_hostname();
    let uri = generate_totp_uri(&secret, &handle, hostname);

    let qr_code = generate_qr_png_base64(&secret, &handle, hostname).map_err(|e| {
        error!("Failed to generate QR code: {:?}", e);
        ApiError::InternalError(Some("Failed to generate QR code".into()))
    })?;

    let encrypted_secret = encrypt_totp_secret(&secret).map_err(|e| {
        error!("Failed to encrypt TOTP secret: {:?}", e);
        ApiError::InternalError(None)
    })?;

    state
        .user_repo
        .upsert_totp_secret(&auth.did, &encrypted_secret, ENCRYPTION_VERSION)
        .await
        .log_db_err("storing TOTP secret")?;

    let secret_base32 = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &secret);

    info!(did = %&auth.did, "TOTP secret created (pending verification)");

    Ok(Json(CreateTotpSecretResponse {
        secret: secret_base32,
        uri,
        qr_base64: qr_code,
    })
    .into_response())
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
    auth: Auth<Active>,
    Json(input): Json<EnableTotpInput>,
) -> Result<Response, ApiError> {
    use tranquil_db_traits::TotpRecordState;

    let _rate_limit = check_user_rate_limit_with_message::<TotpVerifyLimit>(
        &state,
        &auth.did,
        "Too many verification attempts. Please try again in a few minutes.",
    )
    .await?;

    let unverified_record = match state.user_repo.get_totp_record_state(&auth.did).await {
        Ok(Some(TotpRecordState::Unverified(record))) => record,
        Ok(Some(TotpRecordState::Verified(_))) => return Err(ApiError::TotpAlreadyEnabled),
        Ok(None) => return Err(ApiError::TotpNotEnabled),
        Err(e) => {
            error!("DB error fetching TOTP: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    };

    let secret = decrypt_totp_secret(
        &unverified_record.secret_encrypted,
        unverified_record.encryption_version,
    )
    .map_err(|e| {
        error!("Failed to decrypt TOTP secret: {:?}", e);
        ApiError::InternalError(None)
    })?;

    let code = input.code.trim();
    if !verify_totp_code(&secret, code) {
        return Err(ApiError::InvalidCode(Some(
            "Invalid verification code".into(),
        )));
    }

    let backup_codes = generate_backup_codes();
    let backup_hashes: Vec<_> = backup_codes
        .iter()
        .map(|c| hash_backup_code(c))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            error!("Failed to hash backup code: {:?}", e);
            ApiError::InternalError(None)
        })?;

    state
        .user_repo
        .enable_totp_with_backup_codes(&auth.did, &backup_hashes)
        .await
        .log_db_err("enabling TOTP")?;

    info!(did = %&auth.did, "TOTP enabled with {} backup codes", backup_codes.len());

    Ok(Json(EnableTotpResponse { backup_codes }).into_response())
}

#[derive(Deserialize)]
pub struct DisableTotpInput {
    pub password: PlainPassword,
    pub code: String,
}

pub async fn disable_totp(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<DisableTotpInput>,
) -> Result<Response, ApiError> {
    let session_mfa = match require_legacy_session_mfa(&state, &auth).await {
        Ok(proof) => proof,
        Err(response) => return Ok(response),
    };

    let _rate_limit = check_user_rate_limit_with_message::<TotpVerifyLimit>(
        &state,
        session_mfa.did(),
        "Too many verification attempts. Please try again in a few minutes.",
    )
    .await?;

    let password_mfa = verify_password_mfa(&state, &auth, &input.password).await?;
    let totp_mfa = verify_totp_mfa(&state, &auth, &input.code).await?;

    state
        .user_repo
        .delete_totp_and_backup_codes(totp_mfa.did())
        .await
        .log_db_err("deleting TOTP")?;

    info!(did = %session_mfa.did(), "TOTP disabled (verified via {} and {})", password_mfa.method(), totp_mfa.method());

    Ok(EmptyResponse::ok().into_response())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTotpStatusResponse {
    pub enabled: bool,
    pub has_backup_codes: bool,
    pub backup_codes_remaining: i64,
}

pub async fn get_totp_status(
    State(state): State<AppState>,
    auth: Auth<Active>,
) -> Result<Response, ApiError> {
    use tranquil_db_traits::TotpRecordState;

    let enabled = match state.user_repo.get_totp_record_state(&auth.did).await {
        Ok(Some(TotpRecordState::Verified(_))) => true,
        Ok(Some(TotpRecordState::Unverified(_))) | Ok(None) => false,
        Err(e) => {
            error!("DB error fetching TOTP status: {:?}", e);
            return Err(ApiError::InternalError(None));
        }
    };

    let backup_count = state
        .user_repo
        .count_unused_backup_codes(&auth.did)
        .await
        .log_db_err("counting backup codes")?;

    Ok(Json(GetTotpStatusResponse {
        enabled,
        has_backup_codes: backup_count > 0,
        backup_codes_remaining: backup_count,
    })
    .into_response())
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
    auth: Auth<Active>,
    Json(input): Json<RegenerateBackupCodesInput>,
) -> Result<Response, ApiError> {
    let _rate_limit = check_user_rate_limit_with_message::<TotpVerifyLimit>(
        &state,
        &auth.did,
        "Too many verification attempts. Please try again in a few minutes.",
    )
    .await?;

    let password_mfa = verify_password_mfa(&state, &auth, &input.password).await?;
    let totp_mfa = verify_totp_mfa(&state, &auth, &input.code).await?;

    let backup_codes = generate_backup_codes();
    let backup_hashes: Vec<_> = backup_codes
        .iter()
        .map(|c| hash_backup_code(c))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            error!("Failed to hash backup code: {:?}", e);
            ApiError::InternalError(None)
        })?;

    state
        .user_repo
        .replace_backup_codes(totp_mfa.did(), &backup_hashes)
        .await
        .log_db_err("replacing backup codes")?;

    info!(did = %password_mfa.did(), "Backup codes regenerated (verified via {} and {})", password_mfa.method(), totp_mfa.method());

    Ok(Json(RegenerateBackupCodesResponse { backup_codes }).into_response())
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
    use tranquil_db_traits::TotpRecordState;

    let code = code.trim();

    if is_backup_code_format(code) {
        return verify_backup_code_for_user(state, did, code).await;
    }

    let verified_record = match state.user_repo.get_totp_record_state(did).await {
        Ok(Some(TotpRecordState::Verified(record))) => record,
        _ => return false,
    };

    let secret = match decrypt_totp_secret(
        &verified_record.secret_encrypted,
        verified_record.encryption_version,
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
