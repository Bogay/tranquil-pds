use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};
use tranquil_pds::api::EmptyResponse;
use tranquil_pds::api::error::{ApiError, DbResultExt};
use tranquil_pds::auth::{
    Active, Auth, decrypt_totp_secret, encrypt_totp_secret, generate_backup_codes,
    generate_qr_png_base64, generate_totp_secret, generate_totp_uri, hash_backup_code,
    is_backup_code_format, require_legacy_session_mfa, verify_backup_code, verify_password_mfa,
    verify_totp_code, verify_totp_mfa,
};
use tranquil_pds::rate_limit::{TotpVerifyLimit, check_user_rate_limit_with_message};
use tranquil_pds::state::AppState;
use tranquil_pds::types::PlainPassword;

const ENCRYPTION_VERSION: i32 = 1;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTotpSecretOutput {
    pub secret: String,
    pub uri: String,
    pub qr_base64: String,
}

pub async fn create_totp_secret(
    State(state): State<AppState>,
    auth: Auth<Active>,
) -> Result<Json<CreateTotpSecretOutput>, ApiError> {
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

    let hostname = &tranquil_config::get().server.hostname;
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

    Ok(Json(CreateTotpSecretOutput {
        secret: secret_base32,
        uri,
        qr_base64: qr_code,
    }))
}

#[derive(Deserialize)]
pub struct EnableTotpInput {
    pub code: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnableTotpOutput {
    pub backup_codes: Vec<String>,
}

pub async fn enable_totp(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<EnableTotpInput>,
) -> Result<Json<EnableTotpOutput>, ApiError> {
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

    Ok(Json(EnableTotpOutput { backup_codes }))
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
) -> Result<Json<EmptyResponse>, ApiError> {
    let session_mfa = require_legacy_session_mfa(&state, &auth).await?;

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

    tranquil_pds::auth::legacy_2fa::clear_challenge(state.cache.as_ref(), &auth.did).await;

    info!(did = %session_mfa.did(), "TOTP disabled (verified via {} and {})", password_mfa.method(), totp_mfa.method());

    Ok(Json(EmptyResponse {}))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTotpStatusOutput {
    pub enabled: bool,
    pub has_backup_codes: bool,
    pub backup_codes_remaining: i64,
}

pub async fn get_totp_status(
    State(state): State<AppState>,
    auth: Auth<Active>,
) -> Result<Json<GetTotpStatusOutput>, ApiError> {
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

    Ok(Json(GetTotpStatusOutput {
        enabled,
        has_backup_codes: backup_count > 0,
        backup_codes_remaining: backup_count,
    }))
}

#[derive(Deserialize)]
pub struct RegenerateBackupCodesInput {
    pub password: PlainPassword,
    pub code: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegenerateBackupCodesOutput {
    pub backup_codes: Vec<String>,
}

pub async fn regenerate_backup_codes(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<RegenerateBackupCodesInput>,
) -> Result<Json<RegenerateBackupCodesOutput>, ApiError> {
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

    Ok(Json(RegenerateBackupCodesOutput { backup_codes }))
}

async fn verify_backup_code_for_user(
    state: &AppState,
    did: &tranquil_pds::types::Did,
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
    did: &tranquil_pds::types::Did,
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

pub async fn has_totp_enabled(state: &AppState, did: &tranquil_pds::types::Did) -> bool {
    state.user_repo.has_totp_enabled(did).await.unwrap_or(false)
}
