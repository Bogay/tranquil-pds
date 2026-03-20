use crate::api::error::ApiError;

use super::AuthenticatedUser;
use crate::state::AppState;
use crate::types::Did;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfaMethod {
    Totp,
    Passkey,
    Password,
    RecoveryCode,
    SessionReauth,
}

impl MfaMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Totp => "totp",
            Self::Passkey => "passkey",
            Self::Password => "password",
            Self::RecoveryCode => "recovery_code",
            Self::SessionReauth => "session_reauth",
        }
    }
}

impl std::fmt::Display for MfaMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub struct MfaVerified<'a> {
    user: &'a AuthenticatedUser,
    method: MfaMethod,
}

impl<'a> MfaVerified<'a> {
    fn new(user: &'a AuthenticatedUser, method: MfaMethod) -> Self {
        Self { user, method }
    }

    pub(crate) fn from_totp(user: &'a AuthenticatedUser) -> Self {
        Self::new(user, MfaMethod::Totp)
    }

    pub(crate) fn from_password(user: &'a AuthenticatedUser) -> Self {
        Self::new(user, MfaMethod::Password)
    }

    pub(crate) fn from_recovery_code(user: &'a AuthenticatedUser) -> Self {
        Self::new(user, MfaMethod::RecoveryCode)
    }

    pub(crate) fn from_session_reauth(user: &'a AuthenticatedUser) -> Self {
        Self::new(user, MfaMethod::SessionReauth)
    }

    pub fn user(&self) -> &AuthenticatedUser {
        self.user
    }

    pub fn did(&self) -> &Did {
        &self.user.did
    }

    pub fn method(&self) -> MfaMethod {
        self.method
    }
}

pub async fn require_legacy_session_mfa<'a>(
    state: &AppState,
    user: &'a AuthenticatedUser,
) -> Result<MfaVerified<'a>, ApiError> {
    use crate::auth::reauth::check_legacy_session_mfa;

    if check_legacy_session_mfa(&*state.repos.session, &user.did).await {
        Ok(MfaVerified::from_session_reauth(user))
    } else {
        let methods = crate::auth::reauth::get_available_reauth_methods(
            &*state.repos.user,
            &*state.repos.session,
            &user.did,
        )
        .await;
        Err(ApiError::MfaVerificationRequiredWithMethods {
            methods: methods.iter().map(|m| m.as_str().to_string()).collect(),
        })
    }
}

pub async fn require_reauth_window<'a>(
    state: &AppState,
    user: &'a AuthenticatedUser,
) -> Result<MfaVerified<'a>, ApiError> {
    use crate::auth::reauth::REAUTH_WINDOW_SECONDS;
    use chrono::Utc;

    let status = state
        .repos.session
        .get_session_mfa_status(&user.did)
        .await
        .ok()
        .flatten();

    match status {
        Some(s) => {
            if let Some(last_reauth) = s.last_reauth_at {
                let elapsed = Utc::now().signed_duration_since(last_reauth);
                if elapsed.num_seconds() <= REAUTH_WINDOW_SECONDS {
                    return Ok(MfaVerified::from_session_reauth(user));
                }
            }
            let methods = crate::auth::reauth::get_available_reauth_methods(
                &*state.repos.user,
                &*state.repos.session,
                &user.did,
            )
            .await;
            Err(ApiError::ReauthRequired {
                methods: methods.iter().map(|m| m.as_str().to_string()).collect(),
            })
        }
        None => {
            let methods = crate::auth::reauth::get_available_reauth_methods(
                &*state.repos.user,
                &*state.repos.session,
                &user.did,
            )
            .await;
            Err(ApiError::ReauthRequired {
                methods: methods.iter().map(|m| m.as_str().to_string()).collect(),
            })
        }
    }
}

pub async fn require_reauth_window_if_available<'a>(
    state: &AppState,
    user: &'a AuthenticatedUser,
) -> Result<Option<MfaVerified<'a>>, ApiError> {
    use crate::auth::reauth::check_reauth_required_cached;

    let has_password = state
        .repos.user
        .has_password_by_did(&user.did)
        .await
        .ok()
        .flatten()
        .unwrap_or(false);
    let has_passkeys = state
        .repos.user
        .has_passkeys(&user.did)
        .await
        .unwrap_or(false);
    let has_totp = state
        .repos.user
        .has_totp_enabled(&user.did)
        .await
        .unwrap_or(false);

    let has_any_reauth_method = has_password || has_passkeys || has_totp;

    if !has_any_reauth_method {
        return Ok(None);
    }

    if check_reauth_required_cached(&*state.repos.session, &state.cache, &user.did).await {
        let methods = crate::auth::reauth::get_available_reauth_methods(
            &*state.repos.user,
            &*state.repos.session,
            &user.did,
        )
        .await;
        Err(ApiError::ReauthRequired {
            methods: methods.iter().map(|m| m.as_str().to_string()).collect(),
        })
    } else {
        Ok(Some(MfaVerified::from_session_reauth(user)))
    }
}

pub async fn verify_password_mfa<'a>(
    state: &AppState,
    user: &'a AuthenticatedUser,
    password: &str,
) -> Result<MfaVerified<'a>, crate::api::error::ApiError> {
    let hash = state
        .repos.user
        .get_password_hash_by_did(&user.did)
        .await
        .ok()
        .flatten();

    match hash {
        Some(h) => {
            if bcrypt::verify(password, &h).unwrap_or(false) {
                Ok(MfaVerified::from_password(user))
            } else {
                Err(crate::api::error::ApiError::InvalidPassword(
                    "Password is incorrect".into(),
                ))
            }
        }
        None => Err(crate::api::error::ApiError::AccountNotFound),
    }
}

pub async fn verify_totp_mfa<'a>(
    state: &AppState,
    user: &'a AuthenticatedUser,
    code: &str,
) -> Result<MfaVerified<'a>, crate::api::error::ApiError> {
    use crate::auth::{decrypt_totp_secret, is_backup_code_format, verify_totp_code};
    use tranquil_db_traits::TotpRecordState;

    let code = code.trim();

    if is_backup_code_format(code) {
        let backup_codes = state
            .repos.user
            .get_unused_backup_codes(&user.did)
            .await
            .ok()
            .unwrap_or_default();
        let code_upper = code.to_uppercase();

        let matched = backup_codes
            .iter()
            .find(|row| crate::auth::verify_backup_code(&code_upper, &row.code_hash));

        return match matched {
            Some(row) => {
                let _ = state.repos.user.mark_backup_code_used(row.id).await;
                Ok(MfaVerified::from_recovery_code(user))
            }
            None => Err(crate::api::error::ApiError::InvalidCode(Some(
                "Invalid backup code".into(),
            ))),
        };
    }

    let verified_record = match state.repos.user.get_totp_record_state(&user.did).await {
        Ok(Some(TotpRecordState::Verified(record))) => record,
        _ => {
            return Err(crate::api::error::ApiError::TotpNotEnabled);
        }
    };

    let secret = decrypt_totp_secret(
        &verified_record.secret_encrypted,
        verified_record.encryption_version,
    )
    .map_err(|_| crate::api::error::ApiError::InternalError(None))?;

    if verify_totp_code(&secret, code) {
        let _ = state.repos.user.update_totp_last_used(&user.did).await;
        Ok(MfaVerified::from_totp(user))
    } else {
        Err(crate::api::error::ApiError::InvalidCode(Some(
            "Invalid verification code".into(),
        )))
    }
}
