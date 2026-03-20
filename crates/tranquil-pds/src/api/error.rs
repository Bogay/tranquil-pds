use axum::{
    Json,
    http::{HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::borrow::Cow;

#[derive(Debug, Serialize)]
struct ErrorBody<'a> {
    error: Cow<'a, str>,
    message: String,
}

#[derive(Debug)]
pub enum ApiError {
    InternalError(Option<String>),
    AuthenticationRequired,
    AuthenticationFailed(Option<String>),
    InvalidRequest(String),
    InvalidToken(Option<String>),
    ExpiredToken(Option<String>),
    OAuthExpiredToken(Option<String>),
    TokenRequired,
    AccountDeactivated,
    AccountTakedown,
    AccountNotFound,
    RepoNotFound(Option<String>),
    RepoTakendown,
    RepoDeactivated,
    RecordNotFound,
    BlobNotFound(Option<String>),
    InvalidHandle(Option<String>),
    HandleNotAvailable(Option<String>),
    HandleTaken,
    InvalidEmail,
    EmailTaken,
    InvalidInviteCode,
    DuplicateCreate,
    DuplicateAppPassword,
    AppPasswordNotFound,
    SessionNotFound,
    InvalidSwap(Option<String>),
    InvalidPassword(String),
    InvalidRepo(String),
    AccountMigrated,
    AccountNotVerified,
    InvalidCollection,
    InvalidRecord(String),
    Forbidden,
    AdminRequired,
    InsufficientScope(Option<String>),
    InvitesDisabled,
    RateLimitExceeded(Option<String>),
    PayloadTooLarge(String),
    TotpAlreadyEnabled,
    TotpNotEnabled,
    InvalidCode(Option<String>),
    IdentifierMismatch,
    NoPasskeys,
    NoChallengeInProgress,
    InvalidCredential,
    PasskeyCounterAnomaly,
    NoRegistrationInProgress,
    RegistrationFailed,
    PasskeyNotFound,
    InvalidId,
    InvalidScopes(String),
    ControllerNotFound,
    InvalidDelegation(String),
    DelegationNotFound,
    InviteCodeRequired,
    RepoNotReady,
    DeviceNotFound,
    NoEmail,
    MfaVerificationRequired,
    AuthorizationError(String),
    InvalidDid(String),
    InvalidSigningKey,
    SetupExpired,
    InvalidAccount,
    InvalidRecoveryLink,
    RecoveryLinkExpired,
    MissingEmail,
    MissingDiscordId,
    MissingTelegramUsername,
    MissingSignalNumber,
    InvalidVerificationChannel,
    SelfHostedDidWebDisabled,
    AccountAlreadyExists,
    HandleNotFound,
    SubjectNotFound,
    NotFoundMsg(String),
    ServiceUnavailable(Option<String>),
    UpstreamErrorMsg(String),
    DatabaseError,
    UpstreamFailure,
    UpstreamTimeout,
    UpstreamUnavailable(String),
    UpstreamError {
        status: StatusCode,
        error: Option<String>,
        message: Option<String>,
    },
    SsoProviderNotFound,
    SsoProviderNotEnabled,
    SsoInvalidAction,
    SsoNotAuthenticated,
    SsoSessionExpired,
    SsoAlreadyLinked,
    SsoLinkNotFound,
    AuthFactorTokenRequired,
    LegacyLoginBlocked,
    ReauthRequired {
        methods: Vec<String>,
    },
    MfaVerificationRequiredWithMethods {
        methods: Vec<String>,
    },
}

impl ApiError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InternalError(_) | Self::DatabaseError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::UpstreamFailure | Self::UpstreamUnavailable(_) | Self::UpstreamErrorMsg(_) => {
                StatusCode::BAD_GATEWAY
            }
            Self::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::UpstreamTimeout => StatusCode::GATEWAY_TIMEOUT,
            Self::UpstreamError { status, .. } => *status,
            Self::AuthenticationRequired
            | Self::AuthenticationFailed(_)
            | Self::AccountDeactivated
            | Self::AccountTakedown
            | Self::InvalidPassword(_)
            | Self::InvalidToken(_)
            | Self::PasskeyCounterAnomaly
            | Self::OAuthExpiredToken(_)
            | Self::ReauthRequired { .. } => StatusCode::UNAUTHORIZED,
            Self::InvalidCode(_) => StatusCode::BAD_REQUEST,
            Self::ExpiredToken(_) => StatusCode::BAD_REQUEST,
            Self::Forbidden
            | Self::AdminRequired
            | Self::InsufficientScope(_)
            | Self::InvitesDisabled
            | Self::InvalidRepo(_)
            | Self::AccountMigrated
            | Self::AccountNotVerified
            | Self::MfaVerificationRequired
            | Self::MfaVerificationRequiredWithMethods { .. }
            | Self::AuthorizationError(_) => StatusCode::FORBIDDEN,
            Self::RateLimitExceeded(_) => StatusCode::TOO_MANY_REQUESTS,
            Self::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            Self::AccountNotFound
            | Self::RecordNotFound
            | Self::AppPasswordNotFound
            | Self::SessionNotFound
            | Self::DeviceNotFound
            | Self::ControllerNotFound
            | Self::DelegationNotFound
            | Self::InvalidRecoveryLink
            | Self::HandleNotFound
            | Self::SubjectNotFound
            | Self::BlobNotFound(_)
            | Self::NotFoundMsg(_) => StatusCode::NOT_FOUND,
            Self::RepoTakendown | Self::RepoDeactivated | Self::RepoNotFound(_) => {
                StatusCode::BAD_REQUEST
            }
            Self::TotpAlreadyEnabled => StatusCode::CONFLICT,
            Self::InvalidSwap(_) => StatusCode::BAD_REQUEST,
            Self::InvalidRequest(_)
            | Self::InvalidHandle(_)
            | Self::HandleNotAvailable(_)
            | Self::HandleTaken
            | Self::InvalidEmail
            | Self::EmailTaken
            | Self::InvalidInviteCode
            | Self::DuplicateCreate
            | Self::DuplicateAppPassword
            | Self::InvalidCollection
            | Self::InvalidRecord(_)
            | Self::TotpNotEnabled
            | Self::IdentifierMismatch
            | Self::NoPasskeys
            | Self::NoChallengeInProgress
            | Self::InvalidCredential
            | Self::NoEmail
            | Self::NoRegistrationInProgress
            | Self::RegistrationFailed
            | Self::InvalidId
            | Self::InvalidScopes(_)
            | Self::InvalidDelegation(_)
            | Self::InviteCodeRequired
            | Self::RepoNotReady
            | Self::InvalidDid(_)
            | Self::InvalidSigningKey
            | Self::SetupExpired
            | Self::InvalidAccount
            | Self::RecoveryLinkExpired
            | Self::MissingEmail
            | Self::MissingDiscordId
            | Self::MissingTelegramUsername
            | Self::MissingSignalNumber
            | Self::InvalidVerificationChannel
            | Self::SelfHostedDidWebDisabled
            | Self::AccountAlreadyExists
            | Self::TokenRequired
            | Self::SsoProviderNotFound
            | Self::SsoProviderNotEnabled
            | Self::SsoInvalidAction
            | Self::SsoNotAuthenticated
            | Self::SsoSessionExpired
            | Self::SsoAlreadyLinked
            | Self::AuthFactorTokenRequired
            | Self::LegacyLoginBlocked => StatusCode::BAD_REQUEST,
            Self::PasskeyNotFound | Self::SsoLinkNotFound => StatusCode::NOT_FOUND,
        }
    }
    fn error_name(&self) -> Cow<'static, str> {
        match self {
            Self::InternalError(_) | Self::DatabaseError => Cow::Borrowed("InternalServerError"),
            Self::UpstreamFailure | Self::UpstreamUnavailable(_) | Self::UpstreamErrorMsg(_) => {
                Cow::Borrowed("UpstreamError")
            }
            Self::ServiceUnavailable(_) => Cow::Borrowed("ServiceUnavailable"),
            Self::NotFoundMsg(_) => Cow::Borrowed("NotFound"),
            Self::UpstreamTimeout => Cow::Borrowed("UpstreamTimeout"),
            Self::UpstreamError { error, .. } => {
                if let Some(e) = error {
                    return Cow::Owned(e.clone());
                }
                Cow::Borrowed("UpstreamError")
            }
            Self::AuthenticationRequired => Cow::Borrowed("AuthenticationRequired"),
            Self::AuthenticationFailed(_) => Cow::Borrowed("AuthenticationFailed"),
            Self::InvalidToken(_) => Cow::Borrowed("InvalidToken"),
            Self::ExpiredToken(_) | Self::OAuthExpiredToken(_) => Cow::Borrowed("ExpiredToken"),
            Self::TokenRequired => Cow::Borrowed("TokenRequired"),
            Self::AccountDeactivated => Cow::Borrowed("AccountDeactivated"),
            Self::AccountTakedown => Cow::Borrowed("AccountTakedown"),
            Self::Forbidden => Cow::Borrowed("Forbidden"),
            Self::AdminRequired => Cow::Borrowed("AdminRequired"),
            Self::InsufficientScope(_) => Cow::Borrowed("InsufficientScope"),
            Self::InvitesDisabled => Cow::Borrowed("InvitesDisabled"),
            Self::AccountNotFound => Cow::Borrowed("AccountNotFound"),
            Self::RepoNotFound(_) => Cow::Borrowed("RepoNotFound"),
            Self::RepoTakendown => Cow::Borrowed("RepoTakendown"),
            Self::RepoDeactivated => Cow::Borrowed("RepoDeactivated"),
            Self::RecordNotFound => Cow::Borrowed("RecordNotFound"),
            Self::BlobNotFound(_) => Cow::Borrowed("BlobNotFound"),
            Self::AppPasswordNotFound => Cow::Borrowed("AppPasswordNotFound"),
            Self::SessionNotFound => Cow::Borrowed("SessionNotFound"),
            Self::InvalidRequest(_) => Cow::Borrowed("InvalidRequest"),
            Self::InvalidHandle(_) => Cow::Borrowed("InvalidHandle"),
            Self::HandleNotAvailable(_) => Cow::Borrowed("HandleNotAvailable"),
            Self::HandleTaken => Cow::Borrowed("HandleTaken"),
            Self::InvalidEmail => Cow::Borrowed("InvalidEmail"),
            Self::EmailTaken => Cow::Borrowed("EmailTaken"),
            Self::InvalidInviteCode => Cow::Borrowed("InvalidInviteCode"),
            Self::DuplicateCreate => Cow::Borrowed("DuplicateCreate"),
            Self::DuplicateAppPassword => Cow::Borrowed("DuplicateAppPassword"),
            Self::InvalidSwap(_) => Cow::Borrowed("InvalidSwap"),
            Self::InvalidPassword(_) => Cow::Borrowed("InvalidPassword"),
            Self::InvalidRepo(_) => Cow::Borrowed("InvalidRepo"),
            Self::AccountMigrated => Cow::Borrowed("AccountMigrated"),
            Self::AccountNotVerified => Cow::Borrowed("AccountNotVerified"),
            Self::InvalidCollection => Cow::Borrowed("InvalidCollection"),
            Self::InvalidRecord(_) => Cow::Borrowed("InvalidRecord"),
            Self::TotpAlreadyEnabled => Cow::Borrowed("TotpAlreadyEnabled"),
            Self::TotpNotEnabled => Cow::Borrowed("TotpNotEnabled"),
            Self::InvalidCode(_) => Cow::Borrowed("InvalidCode"),
            Self::IdentifierMismatch => Cow::Borrowed("IdentifierMismatch"),
            Self::NoPasskeys => Cow::Borrowed("NoPasskeys"),
            Self::NoChallengeInProgress => Cow::Borrowed("NoChallengeInProgress"),
            Self::InvalidCredential => Cow::Borrowed("InvalidCredential"),
            Self::PasskeyCounterAnomaly => Cow::Borrowed("PasskeyCounterAnomaly"),
            Self::NoRegistrationInProgress => Cow::Borrowed("NoRegistrationInProgress"),
            Self::RegistrationFailed => Cow::Borrowed("RegistrationFailed"),
            Self::PasskeyNotFound => Cow::Borrowed("PasskeyNotFound"),
            Self::InvalidId => Cow::Borrowed("InvalidId"),
            Self::InvalidScopes(_) => Cow::Borrowed("InvalidScopes"),
            Self::ControllerNotFound => Cow::Borrowed("ControllerNotFound"),
            Self::InvalidDelegation(_) => Cow::Borrowed("InvalidDelegation"),
            Self::DelegationNotFound => Cow::Borrowed("DelegationNotFound"),
            Self::InviteCodeRequired => Cow::Borrowed("InviteCodeRequired"),
            Self::RepoNotReady => Cow::Borrowed("RepoNotReady"),
            Self::MfaVerificationRequired => Cow::Borrowed("MfaVerificationRequired"),
            Self::RateLimitExceeded(_) => Cow::Borrowed("RateLimitExceeded"),
            Self::PayloadTooLarge(_) => Cow::Borrowed("PayloadTooLarge"),
            Self::DeviceNotFound => Cow::Borrowed("DeviceNotFound"),
            Self::NoEmail => Cow::Borrowed("NoEmail"),
            Self::AuthorizationError(_) => Cow::Borrowed("AuthorizationError"),
            Self::InvalidDid(_) => Cow::Borrowed("InvalidDid"),
            Self::InvalidSigningKey => Cow::Borrowed("InvalidSigningKey"),
            Self::SetupExpired => Cow::Borrowed("SetupExpired"),
            Self::InvalidAccount => Cow::Borrowed("InvalidAccount"),
            Self::InvalidRecoveryLink => Cow::Borrowed("InvalidRecoveryLink"),
            Self::RecoveryLinkExpired => Cow::Borrowed("RecoveryLinkExpired"),
            Self::MissingEmail => Cow::Borrowed("MissingEmail"),
            Self::MissingDiscordId => Cow::Borrowed("MissingDiscordId"),
            Self::MissingTelegramUsername => Cow::Borrowed("MissingTelegramUsername"),
            Self::MissingSignalNumber => Cow::Borrowed("MissingSignalNumber"),
            Self::InvalidVerificationChannel => Cow::Borrowed("InvalidVerificationChannel"),
            Self::SelfHostedDidWebDisabled => Cow::Borrowed("SelfHostedDidWebDisabled"),
            Self::AccountAlreadyExists => Cow::Borrowed("AccountAlreadyExists"),
            Self::HandleNotFound => Cow::Borrowed("HandleNotFound"),
            Self::SubjectNotFound => Cow::Borrowed("SubjectNotFound"),
            Self::SsoProviderNotFound => Cow::Borrowed("SsoProviderNotFound"),
            Self::SsoProviderNotEnabled => Cow::Borrowed("SsoProviderNotEnabled"),
            Self::SsoInvalidAction => Cow::Borrowed("SsoInvalidAction"),
            Self::SsoNotAuthenticated => Cow::Borrowed("SsoNotAuthenticated"),
            Self::SsoSessionExpired => Cow::Borrowed("SsoSessionExpired"),
            Self::SsoAlreadyLinked => Cow::Borrowed("SsoAlreadyLinked"),
            Self::SsoLinkNotFound => Cow::Borrowed("SsoLinkNotFound"),
            Self::AuthFactorTokenRequired => Cow::Borrowed("AuthFactorTokenRequired"),
            Self::LegacyLoginBlocked => Cow::Borrowed("MfaRequired"),
            Self::ReauthRequired { .. } => Cow::Borrowed("ReauthRequired"),
            Self::MfaVerificationRequiredWithMethods { .. } => {
                Cow::Borrowed("MfaVerificationRequired")
            }
        }
    }
    fn message(&self) -> String {
        match self {
            Self::InternalError(msg) => msg
                .clone()
                .unwrap_or_else(|| "Internal Server Error".into()),
            Self::AuthenticationFailed(msg) => msg
                .clone()
                .unwrap_or_else(|| "Authentication failed".into()),
            Self::InvalidToken(msg) => {
                msg.clone().unwrap_or_else(|| "Invalid token".into())
            }
            Self::ExpiredToken(msg) | Self::OAuthExpiredToken(msg) => {
                msg.clone().unwrap_or_else(|| "Token has expired".into())
            }
            Self::RepoNotFound(msg) => msg
                .clone()
                .unwrap_or_else(|| "Repository not found".into()),
            Self::BlobNotFound(msg) => {
                msg.clone().unwrap_or_else(|| "Blob not found".into())
            }
            Self::InvalidHandle(msg) => {
                msg.clone().unwrap_or_else(|| "Invalid handle".into())
            }
            Self::HandleNotAvailable(msg) => msg
                .clone()
                .unwrap_or_else(|| "Handle not available".into()),
            Self::InvalidSwap(msg) => {
                msg.clone().unwrap_or_else(|| "Invalid swap".into())
            }
            Self::InsufficientScope(msg) => msg
                .clone()
                .unwrap_or_else(|| "Insufficient scope".into()),
            Self::InvalidCode(msg) => {
                msg.clone().unwrap_or_else(|| "Invalid code".into())
            }
            Self::RateLimitExceeded(msg) => msg
                .clone()
                .unwrap_or_else(|| "Rate limit exceeded".into()),
            Self::ServiceUnavailable(msg) => msg
                .clone()
                .unwrap_or_else(|| "Service temporarily unavailable".into()),
            Self::InvalidRequest(msg)
            | Self::UpstreamUnavailable(msg)
            | Self::InvalidPassword(msg)
            | Self::InvalidRepo(msg)
            | Self::InvalidRecord(msg)
            | Self::NotFoundMsg(msg)
            | Self::UpstreamErrorMsg(msg)
            | Self::PayloadTooLarge(msg)
            | Self::InvalidScopes(msg)
            | Self::InvalidDelegation(msg)
            | Self::AuthorizationError(msg)
            | Self::InvalidDid(msg) => msg.clone(),
            Self::UpstreamError { message, .. } => message
                .clone()
                .unwrap_or_else(|| "Upstream error".into()),
            Self::DatabaseError => "Internal Server Error".into(),
            Self::AuthenticationRequired => "Authentication required".into(),
            Self::TokenRequired => "Authentication token required".into(),
            Self::AccountDeactivated => "Account is deactivated".into(),
            Self::AccountTakedown => "Account has been taken down".into(),
            Self::AccountNotFound => "Account not found".into(),
            Self::RecordNotFound => "Record not found".into(),
            Self::Forbidden => "Forbidden".into(),
            Self::InvitesDisabled => "Invite codes are disabled on this server".into(),
            Self::InvalidCollection => "Invalid collection".into(),
            Self::TotpAlreadyEnabled => "TOTP is already enabled".into(),
            Self::TotpNotEnabled => "TOTP is not enabled".into(),
            Self::DuplicateAppPassword => "An app password with this name already exists".into(),
            Self::AppPasswordNotFound => "App password not found".into(),
            Self::SessionNotFound => "Session not found".into(),
            Self::UpstreamFailure => "Upstream service failed".into(),
            Self::RepoTakendown => "Repository has been taken down".into(),
            Self::RepoDeactivated => "Repository is deactivated".into(),
            Self::AccountMigrated => {
                "Account has been migrated to another PDS. Repo operations are not allowed.".into()
            }
            Self::AccountNotVerified => {
                "You must verify at least one notification channel before creating records".into()
            }
            Self::NoPasskeys => "No passkeys registered for this account".into(),
            Self::NoChallengeInProgress => {
                "No passkey authentication in progress or challenge expired".into()
            }
            Self::InvalidCredential => "Failed to parse credential response".into(),
            Self::NoRegistrationInProgress => {
                "No registration in progress. Call startPasskeyRegistration first.".into()
            }
            Self::RegistrationFailed => "Failed to verify passkey registration".into(),
            Self::PasskeyNotFound => "Passkey not found".into(),
            Self::InvalidId => "Invalid ID format".into(),
            Self::ControllerNotFound => "Controller account not found".into(),
            Self::DelegationNotFound => {
                "No active delegation found for this controller".into()
            }
            Self::InviteCodeRequired => {
                "An invite code is required to create an account".into()
            }
            Self::RepoNotReady => "Repository not ready".into(),
            Self::PasskeyCounterAnomaly => {
                "Authentication failed: security key counter anomaly detected. This may indicate a cloned key.".into()
            }
            Self::MfaVerificationRequired => {
                "This sensitive operation requires MFA verification".into()
            }
            Self::DeviceNotFound => "Device not found".into(),
            Self::NoEmail => "Recipient has no email address".into(),
            Self::InvalidSigningKey => {
                "Signing key not found, already used, or expired".into()
            }
            Self::SetupExpired => "Setup has already been completed or expired".into(),
            Self::InvalidAccount => "This account is not a passkey-only account".into(),
            Self::InvalidRecoveryLink => "Invalid recovery link".into(),
            Self::RecoveryLinkExpired => "Recovery link has expired".into(),
            Self::MissingEmail => "Email is required when using email verification".into(),
            Self::MissingDiscordId => {
                "Discord ID is required when using Discord verification".into()
            }
            Self::MissingTelegramUsername => {
                "Telegram username is required when using Telegram verification".into()
            }
            Self::MissingSignalNumber => {
                "Signal username is required when using Signal verification".into()
            }
            Self::InvalidVerificationChannel => "Invalid verification channel".into(),
            Self::SelfHostedDidWebDisabled => {
                "Self-hosted did:web accounts are disabled on this server".into()
            }
            Self::AccountAlreadyExists => "Account already exists".into(),
            Self::HandleNotFound => "Unable to resolve handle".into(),
            Self::SubjectNotFound => "Subject not found".into(),
            Self::SsoProviderNotFound => "Unknown SSO provider".into(),
            Self::SsoProviderNotEnabled => "SSO provider is not enabled".into(),
            Self::SsoInvalidAction => "Action must be login, link, or register".into(),
            Self::SsoNotAuthenticated => {
                "Must be authenticated to link SSO account".into()
            }
            Self::SsoSessionExpired => "SSO session expired or invalid".into(),
            Self::SsoAlreadyLinked => {
                "This SSO account is already linked to a different user".into()
            }
            Self::SsoLinkNotFound => "Linked account not found".into(),
            Self::IdentifierMismatch => {
                "The identifier does not match the verification token".into()
            }
            Self::UpstreamTimeout => "Upstream service timed out".into(),
            Self::AdminRequired => "This action requires admin privileges".into(),
            Self::EmailTaken => "This email address is already registered".into(),
            Self::HandleTaken => "This handle is already taken".into(),
            Self::InvalidEmail => "Please provide a valid email address".into(),
            Self::InvalidInviteCode => "The invite code provided is invalid".into(),
            Self::DuplicateCreate => "Account creation failed: duplicate request".into(),
            Self::LegacyLoginBlocked => {
                "This account requires MFA. Please use an OAuth client that supports TOTP verification.".into()
            }
            Self::AuthFactorTokenRequired => {
                "A sign-in code has been sent to your email address".into()
            }
            Self::ReauthRequired { .. } => {
                "Re-authentication required for this action".into()
            }
            Self::MfaVerificationRequiredWithMethods { .. } => {
                "This sensitive operation requires MFA verification".into()
            }
        }
    }
    pub fn from_upstream_response(status: StatusCode, body: &[u8]) -> Self {
        if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(body) {
            let error = parsed
                .get("error")
                .and_then(|v| v.as_str())
                .map(String::from);
            let message = parsed
                .get("message")
                .and_then(|v| v.as_str())
                .map(String::from);
            return Self::UpstreamError {
                status,
                error,
                message,
            };
        }
        Self::UpstreamError {
            status,
            error: None,
            message: None,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            Self::ReauthRequired { ref methods } => {
                return (
                    self.status_code(),
                    Json(serde_json::json!({
                        "error": "ReauthRequired",
                        "message": "Re-authentication required for this action",
                        "reauthMethods": methods,
                    })),
                )
                    .into_response();
            }
            Self::MfaVerificationRequiredWithMethods { ref methods } => {
                return (
                    self.status_code(),
                    Json(serde_json::json!({
                        "error": "MfaVerificationRequired",
                        "message": "This sensitive operation requires MFA verification",
                        "reauthMethods": methods,
                    })),
                )
                    .into_response();
            }
            _ => {}
        }
        let body = ErrorBody {
            error: self.error_name(),
            message: self.message(),
        };
        let mut response = (self.status_code(), Json(body)).into_response();
        match &self {
            Self::ExpiredToken(_) => {
                response.headers_mut().insert(
                    http::header::WWW_AUTHENTICATE,
                    HeaderValue::from_static(
                        "Bearer error=\"invalid_token\", error_description=\"Token has expired\"",
                    ),
                );
            }
            Self::OAuthExpiredToken(_) => {
                response.headers_mut().insert(
                    http::header::WWW_AUTHENTICATE,
                    HeaderValue::from_static(
                        "DPoP error=\"invalid_token\", error_description=\"Token has expired\"",
                    ),
                );
            }
            _ => {}
        }
        response
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        tracing::error!("Database error: {:?}", e);
        Self::DatabaseError
    }
}

impl From<tranquil_db_traits::DbError> for ApiError {
    fn from(e: tranquil_db_traits::DbError) -> Self {
        tracing::error!("Database error: {:?}", e);
        Self::DatabaseError
    }
}

impl From<crate::auth::TokenValidationError> for ApiError {
    fn from(e: crate::auth::TokenValidationError) -> Self {
        match e {
            crate::auth::TokenValidationError::AccountDeactivated => Self::AccountDeactivated,
            crate::auth::TokenValidationError::AccountTakedown => Self::AccountTakedown,
            crate::auth::TokenValidationError::KeyDecryptionFailed => Self::InternalError(None),
            crate::auth::TokenValidationError::AuthenticationFailed => {
                Self::AuthenticationFailed(None)
            }
            crate::auth::TokenValidationError::TokenExpired => Self::ExpiredToken(None),
            crate::auth::TokenValidationError::OAuthTokenExpired => {
                Self::OAuthExpiredToken(Some("Token has expired".to_string()))
            }
            crate::auth::TokenValidationError::InvalidToken => {
                Self::AuthenticationFailed(Some("Invalid token format".to_string()))
            }
        }
    }
}

impl From<crate::auth::extractor::AuthError> for ApiError {
    fn from(e: crate::auth::extractor::AuthError) -> Self {
        match e {
            crate::auth::extractor::AuthError::MissingToken => Self::AuthenticationRequired,
            crate::auth::extractor::AuthError::InvalidFormat => {
                Self::AuthenticationFailed(Some("Invalid authorization header format".to_string()))
            }
            crate::auth::extractor::AuthError::AuthenticationFailed => {
                Self::AuthenticationFailed(None)
            }
            crate::auth::extractor::AuthError::TokenExpired => {
                Self::ExpiredToken(Some("Token has expired".to_string()))
            }
            crate::auth::extractor::AuthError::AccountDeactivated => Self::AccountDeactivated,
            crate::auth::extractor::AuthError::AccountTakedown => Self::AccountTakedown,
            crate::auth::extractor::AuthError::AdminRequired => Self::AdminRequired,
            crate::auth::extractor::AuthError::ServiceAuthNotAllowed => Self::AuthenticationFailed(
                Some("Service authentication not allowed for this endpoint".to_string()),
            ),
            crate::auth::extractor::AuthError::InsufficientScope(msg) => {
                Self::InsufficientScope(Some(msg))
            }
            crate::auth::extractor::AuthError::OAuthExpiredToken(msg) => {
                Self::OAuthExpiredToken(Some(msg))
            }
            crate::auth::extractor::AuthError::UseDpopNonce(_)
            | crate::auth::extractor::AuthError::InvalidDpopProof(_) => {
                Self::AuthenticationFailed(None)
            }
        }
    }
}

impl From<crate::auth::scope_verified::ScopeVerificationError> for ApiError {
    fn from(e: crate::auth::scope_verified::ScopeVerificationError) -> Self {
        Self::InsufficientScope(Some(e.to_string()))
    }
}

impl From<crate::handle::HandleResolutionError> for ApiError {
    fn from(e: crate::handle::HandleResolutionError) -> Self {
        match e {
            crate::handle::HandleResolutionError::NotFound => Self::HandleNotFound,
            crate::handle::HandleResolutionError::InvalidDid => {
                Self::InvalidHandle(Some("Invalid DID format in handle record".to_string()))
            }
            crate::handle::HandleResolutionError::DidMismatch { expected, actual } => {
                Self::InvalidHandle(Some(format!(
                    "Handle DID mismatch: expected {}, got {}",
                    expected, actual
                )))
            }
            crate::handle::HandleResolutionError::DnsError(msg) => {
                Self::InternalError(Some(format!("DNS resolution failed: {}", msg)))
            }
            crate::handle::HandleResolutionError::HttpError(msg) => {
                Self::InternalError(Some(format!("Handle HTTP resolution failed: {}", msg)))
            }
        }
    }
}

impl From<crate::auth::verification_token::VerifyError> for ApiError {
    fn from(e: crate::auth::verification_token::VerifyError) -> Self {
        use crate::auth::verification_token::VerifyError;
        match e {
            VerifyError::InvalidFormat => {
                Self::InvalidRequest("The verification code is invalid or malformed".to_string())
            }
            VerifyError::UnsupportedVersion => {
                Self::InvalidRequest("This verification code version is not supported".to_string())
            }
            VerifyError::Expired => Self::InvalidRequest(
                "The verification code has expired. Please request a new one.".to_string(),
            ),
            VerifyError::InvalidSignature => {
                Self::InvalidRequest("The verification code is invalid".to_string())
            }
            VerifyError::IdentifierMismatch => Self::IdentifierMismatch,
            VerifyError::PurposeMismatch => {
                Self::InvalidRequest("Verification code purpose does not match".to_string())
            }
            VerifyError::ChannelMismatch => {
                Self::InvalidRequest("Verification code channel does not match".to_string())
            }
        }
    }
}

impl From<crate::api::validation::HandleValidationError> for ApiError {
    fn from(e: crate::api::validation::HandleValidationError) -> Self {
        use crate::api::validation::HandleValidationError;
        match e {
            HandleValidationError::Reserved => Self::HandleNotAvailable(None),
            HandleValidationError::BannedWord => {
                Self::InvalidHandle(Some("Inappropriate language in handle".to_string()))
            }
            _ => Self::InvalidHandle(Some(e.to_string())),
        }
    }
}

impl From<jacquard_common::types::string::AtStrError> for ApiError {
    fn from(e: jacquard_common::types::string::AtStrError) -> Self {
        Self::InvalidRequest(format!("Invalid {}: {}", e.spec, e.kind))
    }
}

impl From<crate::plc::PlcError> for ApiError {
    fn from(e: crate::plc::PlcError) -> Self {
        use crate::plc::PlcError;
        match e {
            PlcError::NotFound => Self::NotFoundMsg("DID not found in PLC directory".into()),
            PlcError::Tombstoned => Self::InvalidRequest("DID is tombstoned".into()),
            PlcError::Timeout => Self::UpstreamTimeout,
            PlcError::CircuitBreakerOpen => Self::ServiceUnavailable(Some(
                "PLC directory service temporarily unavailable".into(),
            )),
            PlcError::Http(err) => {
                tracing::error!("PLC HTTP error: {:?}", err);
                Self::UpstreamErrorMsg("Failed to communicate with PLC directory".into())
            }
            PlcError::InvalidResponse(msg) => {
                tracing::error!("PLC invalid response: {}", msg);
                Self::UpstreamErrorMsg(format!("Invalid response from PLC directory: {}", msg))
            }
            PlcError::Serialization(msg) => {
                tracing::error!("PLC serialization error: {}", msg);
                Self::InternalError(Some(format!("PLC serialization error: {}", msg)))
            }
            PlcError::Signing(msg) => {
                tracing::error!("PLC signing error: {}", msg);
                Self::InternalError(Some(format!("PLC signing error: {}", msg)))
            }
        }
    }
}

impl From<bcrypt::BcryptError> for ApiError {
    fn from(e: bcrypt::BcryptError) -> Self {
        tracing::error!("Bcrypt error: {:?}", e);
        Self::InternalError(None)
    }
}

impl From<cid::Error> for ApiError {
    fn from(e: cid::Error) -> Self {
        Self::InvalidRequest(format!("Invalid CID: {}", e))
    }
}

impl From<crate::circuit_breaker::CircuitBreakerError<crate::plc::PlcError>> for ApiError {
    fn from(e: crate::circuit_breaker::CircuitBreakerError<crate::plc::PlcError>) -> Self {
        use crate::circuit_breaker::CircuitBreakerError;
        match e {
            CircuitBreakerError::CircuitOpen(err) => {
                tracing::warn!("PLC directory circuit breaker open: {}", err);
                Self::ServiceUnavailable(Some(
                    "PLC directory service temporarily unavailable".into(),
                ))
            }
            CircuitBreakerError::OperationFailed(plc_err) => Self::from(plc_err),
        }
    }
}

impl From<crate::storage::StorageError> for ApiError {
    fn from(e: crate::storage::StorageError) -> Self {
        tracing::error!("Storage error: {:?}", e);
        Self::InternalError(Some("Storage operation failed".into()))
    }
}

impl From<crate::rate_limit::UserRateLimitError> for ApiError {
    fn from(e: crate::rate_limit::UserRateLimitError) -> Self {
        Self::RateLimitExceeded(e.message)
    }
}

#[allow(clippy::result_large_err)]
pub fn parse_did(s: &str) -> Result<tranquil_types::Did, Response> {
    s.parse()
        .map_err(|_| ApiError::InvalidDid("Invalid DID format".into()).into_response())
}

#[allow(clippy::result_large_err)]
pub fn parse_did_option(s: Option<&str>) -> Result<Option<tranquil_types::Did>, Response> {
    s.map(parse_did).transpose()
}

pub trait DbResultExt<T> {
    fn log_db_err(self, ctx: &str) -> Result<T, ApiError>;
}

impl<T, E: std::fmt::Debug> DbResultExt<T> for Result<T, E> {
    fn log_db_err(self, ctx: &str) -> Result<T, ApiError> {
        self.map_err(|e| {
            tracing::error!("DB error {}: {:?}", ctx, e);
            ApiError::DatabaseError
        })
    }
}
