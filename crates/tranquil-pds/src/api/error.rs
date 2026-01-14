use axum::{
    Json,
    extract::{FromRequest, Request, rejection::JsonRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Serialize, de::DeserializeOwned};
use std::borrow::Cow;

#[derive(Debug, Serialize)]
struct ErrorBody<'a> {
    error: Cow<'a, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
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
    InvalidChannel,
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
    BackupNotFound,
    BackupsDisabled,
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
        status: u16,
        error: Option<String>,
        message: Option<String>,
    },
}

impl ApiError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InternalError(_) | Self::DatabaseError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::UpstreamFailure | Self::UpstreamUnavailable(_) | Self::UpstreamErrorMsg(_) => {
                StatusCode::BAD_GATEWAY
            }
            Self::ServiceUnavailable(_) | Self::BackupsDisabled => StatusCode::SERVICE_UNAVAILABLE,
            Self::UpstreamTimeout => StatusCode::GATEWAY_TIMEOUT,
            Self::UpstreamError { status, .. } => {
                StatusCode::from_u16(*status).unwrap_or(StatusCode::BAD_GATEWAY)
            }
            Self::AuthenticationRequired
            | Self::AuthenticationFailed(_)
            | Self::AccountDeactivated
            | Self::AccountTakedown
            | Self::InvalidCode(_)
            | Self::InvalidPassword(_)
            | Self::InvalidToken(_)
            | Self::PasskeyCounterAnomaly
            | Self::OAuthExpiredToken(_) => StatusCode::UNAUTHORIZED,
            Self::ExpiredToken(_) => StatusCode::BAD_REQUEST,
            Self::Forbidden
            | Self::AdminRequired
            | Self::InsufficientScope(_)
            | Self::InvitesDisabled
            | Self::InvalidRepo(_)
            | Self::AccountMigrated
            | Self::AccountNotVerified
            | Self::MfaVerificationRequired
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
            | Self::BackupNotFound
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
            | Self::InvalidChannel
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
            | Self::TokenRequired => StatusCode::BAD_REQUEST,
            Self::PasskeyNotFound => StatusCode::NOT_FOUND,
        }
    }
    fn error_name(&self) -> Cow<'static, str> {
        match self {
            Self::InternalError(_) | Self::DatabaseError => Cow::Borrowed("InternalError"),
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
            Self::InvalidChannel => Cow::Borrowed("InvalidChannel"),
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
            Self::BackupNotFound => Cow::Borrowed("BackupNotFound"),
            Self::BackupsDisabled => Cow::Borrowed("BackupsDisabled"),
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
        }
    }
    fn message(&self) -> Option<String> {
        match self {
            Self::InternalError(msg)
            | Self::AuthenticationFailed(msg)
            | Self::InvalidToken(msg)
            | Self::ExpiredToken(msg)
            | Self::OAuthExpiredToken(msg)
            | Self::RepoNotFound(msg)
            | Self::BlobNotFound(msg)
            | Self::InvalidHandle(msg)
            | Self::HandleNotAvailable(msg)
            | Self::InvalidSwap(msg)
            | Self::InsufficientScope(msg)
            | Self::InvalidCode(msg)
            | Self::RateLimitExceeded(msg)
            | Self::ServiceUnavailable(msg) => msg.clone(),
            Self::InvalidRequest(msg)
            | Self::UpstreamUnavailable(msg)
            | Self::InvalidPassword(msg)
            | Self::InvalidRepo(msg)
            | Self::InvalidRecord(msg)
            | Self::NotFoundMsg(msg)
            | Self::UpstreamErrorMsg(msg)
            | Self::PayloadTooLarge(msg) => Some(msg.clone()),
            Self::AccountMigrated => Some(
                "Account has been migrated to another PDS. Repo operations are not allowed."
                    .to_string(),
            ),
            Self::AccountNotVerified => Some(
                "You must verify at least one notification channel before creating records"
                    .to_string(),
            ),
            Self::NoPasskeys => {
                Some("No passkeys registered for this account".to_string())
            }
            Self::NoChallengeInProgress => Some(
                "No passkey authentication in progress or challenge expired".to_string(),
            ),
            Self::InvalidCredential => Some("Failed to parse credential response".to_string()),
            Self::NoRegistrationInProgress => Some(
                "No registration in progress. Call startPasskeyRegistration first.".to_string(),
            ),
            Self::RegistrationFailed => {
                Some("Failed to verify passkey registration".to_string())
            }
            Self::PasskeyNotFound => Some("Passkey not found".to_string()),
            Self::InvalidId => Some("Invalid ID format".to_string()),
            Self::InvalidScopes(msg) | Self::InvalidDelegation(msg) => Some(msg.clone()),
            Self::ControllerNotFound => Some("Controller account not found".to_string()),
            Self::DelegationNotFound => {
                Some("No active delegation found for this controller".to_string())
            }
            Self::InviteCodeRequired => {
                Some("An invite code is required to create an account".to_string())
            }
            Self::BackupNotFound => Some("Backup not found".to_string()),
            Self::BackupsDisabled => Some("Backup storage not configured".to_string()),
            Self::RepoNotReady => Some("Repository not ready for backup".to_string()),
            Self::PasskeyCounterAnomaly => Some(
                "Authentication failed: security key counter anomaly detected. This may indicate a cloned key.".to_string(),
            ),
            Self::MfaVerificationRequired => Some(
                "This sensitive operation requires MFA verification".to_string(),
            ),
            Self::DeviceNotFound => Some("Device not found".to_string()),
            Self::NoEmail => Some("Recipient has no email address".to_string()),
            Self::AuthorizationError(msg) | Self::InvalidDid(msg) => Some(msg.clone()),
            Self::InvalidSigningKey => {
                Some("Signing key not found, already used, or expired".to_string())
            }
            Self::SetupExpired => {
                Some("Setup has already been completed or expired".to_string())
            }
            Self::InvalidAccount => {
                Some("This account is not a passkey-only account".to_string())
            }
            Self::InvalidRecoveryLink => Some("Invalid recovery link".to_string()),
            Self::RecoveryLinkExpired => Some("Recovery link has expired".to_string()),
            Self::MissingEmail => {
                Some("Email is required when using email verification".to_string())
            }
            Self::MissingDiscordId => {
                Some("Discord ID is required when using Discord verification".to_string())
            }
            Self::MissingTelegramUsername => {
                Some("Telegram username is required when using Telegram verification".to_string())
            }
            Self::MissingSignalNumber => {
                Some("Signal phone number is required when using Signal verification".to_string())
            }
            Self::InvalidVerificationChannel => Some("Invalid verification channel".to_string()),
            Self::SelfHostedDidWebDisabled => {
                Some("Self-hosted did:web accounts are disabled on this server".to_string())
            }
            Self::AccountAlreadyExists => Some("Account already exists".to_string()),
            Self::HandleNotFound => Some("Unable to resolve handle".to_string()),
            Self::SubjectNotFound => Some("Subject not found".to_string()),
            Self::IdentifierMismatch => {
                Some("The identifier does not match the verification token".to_string())
            }
            Self::UpstreamError { message, .. } => message.clone(),
            Self::UpstreamTimeout => Some("Upstream service timed out".to_string()),
            Self::AdminRequired => Some("This action requires admin privileges".to_string()),
            _ => None,
        }
    }
    pub fn from_upstream_response(status: u16, body: &[u8]) -> Self {
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
        let body = ErrorBody {
            error: self.error_name(),
            message: self.message(),
        };
        let mut response = (self.status_code(), Json(body)).into_response();
        match &self {
            Self::ExpiredToken(_) => {
                response.headers_mut().insert(
                    "WWW-Authenticate",
                    "Bearer error=\"invalid_token\", error_description=\"Token has expired\""
                        .parse()
                        .unwrap(),
                );
            }
            Self::OAuthExpiredToken(_) => {
                response.headers_mut().insert(
                    "WWW-Authenticate",
                    "DPoP error=\"invalid_token\", error_description=\"Token has expired\""
                        .parse()
                        .unwrap(),
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
        }
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

impl From<jacquard::types::string::AtStrError> for ApiError {
    fn from(e: jacquard::types::string::AtStrError) -> Self {
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

pub fn parse_did(s: &str) -> Result<tranquil_types::Did, Response> {
    s.parse()
        .map_err(|_| ApiError::InvalidDid("Invalid DID format".into()).into_response())
}

pub fn parse_did_option(s: Option<&str>) -> Result<Option<tranquil_types::Did>, Response> {
    s.map(parse_did).transpose()
}

pub struct AtpJson<T>(pub T);

impl<T, S> FromRequest<S> for AtpJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<serde_json::Value>);

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(AtpJson(value)),
            Err(rejection) => {
                let message = extract_json_error_message(&rejection);
                Err((
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "InvalidRequest",
                        "message": message
                    })),
                ))
            }
        }
    }
}

fn extract_json_error_message(rejection: &JsonRejection) -> String {
    match rejection {
        JsonRejection::JsonDataError(e) => {
            let inner = e.body_text();
            if inner.contains("missing field") {
                let field = inner
                    .split("missing field `")
                    .nth(1)
                    .and_then(|s| s.split('`').next())
                    .unwrap_or("unknown");
                format!("Missing required field: {}", field)
            } else if inner.contains("invalid type") {
                format!("Invalid field type: {}", inner)
            } else {
                inner
            }
        }
        JsonRejection::JsonSyntaxError(_) => "Invalid JSON syntax".to_string(),
        JsonRejection::MissingJsonContentType(_) => {
            "Content-Type must be application/json".to_string()
        }
        JsonRejection::BytesRejection(_) => "Failed to read request body".to_string(),
        _ => "Invalid request body".to_string(),
    }
}
