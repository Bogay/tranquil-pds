use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::borrow::Cow;

#[derive(Debug, Serialize)]
struct ErrorBody<'a> {
    error: Cow<'a, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

#[derive(Debug)]
pub enum ApiError {
    InternalError,
    AuthenticationRequired,
    AuthenticationFailed,
    AuthenticationFailedMsg(String),
    InvalidRequest(String),
    InvalidToken,
    ExpiredToken,
    ExpiredTokenMsg(String),
    TokenRequired,
    AccountDeactivated,
    AccountTakedown,
    AccountNotFound,
    RepoNotFound,
    RepoNotFoundMsg(String),
    RecordNotFound,
    BlobNotFound,
    InvalidHandle,
    HandleNotAvailable,
    HandleTaken,
    InvalidEmail,
    EmailTaken,
    InvalidInviteCode,
    DuplicateCreate,
    DuplicateAppPassword,
    AppPasswordNotFound,
    InvalidSwap,
    Forbidden,
    InvitesDisabled,
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
            Self::InternalError | Self::DatabaseError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::UpstreamFailure | Self::UpstreamUnavailable(_) => StatusCode::BAD_GATEWAY,
            Self::UpstreamTimeout => StatusCode::GATEWAY_TIMEOUT,
            Self::UpstreamError { status, .. } => {
                StatusCode::from_u16(*status).unwrap_or(StatusCode::BAD_GATEWAY)
            }
            Self::AuthenticationRequired
            | Self::AuthenticationFailed
            | Self::AuthenticationFailedMsg(_)
            | Self::InvalidToken
            | Self::ExpiredToken
            | Self::ExpiredTokenMsg(_)
            | Self::TokenRequired
            | Self::AccountDeactivated
            | Self::AccountTakedown => StatusCode::UNAUTHORIZED,
            Self::Forbidden | Self::InvitesDisabled => StatusCode::FORBIDDEN,
            Self::AccountNotFound
            | Self::RepoNotFound
            | Self::RepoNotFoundMsg(_)
            | Self::RecordNotFound
            | Self::BlobNotFound
            | Self::AppPasswordNotFound => StatusCode::NOT_FOUND,
            Self::InvalidRequest(_)
            | Self::InvalidHandle
            | Self::HandleNotAvailable
            | Self::HandleTaken
            | Self::InvalidEmail
            | Self::EmailTaken
            | Self::InvalidInviteCode
            | Self::DuplicateCreate
            | Self::DuplicateAppPassword
            | Self::InvalidSwap => StatusCode::BAD_REQUEST,
        }
    }
    fn error_name(&self) -> Cow<'static, str> {
        match self {
            Self::InternalError | Self::DatabaseError => Cow::Borrowed("InternalError"),
            Self::UpstreamFailure | Self::UpstreamUnavailable(_) => {
                Cow::Borrowed("UpstreamFailure")
            }
            Self::UpstreamTimeout => Cow::Borrowed("UpstreamTimeout"),
            Self::UpstreamError { error, .. } => {
                if let Some(e) = error {
                    return Cow::Owned(e.clone());
                }
                Cow::Borrowed("UpstreamError")
            }
            Self::AuthenticationRequired => Cow::Borrowed("AuthenticationRequired"),
            Self::AuthenticationFailed | Self::AuthenticationFailedMsg(_) => {
                Cow::Borrowed("AuthenticationFailed")
            }
            Self::InvalidToken => Cow::Borrowed("InvalidToken"),
            Self::ExpiredToken | Self::ExpiredTokenMsg(_) => Cow::Borrowed("ExpiredToken"),
            Self::TokenRequired => Cow::Borrowed("TokenRequired"),
            Self::AccountDeactivated => Cow::Borrowed("AccountDeactivated"),
            Self::AccountTakedown => Cow::Borrowed("AccountTakedown"),
            Self::Forbidden => Cow::Borrowed("Forbidden"),
            Self::InvitesDisabled => Cow::Borrowed("InvitesDisabled"),
            Self::AccountNotFound => Cow::Borrowed("AccountNotFound"),
            Self::RepoNotFound | Self::RepoNotFoundMsg(_) => Cow::Borrowed("RepoNotFound"),
            Self::RecordNotFound => Cow::Borrowed("RecordNotFound"),
            Self::BlobNotFound => Cow::Borrowed("BlobNotFound"),
            Self::AppPasswordNotFound => Cow::Borrowed("AppPasswordNotFound"),
            Self::InvalidRequest(_) => Cow::Borrowed("InvalidRequest"),
            Self::InvalidHandle => Cow::Borrowed("InvalidHandle"),
            Self::HandleNotAvailable => Cow::Borrowed("HandleNotAvailable"),
            Self::HandleTaken => Cow::Borrowed("HandleTaken"),
            Self::InvalidEmail => Cow::Borrowed("InvalidEmail"),
            Self::EmailTaken => Cow::Borrowed("EmailTaken"),
            Self::InvalidInviteCode => Cow::Borrowed("InvalidInviteCode"),
            Self::DuplicateCreate => Cow::Borrowed("DuplicateCreate"),
            Self::DuplicateAppPassword => Cow::Borrowed("DuplicateAppPassword"),
            Self::InvalidSwap => Cow::Borrowed("InvalidSwap"),
        }
    }
    fn message(&self) -> Option<String> {
        match self {
            Self::AuthenticationFailedMsg(msg)
            | Self::ExpiredTokenMsg(msg)
            | Self::InvalidRequest(msg)
            | Self::RepoNotFoundMsg(msg)
            | Self::UpstreamUnavailable(msg) => Some(msg.clone()),
            Self::UpstreamError { message, .. } => message.clone(),
            Self::UpstreamTimeout => Some("Upstream service timed out".to_string()),
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
        (self.status_code(), Json(body)).into_response()
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
            crate::auth::TokenValidationError::KeyDecryptionFailed => Self::InternalError,
            crate::auth::TokenValidationError::AuthenticationFailed => Self::AuthenticationFailed,
        }
    }
}

impl From<crate::util::DbLookupError> for ApiError {
    fn from(e: crate::util::DbLookupError) -> Self {
        match e {
            crate::util::DbLookupError::NotFound => Self::AccountNotFound,
            crate::util::DbLookupError::DatabaseError(db_err) => {
                tracing::error!("Database error: {:?}", db_err);
                Self::DatabaseError
            }
        }
    }
}
