use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: &'static str,
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
}

impl ApiError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InternalError | Self::DatabaseError | Self::UpstreamFailure => {
                StatusCode::INTERNAL_SERVER_ERROR
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

    fn error_name(&self) -> &'static str {
        match self {
            Self::InternalError | Self::DatabaseError | Self::UpstreamFailure => "InternalError",
            Self::AuthenticationRequired => "AuthenticationRequired",
            Self::AuthenticationFailed | Self::AuthenticationFailedMsg(_) => "AuthenticationFailed",
            Self::InvalidToken => "InvalidToken",
            Self::ExpiredToken | Self::ExpiredTokenMsg(_) => "ExpiredToken",
            Self::TokenRequired => "TokenRequired",
            Self::AccountDeactivated => "AccountDeactivated",
            Self::AccountTakedown => "AccountTakedown",
            Self::Forbidden => "Forbidden",
            Self::InvitesDisabled => "InvitesDisabled",
            Self::AccountNotFound => "AccountNotFound",
            Self::RepoNotFound | Self::RepoNotFoundMsg(_) => "RepoNotFound",
            Self::RecordNotFound => "RecordNotFound",
            Self::BlobNotFound => "BlobNotFound",
            Self::AppPasswordNotFound => "AppPasswordNotFound",
            Self::InvalidRequest(_) => "InvalidRequest",
            Self::InvalidHandle => "InvalidHandle",
            Self::HandleNotAvailable => "HandleNotAvailable",
            Self::HandleTaken => "HandleTaken",
            Self::InvalidEmail => "InvalidEmail",
            Self::EmailTaken => "EmailTaken",
            Self::InvalidInviteCode => "InvalidInviteCode",
            Self::DuplicateCreate => "DuplicateCreate",
            Self::DuplicateAppPassword => "DuplicateAppPassword",
            Self::InvalidSwap => "InvalidSwap",
        }
    }

    fn message(&self) -> Option<String> {
        match self {
            Self::AuthenticationFailedMsg(msg)
            | Self::ExpiredTokenMsg(msg)
            | Self::InvalidRequest(msg)
            | Self::RepoNotFoundMsg(msg) => Some(msg.clone()),
            _ => None,
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
