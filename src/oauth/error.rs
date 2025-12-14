use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
#[derive(Debug)]
pub enum OAuthError {
    InvalidRequest(String),
    InvalidClient(String),
    InvalidGrant(String),
    UnauthorizedClient(String),
    UnsupportedGrantType(String),
    InvalidScope(String),
    AccessDenied(String),
    ServerError(String),
    UseDpopNonce(String),
    InvalidDpopProof(String),
    ExpiredToken(String),
    InvalidToken(String),
    RateLimited,
}
#[derive(Serialize)]
struct OAuthErrorResponse {
    error: String,
    error_description: Option<String>,
}
impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let (status, error, description) = match self {
            OAuthError::InvalidRequest(msg) => {
                (StatusCode::BAD_REQUEST, "invalid_request", Some(msg))
            }
            OAuthError::InvalidClient(msg) => {
                (StatusCode::UNAUTHORIZED, "invalid_client", Some(msg))
            }
            OAuthError::InvalidGrant(msg) => {
                (StatusCode::BAD_REQUEST, "invalid_grant", Some(msg))
            }
            OAuthError::UnauthorizedClient(msg) => {
                (StatusCode::UNAUTHORIZED, "unauthorized_client", Some(msg))
            }
            OAuthError::UnsupportedGrantType(msg) => {
                (StatusCode::BAD_REQUEST, "unsupported_grant_type", Some(msg))
            }
            OAuthError::InvalidScope(msg) => {
                (StatusCode::BAD_REQUEST, "invalid_scope", Some(msg))
            }
            OAuthError::AccessDenied(msg) => {
                (StatusCode::FORBIDDEN, "access_denied", Some(msg))
            }
            OAuthError::ServerError(msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "server_error", Some(msg))
            }
            OAuthError::UseDpopNonce(nonce) => {
                return (
                    StatusCode::BAD_REQUEST,
                    [("DPoP-Nonce", nonce)],
                    Json(OAuthErrorResponse {
                        error: "use_dpop_nonce".to_string(),
                        error_description: Some("A DPoP nonce is required".to_string()),
                    }),
                )
                    .into_response();
            }
            OAuthError::InvalidDpopProof(msg) => {
                (StatusCode::UNAUTHORIZED, "invalid_dpop_proof", Some(msg))
            }
            OAuthError::ExpiredToken(msg) => {
                (StatusCode::UNAUTHORIZED, "invalid_token", Some(msg))
            }
            OAuthError::InvalidToken(msg) => {
                (StatusCode::UNAUTHORIZED, "invalid_token", Some(msg))
            }
            OAuthError::RateLimited => {
                (StatusCode::TOO_MANY_REQUESTS, "rate_limited", Some("Too many requests. Please try again later.".to_string()))
            }
        };
        (
            status,
            Json(OAuthErrorResponse {
                error: error.to_string(),
                error_description: description,
            }),
        )
            .into_response()
    }
}
impl From<sqlx::Error> for OAuthError {
    fn from(err: sqlx::Error) -> Self {
        tracing::error!("Database error in OAuth flow: {}", err);
        OAuthError::ServerError("An internal error occurred".to_string())
    }
}
impl From<anyhow::Error> for OAuthError {
    fn from(err: anyhow::Error) -> Self {
        tracing::error!("Internal error in OAuth flow: {}", err);
        OAuthError::ServerError("An internal error occurred".to_string())
    }
}
