use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts, header::AUTHORIZATION},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::state::AppState;
use super::{AuthenticatedUser, validate_bearer_token};

pub struct BearerAuth(pub AuthenticatedUser);

#[derive(Debug)]
pub enum AuthError {
    MissingToken,
    InvalidFormat,
    AuthenticationFailed,
    AccountDeactivated,
    AccountTakedown,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error, message) = match self {
            AuthError::MissingToken => (
                StatusCode::UNAUTHORIZED,
                "AuthenticationRequired",
                "Authorization header is required",
            ),
            AuthError::InvalidFormat => (
                StatusCode::UNAUTHORIZED,
                "InvalidToken",
                "Invalid authorization header format",
            ),
            AuthError::AuthenticationFailed => (
                StatusCode::UNAUTHORIZED,
                "AuthenticationFailed",
                "Invalid or expired token",
            ),
            AuthError::AccountDeactivated => (
                StatusCode::UNAUTHORIZED,
                "AccountDeactivated",
                "Account is deactivated",
            ),
            AuthError::AccountTakedown => (
                StatusCode::UNAUTHORIZED,
                "AccountTakedown",
                "Account has been taken down",
            ),
        };

        (status, Json(json!({ "error": error, "message": message }))).into_response()
    }
}

fn extract_bearer_token(auth_header: &str) -> Result<&str, AuthError> {
    let auth_header = auth_header.trim();

    if auth_header.len() < 8 {
        return Err(AuthError::InvalidFormat);
    }

    let prefix = &auth_header[..7];
    if !prefix.eq_ignore_ascii_case("bearer ") {
        return Err(AuthError::InvalidFormat);
    }

    let token = auth_header[7..].trim();
    if token.is_empty() {
        return Err(AuthError::InvalidFormat);
    }

    Ok(token)
}

pub fn extract_bearer_token_from_header(auth_header: Option<&str>) -> Option<String> {
    let header = auth_header?;
    let header = header.trim();

    if header.len() < 7 {
        return None;
    }

    if !header[..7].eq_ignore_ascii_case("bearer ") {
        return None;
    }

    let token = header[7..].trim();
    if token.is_empty() {
        return None;
    }

    Some(token.to_string())
}

impl FromRequestParts<AppState> for BearerAuth {
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .ok_or(AuthError::MissingToken)?
            .to_str()
            .map_err(|_| AuthError::InvalidFormat)?;

        let token = extract_bearer_token(auth_header)?;

        match validate_bearer_token(&state.db, token).await {
            Ok(user) => Ok(BearerAuth(user)),
            Err("AccountDeactivated") => Err(AuthError::AccountDeactivated),
            Err("AccountTakedown") => Err(AuthError::AccountTakedown),
            Err(_) => Err(AuthError::AuthenticationFailed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_bearer_token() {
        assert_eq!(extract_bearer_token("Bearer abc123").unwrap(), "abc123");
        assert_eq!(extract_bearer_token("bearer abc123").unwrap(), "abc123");
        assert_eq!(extract_bearer_token("BEARER abc123").unwrap(), "abc123");
        assert_eq!(extract_bearer_token("Bearer  abc123").unwrap(), "abc123");
        assert_eq!(extract_bearer_token(" Bearer abc123 ").unwrap(), "abc123");

        assert!(extract_bearer_token("Basic abc123").is_err());
        assert!(extract_bearer_token("Bearer").is_err());
        assert!(extract_bearer_token("Bearer ").is_err());
        assert!(extract_bearer_token("abc123").is_err());
        assert!(extract_bearer_token("").is_err());
    }
}
