use axum::{
    extract::FromRequestParts,
    http::{header::AUTHORIZATION, request::Parts},
    response::{IntoResponse, Response},
};

use super::{
    AuthenticatedUser, TokenValidationError, validate_bearer_token_cached,
    validate_bearer_token_cached_allow_deactivated, validate_token_with_dpop,
};
use crate::api::error::ApiError;
use crate::state::AppState;
use crate::util::build_full_url;

pub struct BearerAuth(pub AuthenticatedUser);

#[derive(Debug)]
pub enum AuthError {
    MissingToken,
    InvalidFormat,
    AuthenticationFailed,
    TokenExpired,
    AccountDeactivated,
    AccountTakedown,
    AdminRequired,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        ApiError::from(self).into_response()
    }
}

#[cfg(test)]
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

pub struct ExtractedToken {
    pub token: String,
    pub is_dpop: bool,
}

pub fn extract_auth_token_from_header(auth_header: Option<&str>) -> Option<ExtractedToken> {
    let header = auth_header?;
    let header = header.trim();

    if header.len() >= 7 && header[..7].eq_ignore_ascii_case("bearer ") {
        let token = header[7..].trim();
        if token.is_empty() {
            return None;
        }
        return Some(ExtractedToken {
            token: token.to_string(),
            is_dpop: false,
        });
    }

    if header.len() >= 5 && header[..5].eq_ignore_ascii_case("dpop ") {
        let token = header[5..].trim();
        if token.is_empty() {
            return None;
        }
        return Some(ExtractedToken {
            token: token.to_string(),
            is_dpop: true,
        });
    }

    None
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

        let extracted =
            extract_auth_token_from_header(Some(auth_header)).ok_or(AuthError::InvalidFormat)?;

        if extracted.is_dpop {
            let dpop_proof = parts.headers.get("dpop").and_then(|h| h.to_str().ok());
            let method = parts.method.as_str();
            let uri = build_full_url(&parts.uri.to_string());

            match validate_token_with_dpop(
                &state.db,
                &extracted.token,
                true,
                dpop_proof,
                method,
                &uri,
                false,
            )
            .await
            {
                Ok(user) => Ok(BearerAuth(user)),
                Err(TokenValidationError::AccountDeactivated) => Err(AuthError::AccountDeactivated),
                Err(TokenValidationError::AccountTakedown) => Err(AuthError::AccountTakedown),
                Err(TokenValidationError::TokenExpired) => Err(AuthError::TokenExpired),
                Err(_) => Err(AuthError::AuthenticationFailed),
            }
        } else {
            match validate_bearer_token_cached(&state.db, state.cache.as_ref(), &extracted.token)
                .await
            {
                Ok(user) => Ok(BearerAuth(user)),
                Err(TokenValidationError::AccountDeactivated) => Err(AuthError::AccountDeactivated),
                Err(TokenValidationError::AccountTakedown) => Err(AuthError::AccountTakedown),
                Err(TokenValidationError::TokenExpired) => Err(AuthError::TokenExpired),
                Err(_) => Err(AuthError::AuthenticationFailed),
            }
        }
    }
}

pub struct BearerAuthAllowDeactivated(pub AuthenticatedUser);

impl FromRequestParts<AppState> for BearerAuthAllowDeactivated {
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

        let extracted =
            extract_auth_token_from_header(Some(auth_header)).ok_or(AuthError::InvalidFormat)?;

        if extracted.is_dpop {
            let dpop_proof = parts.headers.get("dpop").and_then(|h| h.to_str().ok());
            let method = parts.method.as_str();
            let uri = build_full_url(&parts.uri.to_string());

            match validate_token_with_dpop(
                &state.db,
                &extracted.token,
                true,
                dpop_proof,
                method,
                &uri,
                true,
            )
            .await
            {
                Ok(user) => Ok(BearerAuthAllowDeactivated(user)),
                Err(TokenValidationError::AccountTakedown) => Err(AuthError::AccountTakedown),
                Err(TokenValidationError::TokenExpired) => Err(AuthError::TokenExpired),
                Err(_) => Err(AuthError::AuthenticationFailed),
            }
        } else {
            match validate_bearer_token_cached_allow_deactivated(
                &state.db,
                state.cache.as_ref(),
                &extracted.token,
            )
            .await
            {
                Ok(user) => Ok(BearerAuthAllowDeactivated(user)),
                Err(TokenValidationError::AccountTakedown) => Err(AuthError::AccountTakedown),
                Err(TokenValidationError::TokenExpired) => Err(AuthError::TokenExpired),
                Err(_) => Err(AuthError::AuthenticationFailed),
            }
        }
    }
}

pub struct BearerAuthAdmin(pub AuthenticatedUser);

impl FromRequestParts<AppState> for BearerAuthAdmin {
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

        let extracted =
            extract_auth_token_from_header(Some(auth_header)).ok_or(AuthError::InvalidFormat)?;

        let user = if extracted.is_dpop {
            let dpop_proof = parts.headers.get("dpop").and_then(|h| h.to_str().ok());
            let method = parts.method.as_str();
            let uri = build_full_url(&parts.uri.to_string());

            match validate_token_with_dpop(
                &state.db,
                &extracted.token,
                true,
                dpop_proof,
                method,
                &uri,
                false,
            )
            .await
            {
                Ok(user) => user,
                Err(TokenValidationError::AccountDeactivated) => {
                    return Err(AuthError::AccountDeactivated);
                }
                Err(TokenValidationError::AccountTakedown) => {
                    return Err(AuthError::AccountTakedown);
                }
                Err(TokenValidationError::TokenExpired) => {
                    return Err(AuthError::TokenExpired);
                }
                Err(_) => return Err(AuthError::AuthenticationFailed),
            }
        } else {
            match validate_bearer_token_cached(&state.db, state.cache.as_ref(), &extracted.token)
                .await
            {
                Ok(user) => user,
                Err(TokenValidationError::AccountDeactivated) => {
                    return Err(AuthError::AccountDeactivated);
                }
                Err(TokenValidationError::AccountTakedown) => {
                    return Err(AuthError::AccountTakedown);
                }
                Err(TokenValidationError::TokenExpired) => {
                    return Err(AuthError::TokenExpired);
                }
                Err(_) => return Err(AuthError::AuthenticationFailed),
            }
        };

        if !user.is_admin {
            return Err(AuthError::AdminRequired);
        }
        Ok(BearerAuthAdmin(user))
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
