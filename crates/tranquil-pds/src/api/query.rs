use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use serde::de::DeserializeOwned;

use super::error::ApiError;

pub struct XrpcQuery<T>(pub T);

impl<T: DeserializeOwned, S: Send + Sync> FromRequestParts<S> for XrpcQuery<T> {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let raw = parts.uri.query().unwrap_or_default();
        serde_urlencoded::from_str(raw)
            .map(Self)
            .map_err(|e| ApiError::InvalidRequest(e.to_string()))
    }
}
