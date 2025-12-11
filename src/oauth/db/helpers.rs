use serde::{de::DeserializeOwned, Serialize};

use super::super::OAuthError;

pub fn to_json<T: Serialize>(value: &T) -> Result<serde_json::Value, OAuthError> {
    serde_json::to_value(value).map_err(|e| {
        tracing::error!("JSON serialization error: {}", e);
        OAuthError::ServerError("Internal serialization error".to_string())
    })
}

pub fn from_json<T: DeserializeOwned>(value: serde_json::Value) -> Result<T, OAuthError> {
    serde_json::from_value(value).map_err(|e| {
        tracing::error!("JSON deserialization error: {}", e);
        OAuthError::ServerError("Internal data corruption".to_string())
    })
}
