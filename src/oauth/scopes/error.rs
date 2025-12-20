use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug, Clone)]
pub enum ScopeError {
    InsufficientScope { required: String, message: String },
    InvalidScope(String),
}

impl std::fmt::Display for ScopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScopeError::InsufficientScope { message, .. } => write!(f, "{}", message),
            ScopeError::InvalidScope(msg) => write!(f, "Invalid scope: {}", msg),
        }
    }
}

impl std::error::Error for ScopeError {}

impl IntoResponse for ScopeError {
    fn into_response(self) -> Response {
        let (status, error_code, message) = match &self {
            ScopeError::InsufficientScope { message, .. } => {
                (StatusCode::FORBIDDEN, "InsufficientScope", message.clone())
            }
            ScopeError::InvalidScope(msg) => (StatusCode::BAD_REQUEST, "InvalidScope", msg.clone()),
        };
        (
            status,
            axum::Json(json!({
                "error": error_code,
                "message": message
            })),
        )
            .into_response()
    }
}
