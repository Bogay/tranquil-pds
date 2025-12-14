use crate::validation::{RecordValidator, ValidationError};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
pub fn validate_record(record: &serde_json::Value, collection: &str) -> Result<(), Response> {
    let validator = RecordValidator::new();
    match validator.validate(record, collection) {
        Ok(_) => Ok(()),
        Err(ValidationError::MissingType) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRecord", "message": "Record must have a $type field"})),
        ).into_response()),
        Err(ValidationError::TypeMismatch { expected, actual }) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRecord", "message": format!("Record $type '{}' does not match collection '{}'", actual, expected)})),
        ).into_response()),
        Err(ValidationError::MissingField(field)) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRecord", "message": format!("Missing required field: {}", field)})),
        ).into_response()),
        Err(ValidationError::InvalidField { path, message }) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRecord", "message": format!("Invalid field '{}': {}", path, message)})),
        ).into_response()),
        Err(ValidationError::InvalidDatetime { path }) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRecord", "message": format!("Invalid datetime format at '{}'", path)})),
        ).into_response()),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRecord", "message": e.to_string()})),
        ).into_response()),
    }
}
