use crate::validation::{RecordValidator, ValidationError};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

pub fn validate_record(record: &serde_json::Value, collection: &str) -> Result<(), Box<Response>> {
    validate_record_with_rkey(record, collection, None)
}

pub fn validate_record_with_rkey(
    record: &serde_json::Value,
    collection: &str,
    rkey: Option<&str>,
) -> Result<(), Box<Response>> {
    let validator = RecordValidator::new();
    match validator.validate_with_rkey(record, collection, rkey) {
        Ok(_) => Ok(()),
        Err(ValidationError::MissingType) => Err(Box::new((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRecord", "message": "Record must have a $type field"})),
        ).into_response())),
        Err(ValidationError::TypeMismatch { expected, actual }) => Err(Box::new((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRecord", "message": format!("Record $type '{}' does not match collection '{}'", actual, expected)})),
        ).into_response())),
        Err(ValidationError::MissingField(field)) => Err(Box::new((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRecord", "message": format!("Missing required field: {}", field)})),
        ).into_response())),
        Err(ValidationError::InvalidField { path, message }) => Err(Box::new((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRecord", "message": format!("Invalid field '{}': {}", path, message)})),
        ).into_response())),
        Err(ValidationError::InvalidDatetime { path }) => Err(Box::new((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRecord", "message": format!("Invalid datetime format at '{}'", path)})),
        ).into_response())),
        Err(ValidationError::BannedContent { path }) => Err(Box::new((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRecord", "message": format!("Unacceptable slur in record at '{}'", path)})),
        ).into_response())),
        Err(e) => Err(Box::new((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRecord", "message": e.to_string()})),
        ).into_response())),
    }
}
