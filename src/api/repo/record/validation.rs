use crate::validation::{RecordValidator, ValidationError, ValidationStatus};
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
    validation_error_to_response(validator.validate_with_rkey(record, collection, rkey))
}

pub fn validate_record_with_status(
    record: &serde_json::Value,
    collection: &str,
    rkey: Option<&str>,
    require_lexicon: bool,
) -> Result<ValidationStatus, Box<Response>> {
    let validator = RecordValidator::new().require_lexicon(require_lexicon);
    match validator.validate_with_rkey(record, collection, rkey) {
        Ok(status) => Ok(status),
        Err(e) => Err(validation_error_to_box_response(e)),
    }
}

fn validation_error_to_response(
    result: Result<ValidationStatus, ValidationError>,
) -> Result<(), Box<Response>> {
    match result {
        Ok(_) => Ok(()),
        Err(e) => Err(validation_error_to_box_response(e)),
    }
}

fn validation_error_to_box_response(e: ValidationError) -> Box<Response> {
    match e {
        ValidationError::MissingType => Box::new(
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidRecord", "message": "Record must have a $type field"})),
            )
                .into_response(),
        ),
        ValidationError::TypeMismatch { expected, actual } => Box::new(
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidRecord", "message": format!("Record $type '{}' does not match collection '{}'", actual, expected)})),
            )
                .into_response(),
        ),
        ValidationError::MissingField(field) => Box::new(
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidRecord", "message": format!("Missing required field: {}", field)})),
            )
                .into_response(),
        ),
        ValidationError::InvalidField { path, message } => Box::new(
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidRecord", "message": format!("Invalid field '{}': {}", path, message)})),
            )
                .into_response(),
        ),
        ValidationError::InvalidDatetime { path } => Box::new(
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidRecord", "message": format!("Invalid datetime format at '{}'", path)})),
            )
                .into_response(),
        ),
        ValidationError::BannedContent { path } => Box::new(
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidRecord", "message": format!("Unacceptable slur in record at '{}'", path)})),
            )
                .into_response(),
        ),
        ValidationError::UnknownType(type_name) => Box::new(
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidRecord", "message": format!("Lexicon not found: lex:{}", type_name)})),
            )
                .into_response(),
        ),
        e => Box::new(
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "InvalidRecord", "message": e.to_string()})),
            )
                .into_response(),
        ),
    }
}
