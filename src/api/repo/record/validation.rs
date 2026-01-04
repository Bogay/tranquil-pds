use crate::api::error::ApiError;
use crate::validation::{RecordValidator, ValidationError, ValidationStatus};
use axum::response::Response;

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
    use axum::response::IntoResponse;
    let msg = match e {
        ValidationError::MissingType => "Record must have a $type field".to_string(),
        ValidationError::TypeMismatch { expected, actual } => {
            format!(
                "Record $type '{}' does not match collection '{}'",
                actual, expected
            )
        }
        ValidationError::MissingField(field) => format!("Missing required field: {}", field),
        ValidationError::InvalidField { path, message } => {
            format!("Invalid field '{}': {}", path, message)
        }
        ValidationError::InvalidDatetime { path } => {
            format!("Invalid datetime format at '{}'", path)
        }
        ValidationError::BannedContent { path } => {
            format!("Unacceptable slur in record at '{}'", path)
        }
        ValidationError::UnknownType(type_name) => format!("Lexicon not found: lex:{}", type_name),
        e => e.to_string(),
    };
    Box::new(ApiError::InvalidRecord(msg).into_response())
}
