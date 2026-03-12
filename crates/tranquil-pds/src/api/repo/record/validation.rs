use crate::api::error::ApiError;
use crate::types::{Nsid, Rkey};
use crate::validation::{RecordValidator, ValidationError, ValidationStatus};
use axum::response::Response;

pub async fn validate_record_with_status(
    record: &serde_json::Value,
    collection: &Nsid,
    rkey: Option<&Rkey>,
    require_lexicon: bool,
) -> Result<ValidationStatus, Box<Response>> {
    let registry = tranquil_lexicon::LexiconRegistry::global();
    if !registry.has_schema(collection.as_str()) {
        let _ = registry.resolve_dynamic(collection.as_str()).await;
    }

    let validator = RecordValidator::new().require_lexicon(require_lexicon);
    match validator.validate_with_rkey(record, collection.as_str(), rkey.map(|r| r.as_str())) {
        Ok(status) => Ok(status),
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
