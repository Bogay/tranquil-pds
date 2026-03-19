use tranquil_pds::api::error::ApiError;
use tranquil_pds::types::{Nsid, Rkey};
use tranquil_pds::validation::{RecordValidator, ValidationError, ValidationStatus};

pub async fn validate_record_with_status(
    record: &serde_json::Value,
    collection: &Nsid,
    rkey: Option<&Rkey>,
    require_lexicon: bool,
) -> Result<ValidationStatus, ApiError> {
    let registry = tranquil_lexicon::LexiconRegistry::global();
    if !registry.has_schema(collection.as_str()) {
        let _ = registry.resolve_dynamic(collection.as_str()).await;
    }

    let validator = RecordValidator::new().require_lexicon(require_lexicon);
    validator
        .validate_with_rkey(record, collection.as_str(), rkey.map(|v| v.as_str()))
        .map_err(validation_error_to_api_error)
}

fn validation_error_to_api_error(e: ValidationError) -> ApiError {
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
    ApiError::InvalidRecord(msg)
}
