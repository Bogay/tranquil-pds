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
    if !registry.has_schema(collection) {
        let _ = registry.resolve_dynamic(collection).await;
    }

    let validator = RecordValidator::new().require_lexicon(require_lexicon);
    validator
        .validate_with_rkey(record, collection, rkey)
        .map_err(validation_error_to_api_error)
}

// There is no hard limit on record sizes when creating records, just a recommendation to stay under
// 1MiB, however the Sync spec limits commit blocks to not be larger than 1MB. Anecdotally, creating a
// 10MiB record causes the relays to choke on the commit event with pretty bad outcomes.
//
// > A reasonable maximum record size limit (MAX_CBOR_RECORD_SIZE) is 1 MiByte (1 mebibyte, or 1,048,576 bytes).
// https://atproto.com/guides/data-validation#recommended-data-limits
//
// > individual record blocks within the blocks field have a hard limit of one million bytes
// https://atproto.com/specs/sync#commit-events
const MAX_CBOR_RECORD_SIZE: usize = 1_000_000;

pub fn validate_record_size(record_bytes: &[u8]) -> Result<(), ApiError> {
    if record_bytes.len() > MAX_CBOR_RECORD_SIZE {
        return Err(ApiError::InvalidRecord(format!(
            "Record is {} bytes; maximum size is {MAX_CBOR_RECORD_SIZE} bytes",
            record_bytes.len()
        )));
    }

    Ok(())
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
