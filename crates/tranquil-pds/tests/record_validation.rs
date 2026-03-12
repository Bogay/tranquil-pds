use serde_json::json;
use tranquil_pds::validation::{
    RecordValidator, ValidationError, ValidationStatus, validate_collection_nsid,
    validate_record_key,
};

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[test]
fn test_type_mismatch() {
    let validator = RecordValidator::new();
    let record = json!({
        "$type": "com.example.other",
        "createdAt": now()
    });
    assert!(matches!(
        validator.validate(&record, "com.example.expected"),
        Err(ValidationError::TypeMismatch { expected, actual })
            if expected == "com.example.expected" && actual == "com.example.other"
    ));
}

#[test]
fn test_missing_type() {
    let validator = RecordValidator::new();
    let record = json!({"text": "Hello"});
    assert!(matches!(
        validator.validate(&record, "com.example.test"),
        Err(ValidationError::MissingType)
    ));
}

#[test]
fn test_not_object() {
    let validator = RecordValidator::new();
    let record = json!("just a string");
    assert!(matches!(
        validator.validate(&record, "com.example.test"),
        Err(ValidationError::InvalidRecord(_))
    ));
}

#[test]
fn test_unknown_type_lenient() {
    let validator = RecordValidator::new();
    let record = json!({"$type": "com.custom.record", "data": "test"});
    assert_eq!(
        validator.validate(&record, "com.custom.record").unwrap(),
        ValidationStatus::Unknown
    );
}

#[test]
fn test_unknown_type_strict() {
    let validator = RecordValidator::new().require_lexicon(true);
    let record = json!({"$type": "com.custom.record", "data": "test"});
    assert!(matches!(
        validator.validate(&record, "com.custom.record"),
        Err(ValidationError::UnknownType(_))
    ));
}

#[test]
fn test_datetime_validation() {
    let validator = RecordValidator::new();

    let valid = json!({"$type": "com.custom.record", "createdAt": "2024-01-15T10:30:00.000Z"});
    assert_eq!(
        validator.validate(&valid, "com.custom.record").unwrap(),
        ValidationStatus::Unknown
    );

    let with_offset =
        json!({"$type": "com.custom.record", "createdAt": "2024-01-15T10:30:00+05:30"});
    assert_eq!(
        validator
            .validate(&with_offset, "com.custom.record")
            .unwrap(),
        ValidationStatus::Unknown
    );

    let invalid = json!({"$type": "com.custom.record", "createdAt": "2024/01/15"});
    assert!(matches!(
        validator.validate(&invalid, "com.custom.record"),
        Err(ValidationError::InvalidDatetime { .. })
    ));
}

#[test]
fn test_record_key_validation() {
    assert!(validate_record_key("3k2n5j2").is_ok());
    assert!(validate_record_key("valid-key").is_ok());
    assert!(validate_record_key("valid_key").is_ok());
    assert!(validate_record_key("valid.key").is_ok());
    assert!(validate_record_key("valid~key").is_ok());
    assert!(validate_record_key("self").is_ok());

    assert!(matches!(
        validate_record_key(""),
        Err(ValidationError::InvalidRecord(_))
    ));

    assert!(validate_record_key(".").is_err());
    assert!(validate_record_key("..").is_err());

    assert!(validate_record_key("invalid/key").is_err());
    assert!(validate_record_key("invalid key").is_err());
    assert!(validate_record_key("invalid@key").is_err());
    assert!(validate_record_key("invalid#key").is_err());

    assert!(matches!(
        validate_record_key(&"k".repeat(513)),
        Err(ValidationError::InvalidRecord(_))
    ));
    assert!(validate_record_key(&"k".repeat(512)).is_ok());

    assert!(
        validate_record_key("key:with:colons").is_ok(),
        "AT Protocol record keys allow colons"
    );
    assert!(validate_record_key("at:something").is_ok());
}

#[test]
fn test_collection_nsid_validation() {
    assert!(validate_collection_nsid("app.bsky.feed.post").is_ok());
    assert!(validate_collection_nsid("com.atproto.repo.record").is_ok());
    assert!(validate_collection_nsid("a.b.c").is_ok());
    assert!(validate_collection_nsid("my-app.domain.record-type").is_ok());

    assert!(matches!(
        validate_collection_nsid(""),
        Err(ValidationError::InvalidRecord(_))
    ));

    assert!(validate_collection_nsid("a").is_err());
    assert!(validate_collection_nsid("a.b").is_err());

    assert!(validate_collection_nsid("a..b.c").is_err());
    assert!(validate_collection_nsid(".a.b.c").is_err());
    assert!(validate_collection_nsid("a.b.c.").is_err());

    assert!(validate_collection_nsid("a.b.c/d").is_err());
    assert!(validate_collection_nsid("a.b.c_d").is_err());
    assert!(validate_collection_nsid("a.b.c@d").is_err());
}
