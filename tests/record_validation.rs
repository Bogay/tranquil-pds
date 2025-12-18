use tranquil_pds::validation::{
    RecordValidator, ValidationError, ValidationStatus, validate_collection_nsid,
    validate_record_key,
};
use serde_json::json;

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[test]
fn test_post_record_validation() {
    let validator = RecordValidator::new();

    let valid_post = json!({
        "$type": "app.bsky.feed.post",
        "text": "Hello world!",
        "createdAt": now()
    });
    assert_eq!(validator.validate(&valid_post, "app.bsky.feed.post").unwrap(), ValidationStatus::Valid);

    let missing_text = json!({
        "$type": "app.bsky.feed.post",
        "createdAt": now()
    });
    assert!(matches!(validator.validate(&missing_text, "app.bsky.feed.post"), Err(ValidationError::MissingField(f)) if f == "text"));

    let missing_created_at = json!({
        "$type": "app.bsky.feed.post",
        "text": "Hello"
    });
    assert!(matches!(validator.validate(&missing_created_at, "app.bsky.feed.post"), Err(ValidationError::MissingField(f)) if f == "createdAt"));

    let text_too_long = json!({
        "$type": "app.bsky.feed.post",
        "text": "a".repeat(3001),
        "createdAt": now()
    });
    assert!(matches!(validator.validate(&text_too_long, "app.bsky.feed.post"), Err(ValidationError::InvalidField { path, .. }) if path == "text"));

    let text_at_limit = json!({
        "$type": "app.bsky.feed.post",
        "text": "a".repeat(3000),
        "createdAt": now()
    });
    assert_eq!(validator.validate(&text_at_limit, "app.bsky.feed.post").unwrap(), ValidationStatus::Valid);

    let too_many_langs = json!({
        "$type": "app.bsky.feed.post",
        "text": "Hello",
        "createdAt": now(),
        "langs": ["en", "fr", "de", "es"]
    });
    assert!(matches!(validator.validate(&too_many_langs, "app.bsky.feed.post"), Err(ValidationError::InvalidField { path, .. }) if path == "langs"));

    let three_langs_ok = json!({
        "$type": "app.bsky.feed.post",
        "text": "Hello",
        "createdAt": now(),
        "langs": ["en", "fr", "de"]
    });
    assert_eq!(validator.validate(&three_langs_ok, "app.bsky.feed.post").unwrap(), ValidationStatus::Valid);

    let too_many_tags = json!({
        "$type": "app.bsky.feed.post",
        "text": "Hello",
        "createdAt": now(),
        "tags": ["tag1", "tag2", "tag3", "tag4", "tag5", "tag6", "tag7", "tag8", "tag9"]
    });
    assert!(matches!(validator.validate(&too_many_tags, "app.bsky.feed.post"), Err(ValidationError::InvalidField { path, .. }) if path == "tags"));

    let eight_tags_ok = json!({
        "$type": "app.bsky.feed.post",
        "text": "Hello",
        "createdAt": now(),
        "tags": ["tag1", "tag2", "tag3", "tag4", "tag5", "tag6", "tag7", "tag8"]
    });
    assert_eq!(validator.validate(&eight_tags_ok, "app.bsky.feed.post").unwrap(), ValidationStatus::Valid);

    let tag_too_long = json!({
        "$type": "app.bsky.feed.post",
        "text": "Hello",
        "createdAt": now(),
        "tags": ["t".repeat(641)]
    });
    assert!(matches!(validator.validate(&tag_too_long, "app.bsky.feed.post"), Err(ValidationError::InvalidField { path, .. }) if path.starts_with("tags/")));
}

#[test]
fn test_profile_record_validation() {
    let validator = RecordValidator::new();

    let valid = json!({
        "$type": "app.bsky.actor.profile",
        "displayName": "Test User",
        "description": "A test user profile"
    });
    assert_eq!(validator.validate(&valid, "app.bsky.actor.profile").unwrap(), ValidationStatus::Valid);

    let empty_ok = json!({
        "$type": "app.bsky.actor.profile"
    });
    assert_eq!(validator.validate(&empty_ok, "app.bsky.actor.profile").unwrap(), ValidationStatus::Valid);

    let displayname_too_long = json!({
        "$type": "app.bsky.actor.profile",
        "displayName": "n".repeat(641)
    });
    assert!(matches!(validator.validate(&displayname_too_long, "app.bsky.actor.profile"), Err(ValidationError::InvalidField { path, .. }) if path == "displayName"));

    let description_too_long = json!({
        "$type": "app.bsky.actor.profile",
        "description": "d".repeat(2561)
    });
    assert!(matches!(validator.validate(&description_too_long, "app.bsky.actor.profile"), Err(ValidationError::InvalidField { path, .. }) if path == "description"));
}

#[test]
fn test_like_and_repost_validation() {
    let validator = RecordValidator::new();

    let valid_like = json!({
        "$type": "app.bsky.feed.like",
        "subject": {
            "uri": "at://did:plc:test/app.bsky.feed.post/123",
            "cid": "bafyreig6xxxxxyyyyyzzzzzz"
        },
        "createdAt": now()
    });
    assert_eq!(validator.validate(&valid_like, "app.bsky.feed.like").unwrap(), ValidationStatus::Valid);

    let missing_subject = json!({
        "$type": "app.bsky.feed.like",
        "createdAt": now()
    });
    assert!(matches!(validator.validate(&missing_subject, "app.bsky.feed.like"), Err(ValidationError::MissingField(f)) if f == "subject"));

    let missing_subject_uri = json!({
        "$type": "app.bsky.feed.like",
        "subject": {
            "cid": "bafyreig6xxxxxyyyyyzzzzzz"
        },
        "createdAt": now()
    });
    assert!(matches!(validator.validate(&missing_subject_uri, "app.bsky.feed.like"), Err(ValidationError::MissingField(f)) if f.contains("uri")));

    let invalid_subject_uri = json!({
        "$type": "app.bsky.feed.like",
        "subject": {
            "uri": "https://example.com/not-at-uri",
            "cid": "bafyreig6xxxxxyyyyyzzzzzz"
        },
        "createdAt": now()
    });
    assert!(matches!(validator.validate(&invalid_subject_uri, "app.bsky.feed.like"), Err(ValidationError::InvalidField { path, .. }) if path.contains("uri")));

    let valid_repost = json!({
        "$type": "app.bsky.feed.repost",
        "subject": {
            "uri": "at://did:plc:test/app.bsky.feed.post/123",
            "cid": "bafyreig6xxxxxyyyyyzzzzzz"
        },
        "createdAt": now()
    });
    assert_eq!(validator.validate(&valid_repost, "app.bsky.feed.repost").unwrap(), ValidationStatus::Valid);

    let repost_missing_subject = json!({
        "$type": "app.bsky.feed.repost",
        "createdAt": now()
    });
    assert!(matches!(validator.validate(&repost_missing_subject, "app.bsky.feed.repost"), Err(ValidationError::MissingField(f)) if f == "subject"));
}

#[test]
fn test_follow_and_block_validation() {
    let validator = RecordValidator::new();

    let valid_follow = json!({
        "$type": "app.bsky.graph.follow",
        "subject": "did:plc:test12345",
        "createdAt": now()
    });
    assert_eq!(validator.validate(&valid_follow, "app.bsky.graph.follow").unwrap(), ValidationStatus::Valid);

    let missing_follow_subject = json!({
        "$type": "app.bsky.graph.follow",
        "createdAt": now()
    });
    assert!(matches!(validator.validate(&missing_follow_subject, "app.bsky.graph.follow"), Err(ValidationError::MissingField(f)) if f == "subject"));

    let invalid_follow_subject = json!({
        "$type": "app.bsky.graph.follow",
        "subject": "not-a-did",
        "createdAt": now()
    });
    assert!(matches!(validator.validate(&invalid_follow_subject, "app.bsky.graph.follow"), Err(ValidationError::InvalidField { path, .. }) if path == "subject"));

    let valid_block = json!({
        "$type": "app.bsky.graph.block",
        "subject": "did:plc:blocked123",
        "createdAt": now()
    });
    assert_eq!(validator.validate(&valid_block, "app.bsky.graph.block").unwrap(), ValidationStatus::Valid);

    let invalid_block_subject = json!({
        "$type": "app.bsky.graph.block",
        "subject": "not-a-did",
        "createdAt": now()
    });
    assert!(matches!(validator.validate(&invalid_block_subject, "app.bsky.graph.block"), Err(ValidationError::InvalidField { path, .. }) if path == "subject"));
}

#[test]
fn test_list_and_graph_records_validation() {
    let validator = RecordValidator::new();

    let valid_list = json!({
        "$type": "app.bsky.graph.list",
        "name": "My List",
        "purpose": "app.bsky.graph.defs#modlist",
        "createdAt": now()
    });
    assert_eq!(validator.validate(&valid_list, "app.bsky.graph.list").unwrap(), ValidationStatus::Valid);

    let list_name_too_long = json!({
        "$type": "app.bsky.graph.list",
        "name": "n".repeat(65),
        "purpose": "app.bsky.graph.defs#modlist",
        "createdAt": now()
    });
    assert!(matches!(validator.validate(&list_name_too_long, "app.bsky.graph.list"), Err(ValidationError::InvalidField { path, .. }) if path == "name"));

    let list_empty_name = json!({
        "$type": "app.bsky.graph.list",
        "name": "",
        "purpose": "app.bsky.graph.defs#modlist",
        "createdAt": now()
    });
    assert!(matches!(validator.validate(&list_empty_name, "app.bsky.graph.list"), Err(ValidationError::InvalidField { path, .. }) if path == "name"));

    let valid_list_item = json!({
        "$type": "app.bsky.graph.listitem",
        "subject": "did:plc:test123",
        "list": "at://did:plc:owner/app.bsky.graph.list/mylist",
        "createdAt": now()
    });
    assert_eq!(validator.validate(&valid_list_item, "app.bsky.graph.listitem").unwrap(), ValidationStatus::Valid);
}

#[test]
fn test_misc_record_types_validation() {
    let validator = RecordValidator::new();

    let valid_generator = json!({
        "$type": "app.bsky.feed.generator",
        "did": "did:web:example.com",
        "displayName": "My Feed",
        "createdAt": now()
    });
    assert_eq!(validator.validate(&valid_generator, "app.bsky.feed.generator").unwrap(), ValidationStatus::Valid);

    let generator_displayname_too_long = json!({
        "$type": "app.bsky.feed.generator",
        "did": "did:web:example.com",
        "displayName": "f".repeat(241),
        "createdAt": now()
    });
    assert!(matches!(validator.validate(&generator_displayname_too_long, "app.bsky.feed.generator"), Err(ValidationError::InvalidField { path, .. }) if path == "displayName"));

    let valid_threadgate = json!({
        "$type": "app.bsky.feed.threadgate",
        "post": "at://did:plc:test/app.bsky.feed.post/123",
        "createdAt": now()
    });
    assert_eq!(validator.validate(&valid_threadgate, "app.bsky.feed.threadgate").unwrap(), ValidationStatus::Valid);

    let valid_labeler = json!({
        "$type": "app.bsky.labeler.service",
        "policies": {
            "labelValues": ["spam", "nsfw"]
        },
        "createdAt": now()
    });
    assert_eq!(validator.validate(&valid_labeler, "app.bsky.labeler.service").unwrap(), ValidationStatus::Valid);
}

#[test]
fn test_type_and_format_validation() {
    let validator = RecordValidator::new();
    let strict_validator = RecordValidator::new().require_lexicon(true);

    let custom_record = json!({
        "$type": "com.custom.record",
        "data": "test"
    });
    assert_eq!(validator.validate(&custom_record, "com.custom.record").unwrap(), ValidationStatus::Unknown);
    assert!(matches!(strict_validator.validate(&custom_record, "com.custom.record"), Err(ValidationError::UnknownType(_))));

    let type_mismatch = json!({
        "$type": "app.bsky.feed.like",
        "subject": {"uri": "at://test", "cid": "bafytest"},
        "createdAt": now()
    });
    assert!(matches!(
        validator.validate(&type_mismatch, "app.bsky.feed.post"),
        Err(ValidationError::TypeMismatch { expected, actual }) if expected == "app.bsky.feed.post" && actual == "app.bsky.feed.like"
    ));

    let missing_type = json!({
        "text": "Hello"
    });
    assert!(matches!(validator.validate(&missing_type, "app.bsky.feed.post"), Err(ValidationError::MissingType)));

    let not_object = json!("just a string");
    assert!(matches!(validator.validate(&not_object, "app.bsky.feed.post"), Err(ValidationError::InvalidRecord(_))));

    let valid_datetime = json!({
        "$type": "app.bsky.feed.post",
        "text": "Test",
        "createdAt": "2024-01-15T10:30:00.000Z"
    });
    assert_eq!(validator.validate(&valid_datetime, "app.bsky.feed.post").unwrap(), ValidationStatus::Valid);

    let datetime_with_offset = json!({
        "$type": "app.bsky.feed.post",
        "text": "Test",
        "createdAt": "2024-01-15T10:30:00+05:30"
    });
    assert_eq!(validator.validate(&datetime_with_offset, "app.bsky.feed.post").unwrap(), ValidationStatus::Valid);

    let invalid_datetime = json!({
        "$type": "app.bsky.feed.post",
        "text": "Test",
        "createdAt": "2024/01/15"
    });
    assert!(matches!(validator.validate(&invalid_datetime, "app.bsky.feed.post"), Err(ValidationError::InvalidDatetime { .. })));
}

#[test]
fn test_record_key_validation() {
    assert!(validate_record_key("3k2n5j2").is_ok());
    assert!(validate_record_key("valid-key").is_ok());
    assert!(validate_record_key("valid_key").is_ok());
    assert!(validate_record_key("valid.key").is_ok());
    assert!(validate_record_key("valid~key").is_ok());
    assert!(validate_record_key("self").is_ok());

    assert!(matches!(validate_record_key(""), Err(ValidationError::InvalidRecord(_))));

    assert!(validate_record_key(".").is_err());
    assert!(validate_record_key("..").is_err());

    assert!(validate_record_key("invalid/key").is_err());
    assert!(validate_record_key("invalid key").is_err());
    assert!(validate_record_key("invalid@key").is_err());
    assert!(validate_record_key("invalid#key").is_err());

    assert!(matches!(validate_record_key(&"k".repeat(513)), Err(ValidationError::InvalidRecord(_))));
    assert!(validate_record_key(&"k".repeat(512)).is_ok());
}

#[test]
fn test_collection_nsid_validation() {
    assert!(validate_collection_nsid("app.bsky.feed.post").is_ok());
    assert!(validate_collection_nsid("com.atproto.repo.record").is_ok());
    assert!(validate_collection_nsid("a.b.c").is_ok());
    assert!(validate_collection_nsid("my-app.domain.record-type").is_ok());

    assert!(matches!(validate_collection_nsid(""), Err(ValidationError::InvalidRecord(_))));

    assert!(validate_collection_nsid("a").is_err());
    assert!(validate_collection_nsid("a.b").is_err());

    assert!(validate_collection_nsid("a..b.c").is_err());
    assert!(validate_collection_nsid(".a.b.c").is_err());
    assert!(validate_collection_nsid("a.b.c.").is_err());

    assert!(validate_collection_nsid("a.b.c/d").is_err());
    assert!(validate_collection_nsid("a.b.c_d").is_err());
    assert!(validate_collection_nsid("a.b.c@d").is_err());
}
