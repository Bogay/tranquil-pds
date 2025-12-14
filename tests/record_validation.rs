use bspds::validation::{RecordValidator, ValidationError, ValidationStatus, validate_record_key, validate_collection_nsid};
use serde_json::json;
fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}
#[test]
fn test_validate_post_valid() {
    let validator = RecordValidator::new();
    let post = json!({
        "$type": "app.bsky.feed.post",
        "text": "Hello world!",
        "createdAt": now()
    });
    let result = validator.validate(&post, "app.bsky.feed.post");
    assert_eq!(result.unwrap(), ValidationStatus::Valid);
}
#[test]
fn test_validate_post_missing_text() {
    let validator = RecordValidator::new();
    let post = json!({
        "$type": "app.bsky.feed.post",
        "createdAt": now()
    });
    let result = validator.validate(&post, "app.bsky.feed.post");
    assert!(matches!(result, Err(ValidationError::MissingField(f)) if f == "text"));
}
#[test]
fn test_validate_post_missing_created_at() {
    let validator = RecordValidator::new();
    let post = json!({
        "$type": "app.bsky.feed.post",
        "text": "Hello"
    });
    let result = validator.validate(&post, "app.bsky.feed.post");
    assert!(matches!(result, Err(ValidationError::MissingField(f)) if f == "createdAt"));
}
#[test]
fn test_validate_post_text_too_long() {
    let validator = RecordValidator::new();
    let long_text = "a".repeat(3001);
    let post = json!({
        "$type": "app.bsky.feed.post",
        "text": long_text,
        "createdAt": now()
    });
    let result = validator.validate(&post, "app.bsky.feed.post");
    assert!(matches!(result, Err(ValidationError::InvalidField { path, .. }) if path == "text"));
}
#[test]
fn test_validate_post_text_at_limit() {
    let validator = RecordValidator::new();
    let limit_text = "a".repeat(3000);
    let post = json!({
        "$type": "app.bsky.feed.post",
        "text": limit_text,
        "createdAt": now()
    });
    let result = validator.validate(&post, "app.bsky.feed.post");
    assert_eq!(result.unwrap(), ValidationStatus::Valid);
}
#[test]
fn test_validate_post_too_many_langs() {
    let validator = RecordValidator::new();
    let post = json!({
        "$type": "app.bsky.feed.post",
        "text": "Hello",
        "createdAt": now(),
        "langs": ["en", "fr", "de", "es"]
    });
    let result = validator.validate(&post, "app.bsky.feed.post");
    assert!(matches!(result, Err(ValidationError::InvalidField { path, .. }) if path == "langs"));
}
#[test]
fn test_validate_post_three_langs_ok() {
    let validator = RecordValidator::new();
    let post = json!({
        "$type": "app.bsky.feed.post",
        "text": "Hello",
        "createdAt": now(),
        "langs": ["en", "fr", "de"]
    });
    let result = validator.validate(&post, "app.bsky.feed.post");
    assert_eq!(result.unwrap(), ValidationStatus::Valid);
}
#[test]
fn test_validate_post_too_many_tags() {
    let validator = RecordValidator::new();
    let post = json!({
        "$type": "app.bsky.feed.post",
        "text": "Hello",
        "createdAt": now(),
        "tags": ["tag1", "tag2", "tag3", "tag4", "tag5", "tag6", "tag7", "tag8", "tag9"]
    });
    let result = validator.validate(&post, "app.bsky.feed.post");
    assert!(matches!(result, Err(ValidationError::InvalidField { path, .. }) if path == "tags"));
}
#[test]
fn test_validate_post_eight_tags_ok() {
    let validator = RecordValidator::new();
    let post = json!({
        "$type": "app.bsky.feed.post",
        "text": "Hello",
        "createdAt": now(),
        "tags": ["tag1", "tag2", "tag3", "tag4", "tag5", "tag6", "tag7", "tag8"]
    });
    let result = validator.validate(&post, "app.bsky.feed.post");
    assert_eq!(result.unwrap(), ValidationStatus::Valid);
}
#[test]
fn test_validate_post_tag_too_long() {
    let validator = RecordValidator::new();
    let long_tag = "t".repeat(641);
    let post = json!({
        "$type": "app.bsky.feed.post",
        "text": "Hello",
        "createdAt": now(),
        "tags": [long_tag]
    });
    let result = validator.validate(&post, "app.bsky.feed.post");
    assert!(matches!(result, Err(ValidationError::InvalidField { path, .. }) if path.starts_with("tags/")));
}
#[test]
fn test_validate_profile_valid() {
    let validator = RecordValidator::new();
    let profile = json!({
        "$type": "app.bsky.actor.profile",
        "displayName": "Test User",
        "description": "A test user profile"
    });
    let result = validator.validate(&profile, "app.bsky.actor.profile");
    assert_eq!(result.unwrap(), ValidationStatus::Valid);
}
#[test]
fn test_validate_profile_empty_ok() {
    let validator = RecordValidator::new();
    let profile = json!({
        "$type": "app.bsky.actor.profile"
    });
    let result = validator.validate(&profile, "app.bsky.actor.profile");
    assert_eq!(result.unwrap(), ValidationStatus::Valid);
}
#[test]
fn test_validate_profile_displayname_too_long() {
    let validator = RecordValidator::new();
    let long_name = "n".repeat(641);
    let profile = json!({
        "$type": "app.bsky.actor.profile",
        "displayName": long_name
    });
    let result = validator.validate(&profile, "app.bsky.actor.profile");
    assert!(matches!(result, Err(ValidationError::InvalidField { path, .. }) if path == "displayName"));
}
#[test]
fn test_validate_profile_description_too_long() {
    let validator = RecordValidator::new();
    let long_desc = "d".repeat(2561);
    let profile = json!({
        "$type": "app.bsky.actor.profile",
        "description": long_desc
    });
    let result = validator.validate(&profile, "app.bsky.actor.profile");
    assert!(matches!(result, Err(ValidationError::InvalidField { path, .. }) if path == "description"));
}
#[test]
fn test_validate_like_valid() {
    let validator = RecordValidator::new();
    let like = json!({
        "$type": "app.bsky.feed.like",
        "subject": {
            "uri": "at://did:plc:test/app.bsky.feed.post/123",
            "cid": "bafyreig6xxxxxyyyyyzzzzzz"
        },
        "createdAt": now()
    });
    let result = validator.validate(&like, "app.bsky.feed.like");
    assert_eq!(result.unwrap(), ValidationStatus::Valid);
}
#[test]
fn test_validate_like_missing_subject() {
    let validator = RecordValidator::new();
    let like = json!({
        "$type": "app.bsky.feed.like",
        "createdAt": now()
    });
    let result = validator.validate(&like, "app.bsky.feed.like");
    assert!(matches!(result, Err(ValidationError::MissingField(f)) if f == "subject"));
}
#[test]
fn test_validate_like_missing_subject_uri() {
    let validator = RecordValidator::new();
    let like = json!({
        "$type": "app.bsky.feed.like",
        "subject": {
            "cid": "bafyreig6xxxxxyyyyyzzzzzz"
        },
        "createdAt": now()
    });
    let result = validator.validate(&like, "app.bsky.feed.like");
    assert!(matches!(result, Err(ValidationError::MissingField(f)) if f.contains("uri")));
}
#[test]
fn test_validate_like_invalid_subject_uri() {
    let validator = RecordValidator::new();
    let like = json!({
        "$type": "app.bsky.feed.like",
        "subject": {
            "uri": "https://example.com/not-at-uri",
            "cid": "bafyreig6xxxxxyyyyyzzzzzz"
        },
        "createdAt": now()
    });
    let result = validator.validate(&like, "app.bsky.feed.like");
    assert!(matches!(result, Err(ValidationError::InvalidField { path, .. }) if path.contains("uri")));
}
#[test]
fn test_validate_repost_valid() {
    let validator = RecordValidator::new();
    let repost = json!({
        "$type": "app.bsky.feed.repost",
        "subject": {
            "uri": "at://did:plc:test/app.bsky.feed.post/123",
            "cid": "bafyreig6xxxxxyyyyyzzzzzz"
        },
        "createdAt": now()
    });
    let result = validator.validate(&repost, "app.bsky.feed.repost");
    assert_eq!(result.unwrap(), ValidationStatus::Valid);
}
#[test]
fn test_validate_repost_missing_subject() {
    let validator = RecordValidator::new();
    let repost = json!({
        "$type": "app.bsky.feed.repost",
        "createdAt": now()
    });
    let result = validator.validate(&repost, "app.bsky.feed.repost");
    assert!(matches!(result, Err(ValidationError::MissingField(f)) if f == "subject"));
}
#[test]
fn test_validate_follow_valid() {
    let validator = RecordValidator::new();
    let follow = json!({
        "$type": "app.bsky.graph.follow",
        "subject": "did:plc:test12345",
        "createdAt": now()
    });
    let result = validator.validate(&follow, "app.bsky.graph.follow");
    assert_eq!(result.unwrap(), ValidationStatus::Valid);
}
#[test]
fn test_validate_follow_missing_subject() {
    let validator = RecordValidator::new();
    let follow = json!({
        "$type": "app.bsky.graph.follow",
        "createdAt": now()
    });
    let result = validator.validate(&follow, "app.bsky.graph.follow");
    assert!(matches!(result, Err(ValidationError::MissingField(f)) if f == "subject"));
}
#[test]
fn test_validate_follow_invalid_subject() {
    let validator = RecordValidator::new();
    let follow = json!({
        "$type": "app.bsky.graph.follow",
        "subject": "not-a-did",
        "createdAt": now()
    });
    let result = validator.validate(&follow, "app.bsky.graph.follow");
    assert!(matches!(result, Err(ValidationError::InvalidField { path, .. }) if path == "subject"));
}
#[test]
fn test_validate_block_valid() {
    let validator = RecordValidator::new();
    let block = json!({
        "$type": "app.bsky.graph.block",
        "subject": "did:plc:blocked123",
        "createdAt": now()
    });
    let result = validator.validate(&block, "app.bsky.graph.block");
    assert_eq!(result.unwrap(), ValidationStatus::Valid);
}
#[test]
fn test_validate_block_invalid_subject() {
    let validator = RecordValidator::new();
    let block = json!({
        "$type": "app.bsky.graph.block",
        "subject": "not-a-did",
        "createdAt": now()
    });
    let result = validator.validate(&block, "app.bsky.graph.block");
    assert!(matches!(result, Err(ValidationError::InvalidField { path, .. }) if path == "subject"));
}
#[test]
fn test_validate_list_valid() {
    let validator = RecordValidator::new();
    let list = json!({
        "$type": "app.bsky.graph.list",
        "name": "My List",
        "purpose": "app.bsky.graph.defs#modlist",
        "createdAt": now()
    });
    let result = validator.validate(&list, "app.bsky.graph.list");
    assert_eq!(result.unwrap(), ValidationStatus::Valid);
}
#[test]
fn test_validate_list_name_too_long() {
    let validator = RecordValidator::new();
    let long_name = "n".repeat(65);
    let list = json!({
        "$type": "app.bsky.graph.list",
        "name": long_name,
        "purpose": "app.bsky.graph.defs#modlist",
        "createdAt": now()
    });
    let result = validator.validate(&list, "app.bsky.graph.list");
    assert!(matches!(result, Err(ValidationError::InvalidField { path, .. }) if path == "name"));
}
#[test]
fn test_validate_list_empty_name() {
    let validator = RecordValidator::new();
    let list = json!({
        "$type": "app.bsky.graph.list",
        "name": "",
        "purpose": "app.bsky.graph.defs#modlist",
        "createdAt": now()
    });
    let result = validator.validate(&list, "app.bsky.graph.list");
    assert!(matches!(result, Err(ValidationError::InvalidField { path, .. }) if path == "name"));
}
#[test]
fn test_validate_feed_generator_valid() {
    let validator = RecordValidator::new();
    let generator = json!({
        "$type": "app.bsky.feed.generator",
        "did": "did:web:example.com",
        "displayName": "My Feed",
        "createdAt": now()
    });
    let result = validator.validate(&generator, "app.bsky.feed.generator");
    assert_eq!(result.unwrap(), ValidationStatus::Valid);
}
#[test]
fn test_validate_feed_generator_displayname_too_long() {
    let validator = RecordValidator::new();
    let long_name = "f".repeat(241);
    let generator = json!({
        "$type": "app.bsky.feed.generator",
        "did": "did:web:example.com",
        "displayName": long_name,
        "createdAt": now()
    });
    let result = validator.validate(&generator, "app.bsky.feed.generator");
    assert!(matches!(result, Err(ValidationError::InvalidField { path, .. }) if path == "displayName"));
}
#[test]
fn test_validate_unknown_type_returns_unknown() {
    let validator = RecordValidator::new();
    let custom = json!({
        "$type": "com.custom.record",
        "data": "test"
    });
    let result = validator.validate(&custom, "com.custom.record");
    assert_eq!(result.unwrap(), ValidationStatus::Unknown);
}
#[test]
fn test_validate_unknown_type_strict_rejects() {
    let validator = RecordValidator::new().require_lexicon(true);
    let custom = json!({
        "$type": "com.custom.record",
        "data": "test"
    });
    let result = validator.validate(&custom, "com.custom.record");
    assert!(matches!(result, Err(ValidationError::UnknownType(_))));
}
#[test]
fn test_validate_type_mismatch() {
    let validator = RecordValidator::new();
    let record = json!({
        "$type": "app.bsky.feed.like",
        "subject": {"uri": "at://test", "cid": "bafytest"},
        "createdAt": now()
    });
    let result = validator.validate(&record, "app.bsky.feed.post");
    assert!(matches!(result, Err(ValidationError::TypeMismatch { expected, actual })
        if expected == "app.bsky.feed.post" && actual == "app.bsky.feed.like"));
}
#[test]
fn test_validate_missing_type() {
    let validator = RecordValidator::new();
    let record = json!({
        "text": "Hello"
    });
    let result = validator.validate(&record, "app.bsky.feed.post");
    assert!(matches!(result, Err(ValidationError::MissingType)));
}
#[test]
fn test_validate_not_object() {
    let validator = RecordValidator::new();
    let record = json!("just a string");
    let result = validator.validate(&record, "app.bsky.feed.post");
    assert!(matches!(result, Err(ValidationError::InvalidRecord(_))));
}
#[test]
fn test_validate_datetime_format_valid() {
    let validator = RecordValidator::new();
    let post = json!({
        "$type": "app.bsky.feed.post",
        "text": "Test",
        "createdAt": "2024-01-15T10:30:00.000Z"
    });
    let result = validator.validate(&post, "app.bsky.feed.post");
    assert_eq!(result.unwrap(), ValidationStatus::Valid);
}
#[test]
fn test_validate_datetime_with_offset() {
    let validator = RecordValidator::new();
    let post = json!({
        "$type": "app.bsky.feed.post",
        "text": "Test",
        "createdAt": "2024-01-15T10:30:00+05:30"
    });
    let result = validator.validate(&post, "app.bsky.feed.post");
    assert_eq!(result.unwrap(), ValidationStatus::Valid);
}
#[test]
fn test_validate_datetime_invalid_format() {
    let validator = RecordValidator::new();
    let post = json!({
        "$type": "app.bsky.feed.post",
        "text": "Test",
        "createdAt": "2024/01/15"
    });
    let result = validator.validate(&post, "app.bsky.feed.post");
    assert!(matches!(result, Err(ValidationError::InvalidDatetime { .. })));
}
#[test]
fn test_validate_record_key_valid() {
    assert!(validate_record_key("3k2n5j2").is_ok());
    assert!(validate_record_key("valid-key").is_ok());
    assert!(validate_record_key("valid_key").is_ok());
    assert!(validate_record_key("valid.key").is_ok());
    assert!(validate_record_key("valid~key").is_ok());
    assert!(validate_record_key("self").is_ok());
}
#[test]
fn test_validate_record_key_empty() {
    let result = validate_record_key("");
    assert!(matches!(result, Err(ValidationError::InvalidRecord(_))));
}
#[test]
fn test_validate_record_key_dot() {
    assert!(validate_record_key(".").is_err());
    assert!(validate_record_key("..").is_err());
}
#[test]
fn test_validate_record_key_invalid_chars() {
    assert!(validate_record_key("invalid/key").is_err());
    assert!(validate_record_key("invalid key").is_err());
    assert!(validate_record_key("invalid@key").is_err());
    assert!(validate_record_key("invalid#key").is_err());
}
#[test]
fn test_validate_record_key_too_long() {
    let long_key = "k".repeat(513);
    let result = validate_record_key(&long_key);
    assert!(matches!(result, Err(ValidationError::InvalidRecord(_))));
}
#[test]
fn test_validate_record_key_at_max_length() {
    let max_key = "k".repeat(512);
    assert!(validate_record_key(&max_key).is_ok());
}
#[test]
fn test_validate_collection_nsid_valid() {
    assert!(validate_collection_nsid("app.bsky.feed.post").is_ok());
    assert!(validate_collection_nsid("com.atproto.repo.record").is_ok());
    assert!(validate_collection_nsid("a.b.c").is_ok());
    assert!(validate_collection_nsid("my-app.domain.record-type").is_ok());
}
#[test]
fn test_validate_collection_nsid_empty() {
    let result = validate_collection_nsid("");
    assert!(matches!(result, Err(ValidationError::InvalidRecord(_))));
}
#[test]
fn test_validate_collection_nsid_too_few_segments() {
    assert!(validate_collection_nsid("a").is_err());
    assert!(validate_collection_nsid("a.b").is_err());
}
#[test]
fn test_validate_collection_nsid_empty_segment() {
    assert!(validate_collection_nsid("a..b.c").is_err());
    assert!(validate_collection_nsid(".a.b.c").is_err());
    assert!(validate_collection_nsid("a.b.c.").is_err());
}
#[test]
fn test_validate_collection_nsid_invalid_chars() {
    assert!(validate_collection_nsid("a.b.c/d").is_err());
    assert!(validate_collection_nsid("a.b.c_d").is_err());
    assert!(validate_collection_nsid("a.b.c@d").is_err());
}
#[test]
fn test_validate_threadgate() {
    let validator = RecordValidator::new();
    let gate = json!({
        "$type": "app.bsky.feed.threadgate",
        "post": "at://did:plc:test/app.bsky.feed.post/123",
        "createdAt": now()
    });
    let result = validator.validate(&gate, "app.bsky.feed.threadgate");
    assert_eq!(result.unwrap(), ValidationStatus::Valid);
}
#[test]
fn test_validate_labeler_service() {
    let validator = RecordValidator::new();
    let labeler = json!({
        "$type": "app.bsky.labeler.service",
        "policies": {
            "labelValues": ["spam", "nsfw"]
        },
        "createdAt": now()
    });
    let result = validator.validate(&labeler, "app.bsky.labeler.service");
    assert_eq!(result.unwrap(), ValidationStatus::Valid);
}
#[test]
fn test_validate_list_item() {
    let validator = RecordValidator::new();
    let item = json!({
        "$type": "app.bsky.graph.listitem",
        "subject": "did:plc:test123",
        "list": "at://did:plc:owner/app.bsky.graph.list/mylist",
        "createdAt": now()
    });
    let result = validator.validate(&item, "app.bsky.graph.listitem");
    assert_eq!(result.unwrap(), ValidationStatus::Valid);
}
