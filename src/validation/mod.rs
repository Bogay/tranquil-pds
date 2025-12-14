use serde_json::Value;
use thiserror::Error;
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("No $type provided")]
    MissingType,
    #[error("Invalid $type: expected {expected}, got {actual}")]
    TypeMismatch { expected: String, actual: String },
    #[error("Missing required field: {0}")]
    MissingField(String),
    #[error("Invalid field value at {path}: {message}")]
    InvalidField { path: String, message: String },
    #[error("Invalid datetime format at {path}: must be RFC-3339/ISO-8601")]
    InvalidDatetime { path: String },
    #[error("Invalid record: {0}")]
    InvalidRecord(String),
    #[error("Unknown record type: {0}")]
    UnknownType(String),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationStatus {
    Valid,
    Unknown,
    Invalid,
}
pub struct RecordValidator {
    require_lexicon: bool,
}
impl Default for RecordValidator {
    fn default() -> Self {
        Self::new()
    }
}
impl RecordValidator {
    pub fn new() -> Self {
        Self {
            require_lexicon: false,
        }
    }
    pub fn require_lexicon(mut self, require: bool) -> Self {
        self.require_lexicon = require;
        self
    }
    pub fn validate(
        &self,
        record: &Value,
        collection: &str,
    ) -> Result<ValidationStatus, ValidationError> {
        let obj = record
            .as_object()
            .ok_or_else(|| ValidationError::InvalidRecord("Record must be an object".to_string()))?;
        let record_type = obj
            .get("$type")
            .and_then(|v| v.as_str())
            .ok_or(ValidationError::MissingType)?;
        if record_type != collection {
            return Err(ValidationError::TypeMismatch {
                expected: collection.to_string(),
                actual: record_type.to_string(),
            });
        }
        if let Some(created_at) = obj.get("createdAt").and_then(|v| v.as_str()) {
            validate_datetime(created_at, "createdAt")?;
        }
        match record_type {
            "app.bsky.feed.post" => self.validate_post(obj)?,
            "app.bsky.actor.profile" => self.validate_profile(obj)?,
            "app.bsky.feed.like" => self.validate_like(obj)?,
            "app.bsky.feed.repost" => self.validate_repost(obj)?,
            "app.bsky.graph.follow" => self.validate_follow(obj)?,
            "app.bsky.graph.block" => self.validate_block(obj)?,
            "app.bsky.graph.list" => self.validate_list(obj)?,
            "app.bsky.graph.listitem" => self.validate_list_item(obj)?,
            "app.bsky.feed.generator" => self.validate_feed_generator(obj)?,
            "app.bsky.feed.threadgate" => self.validate_threadgate(obj)?,
            "app.bsky.labeler.service" => self.validate_labeler_service(obj)?,
            _ => {
                if self.require_lexicon {
                    return Err(ValidationError::UnknownType(record_type.to_string()));
                }
                return Ok(ValidationStatus::Unknown);
            }
        }
        Ok(ValidationStatus::Valid)
    }
    fn validate_post(&self, obj: &serde_json::Map<String, Value>) -> Result<(), ValidationError> {
        if !obj.contains_key("text") {
            return Err(ValidationError::MissingField("text".to_string()));
        }
        if !obj.contains_key("createdAt") {
            return Err(ValidationError::MissingField("createdAt".to_string()));
        }
        if let Some(text) = obj.get("text").and_then(|v| v.as_str()) {
            let grapheme_count = text.chars().count();
            if grapheme_count > 3000 {
                return Err(ValidationError::InvalidField {
                    path: "text".to_string(),
                    message: format!("Text exceeds maximum length of 3000 characters (got {})", grapheme_count),
                });
            }
        }
        if let Some(langs) = obj.get("langs").and_then(|v| v.as_array()) {
            if langs.len() > 3 {
                return Err(ValidationError::InvalidField {
                    path: "langs".to_string(),
                    message: "Maximum 3 languages allowed".to_string(),
                });
            }
        }
        if let Some(tags) = obj.get("tags").and_then(|v| v.as_array()) {
            if tags.len() > 8 {
                return Err(ValidationError::InvalidField {
                    path: "tags".to_string(),
                    message: "Maximum 8 tags allowed".to_string(),
                });
            }
            for (i, tag) in tags.iter().enumerate() {
                if let Some(tag_str) = tag.as_str() {
                    if tag_str.len() > 640 {
                        return Err(ValidationError::InvalidField {
                            path: format!("tags/{}", i),
                            message: "Tag exceeds maximum length of 640 bytes".to_string(),
                        });
                    }
                }
            }
        }
        Ok(())
    }
    fn validate_profile(&self, obj: &serde_json::Map<String, Value>) -> Result<(), ValidationError> {
        if let Some(display_name) = obj.get("displayName").and_then(|v| v.as_str()) {
            let grapheme_count = display_name.chars().count();
            if grapheme_count > 640 {
                return Err(ValidationError::InvalidField {
                    path: "displayName".to_string(),
                    message: format!("Display name exceeds maximum length of 640 characters (got {})", grapheme_count),
                });
            }
        }
        if let Some(description) = obj.get("description").and_then(|v| v.as_str()) {
            let grapheme_count = description.chars().count();
            if grapheme_count > 2560 {
                return Err(ValidationError::InvalidField {
                    path: "description".to_string(),
                    message: format!("Description exceeds maximum length of 2560 characters (got {})", grapheme_count),
                });
            }
        }
        Ok(())
    }
    fn validate_like(&self, obj: &serde_json::Map<String, Value>) -> Result<(), ValidationError> {
        if !obj.contains_key("subject") {
            return Err(ValidationError::MissingField("subject".to_string()));
        }
        if !obj.contains_key("createdAt") {
            return Err(ValidationError::MissingField("createdAt".to_string()));
        }
        self.validate_strong_ref(obj.get("subject"), "subject")?;
        Ok(())
    }
    fn validate_repost(&self, obj: &serde_json::Map<String, Value>) -> Result<(), ValidationError> {
        if !obj.contains_key("subject") {
            return Err(ValidationError::MissingField("subject".to_string()));
        }
        if !obj.contains_key("createdAt") {
            return Err(ValidationError::MissingField("createdAt".to_string()));
        }
        self.validate_strong_ref(obj.get("subject"), "subject")?;
        Ok(())
    }
    fn validate_follow(&self, obj: &serde_json::Map<String, Value>) -> Result<(), ValidationError> {
        if !obj.contains_key("subject") {
            return Err(ValidationError::MissingField("subject".to_string()));
        }
        if !obj.contains_key("createdAt") {
            return Err(ValidationError::MissingField("createdAt".to_string()));
        }
        if let Some(subject) = obj.get("subject").and_then(|v| v.as_str()) {
            if !subject.starts_with("did:") {
                return Err(ValidationError::InvalidField {
                    path: "subject".to_string(),
                    message: "Subject must be a DID".to_string(),
                });
            }
        }
        Ok(())
    }
    fn validate_block(&self, obj: &serde_json::Map<String, Value>) -> Result<(), ValidationError> {
        if !obj.contains_key("subject") {
            return Err(ValidationError::MissingField("subject".to_string()));
        }
        if !obj.contains_key("createdAt") {
            return Err(ValidationError::MissingField("createdAt".to_string()));
        }
        if let Some(subject) = obj.get("subject").and_then(|v| v.as_str()) {
            if !subject.starts_with("did:") {
                return Err(ValidationError::InvalidField {
                    path: "subject".to_string(),
                    message: "Subject must be a DID".to_string(),
                });
            }
        }
        Ok(())
    }
    fn validate_list(&self, obj: &serde_json::Map<String, Value>) -> Result<(), ValidationError> {
        if !obj.contains_key("name") {
            return Err(ValidationError::MissingField("name".to_string()));
        }
        if !obj.contains_key("purpose") {
            return Err(ValidationError::MissingField("purpose".to_string()));
        }
        if !obj.contains_key("createdAt") {
            return Err(ValidationError::MissingField("createdAt".to_string()));
        }
        if let Some(name) = obj.get("name").and_then(|v| v.as_str()) {
            if name.is_empty() || name.len() > 64 {
                return Err(ValidationError::InvalidField {
                    path: "name".to_string(),
                    message: "Name must be 1-64 characters".to_string(),
                });
            }
        }
        Ok(())
    }
    fn validate_list_item(&self, obj: &serde_json::Map<String, Value>) -> Result<(), ValidationError> {
        if !obj.contains_key("subject") {
            return Err(ValidationError::MissingField("subject".to_string()));
        }
        if !obj.contains_key("list") {
            return Err(ValidationError::MissingField("list".to_string()));
        }
        if !obj.contains_key("createdAt") {
            return Err(ValidationError::MissingField("createdAt".to_string()));
        }
        Ok(())
    }
    fn validate_feed_generator(&self, obj: &serde_json::Map<String, Value>) -> Result<(), ValidationError> {
        if !obj.contains_key("did") {
            return Err(ValidationError::MissingField("did".to_string()));
        }
        if !obj.contains_key("displayName") {
            return Err(ValidationError::MissingField("displayName".to_string()));
        }
        if !obj.contains_key("createdAt") {
            return Err(ValidationError::MissingField("createdAt".to_string()));
        }
        if let Some(display_name) = obj.get("displayName").and_then(|v| v.as_str()) {
            if display_name.is_empty() || display_name.len() > 240 {
                return Err(ValidationError::InvalidField {
                    path: "displayName".to_string(),
                    message: "displayName must be 1-240 characters".to_string(),
                });
            }
        }
        Ok(())
    }
    fn validate_threadgate(&self, obj: &serde_json::Map<String, Value>) -> Result<(), ValidationError> {
        if !obj.contains_key("post") {
            return Err(ValidationError::MissingField("post".to_string()));
        }
        if !obj.contains_key("createdAt") {
            return Err(ValidationError::MissingField("createdAt".to_string()));
        }
        Ok(())
    }
    fn validate_labeler_service(&self, obj: &serde_json::Map<String, Value>) -> Result<(), ValidationError> {
        if !obj.contains_key("policies") {
            return Err(ValidationError::MissingField("policies".to_string()));
        }
        if !obj.contains_key("createdAt") {
            return Err(ValidationError::MissingField("createdAt".to_string()));
        }
        Ok(())
    }
    fn validate_strong_ref(&self, value: Option<&Value>, path: &str) -> Result<(), ValidationError> {
        let obj = value
            .and_then(|v| v.as_object())
            .ok_or_else(|| ValidationError::InvalidField {
                path: path.to_string(),
                message: "Must be a strong reference object".to_string(),
            })?;
        if !obj.contains_key("uri") {
            return Err(ValidationError::MissingField(format!("{}/uri", path)));
        }
        if !obj.contains_key("cid") {
            return Err(ValidationError::MissingField(format!("{}/cid", path)));
        }
        if let Some(uri) = obj.get("uri").and_then(|v| v.as_str()) {
            if !uri.starts_with("at://") {
                return Err(ValidationError::InvalidField {
                    path: format!("{}/uri", path),
                    message: "URI must be an at:// URI".to_string(),
                });
            }
        }
        Ok(())
    }
}
fn validate_datetime(value: &str, path: &str) -> Result<(), ValidationError> {
    if chrono::DateTime::parse_from_rfc3339(value).is_err() {
        return Err(ValidationError::InvalidDatetime {
            path: path.to_string(),
        });
    }
    Ok(())
}
pub fn validate_record_key(rkey: &str) -> Result<(), ValidationError> {
    if rkey.is_empty() {
        return Err(ValidationError::InvalidRecord("Record key cannot be empty".to_string()));
    }
    if rkey.len() > 512 {
        return Err(ValidationError::InvalidRecord("Record key exceeds maximum length of 512".to_string()));
    }
    if rkey == "." || rkey == ".." {
        return Err(ValidationError::InvalidRecord("Record key cannot be '.' or '..'".to_string()));
    }
    let valid_chars = rkey.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' || c == '~'
    });
    if !valid_chars {
        return Err(ValidationError::InvalidRecord(
            "Record key contains invalid characters (must be alphanumeric, '.', '-', '_', or '~')".to_string()
        ));
    }
    Ok(())
}
pub fn validate_collection_nsid(collection: &str) -> Result<(), ValidationError> {
    if collection.is_empty() {
        return Err(ValidationError::InvalidRecord("Collection NSID cannot be empty".to_string()));
    }
    let parts: Vec<&str> = collection.split('.').collect();
    if parts.len() < 3 {
        return Err(ValidationError::InvalidRecord(
            "Collection NSID must have at least 3 segments".to_string()
        ));
    }
    for part in &parts {
        if part.is_empty() {
            return Err(ValidationError::InvalidRecord(
                "Collection NSID segments cannot be empty".to_string()
            ));
        }
        if !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(ValidationError::InvalidRecord(
                "Collection NSID segments must be alphanumeric or hyphens".to_string()
            ));
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn test_validate_post() {
        let validator = RecordValidator::new();
        let valid_post = json!({
            "$type": "app.bsky.feed.post",
            "text": "Hello, world!",
            "createdAt": "2024-01-01T00:00:00.000Z"
        });
        assert_eq!(
            validator.validate(&valid_post, "app.bsky.feed.post").unwrap(),
            ValidationStatus::Valid
        );
    }
    #[test]
    fn test_validate_post_missing_text() {
        let validator = RecordValidator::new();
        let invalid_post = json!({
            "$type": "app.bsky.feed.post",
            "createdAt": "2024-01-01T00:00:00.000Z"
        });
        assert!(validator.validate(&invalid_post, "app.bsky.feed.post").is_err());
    }
    #[test]
    fn test_validate_type_mismatch() {
        let validator = RecordValidator::new();
        let record = json!({
            "$type": "app.bsky.feed.like",
            "subject": {"uri": "at://did:plc:test/app.bsky.feed.post/123", "cid": "bafyrei..."},
            "createdAt": "2024-01-01T00:00:00.000Z"
        });
        let result = validator.validate(&record, "app.bsky.feed.post");
        assert!(matches!(result, Err(ValidationError::TypeMismatch { .. })));
    }
    #[test]
    fn test_validate_unknown_type() {
        let validator = RecordValidator::new();
        let record = json!({
            "$type": "com.example.custom",
            "data": "test"
        });
        assert_eq!(
            validator.validate(&record, "com.example.custom").unwrap(),
            ValidationStatus::Unknown
        );
    }
    #[test]
    fn test_validate_unknown_type_strict() {
        let validator = RecordValidator::new().require_lexicon(true);
        let record = json!({
            "$type": "com.example.custom",
            "data": "test"
        });
        let result = validator.validate(&record, "com.example.custom");
        assert!(matches!(result, Err(ValidationError::UnknownType(_))));
    }
    #[test]
    fn test_validate_record_key() {
        assert!(validate_record_key("valid-key_123").is_ok());
        assert!(validate_record_key("3k2n5j2").is_ok());
        assert!(validate_record_key(".").is_err());
        assert!(validate_record_key("..").is_err());
        assert!(validate_record_key("").is_err());
        assert!(validate_record_key("invalid/key").is_err());
    }
    #[test]
    fn test_validate_collection_nsid() {
        assert!(validate_collection_nsid("app.bsky.feed.post").is_ok());
        assert!(validate_collection_nsid("com.atproto.repo.record").is_ok());
        assert!(validate_collection_nsid("invalid").is_err());
        assert!(validate_collection_nsid("a.b").is_err());
        assert!(validate_collection_nsid("").is_err());
    }
}
