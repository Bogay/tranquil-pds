use serde_json::Value;
use thiserror::Error;
use tranquil_lexicon::LexValidationError;

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
    #[error("Unacceptable slur in record at {path}")]
    BannedContent { path: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ValidationStatus {
    Valid,
    Unknown,
    Invalid,
}

impl std::fmt::Display for ValidationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Valid => write!(f, "valid"),
            Self::Unknown => write!(f, "unknown"),
            Self::Invalid => write!(f, "invalid"),
        }
    }
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
        self.validate_with_rkey(record, collection, None)
    }

    pub fn validate_with_rkey(
        &self,
        record: &Value,
        collection: &str,
        rkey: Option<&str>,
    ) -> Result<ValidationStatus, ValidationError> {
        let (record_type, obj) = validate_preamble(record, collection)?;
        let registry = tranquil_lexicon::LexiconRegistry::global();

        match tranquil_lexicon::validate_record(registry, record_type, record) {
            Ok(()) => {
                check_banned_content(record_type, obj, rkey)?;
                Ok(ValidationStatus::Valid)
            }
            Err(LexValidationError::LexiconNotFound(_)) => {
                if self.require_lexicon {
                    Err(ValidationError::UnknownType(record_type.to_string()))
                } else {
                    check_banned_content(record_type, obj, rkey)?;
                    Ok(ValidationStatus::Unknown)
                }
            }
            Err(LexValidationError::MissingRequired { path }) => {
                Err(ValidationError::MissingField(path))
            }
            Err(LexValidationError::InvalidField { path, message }) => {
                Err(ValidationError::InvalidField { path, message })
            }
            Err(LexValidationError::RecursionDepthExceeded { path }) => {
                Err(ValidationError::InvalidField {
                    path,
                    message: "recursion depth exceeded".to_string(),
                })
            }
        }
    }
}

fn validate_preamble<'a>(
    record: &'a Value,
    collection: &str,
) -> Result<(&'a str, &'a serde_json::Map<String, Value>), ValidationError> {
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
    Ok((record_type, obj))
}

fn check_banned_content(
    record_type: &str,
    obj: &serde_json::Map<String, Value>,
    rkey: Option<&str>,
) -> Result<(), ValidationError> {
    match record_type {
        "app.bsky.feed.post" => {
            check_post_banned_content(obj)?;
        }
        "app.bsky.actor.profile" => {
            check_string_field(obj, "displayName")?;
            check_string_field(obj, "description")?;
        }
        "app.bsky.graph.list" => {
            check_string_field(obj, "name")?;
        }
        "app.bsky.graph.starterpack" => {
            check_string_field(obj, "name")?;
            check_string_field(obj, "description")?;
        }
        "app.bsky.feed.generator" => {
            if let Some(rkey) = rkey
                && crate::moderation::has_explicit_slur(rkey)
            {
                return Err(ValidationError::BannedContent {
                    path: "rkey".to_string(),
                });
            }
            check_string_field(obj, "displayName")?;
        }
        _ => {}
    }
    Ok(())
}

fn check_post_banned_content(obj: &serde_json::Map<String, Value>) -> Result<(), ValidationError> {
    if let Some(tags) = obj.get("tags").and_then(|v| v.as_array()) {
        tags.iter().enumerate().try_for_each(|(i, tag)| {
            if let Some(tag_str) = tag.as_str()
                && crate::moderation::has_explicit_slur(tag_str)
            {
                return Err(ValidationError::BannedContent {
                    path: format!("tags/{}", i),
                });
            }
            Ok(())
        })?;
    }
    if let Some(facets) = obj.get("facets").and_then(|v| v.as_array()) {
        facets.iter().enumerate().try_for_each(|(i, facet)| {
            if let Some(features) = facet.get("features").and_then(|v| v.as_array()) {
                features.iter().enumerate().try_for_each(|(j, feature)| {
                    let is_tag = feature
                        .get("$type")
                        .and_then(|v| v.as_str())
                        .is_some_and(|t| t == "app.bsky.richtext.facet#tag");
                    if is_tag
                        && let Some(tag) = feature.get("tag").and_then(|v| v.as_str())
                        && crate::moderation::has_explicit_slur(tag)
                    {
                        return Err(ValidationError::BannedContent {
                            path: format!("facets/{}/features/{}/tag", i, j),
                        });
                    }
                    Ok(())
                })?;
            }
            Ok(())
        })?;
    }
    Ok(())
}

fn check_string_field(
    obj: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<(), ValidationError> {
    if let Some(value) = obj.get(field).and_then(|v| v.as_str())
        && crate::moderation::has_explicit_slur(value)
    {
        return Err(ValidationError::BannedContent {
            path: field.to_string(),
        });
    }
    Ok(())
}

fn validate_datetime(value: &str, path: &str) -> Result<(), ValidationError> {
    if !tranquil_lexicon::is_valid_datetime(value) {
        return Err(ValidationError::InvalidDatetime {
            path: path.to_string(),
        });
    }
    Ok(())
}

pub fn validate_record_key(rkey: &str) -> Result<(), ValidationError> {
    if !tranquil_lexicon::is_valid_record_key(rkey) {
        return Err(ValidationError::InvalidRecord(format!(
            "Invalid record key: '{}'",
            rkey
        )));
    }
    Ok(())
}

pub fn validate_collection_nsid(collection: &str) -> Result<(), ValidationError> {
    if !tranquil_lexicon::is_valid_nsid(collection) {
        return Err(ValidationError::InvalidRecord(format!(
            "Invalid collection NSID: '{}'",
            collection
        )));
    }
    Ok(())
}

#[derive(Debug)]
pub struct PasswordValidationError {
    pub errors: Vec<String>,
}

impl std::fmt::Display for PasswordValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.errors.join("; "))
    }
}

impl std::error::Error for PasswordValidationError {}

pub fn validate_password(password: &str) -> Result<(), PasswordValidationError> {
    let errors: Vec<&'static str> = [
        (password.len() < 8).then_some("Password must be at least 8 characters"),
        (password.len() > 256).then_some("Password must be at most 256 characters"),
        (!password.chars().any(|c| c.is_ascii_lowercase()))
            .then_some("Password must contain at least one lowercase letter"),
        (!password.chars().any(|c| c.is_ascii_uppercase()))
            .then_some("Password must contain at least one uppercase letter"),
        (!password.chars().any(|c| c.is_ascii_digit()))
            .then_some("Password must contain at least one number"),
        is_common_password(password)
            .then_some("Password is too common, please choose a different one"),
    ]
    .into_iter()
    .flatten()
    .collect();

    if errors.is_empty() {
        Ok(())
    } else {
        Err(PasswordValidationError {
            errors: errors.iter().map(|s| (*s).to_string()).collect(),
        })
    }
}

fn is_common_password(password: &str) -> bool {
    const COMMON_PASSWORDS: &[&str] = &[
        "password",
        "Password1",
        "Password123",
        "Passw0rd",
        "Passw0rd!",
        "12345678",
        "123456789",
        "1234567890",
        "qwerty123",
        "Qwerty123",
        "qwertyui",
        "Qwertyui",
        "letmein1",
        "Letmein1",
        "welcome1",
        "Welcome1",
        "admin123",
        "Admin123",
        "password1",
        "Password1!",
        "iloveyou",
        "Iloveyou1",
        "monkey123",
        "Monkey123",
        "dragon12",
        "Dragon123",
        "master12",
        "Master123",
        "login123",
        "Login123",
        "abc12345",
        "Abc12345",
        "football",
        "Football1",
        "baseball",
        "Baseball1",
        "trustno1",
        "Trustno1",
        "sunshine",
        "Sunshine1",
        "princess",
        "Princess1",
        "computer",
        "Computer1",
        "whatever",
        "Whatever1",
        "nintendo",
        "Nintendo1",
        "bluesky1",
        "Bluesky1",
        "Bluesky123",
    ];

    let lower = password.to_lowercase();
    COMMON_PASSWORDS.iter().any(|p| p.to_lowercase() == lower)
}
