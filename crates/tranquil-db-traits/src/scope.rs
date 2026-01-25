use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbScope(String);

impl DbScope {
    pub fn new(scope: impl Into<String>) -> Result<Self, InvalidScopeError> {
        let scope = scope.into();
        validate_scope_string(&scope)?;
        Ok(Self(scope))
    }

    pub fn empty() -> Self {
        Self(String::new())
    }

    pub fn from_db(scope: String) -> Self {
        match validate_scope_string(&scope) {
            Ok(()) => Self(scope),
            Err(e) => panic!("corrupted scope data from database: {}", e),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Default for DbScope {
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Display for DbScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for DbScope {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Serialize for DbScope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DbScope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::new(s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone)]
pub struct InvalidScopeError {
    message: String,
}

impl InvalidScopeError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for InvalidScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for InvalidScopeError {}

fn validate_scope_string(scopes: &str) -> Result<(), InvalidScopeError> {
    if scopes.is_empty() {
        return Ok(());
    }

    scopes.split_whitespace().try_for_each(|scope| {
        let base = scope.split_once('?').map_or(scope, |(b, _)| b);
        if is_valid_scope_prefix(base) {
            Ok(())
        } else {
            Err(InvalidScopeError::new(format!("Invalid scope: {}", scope)))
        }
    })
}

fn is_valid_scope_prefix(base: &str) -> bool {
    const VALID_PREFIXES: [&str; 8] = [
        "atproto",
        "repo:",
        "blob:",
        "rpc:",
        "account:",
        "identity:",
        "transition:",
        "include:",
    ];

    VALID_PREFIXES
        .iter()
        .any(|prefix| base == prefix.trim_end_matches(':') || base.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_scopes() {
        assert!(DbScope::new("atproto").is_ok());
        assert!(DbScope::new("repo:*").is_ok());
        assert!(DbScope::new("blob:*/*").is_ok());
        assert!(DbScope::new("repo:* blob:*/*").is_ok());
        assert!(DbScope::new("").is_ok());
        assert!(DbScope::new("account:email?action=read").is_ok());
        assert!(DbScope::new("identity:handle").is_ok());
        assert!(DbScope::new("transition:generic").is_ok());
        assert!(DbScope::new("include:app.bsky.authFullApp").is_ok());
    }

    #[test]
    fn test_invalid_scopes() {
        assert!(DbScope::new("invalid:scope").is_err());
        assert!(DbScope::new("garbage").is_err());
        assert!(DbScope::new("repo:* invalid:scope").is_err());
    }

    #[test]
    fn test_empty_scope() {
        let scope = DbScope::empty();
        assert!(scope.is_empty());
        assert_eq!(scope.as_str(), "");
    }

    #[test]
    fn test_display() {
        let scope = DbScope::new("repo:*").unwrap();
        assert_eq!(format!("{}", scope), "repo:*");
    }

    #[test]
    #[should_panic(expected = "corrupted scope data from database")]
    fn test_from_db_panics_on_corrupted_data() {
        DbScope::from_db("totally_invalid_garbage_scope".to_string());
    }

    #[test]
    fn test_from_db_accepts_valid_data() {
        let scope = DbScope::from_db("repo:* blob:*/*".to_string());
        assert_eq!(scope.as_str(), "repo:* blob:*/*");
    }
}
