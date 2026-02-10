use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::Deref;

pub const MAX_EMAIL_LENGTH: usize = 254;
pub const MAX_LOCAL_PART_LENGTH: usize = 64;
pub const MAX_DOMAIN_LENGTH: usize = 253;
pub const MAX_DOMAIN_LABEL_LENGTH: usize = 63;
const EMAIL_LOCAL_SPECIAL_CHARS: &str = ".!#$%&'*+/=?^_`{|}~-";

pub const MIN_HANDLE_LENGTH: usize = 3;
pub const MAX_HANDLE_LENGTH: usize = 253;
pub const MAX_SERVICE_HANDLE_LOCAL_PART: usize = 18;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ValidatedLocalHandle(String);

impl ValidatedLocalHandle {
    pub fn new(handle: impl AsRef<str>) -> Result<Self, HandleValidationError> {
        let validated = validate_short_handle(handle.as_ref())?;
        Ok(Self(validated))
    }

    pub fn new_allow_reserved(handle: impl AsRef<str>) -> Result<Self, HandleValidationError> {
        let validated = validate_service_handle(handle.as_ref(), ReservedHandlePolicy::Allow)?;
        Ok(Self(validated))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl Deref for ValidatedLocalHandle {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for ValidatedLocalHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<String> for ValidatedLocalHandle {
    type Error = HandleValidationError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ValidatedLocalHandle> for String {
    fn from(handle: ValidatedLocalHandle) -> Self {
        handle.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmailValidationError {
    Empty,
    TooLong,
    MissingAtSign,
    EmptyLocalPart,
    LocalPartTooLong,
    InvalidLocalPart,
    EmptyDomain,
    DomainTooLong,
    MissingDomainDot,
    InvalidDomainLabel,
}

impl fmt::Display for EmailValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "Email cannot be empty"),
            Self::TooLong => write!(
                f,
                "Email exceeds maximum length of {} characters",
                MAX_EMAIL_LENGTH
            ),
            Self::MissingAtSign => write!(f, "Email must contain @"),
            Self::EmptyLocalPart => write!(f, "Email local part cannot be empty"),
            Self::LocalPartTooLong => write!(f, "Email local part exceeds maximum length"),
            Self::InvalidLocalPart => write!(f, "Email local part contains invalid characters"),
            Self::EmptyDomain => write!(f, "Email domain cannot be empty"),
            Self::DomainTooLong => write!(f, "Email domain exceeds maximum length"),
            Self::MissingDomainDot => write!(f, "Email domain must contain a dot"),
            Self::InvalidDomainLabel => write!(f, "Email domain contains invalid label"),
        }
    }
}

impl std::error::Error for EmailValidationError {}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ValidatedEmail(String);

impl ValidatedEmail {
    pub fn new(email: impl AsRef<str>) -> Result<Self, EmailValidationError> {
        let email = email.as_ref().trim();
        validate_email_detailed(email)?;
        Ok(Self(email.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }

    pub fn local_part(&self) -> &str {
        self.0
            .rsplit_once('@')
            .map(|(local, _)| local)
            .unwrap_or("")
    }

    pub fn domain(&self) -> &str {
        self.0
            .rsplit_once('@')
            .map(|(_, domain)| domain)
            .unwrap_or("")
    }
}

impl Deref for ValidatedEmail {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for ValidatedEmail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<String> for ValidatedEmail {
    type Error = EmailValidationError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ValidatedEmail> for String {
    fn from(email: ValidatedEmail) -> Self {
        email.0
    }
}

fn validate_email_detailed(email: &str) -> Result<(), EmailValidationError> {
    if email.is_empty() {
        return Err(EmailValidationError::Empty);
    }
    if email.len() > MAX_EMAIL_LENGTH {
        return Err(EmailValidationError::TooLong);
    }
    let parts: Vec<&str> = email.rsplitn(2, '@').collect();
    if parts.len() != 2 {
        return Err(EmailValidationError::MissingAtSign);
    }
    let domain = parts[0];
    let local = parts[1];
    if local.is_empty() {
        return Err(EmailValidationError::EmptyLocalPart);
    }
    if local.len() > MAX_LOCAL_PART_LENGTH {
        return Err(EmailValidationError::LocalPartTooLong);
    }
    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return Err(EmailValidationError::InvalidLocalPart);
    }
    if !local
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || EMAIL_LOCAL_SPECIAL_CHARS.contains(c))
    {
        return Err(EmailValidationError::InvalidLocalPart);
    }
    if domain.is_empty() {
        return Err(EmailValidationError::EmptyDomain);
    }
    if domain.len() > MAX_DOMAIN_LENGTH {
        return Err(EmailValidationError::DomainTooLong);
    }
    if !domain.contains('.') {
        return Err(EmailValidationError::MissingDomainDot);
    }
    if !domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= MAX_DOMAIN_LABEL_LENGTH
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    }) {
        return Err(EmailValidationError::InvalidDomainLabel);
    }
    Ok(())
}

#[derive(Debug, PartialEq)]
pub enum HandleValidationError {
    Empty,
    TooShort,
    TooLong,
    InvalidCharacters,
    StartsWithInvalidChar,
    EndsWithInvalidChar,
    ContainsSpaces,
    BannedWord,
    Reserved,
}

impl std::fmt::Display for HandleValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "Handle cannot be empty"),
            Self::TooShort => write!(
                f,
                "Handle must be at least {} characters",
                MIN_HANDLE_LENGTH
            ),
            Self::TooLong => write!(
                f,
                "Handle exceeds maximum length of {} characters",
                MAX_SERVICE_HANDLE_LOCAL_PART
            ),
            Self::InvalidCharacters => write!(
                f,
                "Handle contains invalid characters. Only alphanumeric characters and hyphens are allowed"
            ),
            Self::StartsWithInvalidChar => {
                write!(f, "Handle cannot start with a hyphen")
            }
            Self::EndsWithInvalidChar => write!(f, "Handle cannot end with a hyphen"),
            Self::ContainsSpaces => write!(f, "Handle cannot contain spaces"),
            Self::BannedWord => write!(f, "Inappropriate language in handle"),
            Self::Reserved => write!(f, "Reserved handle"),
        }
    }
}

impl std::error::Error for HandleValidationError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservedHandlePolicy {
    Allow,
    Reject,
}

pub fn validate_short_handle(handle: &str) -> Result<String, HandleValidationError> {
    validate_service_handle(handle, ReservedHandlePolicy::Reject)
}

pub fn validate_service_handle(
    handle: &str,
    reserved_policy: ReservedHandlePolicy,
) -> Result<String, HandleValidationError> {
    let handle = handle.trim();

    if handle.is_empty() {
        return Err(HandleValidationError::Empty);
    }

    if handle.contains(' ') || handle.contains('\t') || handle.contains('\n') {
        return Err(HandleValidationError::ContainsSpaces);
    }

    if handle.len() < MIN_HANDLE_LENGTH {
        return Err(HandleValidationError::TooShort);
    }

    if handle.len() > MAX_SERVICE_HANDLE_LOCAL_PART {
        return Err(HandleValidationError::TooLong);
    }

    if let Some(first_char) = handle.chars().next()
        && first_char == '-'
    {
        return Err(HandleValidationError::StartsWithInvalidChar);
    }

    if let Some(last_char) = handle.chars().last()
        && last_char == '-'
    {
        return Err(HandleValidationError::EndsWithInvalidChar);
    }

    if !handle
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(HandleValidationError::InvalidCharacters);
    }

    if crate::moderation::has_explicit_slur(handle) {
        return Err(HandleValidationError::BannedWord);
    }

    if reserved_policy == ReservedHandlePolicy::Reject
        && crate::handle::reserved::is_reserved_subdomain(handle)
    {
        return Err(HandleValidationError::Reserved);
    }

    Ok(handle.to_lowercase())
}

pub fn is_valid_email(email: &str) -> bool {
    let email = email.trim();
    if email.is_empty() || email.len() > MAX_EMAIL_LENGTH {
        return false;
    }
    let parts: Vec<&str> = email.rsplitn(2, '@').collect();
    if parts.len() != 2 {
        return false;
    }
    let domain = parts[0];
    let local = parts[1];
    if local.is_empty() || local.len() > MAX_LOCAL_PART_LENGTH {
        return false;
    }
    if local.starts_with('.') || local.ends_with('.') {
        return false;
    }
    if local.contains("..") {
        return false;
    }
    if !local
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || EMAIL_LOCAL_SPECIAL_CHARS.contains(c))
    {
        return false;
    }
    if domain.is_empty() || domain.len() > MAX_DOMAIN_LENGTH {
        return false;
    }
    if !domain.contains('.') {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= MAX_DOMAIN_LABEL_LENGTH
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

pub fn is_valid_telegram_username(username: &str) -> bool {
    let clean = username.strip_prefix('@').unwrap_or(username);
    (5..=32).contains(&clean.len()) && clean.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub fn is_valid_discord_username(username: &str) -> bool {
    (2..=32).contains(&username.len())
        && username
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.')
        && !username.starts_with('.')
        && !username.ends_with('.')
        && !username.contains("..")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_handles() {
        assert_eq!(validate_short_handle("alice"), Ok("alice".to_string()));
        assert_eq!(validate_short_handle("bob123"), Ok("bob123".to_string()));
        assert_eq!(
            validate_short_handle("user-name"),
            Ok("user-name".to_string())
        );
        assert_eq!(
            validate_short_handle("UPPERCASE"),
            Ok("uppercase".to_string())
        );
        assert_eq!(
            validate_short_handle("MixedCase123"),
            Ok("mixedcase123".to_string())
        );
        assert_eq!(validate_short_handle("abc"), Ok("abc".to_string()));
    }

    #[test]
    fn test_invalid_handles() {
        assert_eq!(validate_short_handle(""), Err(HandleValidationError::Empty));
        assert_eq!(
            validate_short_handle("   "),
            Err(HandleValidationError::Empty)
        );
        assert_eq!(
            validate_short_handle("ab"),
            Err(HandleValidationError::TooShort)
        );
        assert_eq!(
            validate_short_handle("a"),
            Err(HandleValidationError::TooShort)
        );
        assert_eq!(
            validate_short_handle("test spaces"),
            Err(HandleValidationError::ContainsSpaces)
        );
        assert_eq!(
            validate_short_handle("test\ttab"),
            Err(HandleValidationError::ContainsSpaces)
        );
        assert_eq!(
            validate_short_handle("-starts"),
            Err(HandleValidationError::StartsWithInvalidChar)
        );
        assert_eq!(
            validate_short_handle("_starts"),
            Err(HandleValidationError::InvalidCharacters)
        );
        assert_eq!(
            validate_short_handle("ends-"),
            Err(HandleValidationError::EndsWithInvalidChar)
        );
        assert_eq!(
            validate_short_handle("ends_"),
            Err(HandleValidationError::InvalidCharacters)
        );
        assert_eq!(
            validate_short_handle("user_name"),
            Err(HandleValidationError::InvalidCharacters)
        );
        assert_eq!(
            validate_short_handle("test@user"),
            Err(HandleValidationError::InvalidCharacters)
        );
        assert_eq!(
            validate_short_handle("test!user"),
            Err(HandleValidationError::InvalidCharacters)
        );
        assert_eq!(
            validate_short_handle("test.user"),
            Err(HandleValidationError::InvalidCharacters)
        );
    }

    #[test]
    fn test_handle_trimming() {
        assert_eq!(validate_short_handle("  alice  "), Ok("alice".to_string()));
    }

    #[test]
    fn test_handle_max_length() {
        assert_eq!(
            validate_short_handle("exactly18charslol"),
            Ok("exactly18charslol".to_string())
        );
        assert_eq!(
            validate_short_handle("exactly18charslol1"),
            Ok("exactly18charslol1".to_string())
        );
        assert_eq!(
            validate_short_handle("exactly19characters"),
            Err(HandleValidationError::TooLong)
        );
        assert_eq!(
            validate_short_handle("waytoolongusername123456789"),
            Err(HandleValidationError::TooLong)
        );
    }

    #[test]
    fn test_reserved_subdomains() {
        assert_eq!(
            validate_short_handle("admin"),
            Err(HandleValidationError::Reserved)
        );
        assert_eq!(
            validate_short_handle("api"),
            Err(HandleValidationError::Reserved)
        );
        assert_eq!(
            validate_short_handle("bsky"),
            Err(HandleValidationError::Reserved)
        );
        assert_eq!(
            validate_short_handle("barackobama"),
            Err(HandleValidationError::Reserved)
        );
        assert_eq!(
            validate_short_handle("ADMIN"),
            Err(HandleValidationError::Reserved)
        );
        assert_eq!(validate_short_handle("alice"), Ok("alice".to_string()));
        assert_eq!(
            validate_short_handle("notreserved"),
            Ok("notreserved".to_string())
        );
    }

    #[test]
    fn test_allow_reserved() {
        assert_eq!(
            validate_service_handle("admin", ReservedHandlePolicy::Allow),
            Ok("admin".to_string())
        );
        assert_eq!(
            validate_service_handle("api", ReservedHandlePolicy::Allow),
            Ok("api".to_string())
        );
        assert_eq!(
            validate_service_handle("admin", ReservedHandlePolicy::Reject),
            Err(HandleValidationError::Reserved)
        );
    }

    #[test]
    fn test_valid_emails() {
        assert!(is_valid_email("user@example.com"));
        assert!(is_valid_email("user.name@example.com"));
        assert!(is_valid_email("user+tag@example.com"));
        assert!(is_valid_email("user@sub.example.com"));
        assert!(is_valid_email("USER@EXAMPLE.COM"));
        assert!(is_valid_email("user123@example123.com"));
        assert!(is_valid_email("a@b.co"));
    }
    #[test]
    fn test_invalid_emails() {
        assert!(!is_valid_email(""));
        assert!(!is_valid_email("user"));
        assert!(!is_valid_email("user@"));
        assert!(!is_valid_email("@example.com"));
        assert!(!is_valid_email("user@example"));
        assert!(!is_valid_email("user@@example.com"));
        assert!(!is_valid_email("user@.example.com"));
        assert!(!is_valid_email("user@example..com"));
        assert!(!is_valid_email(".user@example.com"));
        assert!(!is_valid_email("user.@example.com"));
        assert!(!is_valid_email("user..name@example.com"));
        assert!(!is_valid_email("user@-example.com"));
        assert!(!is_valid_email("user@example-.com"));
    }
    #[test]
    fn test_trimmed_whitespace() {
        assert!(is_valid_email("  user@example.com  "));
    }

    #[test]
    fn test_valid_discord_usernames() {
        assert!(is_valid_discord_username("ab"));
        assert!(is_valid_discord_username("alice"));
        assert!(is_valid_discord_username("user_name"));
        assert!(is_valid_discord_username("user.name"));
        assert!(is_valid_discord_username("user123"));
        assert!(is_valid_discord_username("a_b.c_d"));
        assert!(is_valid_discord_username(
            "12345678901234567890123456789012"
        ));
    }

    #[test]
    fn test_invalid_discord_usernames() {
        assert!(!is_valid_discord_username(""));
        assert!(!is_valid_discord_username("a"));
        assert!(!is_valid_discord_username("Alice"));
        assert!(!is_valid_discord_username("ALICE"));
        assert!(!is_valid_discord_username("user-name"));
        assert!(!is_valid_discord_username(".username"));
        assert!(!is_valid_discord_username("username."));
        assert!(!is_valid_discord_username("user..name"));
        assert!(!is_valid_discord_username("user name"));
        assert!(!is_valid_discord_username(
            "123456789012345678901234567890123"
        ));
    }
}
