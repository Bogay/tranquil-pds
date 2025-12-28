pub const MAX_EMAIL_LENGTH: usize = 254;
pub const MAX_LOCAL_PART_LENGTH: usize = 64;
pub const MAX_DOMAIN_LENGTH: usize = 253;
pub const MAX_DOMAIN_LABEL_LENGTH: usize = 63;
const EMAIL_LOCAL_SPECIAL_CHARS: &str = ".!#$%&'*+/=?^_`{|}~-";

pub const MIN_HANDLE_LENGTH: usize = 3;
pub const MAX_HANDLE_LENGTH: usize = 253;

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
                MAX_HANDLE_LENGTH
            ),
            Self::InvalidCharacters => write!(
                f,
                "Handle contains invalid characters. Only alphanumeric, hyphens, and underscores are allowed"
            ),
            Self::StartsWithInvalidChar => {
                write!(f, "Handle cannot start with a hyphen or underscore")
            }
            Self::EndsWithInvalidChar => write!(f, "Handle cannot end with a hyphen or underscore"),
            Self::ContainsSpaces => write!(f, "Handle cannot contain spaces"),
            Self::BannedWord => write!(f, "Inappropriate language in handle"),
        }
    }
}

pub fn validate_short_handle(handle: &str) -> Result<String, HandleValidationError> {
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

    if handle.len() > MAX_HANDLE_LENGTH {
        return Err(HandleValidationError::TooLong);
    }

    if let Some(first_char) = handle.chars().next()
        && (first_char == '-' || first_char == '_')
    {
        return Err(HandleValidationError::StartsWithInvalidChar);
    }

    if let Some(last_char) = handle.chars().last()
        && (last_char == '-' || last_char == '_')
    {
        return Err(HandleValidationError::EndsWithInvalidChar);
    }

    for c in handle.chars() {
        if !c.is_ascii_alphanumeric() && c != '-' && c != '_' {
            return Err(HandleValidationError::InvalidCharacters);
        }
    }

    if crate::moderation::has_explicit_slur(handle) {
        return Err(HandleValidationError::BannedWord);
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
    for c in local.chars() {
        if !c.is_ascii_alphanumeric() && !EMAIL_LOCAL_SPECIAL_CHARS.contains(c) {
            return false;
        }
    }
    if domain.is_empty() || domain.len() > MAX_DOMAIN_LENGTH {
        return false;
    }
    if !domain.contains('.') {
        return false;
    }
    for label in domain.split('.') {
        if label.is_empty() || label.len() > MAX_DOMAIN_LABEL_LENGTH {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        for c in label.chars() {
            if !c.is_ascii_alphanumeric() && c != '-' {
                return false;
            }
        }
    }
    true
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
            validate_short_handle("user_name"),
            Ok("user_name".to_string())
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
            Err(HandleValidationError::StartsWithInvalidChar)
        );
        assert_eq!(
            validate_short_handle("ends-"),
            Err(HandleValidationError::EndsWithInvalidChar)
        );
        assert_eq!(
            validate_short_handle("ends_"),
            Err(HandleValidationError::EndsWithInvalidChar)
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
}
