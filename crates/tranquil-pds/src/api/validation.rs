use crate::types::Handle;

pub const MAX_DOMAIN_LABEL_LENGTH: usize = 63;

pub const MIN_HANDLE_LENGTH: usize = 3;
pub const MAX_HANDLE_LENGTH: usize = 253;
pub const MAX_SERVICE_HANDLE_LOCAL_PART: usize = 18;

#[derive(Debug, PartialEq)]
pub enum HandleValidationError {
    Empty,
    TooShort,
    TooLong { max: usize },
    InvalidCharacters,
    StartsWithInvalidChar,
    EndsWithInvalidChar,
    ContainsSpaces,
    BannedWord,
    Reserved,
    InvalidSyntax,
    DisallowedTld,
    UnusableHandleDomain,
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
            Self::TooLong { max } => {
                write!(f, "Handle exceeds maximum length of {} characters", max)
            }
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
            Self::InvalidSyntax => write!(f, "Handle does not match atproto handle syntax"),
            Self::DisallowedTld => write!(f, "Handle uses a reserved TLD and cannot resolve"),
            Self::UnusableHandleDomain => write!(
                f,
                "This server's handle domain has a reserved TLD, so no handle under it is a valid atproto handle"
            ),
        }
    }
}

impl std::error::Error for HandleValidationError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservedHandlePolicy {
    Allow,
    Reject,
}

pub fn validate_full_domain_handle(handle: &str) -> Result<Handle, HandleValidationError> {
    let handle = handle.trim();

    if handle.is_empty() {
        return Err(HandleValidationError::Empty);
    }

    if handle.contains(' ') || handle.contains('\t') || handle.contains('\n') {
        return Err(HandleValidationError::ContainsSpaces);
    }

    if handle.len() > MAX_HANDLE_LENGTH {
        return Err(HandleValidationError::TooLong {
            max: MAX_HANDLE_LENGTH,
        });
    }

    if handle
        .chars()
        .any(|c| !c.is_ascii_alphanumeric() && c != '.' && c != '-')
    {
        return Err(HandleValidationError::InvalidCharacters);
    }

    if !handle.contains('.') {
        return Err(HandleValidationError::InvalidCharacters);
    }

    let labels: Vec<&str> = handle.split('.').collect();
    let has_invalid_label = labels.iter().any(|label| {
        label.is_empty()
            || label.len() > MAX_DOMAIN_LABEL_LENGTH
            || label.starts_with('-')
            || label.ends_with('-')
    });
    if has_invalid_label {
        return Err(HandleValidationError::InvalidCharacters);
    }

    let handle_lower = handle.to_lowercase();

    if crate::moderation::has_explicit_slur(&handle_lower) {
        return Err(HandleValidationError::BannedWord);
    }

    let handle = Handle::new(handle_lower).map_err(|_| HandleValidationError::InvalidSyntax)?;
    match handle.has_disallowed_tld() {
        true => Err(HandleValidationError::DisallowedTld),
        false => Ok(handle),
    }
}

pub fn validate_short_handle(handle: &str) -> Result<String, HandleValidationError> {
    validate_service_handle(handle, ReservedHandlePolicy::Reject)
}

pub fn resolve_handle_input(input: &str) -> Result<Handle, HandleValidationError> {
    let domains = crate::handle::ServiceDomains::for_user_handles();
    let split = domains.split_handle(input);

    if !input.contains('.') || split.is_some() {
        let (short, domain) = split
            .map(|(domain, short)| (short, domain))
            .unwrap_or((input, domains.primary()));
        let validated = validate_short_handle(short)?;
        let handle = Handle::new(format!("{}.{}", validated, domain))
            .map_err(|_| HandleValidationError::InvalidSyntax)?;
        match handle.has_disallowed_tld() {
            true => Err(HandleValidationError::UnusableHandleDomain),
            false => Ok(handle),
        }
    } else {
        validate_full_domain_handle(input)
    }
}

pub fn domain_forms_valid_handles(domain: &str) -> bool {
    Handle::new(format!("whelk.{domain}")).is_ok_and(|h| !h.has_disallowed_tld())
}

pub fn warn_unusable_handle_domains() {
    crate::handle::ServiceDomains::for_user_handles()
        .iter()
        .filter(|domain| !domain_forms_valid_handles(domain.as_str()))
        .for_each(|domain| {
            tracing::error!(
                domain = %domain,
                "configured handle domain can't form a valid atproto handle, so every account \
                 creation under it will be rejected. Set server.user_handle_domains to a domain \
                 whose TLD isn't reserved."
            );
        });
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
        return Err(HandleValidationError::TooLong {
            max: MAX_SERVICE_HANDLE_LOCAL_PART,
        });
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
    fn full_domain_handles_with_reserved_tlds_are_rejected() {
        assert!(validate_full_domain_handle("whelk.oyster.cafe").is_ok());
        assert_eq!(
            validate_full_domain_handle("whelk.pds.internal"),
            Err(HandleValidationError::DisallowedTld)
        );
        assert_eq!(
            validate_full_domain_handle("handle.invalid"),
            Err(HandleValidationError::DisallowedTld)
        );
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
            Err(HandleValidationError::TooLong {
                max: MAX_SERVICE_HANDLE_LOCAL_PART
            })
        );
        assert_eq!(
            validate_short_handle("waytoolongusername123456789"),
            Err(HandleValidationError::TooLong {
                max: MAX_SERVICE_HANDLE_LOCAL_PART
            })
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
}
