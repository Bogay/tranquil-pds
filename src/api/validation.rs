pub const MAX_EMAIL_LENGTH: usize = 254;
pub const MAX_LOCAL_PART_LENGTH: usize = 64;
pub const MAX_DOMAIN_LENGTH: usize = 253;
pub const MAX_DOMAIN_LABEL_LENGTH: usize = 63;

const EMAIL_LOCAL_SPECIAL_CHARS: &str = ".!#$%&'*+/=?^_`{|}~-";

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
