pub fn is_valid_did(s: &str) -> bool {
    s.strip_prefix("did:")
        .and_then(|rest| rest.split_once(':'))
        .is_some_and(|(method, id)| {
            !method.is_empty()
                && method
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                && !id.is_empty()
        })
}

pub fn is_valid_handle(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.contains('.')
        && s.split('.').all(|seg| {
            !seg.is_empty()
                && seg.len() <= 63
                && seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !seg.starts_with('-')
                && !seg.ends_with('-')
        })
}

pub fn is_valid_at_uri(s: &str) -> bool {
    s.strip_prefix("at://").is_some_and(|rest| {
        let authority = rest.split('/').next().unwrap_or("");
        is_valid_did(authority) || is_valid_handle(authority)
    })
}

pub fn is_valid_datetime(s: &str) -> bool {
    chrono::DateTime::parse_from_rfc3339(s).is_ok()
}

pub fn is_valid_uri(s: &str) -> bool {
    s.split_once("://").is_some_and(|(scheme, rest)| {
        !scheme.is_empty()
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '.' || c == '-')
            && scheme.starts_with(|c: char| c.is_ascii_alphabetic())
            && !rest.is_empty()
    })
}

pub fn is_valid_cid(s: &str) -> bool {
    s.len() >= 8
        && s.chars().all(|c| c.is_ascii_alphanumeric())
        && s.starts_with(|c: char| c == 'b' || c == 'z' || c == 'Q')
}

pub fn is_valid_language(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

pub fn is_valid_tid(s: &str) -> bool {
    s.len() == 13
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

pub fn is_valid_record_key(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 512
        && s != "."
        && s != ".."
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' || c == '~' || c == ':'
        })
}

pub fn is_valid_at_identifier(s: &str) -> bool {
    is_valid_did(s) || is_valid_handle(s)
}

pub fn is_valid_nsid(s: &str) -> bool {
    !s.is_empty()
        && s.split('.').count() >= 3
        && s.split('.').all(|seg| {
            !seg.is_empty() && seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

use crate::schema::StringFormat;

pub fn validate_format(format: &StringFormat, value: &str) -> bool {
    match format {
        StringFormat::Did => is_valid_did(value),
        StringFormat::Handle => is_valid_handle(value),
        StringFormat::AtUri => is_valid_at_uri(value),
        StringFormat::Datetime => is_valid_datetime(value),
        StringFormat::Uri => is_valid_uri(value),
        StringFormat::Cid => is_valid_cid(value),
        StringFormat::Language => is_valid_language(value),
        StringFormat::Tid => is_valid_tid(value),
        StringFormat::RecordKey => is_valid_record_key(value),
        StringFormat::AtIdentifier => is_valid_at_identifier(value),
        StringFormat::Nsid => is_valid_nsid(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_dids() {
        assert!(is_valid_did("did:plc:1234567890abcdefghijk"));
        assert!(is_valid_did("did:web:example.com"));
        assert!(!is_valid_did(""));
        assert!(!is_valid_did("plc:123"));
        assert!(!is_valid_did("did:"));
        assert!(!is_valid_did("did:plc:"));
    }

    #[test]
    fn test_valid_handles() {
        assert!(is_valid_handle("user.bsky.social"));
        assert!(is_valid_handle("example.com"));
        assert!(!is_valid_handle("noperiod"));
        assert!(!is_valid_handle(""));
    }

    #[test]
    fn test_valid_at_uris() {
        assert!(is_valid_at_uri("at://did:plc:abc/app.bsky.feed.post/123"));
        assert!(is_valid_at_uri(
            "at://user.bsky.social/app.bsky.feed.post/123"
        ));
        assert!(!is_valid_at_uri("https://example.com"));
        assert!(!is_valid_at_uri("at://"));
        assert!(!is_valid_at_uri("at://not valid"));
    }

    #[test]
    fn test_valid_datetimes() {
        assert!(is_valid_datetime("2024-01-01T00:00:00.000Z"));
        assert!(is_valid_datetime("2024-01-01T00:00:00Z"));
        assert!(!is_valid_datetime("not-a-date"));
        assert!(!is_valid_datetime("2024-13-01T00:00:00Z"));
    }

    #[test]
    fn test_valid_uris() {
        assert!(is_valid_uri("https://example.com"));
        assert!(is_valid_uri("http://localhost"));
        assert!(is_valid_uri("ftp://files.example.com/path"));
        assert!(!is_valid_uri("://x"));
        assert!(!is_valid_uri("not a uri"));
        assert!(!is_valid_uri("123://bad"));
        assert!(!is_valid_uri("https://"));
    }

    #[test]
    fn test_valid_cids() {
        assert!(is_valid_cid("bafyreiabcdef123456"));
        assert!(is_valid_cid(
            "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
        ));
        assert!(is_valid_cid("zQmSomeMultibase"));
        assert!(!is_valid_cid("abc"));
        assert!(!is_valid_cid(""));
        assert!(!is_valid_cid("xyzinvalidprefix1234"));
    }

    #[test]
    fn test_valid_tids() {
        assert!(is_valid_tid("3k2n5j2abcdef"));
        assert!(!is_valid_tid("short"));
        assert!(!is_valid_tid("3K2N5J2ABCDEF"));
    }

    #[test]
    fn test_valid_record_keys() {
        assert!(is_valid_record_key("valid-key_123"));
        assert!(is_valid_record_key("self"));
        assert!(!is_valid_record_key(""));
        assert!(!is_valid_record_key("."));
        assert!(!is_valid_record_key(".."));
    }

    #[test]
    fn test_valid_nsids() {
        assert!(is_valid_nsid("app.bsky.feed.post"));
        assert!(is_valid_nsid("com.atproto.repo.strongRef"));
        assert!(!is_valid_nsid("too.short"));
        assert!(!is_valid_nsid(""));
    }

    #[test]
    fn test_did_method_with_digits() {
        assert!(is_valid_did(
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        ));
        assert!(is_valid_did("did:3:abc123"));
        assert!(is_valid_did("did:a1b2:test"));
        assert!(!is_valid_did("did:UPPER:test"));
        assert!(!is_valid_did("did::test"));
    }

    #[test]
    fn test_record_key_with_colon() {
        assert!(is_valid_record_key("self"));
        assert!(is_valid_record_key("key:with:colons"));
        assert!(is_valid_record_key("at:something"));
    }

    #[test]
    fn test_valid_languages() {
        assert!(is_valid_language("en"));
        assert!(is_valid_language("en-US"));
        assert!(is_valid_language("pt-BR"));
        assert!(!is_valid_language(""));
    }
}
