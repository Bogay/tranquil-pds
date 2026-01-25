use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedLoginIdentifier(String);

impl NormalizedLoginIdentifier {
    pub fn normalize(identifier: &str, pds_hostname: &str) -> Self {
        let trimmed = identifier.trim();
        let stripped = trimmed.strip_prefix('@').unwrap_or(trimmed);

        let normalized = match () {
            _ if stripped.starts_with("did:") => stripped.to_string(),
            _ if stripped.contains('@') => stripped.to_string(),
            _ if !stripped.contains('.') => {
                format!("{}.{}", stripped.to_lowercase(), pds_hostname)
            }
            _ => stripped.to_lowercase(),
        };

        Self(normalized)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for NormalizedLoginIdentifier {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NormalizedLoginIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BareLoginIdentifier(String);

impl BareLoginIdentifier {
    pub fn from_identifier(identifier: &str, pds_hostname: &str) -> Self {
        let trimmed = identifier.trim();
        let stripped = trimmed.strip_prefix('@').unwrap_or(trimmed);
        let suffix = format!(".{}", pds_hostname);
        let bare = stripped.strip_suffix(&suffix).unwrap_or(stripped);
        Self(bare.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for BareLoginIdentifier {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BareLoginIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalized_identifier_handles_did() {
        let id = NormalizedLoginIdentifier::normalize("did:plc:abc123", "example.com");
        assert_eq!(id.as_str(), "did:plc:abc123");
    }

    #[test]
    fn normalized_identifier_handles_email() {
        let id = NormalizedLoginIdentifier::normalize("user@example.org", "pds.example.com");
        assert_eq!(id.as_str(), "user@example.org");
    }

    #[test]
    fn normalized_identifier_handles_bare_handle() {
        let id = NormalizedLoginIdentifier::normalize("alice", "pds.example.com");
        assert_eq!(id.as_str(), "alice.pds.example.com");
    }

    #[test]
    fn normalized_identifier_handles_bare_handle_with_at_prefix() {
        let id = NormalizedLoginIdentifier::normalize("@alice", "pds.example.com");
        assert_eq!(id.as_str(), "alice.pds.example.com");
    }

    #[test]
    fn normalized_identifier_handles_full_handle() {
        let id = NormalizedLoginIdentifier::normalize("alice.bsky.social", "pds.example.com");
        assert_eq!(id.as_str(), "alice.bsky.social");
    }

    #[test]
    fn normalized_identifier_handles_uppercase() {
        let id = NormalizedLoginIdentifier::normalize("ALICE", "pds.example.com");
        assert_eq!(id.as_str(), "alice.pds.example.com");

        let id2 = NormalizedLoginIdentifier::normalize("ALICE.BSKY.SOCIAL", "pds.example.com");
        assert_eq!(id2.as_str(), "alice.bsky.social");
    }

    #[test]
    fn normalized_identifier_trims_whitespace() {
        let id = NormalizedLoginIdentifier::normalize("  alice  ", "pds.example.com");
        assert_eq!(id.as_str(), "alice.pds.example.com");
    }

    #[test]
    fn bare_identifier_strips_hostname_suffix() {
        let id = BareLoginIdentifier::from_identifier("alice.pds.example.com", "pds.example.com");
        assert_eq!(id.as_str(), "alice");
    }

    #[test]
    fn bare_identifier_preserves_non_matching() {
        let id = BareLoginIdentifier::from_identifier("alice.bsky.social", "pds.example.com");
        assert_eq!(id.as_str(), "alice.bsky.social");
    }

    #[test]
    fn bare_identifier_strips_at_prefix() {
        let id = BareLoginIdentifier::from_identifier("@alice.pds.example.com", "pds.example.com");
        assert_eq!(id.as_str(), "alice");
    }
}
