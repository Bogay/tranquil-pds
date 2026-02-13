use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::Mac;
use sha2::{Digest, Sha256};
use tranquil_db_traits::CommsChannel;
use tranquil_types::Did;

type HmacSha256 = hmac::Hmac<Sha256>;

const TOKEN_VERSION: u8 = 1;
const DEFAULT_SIGNUP_EXPIRY_MINUTES: u64 = 30;
const DEFAULT_MIGRATION_EXPIRY_HOURS: u64 = 48;
const DEFAULT_CHANNEL_UPDATE_EXPIRY_MINUTES: u64 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationPurpose {
    Signup,
    Migration,
    ChannelUpdate,
}

impl VerificationPurpose {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Signup => "signup",
            Self::Migration => "migration",
            Self::ChannelUpdate => "channel_update",
        }
    }

    fn default_expiry_seconds(&self) -> u64 {
        match self {
            Self::Signup => DEFAULT_SIGNUP_EXPIRY_MINUTES * 60,
            Self::Migration => DEFAULT_MIGRATION_EXPIRY_HOURS * 3600,
            Self::ChannelUpdate => DEFAULT_CHANNEL_UPDATE_EXPIRY_MINUTES * 60,
        }
    }
}

impl std::str::FromStr for VerificationPurpose {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "signup" => Ok(Self::Signup),
            "migration" => Ok(Self::Migration),
            "channel_update" => Ok(Self::ChannelUpdate),
            _ => Err(()),
        }
    }
}

#[derive(Debug)]
pub struct VerificationToken {
    pub did: Did,
    pub purpose: VerificationPurpose,
    pub channel: CommsChannel,
    pub identifier_hash: String,
    pub expires_at: u64,
}

fn derive_verification_key() -> [u8; 32] {
    use hkdf::Hkdf;
    let master_key = tranquil_config::get().secrets.master_key_or_default();
    let hk = Hkdf::<Sha256>::new(None, master_key.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"tranquil-pds-verification-token-v1", &mut key)
        .expect("HKDF expansion failed");
    key
}

pub fn hash_identifier(identifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(identifier.to_lowercase().as_bytes());
    let result = hasher.finalize();
    URL_SAFE_NO_PAD.encode(&result[..16])
}

pub fn generate_signup_token(did: &Did, channel: CommsChannel, identifier: &str) -> String {
    generate_token(did, VerificationPurpose::Signup, channel, identifier)
}

pub fn generate_migration_token(did: &Did, email: &str) -> String {
    generate_token(
        did,
        VerificationPurpose::Migration,
        CommsChannel::Email,
        email,
    )
}

pub fn generate_channel_update_token(did: &Did, channel: CommsChannel, identifier: &str) -> String {
    generate_token(did, VerificationPurpose::ChannelUpdate, channel, identifier)
}

pub fn generate_token(
    did: &Did,
    purpose: VerificationPurpose,
    channel: CommsChannel,
    identifier: &str,
) -> String {
    generate_token_with_expiry(
        did,
        purpose,
        channel,
        identifier,
        purpose.default_expiry_seconds(),
    )
}

pub fn generate_token_with_expiry(
    did: &Did,
    purpose: VerificationPurpose,
    channel: CommsChannel,
    identifier: &str,
    expiry_seconds: u64,
) -> String {
    let key = derive_verification_key();
    let identifier_hash = hash_identifier(identifier);
    let channel_str = channel.as_str();
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        + expiry_seconds;

    let payload = format!(
        "{}|{}|{}|{}|{}",
        did,
        purpose.as_str(),
        channel_str,
        identifier_hash,
        expires_at
    );

    let mut mac = <HmacSha256 as Mac>::new_from_slice(&key).expect("HMAC key size is valid");
    mac.update(payload.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

    let token_data = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        TOKEN_VERSION,
        did,
        purpose.as_str(),
        channel_str,
        identifier_hash,
        expires_at,
        signature
    );
    URL_SAFE_NO_PAD.encode(token_data.as_bytes())
}

#[derive(Debug)]
pub enum VerifyError {
    InvalidFormat,
    UnsupportedVersion,
    Expired,
    InvalidSignature,
    IdentifierMismatch,
    PurposeMismatch,
    ChannelMismatch,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFormat => write!(f, "Invalid token format"),
            Self::UnsupportedVersion => write!(f, "Unsupported token version"),
            Self::Expired => write!(f, "Token has expired"),
            Self::InvalidSignature => write!(f, "Invalid token signature"),
            Self::IdentifierMismatch => write!(f, "Identifier does not match token"),
            Self::PurposeMismatch => write!(f, "Token purpose does not match"),
            Self::ChannelMismatch => write!(f, "Token channel does not match"),
        }
    }
}

pub fn verify_signup_token(
    token: &str,
    expected_channel: CommsChannel,
    expected_identifier: &str,
) -> Result<VerificationToken, VerifyError> {
    let parsed = verify_token_signature(token)?;
    if parsed.purpose != VerificationPurpose::Signup {
        return Err(VerifyError::PurposeMismatch);
    }
    if parsed.channel != expected_channel {
        return Err(VerifyError::ChannelMismatch);
    }
    let expected_hash = hash_identifier(expected_identifier);
    if parsed.identifier_hash != expected_hash {
        return Err(VerifyError::IdentifierMismatch);
    }
    Ok(parsed)
}

pub fn verify_migration_token(
    token: &str,
    expected_email: &str,
) -> Result<VerificationToken, VerifyError> {
    let parsed = verify_token_signature(token)?;
    if parsed.purpose != VerificationPurpose::Migration {
        return Err(VerifyError::PurposeMismatch);
    }
    if parsed.channel != CommsChannel::Email {
        return Err(VerifyError::ChannelMismatch);
    }
    let expected_hash = hash_identifier(expected_email);
    if parsed.identifier_hash != expected_hash {
        return Err(VerifyError::IdentifierMismatch);
    }
    Ok(parsed)
}

pub fn verify_channel_update_token(
    token: &str,
    expected_channel: CommsChannel,
    expected_identifier: &str,
) -> Result<VerificationToken, VerifyError> {
    let parsed = verify_token_signature(token)?;
    if parsed.purpose != VerificationPurpose::ChannelUpdate {
        return Err(VerifyError::PurposeMismatch);
    }
    if parsed.channel != expected_channel {
        return Err(VerifyError::ChannelMismatch);
    }
    let expected_hash = hash_identifier(expected_identifier);
    if parsed.identifier_hash != expected_hash {
        return Err(VerifyError::IdentifierMismatch);
    }
    Ok(parsed)
}

pub fn verify_token_for_did(
    token: &str,
    expected_did: &Did,
) -> Result<VerificationToken, VerifyError> {
    let parsed = verify_token_signature(token)?;
    if parsed.did != *expected_did {
        return Err(VerifyError::IdentifierMismatch);
    }
    Ok(parsed)
}

pub fn verify_token_signature(token: &str) -> Result<VerificationToken, VerifyError> {
    let token_bytes = URL_SAFE_NO_PAD
        .decode(token.trim())
        .map_err(|_| VerifyError::InvalidFormat)?;
    let token_str = String::from_utf8(token_bytes).map_err(|_| VerifyError::InvalidFormat)?;

    let parts: Vec<&str> = token_str.split('|').collect();
    if parts.len() != 7 {
        return Err(VerifyError::InvalidFormat);
    }

    let version: u8 = parts[0].parse().map_err(|_| VerifyError::InvalidFormat)?;
    if version != TOKEN_VERSION {
        return Err(VerifyError::UnsupportedVersion);
    }

    let did = parts[1];
    let purpose_str = parts[2];
    let channel_str = parts[3];
    let identifier_hash = parts[4];
    let expires_at: u64 = parts[5].parse().map_err(|_| VerifyError::InvalidFormat)?;
    let provided_signature = parts[6];

    let purpose: VerificationPurpose = purpose_str
        .parse()
        .map_err(|_| VerifyError::InvalidFormat)?;
    let channel: CommsChannel = channel_str
        .parse()
        .map_err(|_| VerifyError::InvalidFormat)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now > expires_at {
        return Err(VerifyError::Expired);
    }

    let key = derive_verification_key();
    let payload = format!(
        "{}|{}|{}|{}|{}",
        did, purpose_str, channel_str, identifier_hash, expires_at
    );
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&key).expect("HMAC key size is valid");
    mac.update(payload.as_bytes());
    let expected_signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

    use subtle::ConstantTimeEq;
    let sig_matches: bool = provided_signature
        .as_bytes()
        .ct_eq(expected_signature.as_bytes())
        .into();
    if !sig_matches {
        return Err(VerifyError::InvalidSignature);
    }

    let parsed_did: Did = did.parse().map_err(|_| VerifyError::InvalidFormat)?;

    Ok(VerificationToken {
        did: parsed_did,
        purpose,
        channel,
        identifier_hash: identifier_hash.to_string(),
        expires_at,
    })
}

pub fn format_token_for_display(token: &str) -> String {
    token.to_string()
}

pub fn normalize_token_input(input: &str) -> String {
    input.chars().filter(|c| !c.is_whitespace()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signup_token() {
        let did: Did = "did:plc:test123".parse().unwrap();
        let channel = CommsChannel::Email;
        let identifier = "test@example.com";
        let token = generate_signup_token(&did, channel, identifier);
        let result = verify_signup_token(&token, channel, identifier);
        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let parsed = result.unwrap();
        assert_eq!(parsed.did, did);
        assert_eq!(parsed.purpose, VerificationPurpose::Signup);
        assert_eq!(parsed.channel, channel);
    }

    #[test]
    fn test_migration_token() {
        let did: Did = "did:plc:test123".parse().unwrap();
        let email = "test@example.com";
        let token = generate_migration_token(&did, email);
        let result = verify_migration_token(&token, email);
        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        let parsed = result.unwrap();
        assert_eq!(parsed.did, did);
        assert_eq!(parsed.purpose, VerificationPurpose::Migration);
    }

    #[test]
    fn test_token_case_insensitive() {
        let did: Did = "did:plc:test123".parse().unwrap();
        let token = generate_signup_token(&did, CommsChannel::Email, "Test@Example.COM");
        let result = verify_signup_token(&token, CommsChannel::Email, "test@example.com");
        assert!(result.is_ok());
    }

    #[test]
    fn test_token_wrong_identifier() {
        let did: Did = "did:plc:test123".parse().unwrap();
        let token = generate_signup_token(&did, CommsChannel::Email, "test@example.com");
        let result = verify_signup_token(&token, CommsChannel::Email, "other@example.com");
        assert!(matches!(result, Err(VerifyError::IdentifierMismatch)));
    }

    #[test]
    fn test_token_wrong_channel() {
        let did: Did = "did:plc:test123".parse().unwrap();
        let token = generate_signup_token(&did, CommsChannel::Email, "test@example.com");
        let result = verify_signup_token(&token, CommsChannel::Discord, "test@example.com");
        assert!(matches!(result, Err(VerifyError::ChannelMismatch)));
    }

    #[test]
    fn test_expired_token() {
        let did: Did = "did:plc:test123".parse().unwrap();
        let token = generate_token_with_expiry(
            &did,
            VerificationPurpose::Signup,
            CommsChannel::Email,
            "test@example.com",
            0,
        );
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let result = verify_signup_token(&token, CommsChannel::Email, "test@example.com");
        assert!(matches!(result, Err(VerifyError::Expired)));
    }

    #[test]
    fn test_invalid_token() {
        let result = verify_signup_token("invalid-token", CommsChannel::Email, "test@example.com");
        assert!(matches!(result, Err(VerifyError::InvalidFormat)));
    }

    #[test]
    fn test_purpose_mismatch() {
        let did: Did = "did:plc:test123".parse().unwrap();
        let email = "test@example.com";
        let signup_token = generate_signup_token(&did, CommsChannel::Email, email);
        let result = verify_migration_token(&signup_token, email);
        assert!(matches!(result, Err(VerifyError::PurposeMismatch)));
    }

    #[test]
    fn test_discord_channel() {
        let did: Did = "did:plc:test123".parse().unwrap();
        let discord_id = "123456789012345678";
        let token = generate_signup_token(&did, CommsChannel::Discord, discord_id);
        let result = verify_signup_token(&token, CommsChannel::Discord, discord_id);
        assert!(result.is_ok());
    }

    #[test]
    fn test_format_token_for_display() {
        let token = "ABCDEFGHIJKLMNOP";
        let formatted = format_token_for_display(token);
        assert_eq!(formatted, "ABCDEFGHIJKLMNOP");
    }

    #[test]
    fn test_normalize_token_input() {
        let input = "  ABCDEFGHIJKLMNOP  ";
        let normalized = normalize_token_input(input);
        assert_eq!(normalized, "ABCDEFGHIJKLMNOP");
    }
}
