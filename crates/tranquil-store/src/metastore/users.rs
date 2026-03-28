use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

use super::encoding::KeyBuilder;
use super::keys::{KeyTag, UserHash};

const USER_SCHEMA_VERSION: u8 = 1;
const PASSKEY_SCHEMA_VERSION: u8 = 1;
const TOTP_SCHEMA_VERSION: u8 = 1;
const BACKUP_CODE_SCHEMA_VERSION: u8 = 1;
const WEBAUTHN_CHALLENGE_SCHEMA_VERSION: u8 = 1;
const RESET_CODE_SCHEMA_VERSION: u8 = 1;
const RECOVERY_TOKEN_SCHEMA_VERSION: u8 = 1;
const DID_WEB_OVERRIDES_SCHEMA_VERSION: u8 = 1;
const HANDLE_RESERVATION_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserValue {
    pub id: uuid::Uuid,
    pub did: String,
    pub handle: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub password_hash: Option<String>,
    pub created_at_ms: i64,
    pub deactivated_at_ms: Option<i64>,
    pub takedown_ref: Option<String>,
    pub is_admin: bool,
    pub preferred_comms_channel: Option<u8>,
    pub key_bytes: Vec<u8>,
    pub encryption_version: i32,
    pub account_type: u8,
    pub password_required: bool,
    pub two_factor_enabled: bool,
    pub email_2fa_enabled: bool,
    pub totp_enabled: bool,
    pub allow_legacy_login: bool,
    pub preferred_locale: Option<String>,
    pub invites_disabled: bool,
    pub migrated_to_pds: Option<String>,
    pub migrated_at_ms: Option<i64>,
    pub discord_username: Option<String>,
    pub discord_id: Option<String>,
    pub discord_verified: bool,
    pub telegram_username: Option<String>,
    pub telegram_chat_id: Option<i64>,
    pub telegram_verified: bool,
    pub signal_username: Option<String>,
    pub signal_verified: bool,
    pub delete_after_ms: Option<i64>,
}

impl UserValue {
    pub fn serialize(&self) -> Vec<u8> {
        let payload = postcard::to_allocvec(self).expect("UserValue serialization cannot fail");
        let mut buf = Vec::with_capacity(1 + payload.len());
        buf.push(USER_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let (&version, payload) = bytes.split_first()?;
        match version {
            USER_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }

    pub fn is_active(&self) -> bool {
        self.deactivated_at_ms.is_none() && self.takedown_ref.is_none()
    }

    pub fn channel_verification(&self) -> u8 {
        let mut flags = 0u8;
        if self.email_verified {
            flags |= 1;
        }
        if self.discord_verified {
            flags |= 2;
        }
        if self.telegram_verified {
            flags |= 4;
        }
        if self.signal_verified {
            flags |= 8;
        }
        flags
    }
}

pub fn account_type_to_u8(t: tranquil_db_traits::AccountType) -> u8 {
    match t {
        tranquil_db_traits::AccountType::Personal => 0,
        tranquil_db_traits::AccountType::Delegated => 1,
    }
}

pub fn u8_to_account_type(v: u8) -> Option<tranquil_db_traits::AccountType> {
    match v {
        0 => Some(tranquil_db_traits::AccountType::Personal),
        1 => Some(tranquil_db_traits::AccountType::Delegated),
        _ => None,
    }
}

pub fn challenge_type_to_u8(t: tranquil_db_traits::WebauthnChallengeType) -> u8 {
    match t {
        tranquil_db_traits::WebauthnChallengeType::Registration => 0,
        tranquil_db_traits::WebauthnChallengeType::Authentication => 1,
    }
}

pub fn u8_to_challenge_type(v: u8) -> Option<tranquil_db_traits::WebauthnChallengeType> {
    match v {
        0 => Some(tranquil_db_traits::WebauthnChallengeType::Registration),
        1 => Some(tranquil_db_traits::WebauthnChallengeType::Authentication),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyValue {
    pub id: uuid::Uuid,
    pub did: String,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: i32,
    pub created_at_ms: i64,
    pub last_used_at_ms: Option<i64>,
    pub friendly_name: Option<String>,
    pub aaguid: Option<Vec<u8>>,
    pub transports: Option<Vec<String>>,
}

impl PasskeyValue {
    pub fn serialize(&self) -> Vec<u8> {
        let payload = postcard::to_allocvec(self).expect("PasskeyValue serialization cannot fail");
        let mut buf = Vec::with_capacity(1 + payload.len());
        buf.push(PASSKEY_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let (&version, payload) = bytes.split_first()?;
        match version {
            PASSKEY_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpValue {
    pub secret_encrypted: Vec<u8>,
    pub encryption_version: i32,
    pub verified: bool,
    pub last_used_at_ms: Option<i64>,
}

impl TotpValue {
    pub fn serialize(&self) -> Vec<u8> {
        let payload = postcard::to_allocvec(self).expect("TotpValue serialization cannot fail");
        let mut buf = Vec::with_capacity(1 + payload.len());
        buf.push(TOTP_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let (&version, payload) = bytes.split_first()?;
        match version {
            TOTP_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupCodeValue {
    pub id: uuid::Uuid,
    pub code_hash: String,
    pub used: bool,
}

impl BackupCodeValue {
    pub fn serialize(&self) -> Vec<u8> {
        let payload =
            postcard::to_allocvec(self).expect("BackupCodeValue serialization cannot fail");
        let mut buf = Vec::with_capacity(1 + payload.len());
        buf.push(BACKUP_CODE_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let (&version, payload) = bytes.split_first()?;
        match version {
            BACKUP_CODE_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebauthnChallengeValue {
    pub id: uuid::Uuid,
    pub challenge_type: u8,
    pub state_json: String,
    pub created_at_ms: i64,
}

impl WebauthnChallengeValue {
    pub fn serialize_with_ttl(&self) -> Vec<u8> {
        let expires_at_ms = self.created_at_ms.saturating_add(300_000);
        let ttl_bytes = u64::try_from(expires_at_ms).unwrap_or(0).to_be_bytes();
        let payload =
            postcard::to_allocvec(self).expect("WebauthnChallengeValue serialization cannot fail");
        let mut buf = Vec::with_capacity(8 + 1 + payload.len());
        buf.extend_from_slice(&ttl_bytes);
        buf.push(WEBAUTHN_CHALLENGE_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let rest = bytes.get(8..)?;
        let (&version, payload) = rest.split_first()?;
        match version {
            WEBAUTHN_CHALLENGE_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResetCodeValue {
    pub user_hash: u64,
    pub user_id: uuid::Uuid,
    pub preferred_comms_channel: Option<u8>,
    pub code: String,
    pub expires_at_ms: i64,
}

impl ResetCodeValue {
    pub fn serialize_with_ttl(&self) -> Vec<u8> {
        let ttl_bytes = u64::try_from(self.expires_at_ms).unwrap_or(0).to_be_bytes();
        let payload =
            postcard::to_allocvec(self).expect("ResetCodeValue serialization cannot fail");
        let mut buf = Vec::with_capacity(8 + 1 + payload.len());
        buf.extend_from_slice(&ttl_bytes);
        buf.push(RESET_CODE_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let rest = bytes.get(8..)?;
        let (&version, payload) = rest.split_first()?;
        match version {
            RESET_CODE_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryTokenValue {
    pub token_hash: String,
    pub expires_at_ms: i64,
}

impl RecoveryTokenValue {
    pub fn serialize(&self) -> Vec<u8> {
        let payload =
            postcard::to_allocvec(self).expect("RecoveryTokenValue serialization cannot fail");
        let mut buf = Vec::with_capacity(1 + payload.len());
        buf.push(RECOVERY_TOKEN_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let (&version, payload) = bytes.split_first()?;
        match version {
            RECOVERY_TOKEN_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidWebOverridesValue {
    pub verification_methods_json: Option<String>,
    pub also_known_as: Option<Vec<String>>,
}

impl DidWebOverridesValue {
    pub fn serialize(&self) -> Vec<u8> {
        let payload =
            postcard::to_allocvec(self).expect("DidWebOverridesValue serialization cannot fail");
        let mut buf = Vec::with_capacity(1 + payload.len());
        buf.push(DID_WEB_OVERRIDES_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let (&version, payload) = bytes.split_first()?;
        match version {
            DID_WEB_OVERRIDES_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleReservationValue {
    pub reserved_by: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

impl HandleReservationValue {
    pub fn serialize_with_ttl(&self) -> Vec<u8> {
        let ttl_bytes = u64::try_from(self.expires_at_ms).unwrap_or(0).to_be_bytes();
        let payload =
            postcard::to_allocvec(self).expect("HandleReservationValue serialization cannot fail");
        let mut buf = Vec::with_capacity(8 + 1 + payload.len());
        buf.extend_from_slice(&ttl_bytes);
        buf.push(HANDLE_RESERVATION_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let rest = bytes.get(8..)?;
        let (&version, payload) = rest.split_first()?;
        match version {
            HANDLE_RESERVATION_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

pub fn user_primary_key(user_hash: UserHash) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::USER_PRIMARY)
        .u64(user_hash.raw())
        .build()
}

pub fn user_primary_prefix() -> SmallVec<[u8; 128]> {
    KeyBuilder::new().tag(KeyTag::USER_PRIMARY).build()
}

pub fn user_by_handle_key(handle: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::USER_BY_HANDLE)
        .string(handle)
        .build()
}

pub fn user_by_email_key(email: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::USER_BY_EMAIL)
        .string(email)
        .build()
}

pub fn passkey_key(user_hash: UserHash, passkey_id: uuid::Uuid) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::USER_PASSKEYS)
        .u64(user_hash.raw())
        .bytes(passkey_id.as_bytes())
        .build()
}

pub fn passkey_prefix(user_hash: UserHash) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::USER_PASSKEYS)
        .u64(user_hash.raw())
        .build()
}

pub fn passkey_by_cred_key(credential_id: &[u8]) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::USER_PASSKEY_BY_CRED)
        .bytes(credential_id)
        .build()
}

pub fn totp_key(user_hash: UserHash) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::USER_TOTP)
        .u64(user_hash.raw())
        .build()
}

pub fn backup_code_key(user_hash: UserHash, code_id: uuid::Uuid) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::USER_BACKUP_CODES)
        .u64(user_hash.raw())
        .bytes(code_id.as_bytes())
        .build()
}

pub fn backup_code_prefix(user_hash: UserHash) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::USER_BACKUP_CODES)
        .u64(user_hash.raw())
        .build()
}

pub fn webauthn_challenge_key(user_hash: UserHash, challenge_type: u8) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::USER_WEBAUTHN_CHALLENGE)
        .u64(user_hash.raw())
        .raw(&[challenge_type])
        .build()
}

pub fn reset_code_key(code: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::USER_RESET_CODE)
        .string(code)
        .build()
}

pub fn recovery_token_key(user_hash: UserHash) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::USER_RECOVERY_TOKEN)
        .u64(user_hash.raw())
        .build()
}

pub fn did_web_overrides_key(user_hash: UserHash) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::USER_DID_WEB_OVERRIDES)
        .u64(user_hash.raw())
        .build()
}

pub fn handle_reservation_key(handle: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::USER_HANDLE_RESERVATION)
        .string(handle)
        .build()
}

pub fn handle_reservation_prefix() -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::USER_HANDLE_RESERVATION)
        .build()
}

pub fn telegram_lookup_key(telegram_username: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::USER_TELEGRAM_LOOKUP)
        .string(telegram_username)
        .build()
}

pub fn discord_lookup_key(discord_username: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::USER_DISCORD_LOOKUP)
        .string(discord_username)
        .build()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyIndexValue {
    pub user_hash: u64,
    pub passkey_id: uuid::Uuid,
}

impl PasskeyIndexValue {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(24);
        buf.extend_from_slice(&self.user_hash.to_be_bytes());
        buf.extend_from_slice(self.passkey_id.as_bytes());
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        (bytes.len() == 24).then(|| {
            let user_hash = u64::from_be_bytes(bytes[..8].try_into().unwrap());
            let passkey_id = uuid::Uuid::from_slice(&bytes[8..24]).unwrap();
            Self {
                user_hash,
                passkey_id,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_value_roundtrip() {
        let val = UserValue {
            id: uuid::Uuid::new_v4(),
            did: "did:plc:test".to_owned(),
            handle: "test.example.com".to_owned(),
            email: Some("test@example.com".to_owned()),
            email_verified: true,
            password_hash: Some("hashed".to_owned()),
            created_at_ms: 1700000000000,
            deactivated_at_ms: None,
            takedown_ref: None,
            is_admin: false,
            preferred_comms_channel: None,
            key_bytes: vec![1, 2, 3],
            encryption_version: 1,
            account_type: 0,
            password_required: true,
            two_factor_enabled: false,
            email_2fa_enabled: false,
            totp_enabled: false,
            allow_legacy_login: false,
            preferred_locale: None,
            invites_disabled: false,
            migrated_to_pds: None,
            migrated_at_ms: None,
            discord_username: None,
            discord_id: None,
            discord_verified: false,
            telegram_username: None,
            telegram_chat_id: None,
            telegram_verified: false,
            signal_username: None,
            signal_verified: false,
            delete_after_ms: None,
        };
        let bytes = val.serialize();
        assert_eq!(bytes[0], USER_SCHEMA_VERSION);
        let decoded = UserValue::deserialize(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn passkey_value_roundtrip() {
        let val = PasskeyValue {
            id: uuid::Uuid::new_v4(),
            did: "did:plc:test".to_owned(),
            credential_id: vec![1, 2, 3, 4],
            public_key: vec![5, 6, 7, 8],
            sign_count: 42,
            created_at_ms: 1700000000000,
            last_used_at_ms: None,
            friendly_name: Some("my key".to_owned()),
            aaguid: None,
            transports: Some(vec!["usb".to_owned()]),
        };
        let bytes = val.serialize();
        assert_eq!(bytes[0], PASSKEY_SCHEMA_VERSION);
        let decoded = PasskeyValue::deserialize(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn totp_value_roundtrip() {
        let val = TotpValue {
            secret_encrypted: vec![10, 20, 30],
            encryption_version: 1,
            verified: true,
            last_used_at_ms: Some(1700000000000),
        };
        let bytes = val.serialize();
        let decoded = TotpValue::deserialize(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn backup_code_value_roundtrip() {
        let val = BackupCodeValue {
            id: uuid::Uuid::new_v4(),
            code_hash: "hash123".to_owned(),
            used: false,
        };
        let bytes = val.serialize();
        let decoded = BackupCodeValue::deserialize(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn webauthn_challenge_value_roundtrip() {
        let val = WebauthnChallengeValue {
            id: uuid::Uuid::new_v4(),
            challenge_type: 0,
            state_json: r#"{"challenge":"abc"}"#.to_owned(),
            created_at_ms: 1700000000000,
        };
        let bytes = val.serialize_with_ttl();
        let ttl = u64::from_be_bytes(bytes[..8].try_into().unwrap());
        assert_eq!(ttl, 1700000300000);
        let decoded = WebauthnChallengeValue::deserialize(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn reset_code_value_roundtrip() {
        let val = ResetCodeValue {
            user_hash: 0xDEAD,
            user_id: uuid::Uuid::new_v4(),
            preferred_comms_channel: Some(0),
            code: "abc123".to_owned(),
            expires_at_ms: 1700000600000,
        };
        let bytes = val.serialize_with_ttl();
        let ttl = u64::from_be_bytes(bytes[..8].try_into().unwrap());
        assert_eq!(ttl, 1700000600000);
        let decoded = ResetCodeValue::deserialize(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn recovery_token_value_roundtrip() {
        let val = RecoveryTokenValue {
            token_hash: "tokenhash".to_owned(),
            expires_at_ms: 1700000600000,
        };
        let bytes = val.serialize();
        let decoded = RecoveryTokenValue::deserialize(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn did_web_overrides_value_roundtrip() {
        let val = DidWebOverridesValue {
            verification_methods_json: Some(r#"[{"id":"key-1"}]"#.to_owned()),
            also_known_as: Some(vec!["at://user.example.com".to_owned()]),
        };
        let bytes = val.serialize();
        let decoded = DidWebOverridesValue::deserialize(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn handle_reservation_value_roundtrip() {
        let val = HandleReservationValue {
            reserved_by: "signup-flow".to_owned(),
            created_at_ms: 1700000000000,
            expires_at_ms: 1700000600000,
        };
        let bytes = val.serialize_with_ttl();
        let ttl = u64::from_be_bytes(bytes[..8].try_into().unwrap());
        assert_eq!(ttl, 1700000600000);
        let decoded = HandleReservationValue::deserialize(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn passkey_index_value_roundtrip() {
        let id = uuid::Uuid::new_v4();
        let val = PasskeyIndexValue {
            user_hash: 0xCAFE_BABE,
            passkey_id: id,
        };
        let bytes = val.serialize();
        let decoded = PasskeyIndexValue::deserialize(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn key_functions_produce_distinct_prefixes() {
        let uh = UserHash::from_did("did:plc:test");
        let id = uuid::Uuid::new_v4();
        let keys: Vec<SmallVec<[u8; 128]>> = vec![
            user_primary_key(uh),
            user_by_handle_key("test.handle"),
            user_by_email_key("test@email.com"),
            passkey_key(uh, id),
            passkey_by_cred_key(&[1, 2, 3]),
            totp_key(uh),
            backup_code_key(uh, id),
            webauthn_challenge_key(uh, 0),
            reset_code_key("code123"),
            recovery_token_key(uh),
            did_web_overrides_key(uh),
            handle_reservation_key("reserved.handle"),
            telegram_lookup_key("tg_user"),
            discord_lookup_key("dc_user"),
        ];
        let tags: Vec<u8> = keys.iter().map(|k| k[0]).collect();
        let mut unique_tags = tags.clone();
        unique_tags.sort();
        unique_tags.dedup();
        assert!(unique_tags.len() >= 12);
    }

    #[test]
    fn passkey_prefix_is_prefix_of_key() {
        let uh = UserHash::from_did("did:plc:test");
        let prefix = passkey_prefix(uh);
        let key = passkey_key(uh, uuid::Uuid::new_v4());
        assert!(key.starts_with(prefix.as_slice()));
    }

    #[test]
    fn backup_code_prefix_is_prefix_of_key() {
        let uh = UserHash::from_did("did:plc:test");
        let prefix = backup_code_prefix(uh);
        let key = backup_code_key(uh, uuid::Uuid::new_v4());
        assert!(key.starts_with(prefix.as_slice()));
    }

    #[test]
    fn account_type_roundtrip() {
        assert_eq!(
            u8_to_account_type(account_type_to_u8(
                tranquil_db_traits::AccountType::Personal
            )),
            Some(tranquil_db_traits::AccountType::Personal)
        );
        assert_eq!(
            u8_to_account_type(account_type_to_u8(
                tranquil_db_traits::AccountType::Delegated
            )),
            Some(tranquil_db_traits::AccountType::Delegated)
        );
        assert_eq!(u8_to_account_type(99), None);
    }

    #[test]
    fn challenge_type_roundtrip() {
        use tranquil_db_traits::WebauthnChallengeType;
        assert_eq!(
            u8_to_challenge_type(challenge_type_to_u8(WebauthnChallengeType::Registration)),
            Some(WebauthnChallengeType::Registration)
        );
        assert_eq!(
            u8_to_challenge_type(challenge_type_to_u8(WebauthnChallengeType::Authentication)),
            Some(WebauthnChallengeType::Authentication)
        );
        assert_eq!(u8_to_challenge_type(99), None);
    }

    #[test]
    fn channel_verification_flags() {
        let mut user = UserValue {
            id: uuid::Uuid::new_v4(),
            did: "did:plc:test".to_owned(),
            handle: "t.invalid".to_owned(),
            email: None,
            email_verified: false,
            password_hash: None,
            created_at_ms: 0,
            deactivated_at_ms: None,
            takedown_ref: None,
            is_admin: false,
            preferred_comms_channel: None,
            key_bytes: vec![],
            encryption_version: 1,
            account_type: 0,
            password_required: false,
            two_factor_enabled: false,
            email_2fa_enabled: false,
            totp_enabled: false,
            allow_legacy_login: false,
            preferred_locale: None,
            invites_disabled: false,
            migrated_to_pds: None,
            migrated_at_ms: None,
            discord_username: None,
            discord_id: None,
            discord_verified: false,
            telegram_username: None,
            telegram_chat_id: None,
            telegram_verified: false,
            signal_username: None,
            signal_verified: false,
            delete_after_ms: None,
        };
        assert_eq!(user.channel_verification(), 0);
        user.email_verified = true;
        assert_eq!(user.channel_verification(), 1);
        user.discord_verified = true;
        assert_eq!(user.channel_verification(), 3);
        user.telegram_verified = true;
        assert_eq!(user.channel_verification(), 7);
        user.signal_verified = true;
        assert_eq!(user.channel_verification(), 15);
    }

    #[test]
    fn deserialize_unknown_version_returns_none() {
        let val = UserValue {
            id: uuid::Uuid::new_v4(),
            did: String::new(),
            handle: String::new(),
            email: None,
            email_verified: false,
            password_hash: None,
            created_at_ms: 0,
            deactivated_at_ms: None,
            takedown_ref: None,
            is_admin: false,
            preferred_comms_channel: None,
            key_bytes: vec![],
            encryption_version: 0,
            account_type: 0,
            password_required: false,
            two_factor_enabled: false,
            email_2fa_enabled: false,
            totp_enabled: false,
            allow_legacy_login: false,
            preferred_locale: None,
            invites_disabled: false,
            migrated_to_pds: None,
            migrated_at_ms: None,
            discord_username: None,
            discord_id: None,
            discord_verified: false,
            telegram_username: None,
            telegram_chat_id: None,
            telegram_verified: false,
            signal_username: None,
            signal_verified: false,
            delete_after_ms: None,
        };
        let mut bytes = val.serialize();
        bytes[0] = 99;
        assert!(UserValue::deserialize(&bytes).is_none());
    }
}
