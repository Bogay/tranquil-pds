use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

use super::encoding::KeyBuilder;
use super::keys::{KeyTag, UserHash};

const IDENTITY_SCHEMA_VERSION: u8 = 1;
const AUTH_STATE_SCHEMA_VERSION: u8 = 1;
const PENDING_REG_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalIdentityValue {
    pub id: uuid::Uuid,
    pub did: String,
    pub provider: u8,
    pub provider_user_id: String,
    pub provider_username: Option<String>,
    pub provider_email: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub last_login_at_ms: Option<i64>,
}

impl ExternalIdentityValue {
    pub fn serialize(&self) -> Vec<u8> {
        let payload =
            postcard::to_allocvec(self).expect("ExternalIdentityValue serialization cannot fail");
        let mut buf = Vec::with_capacity(1 + payload.len());
        buf.push(IDENTITY_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let (&version, payload) = bytes.split_first()?;
        match version {
            IDENTITY_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SsoAuthStateValue {
    pub state: String,
    pub request_uri: String,
    pub provider: u8,
    pub action: String,
    pub nonce: Option<String>,
    pub code_verifier: Option<String>,
    pub did: Option<String>,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

impl SsoAuthStateValue {
    pub fn serialize(&self) -> Vec<u8> {
        let payload =
            postcard::to_allocvec(self).expect("SsoAuthStateValue serialization cannot fail");
        let mut buf = Vec::with_capacity(1 + payload.len());
        buf.push(AUTH_STATE_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let (&version, payload) = bytes.split_first()?;
        match version {
            AUTH_STATE_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRegistrationValue {
    pub token: String,
    pub request_uri: String,
    pub provider: u8,
    pub provider_user_id: String,
    pub provider_username: Option<String>,
    pub provider_email: Option<String>,
    pub provider_email_verified: bool,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

impl PendingRegistrationValue {
    pub fn serialize(&self) -> Vec<u8> {
        let payload = postcard::to_allocvec(self)
            .expect("PendingRegistrationValue serialization cannot fail");
        let mut buf = Vec::with_capacity(1 + payload.len());
        buf.push(PENDING_REG_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let (&version, payload) = bytes.split_first()?;
        match version {
            PENDING_REG_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

pub fn provider_to_u8(p: tranquil_db_traits::SsoProviderType) -> u8 {
    match p {
        tranquil_db_traits::SsoProviderType::Github => 0,
        tranquil_db_traits::SsoProviderType::Discord => 1,
        tranquil_db_traits::SsoProviderType::Google => 2,
        tranquil_db_traits::SsoProviderType::Gitlab => 3,
        tranquil_db_traits::SsoProviderType::Oidc => 4,
        tranquil_db_traits::SsoProviderType::Apple => 5,
    }
}

pub fn u8_to_provider(v: u8) -> Option<tranquil_db_traits::SsoProviderType> {
    match v {
        0 => Some(tranquil_db_traits::SsoProviderType::Github),
        1 => Some(tranquil_db_traits::SsoProviderType::Discord),
        2 => Some(tranquil_db_traits::SsoProviderType::Google),
        3 => Some(tranquil_db_traits::SsoProviderType::Gitlab),
        4 => Some(tranquil_db_traits::SsoProviderType::Oidc),
        5 => Some(tranquil_db_traits::SsoProviderType::Apple),
        _ => None,
    }
}

pub fn identity_key(
    user_hash: UserHash,
    provider: u8,
    provider_user_id: &str,
) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::SSO_IDENTITY)
        .u64(user_hash.raw())
        .raw(&[provider])
        .string(provider_user_id)
        .build()
}

pub fn identity_user_prefix(user_hash: UserHash) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::SSO_IDENTITY)
        .u64(user_hash.raw())
        .build()
}

pub fn by_provider_key(provider: u8, provider_user_id: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::SSO_BY_PROVIDER)
        .raw(&[provider])
        .string(provider_user_id)
        .build()
}

pub fn by_id_key(id: uuid::Uuid) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::SSO_BY_ID)
        .fixed(id.as_bytes())
        .build()
}

pub fn auth_state_key(state: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::SSO_AUTH_STATE)
        .string(state)
        .build()
}

pub fn auth_state_prefix() -> SmallVec<[u8; 128]> {
    KeyBuilder::new().tag(KeyTag::SSO_AUTH_STATE).build()
}

pub fn pending_reg_key(token: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::SSO_PENDING_REG)
        .string(token)
        .build()
}

pub fn pending_reg_prefix() -> SmallVec<[u8; 128]> {
    KeyBuilder::new().tag(KeyTag::SSO_PENDING_REG).build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_value_roundtrip() {
        let val = ExternalIdentityValue {
            id: uuid::Uuid::new_v4(),
            did: "did:plc:test".to_owned(),
            provider: 0,
            provider_user_id: "12345".to_owned(),
            provider_username: Some("user".to_owned()),
            provider_email: Some("user@example.com".to_owned()),
            created_at_ms: 1700000000000,
            updated_at_ms: 1700000000000,
            last_login_at_ms: None,
        };
        let bytes = val.serialize();
        assert_eq!(bytes[0], IDENTITY_SCHEMA_VERSION);
        let decoded = ExternalIdentityValue::deserialize(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn auth_state_value_roundtrip() {
        let val = SsoAuthStateValue {
            state: "random-state".to_owned(),
            request_uri: "urn:ietf:params:oauth:request_uri:abc".to_owned(),
            provider: 0,
            action: "login".to_owned(),
            nonce: None,
            code_verifier: None,
            did: None,
            created_at_ms: 1700000000000,
            expires_at_ms: 1700000600000,
        };
        let bytes = val.serialize();
        let decoded = SsoAuthStateValue::deserialize(&bytes).unwrap();
        assert_eq!(val, decoded);
    }
}
