use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

use super::encoding::KeyBuilder;
use super::keys::{KeyTag, UserHash};

const TOKEN_SCHEMA_VERSION: u8 = 1;
const REQUEST_SCHEMA_VERSION: u8 = 1;
const DEVICE_SCHEMA_VERSION: u8 = 1;
const ACCOUNT_DEVICE_SCHEMA_VERSION: u8 = 1;
const DPOP_JTI_SCHEMA_VERSION: u8 = 1;
const CHALLENGE_SCHEMA_VERSION: u8 = 1;
const SCOPE_PREFS_SCHEMA_VERSION: u8 = 1;
const AUTH_CLIENT_SCHEMA_VERSION: u8 = 1;
const DEVICE_TRUST_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthTokenValue {
    pub family_id: i32,
    pub did: String,
    pub client_id: String,
    pub token_id: String,
    pub refresh_token: String,
    pub previous_refresh_token: Option<String>,
    pub scope: String,
    pub expires_at_ms: i64,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub parameters_json: String,
    pub controller_did: Option<String>,
}

impl OAuthTokenValue {
    pub fn serialize_with_ttl(&self) -> Vec<u8> {
        let ttl_bytes = u64::try_from(self.expires_at_ms).unwrap_or(0).to_be_bytes();
        let payload =
            postcard::to_allocvec(self).expect("OAuthTokenValue serialization cannot fail");
        let mut buf = Vec::with_capacity(8 + 1 + payload.len());
        buf.extend_from_slice(&ttl_bytes);
        buf.push(TOKEN_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 9 {
            return None;
        }
        let (_ttl, rest) = bytes.split_at(8);
        let (&version, payload) = rest.split_first()?;
        match version {
            TOKEN_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthRequestValue {
    pub client_id: String,
    pub client_auth_json: Option<String>,
    pub parameters_json: String,
    pub expires_at_ms: i64,
    pub did: Option<String>,
    pub device_id: Option<String>,
    pub code: Option<String>,
    pub controller_did: Option<String>,
}

impl OAuthRequestValue {
    pub fn serialize_with_ttl(&self) -> Vec<u8> {
        let ttl_bytes = u64::try_from(self.expires_at_ms).unwrap_or(0).to_be_bytes();
        let payload =
            postcard::to_allocvec(self).expect("OAuthRequestValue serialization cannot fail");
        let mut buf = Vec::with_capacity(8 + 1 + payload.len());
        buf.extend_from_slice(&ttl_bytes);
        buf.push(REQUEST_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 9 {
            return None;
        }
        let (_ttl, rest) = bytes.split_at(8);
        let (&version, payload) = rest.split_first()?;
        match version {
            REQUEST_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthDeviceValue {
    pub session_id: String,
    pub user_agent: Option<String>,
    pub ip_address: String,
    pub last_seen_at_ms: i64,
    pub created_at_ms: i64,
}

impl OAuthDeviceValue {
    pub fn serialize(&self) -> Vec<u8> {
        let payload =
            postcard::to_allocvec(self).expect("OAuthDeviceValue serialization cannot fail");
        let mut buf = Vec::with_capacity(8 + 1 + payload.len());
        buf.extend_from_slice(&0u64.to_be_bytes());
        buf.push(DEVICE_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let rest = bytes.get(8..)?;
        let (&version, payload) = rest.split_first()?;
        match version {
            DEVICE_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountDeviceValue {
    pub last_used_at_ms: i64,
}

impl AccountDeviceValue {
    pub fn serialize_with_ttl(&self) -> Vec<u8> {
        let ttl_bytes = 0u64.to_be_bytes();
        let payload =
            postcard::to_allocvec(self).expect("AccountDeviceValue serialization cannot fail");
        let mut buf = Vec::with_capacity(8 + 1 + payload.len());
        buf.extend_from_slice(&ttl_bytes);
        buf.push(ACCOUNT_DEVICE_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 9 {
            return None;
        }
        let (_ttl, rest) = bytes.split_at(8);
        let (&version, payload) = rest.split_first()?;
        match version {
            ACCOUNT_DEVICE_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpopJtiValue {
    pub recorded_at_ms: i64,
}

const DPOP_JTI_WINDOW_MS: i64 = 300_000;

impl DpopJtiValue {
    pub fn serialize_with_ttl(&self) -> Vec<u8> {
        let expires_at_ms = self.recorded_at_ms.saturating_add(DPOP_JTI_WINDOW_MS);
        let ttl_bytes = u64::try_from(expires_at_ms).unwrap_or(0).to_be_bytes();
        let payload = postcard::to_allocvec(self).expect("DpopJtiValue serialization cannot fail");
        let mut buf = Vec::with_capacity(8 + 1 + payload.len());
        buf.extend_from_slice(&ttl_bytes);
        buf.push(DPOP_JTI_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 9 {
            return None;
        }
        let (_ttl, rest) = bytes.split_at(8);
        let (&version, payload) = rest.split_first()?;
        match version {
            DPOP_JTI_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }

    pub fn ttl_ms(bytes: &[u8]) -> Option<u64> {
        if bytes.len() < 8 {
            return None;
        }
        let ttl_bytes: [u8; 8] = bytes[..8].try_into().ok()?;
        Some(u64::from_be_bytes(ttl_bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwoFactorChallengeValue {
    pub id: [u8; 16],
    pub did: String,
    pub request_uri: String,
    pub code: String,
    pub attempts: i32,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

impl TwoFactorChallengeValue {
    pub fn serialize_with_ttl(&self) -> Vec<u8> {
        let ttl_bytes = u64::try_from(self.expires_at_ms).unwrap_or(0).to_be_bytes();
        let payload =
            postcard::to_allocvec(self).expect("TwoFactorChallengeValue serialization cannot fail");
        let mut buf = Vec::with_capacity(8 + 1 + payload.len());
        buf.extend_from_slice(&ttl_bytes);
        buf.push(CHALLENGE_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 9 {
            return None;
        }
        let (_ttl, rest) = bytes.split_at(8);
        let (&version, payload) = rest.split_first()?;
        match version {
            CHALLENGE_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }

    pub fn ttl_ms(bytes: &[u8]) -> Option<u64> {
        if bytes.len() < 8 {
            return None;
        }
        let ttl_bytes: [u8; 8] = bytes[..8].try_into().ok()?;
        Some(u64::from_be_bytes(ttl_bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopePrefsValue {
    pub prefs_json: String,
}

impl ScopePrefsValue {
    pub fn serialize(&self) -> Vec<u8> {
        let payload =
            postcard::to_allocvec(self).expect("ScopePrefsValue serialization cannot fail");
        let mut buf = Vec::with_capacity(8 + 1 + payload.len());
        buf.extend_from_slice(&0u64.to_be_bytes());
        buf.push(SCOPE_PREFS_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let rest = bytes.get(8..)?;
        let (&version, payload) = rest.split_first()?;
        match version {
            SCOPE_PREFS_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedClientValue {
    pub data_json: String,
}

impl AuthorizedClientValue {
    pub fn serialize(&self) -> Vec<u8> {
        let payload =
            postcard::to_allocvec(self).expect("AuthorizedClientValue serialization cannot fail");
        let mut buf = Vec::with_capacity(8 + 1 + payload.len());
        buf.extend_from_slice(&0u64.to_be_bytes());
        buf.push(AUTH_CLIENT_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let rest = bytes.get(8..)?;
        let (&version, payload) = rest.split_first()?;
        match version {
            AUTH_CLIENT_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceTrustValue {
    pub device_id: String,
    pub did: String,
    pub user_agent: Option<String>,
    pub friendly_name: Option<String>,
    pub trusted_at_ms: Option<i64>,
    pub trusted_until_ms: Option<i64>,
    pub last_seen_at_ms: i64,
}

impl DeviceTrustValue {
    pub fn serialize(&self) -> Vec<u8> {
        let payload =
            postcard::to_allocvec(self).expect("DeviceTrustValue serialization cannot fail");
        let mut buf = Vec::with_capacity(8 + 1 + payload.len());
        buf.extend_from_slice(&0u64.to_be_bytes());
        buf.push(DEVICE_TRUST_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let rest = bytes.get(8..)?;
        let (&version, payload) = rest.split_first()?;
        match version {
            DEVICE_TRUST_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsedRefreshValue {
    pub family_id: i32,
}

impl UsedRefreshValue {
    pub fn serialize_with_ttl(&self, expires_at_ms: i64) -> Vec<u8> {
        let ttl_bytes = u64::try_from(expires_at_ms).unwrap_or(0).to_be_bytes();
        let payload =
            postcard::to_allocvec(self).expect("UsedRefreshValue serialization cannot fail");
        let mut buf = Vec::with_capacity(8 + 1 + payload.len());
        buf.extend_from_slice(&ttl_bytes);
        buf.push(TOKEN_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 9 {
            return None;
        }
        let (_ttl, rest) = bytes.split_at(8);
        let (&version, payload) = rest.split_first()?;
        match version {
            TOKEN_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

pub fn oauth_token_key(user_hash: UserHash, family_id: i32) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::OAUTH_TOKEN)
        .u64(user_hash.raw())
        .raw(&family_id.to_be_bytes())
        .build()
}

pub fn oauth_token_user_prefix(user_hash: UserHash) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::OAUTH_TOKEN)
        .u64(user_hash.raw())
        .build()
}

pub fn oauth_token_by_id_key(token_id: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::OAUTH_TOKEN_BY_ID)
        .string(token_id)
        .build()
}

pub fn oauth_token_by_refresh_key(refresh_token: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::OAUTH_TOKEN_BY_REFRESH)
        .string(refresh_token)
        .build()
}

pub fn oauth_token_by_prev_refresh_key(refresh_token: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::OAUTH_TOKEN_BY_PREV_REFRESH)
        .string(refresh_token)
        .build()
}

pub fn oauth_used_refresh_key(refresh_token: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::OAUTH_USED_REFRESH)
        .string(refresh_token)
        .build()
}

pub fn oauth_auth_request_key(request_id: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::OAUTH_AUTH_REQUEST)
        .string(request_id)
        .build()
}

pub fn oauth_auth_request_prefix() -> SmallVec<[u8; 128]> {
    KeyBuilder::new().tag(KeyTag::OAUTH_AUTH_REQUEST).build()
}

pub fn oauth_auth_by_code_key(code: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::OAUTH_AUTH_BY_CODE)
        .string(code)
        .build()
}

pub fn oauth_device_key(device_id: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::OAUTH_DEVICE)
        .string(device_id)
        .build()
}

pub fn oauth_account_device_key(user_hash: UserHash, device_id: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::OAUTH_ACCOUNT_DEVICE)
        .u64(user_hash.raw())
        .string(device_id)
        .build()
}

pub fn oauth_account_device_prefix(user_hash: UserHash) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::OAUTH_ACCOUNT_DEVICE)
        .u64(user_hash.raw())
        .build()
}

pub fn oauth_dpop_jti_key(jti: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::OAUTH_DPOP_JTI)
        .string(jti)
        .build()
}

pub fn oauth_dpop_jti_prefix() -> SmallVec<[u8; 128]> {
    KeyBuilder::new().tag(KeyTag::OAUTH_DPOP_JTI).build()
}

pub fn oauth_2fa_challenge_key(id: &[u8; 16]) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::OAUTH_2FA_CHALLENGE)
        .raw(id)
        .build()
}

pub fn oauth_2fa_challenge_prefix() -> SmallVec<[u8; 128]> {
    KeyBuilder::new().tag(KeyTag::OAUTH_2FA_CHALLENGE).build()
}

pub fn oauth_2fa_by_request_key(request_uri: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::OAUTH_2FA_BY_REQUEST)
        .string(request_uri)
        .build()
}

pub fn oauth_scope_prefs_key(user_hash: UserHash, client_id: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::OAUTH_SCOPE_PREFS)
        .u64(user_hash.raw())
        .string(client_id)
        .build()
}

pub fn oauth_auth_client_key(user_hash: UserHash, client_id: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::OAUTH_AUTH_CLIENT)
        .u64(user_hash.raw())
        .string(client_id)
        .build()
}

pub fn oauth_device_trust_key(user_hash: UserHash, device_id: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::OAUTH_DEVICE_TRUST)
        .u64(user_hash.raw())
        .string(device_id)
        .build()
}

pub fn oauth_device_trust_prefix(user_hash: UserHash) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::OAUTH_DEVICE_TRUST)
        .u64(user_hash.raw())
        .build()
}

pub fn oauth_token_family_counter_key() -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::OAUTH_TOKEN_FAMILY_COUNTER)
        .build()
}

pub fn serialize_family_counter(counter: i32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(12);
    buf.extend_from_slice(&0u64.to_be_bytes());
    buf.extend_from_slice(&counter.to_be_bytes());
    buf
}

pub fn deserialize_family_counter(bytes: &[u8]) -> Option<i32> {
    match bytes.len() {
        4 => Some(i32::from_be_bytes(bytes.try_into().ok()?)),
        n if n >= 12 => {
            let arr: [u8; 4] = bytes[8..12].try_into().ok()?;
            Some(i32::from_be_bytes(arr))
        }
        _ => None,
    }
}

pub fn oauth_token_by_family_key(family_id: i32) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::OAUTH_TOKEN_BY_FAMILY)
        .raw(&family_id.to_be_bytes())
        .build()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenIndexValue {
    pub user_hash: u64,
    pub family_id: i32,
}

impl TokenIndexValue {
    pub fn serialize_with_ttl(&self, expires_at_ms: i64) -> Vec<u8> {
        let ttl_bytes = u64::try_from(expires_at_ms).unwrap_or(0).to_be_bytes();
        let payload =
            postcard::to_allocvec(self).expect("TokenIndexValue serialization cannot fail");
        let mut buf = Vec::with_capacity(8 + 1 + payload.len());
        buf.extend_from_slice(&ttl_bytes);
        buf.push(TOKEN_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 9 {
            return None;
        }
        let (_ttl, rest) = bytes.split_at(8);
        let (&version, payload) = rest.split_first()?;
        match version {
            TOKEN_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}
