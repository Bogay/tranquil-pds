use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

use super::encoding::KeyBuilder;
use super::keys::{KeyTag, UserHash};

const SESSION_SCHEMA_VERSION: u8 = 1;
const APP_PASSWORD_SCHEMA_VERSION: u8 = 1;
const SESSION_INDEX_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionTokenValue {
    pub id: i32,
    pub did: String,
    pub access_jti: String,
    pub refresh_jti: String,
    pub access_expires_at_ms: i64,
    pub refresh_expires_at_ms: i64,
    pub login_type: u8,
    pub mfa_verified: bool,
    pub scope: Option<String>,
    pub controller_did: Option<String>,
    pub app_password_name: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl SessionTokenValue {
    pub fn serialize(&self) -> Vec<u8> {
        let ttl_bytes = u64::try_from(self.refresh_expires_at_ms)
            .unwrap_or(0)
            .to_be_bytes();
        let payload =
            postcard::to_allocvec(self).expect("SessionTokenValue serialization cannot fail");
        let mut buf = Vec::with_capacity(8 + 1 + payload.len());
        buf.extend_from_slice(&ttl_bytes);
        buf.push(SESSION_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let rest = bytes.get(8..)?;
        let (&version, payload) = rest.split_first()?;
        match version {
            SESSION_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppPasswordValue {
    pub id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub name: String,
    pub password_hash: String,
    pub created_at_ms: i64,
    pub privilege: u8,
    pub scopes: Option<String>,
    pub created_by_controller_did: Option<String>,
}

impl AppPasswordValue {
    pub fn serialize(&self) -> Vec<u8> {
        let payload =
            postcard::to_allocvec(self).expect("AppPasswordValue serialization cannot fail");
        let mut buf = Vec::with_capacity(8 + 1 + payload.len());
        buf.extend_from_slice(&0u64.to_be_bytes());
        buf.push(APP_PASSWORD_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let rest = bytes.get(8..)?;
        let (&version, payload) = rest.split_first()?;
        match version {
            APP_PASSWORD_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionIndexValue {
    pub user_hash: u64,
    pub session_id: i32,
}

impl SessionIndexValue {
    pub fn serialize(&self, expires_at_ms: i64) -> Vec<u8> {
        let ttl_bytes = u64::try_from(expires_at_ms).unwrap_or(0).to_be_bytes();
        let payload =
            postcard::to_allocvec(self).expect("SessionIndexValue serialization cannot fail");
        let mut buf = Vec::with_capacity(8 + 1 + payload.len());
        buf.extend_from_slice(&ttl_bytes);
        buf.push(SESSION_INDEX_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let rest = bytes.get(8..)?;
        let (&version, payload) = rest.split_first()?;
        match version {
            SESSION_INDEX_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

pub fn login_type_to_u8(t: tranquil_db_traits::LoginType) -> u8 {
    match t {
        tranquil_db_traits::LoginType::Modern => 0,
        tranquil_db_traits::LoginType::Legacy => 1,
    }
}

pub fn u8_to_login_type(v: u8) -> Option<tranquil_db_traits::LoginType> {
    match v {
        0 => Some(tranquil_db_traits::LoginType::Modern),
        1 => Some(tranquil_db_traits::LoginType::Legacy),
        _ => None,
    }
}

pub fn privilege_to_u8(p: tranquil_db_traits::AppPasswordPrivilege) -> u8 {
    match p {
        tranquil_db_traits::AppPasswordPrivilege::Standard => 0,
        tranquil_db_traits::AppPasswordPrivilege::Privileged => 1,
    }
}

pub fn u8_to_privilege(v: u8) -> Option<tranquil_db_traits::AppPasswordPrivilege> {
    match v {
        0 => Some(tranquil_db_traits::AppPasswordPrivilege::Standard),
        1 => Some(tranquil_db_traits::AppPasswordPrivilege::Privileged),
        _ => None,
    }
}

pub fn session_primary_key(session_id: i32) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::SESSION_PRIMARY)
        .raw(&session_id.to_be_bytes())
        .build()
}

pub fn session_by_access_key(access_jti: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::SESSION_BY_ACCESS)
        .string(access_jti)
        .build()
}

pub fn session_by_refresh_key(refresh_jti: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::SESSION_BY_REFRESH)
        .string(refresh_jti)
        .build()
}

pub fn session_used_refresh_key(refresh_jti: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::SESSION_USED_REFRESH)
        .string(refresh_jti)
        .build()
}

pub fn session_app_password_key(user_hash: UserHash, name: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::SESSION_APP_PASSWORD)
        .u64(user_hash.raw())
        .string(name)
        .build()
}

pub fn session_app_password_prefix(user_hash: UserHash) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::SESSION_APP_PASSWORD)
        .u64(user_hash.raw())
        .build()
}

pub fn session_by_did_key(user_hash: UserHash, session_id: i32) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::SESSION_BY_DID)
        .u64(user_hash.raw())
        .raw(&session_id.to_be_bytes())
        .build()
}

pub fn session_by_did_prefix(user_hash: UserHash) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::SESSION_BY_DID)
        .u64(user_hash.raw())
        .build()
}

pub fn session_last_reauth_key(user_hash: UserHash) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::SESSION_LAST_REAUTH)
        .u64(user_hash.raw())
        .build()
}

pub fn session_id_counter_key() -> SmallVec<[u8; 128]> {
    KeyBuilder::new().tag(KeyTag::SESSION_ID_COUNTER).build()
}

fn serialize_ttl_i32(expires_at_ms: i64, session_id: i32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(12);
    buf.extend_from_slice(&u64::try_from(expires_at_ms).unwrap_or(0).to_be_bytes());
    buf.extend_from_slice(&session_id.to_be_bytes());
    buf
}

fn deserialize_ttl_i32(bytes: &[u8]) -> Option<i32> {
    let rest = bytes.get(8..)?;
    let arr: [u8; 4] = rest.try_into().ok()?;
    Some(i32::from_be_bytes(arr))
}

pub fn serialize_used_refresh_value(expires_at_ms: i64, session_id: i32) -> Vec<u8> {
    serialize_ttl_i32(expires_at_ms, session_id)
}

pub fn deserialize_used_refresh_value(bytes: &[u8]) -> Option<i32> {
    deserialize_ttl_i32(bytes)
}

fn serialize_ttl_i64(timestamp_ms: i64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16);
    buf.extend_from_slice(&0u64.to_be_bytes());
    buf.extend_from_slice(&timestamp_ms.to_be_bytes());
    buf
}

fn deserialize_ttl_i64(bytes: &[u8]) -> Option<i64> {
    let rest = bytes.get(8..)?;
    let arr: [u8; 8] = rest.try_into().ok()?;
    Some(i64::from_be_bytes(arr))
}

pub fn serialize_last_reauth_value(timestamp_ms: i64) -> Vec<u8> {
    serialize_ttl_i64(timestamp_ms)
}

pub fn deserialize_last_reauth_value(bytes: &[u8]) -> Option<i64> {
    deserialize_ttl_i64(bytes)
}

pub fn serialize_by_did_value(expires_at_ms: i64) -> Vec<u8> {
    u64::try_from(expires_at_ms)
        .unwrap_or(0)
        .to_be_bytes()
        .to_vec()
}

pub fn serialize_id_counter_value(counter: i32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(12);
    buf.extend_from_slice(&0u64.to_be_bytes());
    buf.extend_from_slice(&counter.to_be_bytes());
    buf
}

pub fn deserialize_id_counter_value(bytes: &[u8]) -> Option<i32> {
    deserialize_ttl_i32(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_token_value_roundtrip() {
        let val = SessionTokenValue {
            id: 42,
            did: "did:plc:test".to_owned(),
            access_jti: "access_abc".to_owned(),
            refresh_jti: "refresh_xyz".to_owned(),
            access_expires_at_ms: 1700000060000,
            refresh_expires_at_ms: 1700000600000,
            login_type: 0,
            mfa_verified: true,
            scope: Some("atproto".to_owned()),
            controller_did: None,
            app_password_name: None,
            created_at_ms: 1700000000000,
            updated_at_ms: 1700000000000,
        };
        let bytes = val.serialize();
        let ttl = u64::from_be_bytes(bytes[..8].try_into().unwrap());
        assert_eq!(ttl, u64::try_from(val.refresh_expires_at_ms).unwrap_or(0));
        assert_eq!(bytes[8], SESSION_SCHEMA_VERSION);
        let decoded = SessionTokenValue::deserialize(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn app_password_value_roundtrip() {
        let val = AppPasswordValue {
            id: uuid::Uuid::new_v4(),
            user_id: uuid::Uuid::new_v4(),
            name: "test-app".to_owned(),
            password_hash: "hashed".to_owned(),
            created_at_ms: 1700000000000,
            privilege: 0,
            scopes: None,
            created_by_controller_did: None,
        };
        let bytes = val.serialize();
        let ttl = u64::from_be_bytes(bytes[..8].try_into().unwrap());
        assert_eq!(ttl, 0);
        assert_eq!(bytes[8], APP_PASSWORD_SCHEMA_VERSION);
        let decoded = AppPasswordValue::deserialize(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn session_index_value_roundtrip() {
        let val = SessionIndexValue {
            user_hash: 0xDEAD_BEEF,
            session_id: 99,
        };
        let expires_at_ms = 1700000600000i64;
        let bytes = val.serialize(expires_at_ms);
        let ttl = u64::from_be_bytes(bytes[..8].try_into().unwrap());
        assert_eq!(ttl, u64::try_from(expires_at_ms).unwrap_or(0));
        let decoded = SessionIndexValue::deserialize(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn used_refresh_value_roundtrip() {
        let session_id = 7;
        let expires_at_ms = 1700000600000i64;
        let bytes = serialize_used_refresh_value(expires_at_ms, session_id);
        let ttl = u64::from_be_bytes(bytes[..8].try_into().unwrap());
        assert_eq!(ttl, u64::try_from(expires_at_ms).unwrap_or(0));
        assert_eq!(deserialize_used_refresh_value(&bytes), Some(session_id));
    }

    #[test]
    fn last_reauth_value_roundtrip() {
        let ts = 1700000000000i64;
        let bytes = serialize_last_reauth_value(ts);
        let ttl = u64::from_be_bytes(bytes[..8].try_into().unwrap());
        assert_eq!(ttl, 0);
        assert_eq!(deserialize_last_reauth_value(&bytes), Some(ts));
    }

    #[test]
    fn id_counter_value_roundtrip() {
        let counter = 123;
        let bytes = serialize_id_counter_value(counter);
        let ttl = u64::from_be_bytes(bytes[..8].try_into().unwrap());
        assert_eq!(ttl, 0);
        assert_eq!(deserialize_id_counter_value(&bytes), Some(counter));
    }

    #[test]
    fn session_primary_key_roundtrip() {
        use super::super::encoding::KeyReader;
        let key = session_primary_key(42);
        let mut reader = KeyReader::new(&key);
        assert_eq!(reader.tag(), Some(KeyTag::SESSION_PRIMARY.raw()));
        let remaining = reader.remaining();
        let arr: [u8; 4] = remaining.try_into().unwrap();
        assert_eq!(i32::from_be_bytes(arr), 42);
    }

    #[test]
    fn session_by_access_key_roundtrip() {
        use super::super::encoding::KeyReader;
        let key = session_by_access_key("jti_abc");
        let mut reader = KeyReader::new(&key);
        assert_eq!(reader.tag(), Some(KeyTag::SESSION_BY_ACCESS.raw()));
        assert_eq!(reader.string(), Some("jti_abc".to_owned()));
        assert!(reader.is_empty());
    }

    #[test]
    fn session_by_did_prefix_is_prefix_of_key() {
        let uh = UserHash::from_did("did:plc:test");
        let prefix = session_by_did_prefix(uh);
        let key = session_by_did_key(uh, 5);
        assert!(key.starts_with(prefix.as_slice()));
    }

    #[test]
    fn app_password_prefix_is_prefix_of_key() {
        let uh = UserHash::from_did("did:plc:test");
        let prefix = session_app_password_prefix(uh);
        let key = session_app_password_key(uh, "my-app");
        assert!(key.starts_with(prefix.as_slice()));
    }

    #[test]
    fn deserialize_unknown_version_returns_none() {
        let val = SessionTokenValue {
            id: 1,
            did: String::new(),
            access_jti: String::new(),
            refresh_jti: String::new(),
            access_expires_at_ms: 0,
            refresh_expires_at_ms: 0,
            login_type: 0,
            mfa_verified: false,
            scope: None,
            controller_did: None,
            app_password_name: None,
            created_at_ms: 0,
            updated_at_ms: 0,
        };
        let mut bytes = val.serialize();
        bytes[8] = 99;
        assert!(SessionTokenValue::deserialize(&bytes).is_none());
    }

    #[test]
    fn deserialize_too_short_returns_none() {
        assert!(SessionTokenValue::deserialize(&[0; 8]).is_none());
        assert!(SessionTokenValue::deserialize(&[0; 7]).is_none());
        assert!(AppPasswordValue::deserialize(&[0; 8]).is_none());
        assert!(SessionIndexValue::deserialize(&[0; 8]).is_none());
    }

    #[test]
    fn login_type_conversion_roundtrip() {
        assert_eq!(
            u8_to_login_type(login_type_to_u8(tranquil_db_traits::LoginType::Modern)),
            Some(tranquil_db_traits::LoginType::Modern)
        );
        assert_eq!(
            u8_to_login_type(login_type_to_u8(tranquil_db_traits::LoginType::Legacy)),
            Some(tranquil_db_traits::LoginType::Legacy)
        );
        assert_eq!(u8_to_login_type(99), None);
    }

    #[test]
    fn privilege_conversion_roundtrip() {
        assert_eq!(
            u8_to_privilege(privilege_to_u8(
                tranquil_db_traits::AppPasswordPrivilege::Standard
            )),
            Some(tranquil_db_traits::AppPasswordPrivilege::Standard)
        );
        assert_eq!(
            u8_to_privilege(privilege_to_u8(
                tranquil_db_traits::AppPasswordPrivilege::Privileged
            )),
            Some(tranquil_db_traits::AppPasswordPrivilege::Privileged)
        );
        assert_eq!(u8_to_privilege(99), None);
    }
}
