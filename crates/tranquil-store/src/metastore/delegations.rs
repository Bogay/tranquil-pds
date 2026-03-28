use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

use super::encoding::KeyBuilder;
use super::keys::{KeyTag, UserHash};

const GRANT_SCHEMA_VERSION: u8 = 1;
const AUDIT_LOG_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationGrantValue {
    pub id: uuid::Uuid,
    pub delegated_did: String,
    pub controller_did: String,
    pub granted_scopes: String,
    pub granted_at_ms: i64,
    pub granted_by: String,
    pub revoked_at_ms: Option<i64>,
    pub revoked_by: Option<String>,
}

impl DelegationGrantValue {
    pub fn serialize(&self) -> Vec<u8> {
        let payload =
            postcard::to_allocvec(self).expect("DelegationGrantValue serialization cannot fail");
        let mut buf = Vec::with_capacity(1 + payload.len());
        buf.push(GRANT_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let (&version, payload) = bytes.split_first()?;
        match version {
            GRANT_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditLogValue {
    pub id: uuid::Uuid,
    pub delegated_did: String,
    pub actor_did: String,
    pub controller_did: Option<String>,
    pub action_type: u8,
    pub action_details: Option<Vec<u8>>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at_ms: i64,
}

impl AuditLogValue {
    pub fn serialize(&self) -> Vec<u8> {
        let payload = postcard::to_allocvec(self).expect("AuditLogValue serialization cannot fail");
        let mut buf = Vec::with_capacity(1 + payload.len());
        buf.push(AUDIT_LOG_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let (&version, payload) = bytes.split_first()?;
        match version {
            AUDIT_LOG_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

pub fn action_type_to_u8(t: tranquil_db_traits::DelegationActionType) -> u8 {
    match t {
        tranquil_db_traits::DelegationActionType::GrantCreated => 0,
        tranquil_db_traits::DelegationActionType::GrantRevoked => 1,
        tranquil_db_traits::DelegationActionType::ScopesModified => 2,
        tranquil_db_traits::DelegationActionType::TokenIssued => 3,
        tranquil_db_traits::DelegationActionType::RepoWrite => 4,
        tranquil_db_traits::DelegationActionType::BlobUpload => 5,
        tranquil_db_traits::DelegationActionType::AccountAction => 6,
    }
}

pub fn u8_to_action_type(v: u8) -> Option<tranquil_db_traits::DelegationActionType> {
    match v {
        0 => Some(tranquil_db_traits::DelegationActionType::GrantCreated),
        1 => Some(tranquil_db_traits::DelegationActionType::GrantRevoked),
        2 => Some(tranquil_db_traits::DelegationActionType::ScopesModified),
        3 => Some(tranquil_db_traits::DelegationActionType::TokenIssued),
        4 => Some(tranquil_db_traits::DelegationActionType::RepoWrite),
        5 => Some(tranquil_db_traits::DelegationActionType::BlobUpload),
        6 => Some(tranquil_db_traits::DelegationActionType::AccountAction),
        _ => None,
    }
}

pub fn grant_key(delegated_hash: UserHash, controller_hash: UserHash) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::DELEG_GRANT)
        .u64(delegated_hash.raw())
        .u64(controller_hash.raw())
        .build()
}

pub fn grant_prefix(delegated_hash: UserHash) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::DELEG_GRANT)
        .u64(delegated_hash.raw())
        .build()
}

pub fn by_controller_key(
    controller_hash: UserHash,
    delegated_hash: UserHash,
) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::DELEG_BY_CONTROLLER)
        .u64(controller_hash.raw())
        .u64(delegated_hash.raw())
        .build()
}

pub fn by_controller_prefix(controller_hash: UserHash) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::DELEG_BY_CONTROLLER)
        .u64(controller_hash.raw())
        .build()
}

pub fn audit_log_key(
    delegated_hash: UserHash,
    created_at_ms: i64,
    id: uuid::Uuid,
) -> SmallVec<[u8; 128]> {
    let reversed_ts = i64::MAX.saturating_sub(created_at_ms);
    KeyBuilder::new()
        .tag(KeyTag::DELEG_AUDIT_LOG)
        .u64(delegated_hash.raw())
        .i64(reversed_ts)
        .bytes(id.as_bytes())
        .build()
}

pub fn audit_log_prefix(delegated_hash: UserHash) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::DELEG_AUDIT_LOG)
        .u64(delegated_hash.raw())
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_value_roundtrip() {
        let val = DelegationGrantValue {
            id: uuid::Uuid::new_v4(),
            delegated_did: "did:plc:deleg".to_owned(),
            controller_did: "did:plc:ctrl".to_owned(),
            granted_scopes: "atproto".to_owned(),
            granted_at_ms: 1700000000000,
            granted_by: "did:plc:grantor".to_owned(),
            revoked_at_ms: None,
            revoked_by: None,
        };
        let bytes = val.serialize();
        assert_eq!(bytes[0], GRANT_SCHEMA_VERSION);
        let decoded = DelegationGrantValue::deserialize(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn audit_log_value_roundtrip() {
        let val = AuditLogValue {
            id: uuid::Uuid::new_v4(),
            delegated_did: "did:plc:deleg".to_owned(),
            actor_did: "did:plc:actor".to_owned(),
            controller_did: Some("did:plc:ctrl".to_owned()),
            action_type: 0,
            action_details: None,
            ip_address: Some("127.0.0.1".to_owned()),
            user_agent: None,
            created_at_ms: 1700000000000,
        };
        let bytes = val.serialize();
        assert_eq!(bytes[0], AUDIT_LOG_SCHEMA_VERSION);
        let decoded = AuditLogValue::deserialize(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn grant_key_ordering_by_controller() {
        let deleg = UserHash::from_did("did:plc:deleg");
        let ctrl_a = UserHash::from_raw(100);
        let ctrl_b = UserHash::from_raw(200);
        let key_a = grant_key(deleg, ctrl_a);
        let key_b = grant_key(deleg, ctrl_b);
        assert!(key_a.as_slice() < key_b.as_slice());
    }
}
