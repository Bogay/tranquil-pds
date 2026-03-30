use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

use super::encoding::KeyBuilder;
use super::keys::KeyTag;

const COMMS_SCHEMA_VERSION: u8 = 1;
const INVITE_CODE_SCHEMA_VERSION: u8 = 1;
const INVITE_USE_SCHEMA_VERSION: u8 = 1;
const SIGNING_KEY_SCHEMA_V1: u8 = 1;
const SIGNING_KEY_SCHEMA_V2: u8 = 2;
const DELETION_REQUEST_SCHEMA_VERSION: u8 = 1;
const REPORT_SCHEMA_VERSION: u8 = 1;
const NOTIFICATION_HISTORY_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedCommsValue {
    pub id: uuid::Uuid,
    pub user_id: Option<uuid::Uuid>,
    pub channel: u8,
    pub comms_type: u8,
    pub recipient: String,
    pub subject: Option<String>,
    pub body: String,
    pub metadata: Option<Vec<u8>>,
    pub status: u8,
    pub error_message: Option<String>,
    pub attempts: i32,
    pub max_attempts: i32,
    pub created_at_ms: i64,
    pub scheduled_for_ms: i64,
    pub sent_at_ms: Option<i64>,
}

impl QueuedCommsValue {
    pub fn serialize(&self) -> Vec<u8> {
        let payload =
            postcard::to_allocvec(self).expect("QueuedCommsValue serialization cannot fail");
        let mut buf = Vec::with_capacity(1 + payload.len());
        buf.push(COMMS_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let (&version, payload) = bytes.split_first()?;
        match version {
            COMMS_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteCodeValue {
    pub code: String,
    pub available_uses: i32,
    pub disabled: bool,
    pub for_account: Option<String>,
    pub created_by: Option<uuid::Uuid>,
    pub created_at_ms: i64,
}

impl InviteCodeValue {
    pub fn serialize(&self) -> Vec<u8> {
        let payload =
            postcard::to_allocvec(self).expect("InviteCodeValue serialization cannot fail");
        let mut buf = Vec::with_capacity(1 + payload.len());
        buf.push(INVITE_CODE_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let (&version, payload) = bytes.split_first()?;
        match version {
            INVITE_CODE_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteCodeUseValue {
    pub used_by: uuid::Uuid,
    pub used_at_ms: i64,
}

impl InviteCodeUseValue {
    pub fn serialize(&self) -> Vec<u8> {
        let payload =
            postcard::to_allocvec(self).expect("InviteCodeUseValue serialization cannot fail");
        let mut buf = Vec::with_capacity(1 + payload.len());
        buf.push(INVITE_USE_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let (&version, payload) = bytes.split_first()?;
        match version {
            INVITE_USE_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SigningKeyValueV1 {
    id: uuid::Uuid,
    did: Option<String>,
    public_key_did_key: String,
    private_key_bytes: Vec<u8>,
    used: bool,
    created_at_ms: i64,
    expires_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningKeyValue {
    pub id: uuid::Uuid,
    pub did: Option<String>,
    pub public_key_did_key: String,
    pub private_key_bytes: Vec<u8>,
    pub used: bool,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub used_at_ms: Option<i64>,
}

impl SigningKeyValue {
    pub fn serialize(&self) -> Vec<u8> {
        let payload =
            postcard::to_allocvec(self).expect("SigningKeyValue serialization cannot fail");
        let mut buf = Vec::with_capacity(1 + payload.len());
        buf.push(SIGNING_KEY_SCHEMA_V2);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let (&version, payload) = bytes.split_first()?;
        match version {
            SIGNING_KEY_SCHEMA_V1 => {
                let v1: SigningKeyValueV1 = postcard::from_bytes(payload).ok()?;
                Some(Self {
                    id: v1.id,
                    did: v1.did,
                    public_key_did_key: v1.public_key_did_key,
                    private_key_bytes: v1.private_key_bytes,
                    used: v1.used,
                    created_at_ms: v1.created_at_ms,
                    expires_at_ms: v1.expires_at_ms,
                    used_at_ms: None,
                })
            }
            SIGNING_KEY_SCHEMA_V2 => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletionRequestValue {
    pub token: String,
    pub did: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

impl DeletionRequestValue {
    pub fn serialize(&self) -> Vec<u8> {
        let payload =
            postcard::to_allocvec(self).expect("DeletionRequestValue serialization cannot fail");
        let mut buf = Vec::with_capacity(1 + payload.len());
        buf.push(DELETION_REQUEST_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let (&version, payload) = bytes.split_first()?;
        match version {
            DELETION_REQUEST_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportValue {
    pub id: i64,
    pub reason_type: String,
    pub reason: Option<String>,
    pub subject_json: Vec<u8>,
    pub reported_by_did: String,
    pub created_at_ms: i64,
}

impl ReportValue {
    pub fn serialize(&self) -> Vec<u8> {
        let payload = postcard::to_allocvec(self).expect("ReportValue serialization cannot fail");
        let mut buf = Vec::with_capacity(1 + payload.len());
        buf.push(REPORT_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let (&version, payload) = bytes.split_first()?;
        match version {
            REPORT_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationHistoryValue {
    pub id: uuid::Uuid,
    pub channel: u8,
    pub comms_type: u8,
    pub recipient: String,
    pub subject: Option<String>,
    pub body: String,
    pub status: u8,
    pub created_at_ms: i64,
}

impl NotificationHistoryValue {
    pub fn serialize(&self) -> Vec<u8> {
        let payload = postcard::to_allocvec(self)
            .expect("NotificationHistoryValue serialization cannot fail");
        let mut buf = Vec::with_capacity(1 + payload.len());
        buf.push(NOTIFICATION_HISTORY_SCHEMA_VERSION);
        buf.extend_from_slice(&payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let (&version, payload) = bytes.split_first()?;
        match version {
            NOTIFICATION_HISTORY_SCHEMA_VERSION => postcard::from_bytes(payload).ok(),
            _ => None,
        }
    }
}

pub fn channel_to_u8(ch: tranquil_db_traits::CommsChannel) -> u8 {
    match ch {
        tranquil_db_traits::CommsChannel::Email => 0,
        tranquil_db_traits::CommsChannel::Discord => 1,
        tranquil_db_traits::CommsChannel::Telegram => 2,
        tranquil_db_traits::CommsChannel::Signal => 3,
    }
}

pub fn u8_to_channel(v: u8) -> Option<tranquil_db_traits::CommsChannel> {
    match v {
        0 => Some(tranquil_db_traits::CommsChannel::Email),
        1 => Some(tranquil_db_traits::CommsChannel::Discord),
        2 => Some(tranquil_db_traits::CommsChannel::Telegram),
        3 => Some(tranquil_db_traits::CommsChannel::Signal),
        _ => None,
    }
}

pub fn comms_type_to_u8(ct: tranquil_db_traits::CommsType) -> u8 {
    match ct {
        tranquil_db_traits::CommsType::Welcome => 0,
        tranquil_db_traits::CommsType::EmailVerification => 1,
        tranquil_db_traits::CommsType::PasswordReset => 2,
        tranquil_db_traits::CommsType::EmailUpdate => 3,
        tranquil_db_traits::CommsType::AccountDeletion => 4,
        tranquil_db_traits::CommsType::AdminEmail => 5,
        tranquil_db_traits::CommsType::PlcOperation => 6,
        tranquil_db_traits::CommsType::TwoFactorCode => 7,
        tranquil_db_traits::CommsType::PasskeyRecovery => 8,
        tranquil_db_traits::CommsType::LegacyLoginAlert => 9,
        tranquil_db_traits::CommsType::MigrationVerification => 10,
        tranquil_db_traits::CommsType::ChannelVerification => 11,
        tranquil_db_traits::CommsType::ChannelVerified => 12,
    }
}

pub fn u8_to_comms_type(v: u8) -> Option<tranquil_db_traits::CommsType> {
    match v {
        0 => Some(tranquil_db_traits::CommsType::Welcome),
        1 => Some(tranquil_db_traits::CommsType::EmailVerification),
        2 => Some(tranquil_db_traits::CommsType::PasswordReset),
        3 => Some(tranquil_db_traits::CommsType::EmailUpdate),
        4 => Some(tranquil_db_traits::CommsType::AccountDeletion),
        5 => Some(tranquil_db_traits::CommsType::AdminEmail),
        6 => Some(tranquil_db_traits::CommsType::PlcOperation),
        7 => Some(tranquil_db_traits::CommsType::TwoFactorCode),
        8 => Some(tranquil_db_traits::CommsType::PasskeyRecovery),
        9 => Some(tranquil_db_traits::CommsType::LegacyLoginAlert),
        10 => Some(tranquil_db_traits::CommsType::MigrationVerification),
        11 => Some(tranquil_db_traits::CommsType::ChannelVerification),
        12 => Some(tranquil_db_traits::CommsType::ChannelVerified),
        _ => None,
    }
}

pub fn status_to_u8(s: tranquil_db_traits::CommsStatus) -> u8 {
    match s {
        tranquil_db_traits::CommsStatus::Pending => 0,
        tranquil_db_traits::CommsStatus::Processing => 1,
        tranquil_db_traits::CommsStatus::Sent => 2,
        tranquil_db_traits::CommsStatus::Failed => 3,
    }
}

pub fn u8_to_status(v: u8) -> Option<tranquil_db_traits::CommsStatus> {
    match v {
        0 => Some(tranquil_db_traits::CommsStatus::Pending),
        1 => Some(tranquil_db_traits::CommsStatus::Processing),
        2 => Some(tranquil_db_traits::CommsStatus::Sent),
        3 => Some(tranquil_db_traits::CommsStatus::Failed),
        _ => None,
    }
}

pub fn comms_queue_key(id: uuid::Uuid) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::INFRA_COMMS_QUEUE)
        .bytes(id.as_bytes())
        .build()
}

pub fn comms_queue_prefix() -> SmallVec<[u8; 128]> {
    KeyBuilder::new().tag(KeyTag::INFRA_COMMS_QUEUE).build()
}

pub fn invite_code_key(code: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::INFRA_INVITE_CODE)
        .string(code)
        .build()
}

pub fn invite_code_prefix() -> SmallVec<[u8; 128]> {
    KeyBuilder::new().tag(KeyTag::INFRA_INVITE_CODE).build()
}

pub fn invite_use_key(code: &str, used_by: uuid::Uuid) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::INFRA_INVITE_USE)
        .string(code)
        .bytes(used_by.as_bytes())
        .build()
}

pub fn invite_use_prefix(code: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::INFRA_INVITE_USE)
        .string(code)
        .build()
}

pub fn invite_by_account_key(did: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::INFRA_INVITE_BY_ACCOUNT)
        .string(did)
        .build()
}

pub fn invite_by_user_key(user_id: uuid::Uuid) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::INFRA_INVITE_BY_USER)
        .bytes(user_id.as_bytes())
        .build()
}

pub fn invite_by_user_prefix() -> SmallVec<[u8; 128]> {
    KeyBuilder::new().tag(KeyTag::INFRA_INVITE_BY_USER).build()
}

pub fn signing_key_key(public_key_did_key: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::INFRA_SIGNING_KEY)
        .string(public_key_did_key)
        .build()
}

pub fn signing_key_by_id_key(key_id: uuid::Uuid) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::INFRA_SIGNING_KEY_BY_ID)
        .bytes(key_id.as_bytes())
        .build()
}

pub fn deletion_request_key(token: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::INFRA_DELETION_REQUEST)
        .string(token)
        .build()
}

pub fn deletion_by_did_key(did: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::INFRA_DELETION_BY_DID)
        .string(did)
        .build()
}

pub fn deletion_by_did_prefix() -> SmallVec<[u8; 128]> {
    KeyBuilder::new().tag(KeyTag::INFRA_DELETION_BY_DID).build()
}

pub fn account_pref_key(user_id: uuid::Uuid, name: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::INFRA_ACCOUNT_PREF)
        .bytes(user_id.as_bytes())
        .string(name)
        .build()
}

pub fn account_pref_prefix(user_id: uuid::Uuid) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::INFRA_ACCOUNT_PREF)
        .bytes(user_id.as_bytes())
        .build()
}

pub fn server_config_key(key: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::INFRA_SERVER_CONFIG)
        .string(key)
        .build()
}

pub fn report_key(id: i64) -> SmallVec<[u8; 128]> {
    KeyBuilder::new().tag(KeyTag::INFRA_REPORT).i64(id).build()
}

pub fn plc_token_key(user_id: uuid::Uuid, token: &str) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::INFRA_PLC_TOKEN)
        .bytes(user_id.as_bytes())
        .string(token)
        .build()
}

pub fn plc_token_prefix(user_id: uuid::Uuid) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::INFRA_PLC_TOKEN)
        .bytes(user_id.as_bytes())
        .build()
}

pub fn comms_history_key(
    user_id: uuid::Uuid,
    created_at_ms: i64,
    seq: u32,
    id: uuid::Uuid,
) -> SmallVec<[u8; 128]> {
    let reversed_ts = i64::MAX.saturating_sub(created_at_ms);
    let reversed_seq = u32::MAX.saturating_sub(seq);
    KeyBuilder::new()
        .tag(KeyTag::INFRA_COMMS_HISTORY)
        .bytes(user_id.as_bytes())
        .i64(reversed_ts)
        .bytes(&reversed_seq.to_be_bytes())
        .bytes(id.as_bytes())
        .build()
}

pub fn comms_history_prefix(user_id: uuid::Uuid) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::INFRA_COMMS_HISTORY)
        .bytes(user_id.as_bytes())
        .build()
}

pub fn invite_code_used_by_key(user_id: uuid::Uuid) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::INFRA_INVITE_CODE_USED_BY)
        .bytes(user_id.as_bytes())
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metastore::encoding::KeyReader;

    #[test]
    fn queued_comms_value_roundtrip() {
        let val = QueuedCommsValue {
            id: uuid::Uuid::new_v4(),
            user_id: Some(uuid::Uuid::new_v4()),
            channel: 0,
            comms_type: 1,
            recipient: "user@example.com".to_owned(),
            subject: Some("test".to_owned()),
            body: "body text".to_owned(),
            metadata: None,
            status: 0,
            error_message: None,
            attempts: 0,
            max_attempts: 3,
            created_at_ms: 1700000000000,
            scheduled_for_ms: 1700000000000,
            sent_at_ms: None,
        };
        let bytes = val.serialize();
        assert_eq!(bytes[0], COMMS_SCHEMA_VERSION);
        let decoded = QueuedCommsValue::deserialize(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn invite_code_value_roundtrip() {
        let val = InviteCodeValue {
            code: "abc-def-ghi".to_owned(),
            available_uses: 5,
            disabled: false,
            for_account: Some("did:plc:test".to_owned()),
            created_by: Some(uuid::Uuid::new_v4()),
            created_at_ms: 1700000000000,
        };
        let bytes = val.serialize();
        assert_eq!(bytes[0], INVITE_CODE_SCHEMA_VERSION);
        let decoded = InviteCodeValue::deserialize(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn invite_use_value_roundtrip() {
        let val = InviteCodeUseValue {
            used_by: uuid::Uuid::new_v4(),
            used_at_ms: 1700000000000,
        };
        let bytes = val.serialize();
        let decoded = InviteCodeUseValue::deserialize(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn signing_key_value_roundtrip() {
        let val = SigningKeyValue {
            id: uuid::Uuid::new_v4(),
            did: Some("did:plc:test".to_owned()),
            public_key_did_key: "did:key:z123".to_owned(),
            private_key_bytes: vec![1, 2, 3, 4],
            used: false,
            created_at_ms: 1700000000000,
            expires_at_ms: 1700000600000,
            used_at_ms: None,
        };
        let bytes = val.serialize();
        let decoded = SigningKeyValue::deserialize(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn signing_key_value_v1_migration() {
        let v1 = SigningKeyValueV1 {
            id: uuid::Uuid::new_v4(),
            did: Some("did:plc:test".to_owned()),
            public_key_did_key: "did:key:z123".to_owned(),
            private_key_bytes: vec![1, 2, 3, 4],
            used: true,
            created_at_ms: 1700000000000,
            expires_at_ms: 1700000600000,
        };
        let payload = postcard::to_allocvec(&v1).unwrap();
        let mut bytes = Vec::with_capacity(1 + payload.len());
        bytes.push(SIGNING_KEY_SCHEMA_V1);
        bytes.extend_from_slice(&payload);

        let decoded = SigningKeyValue::deserialize(&bytes).unwrap();
        assert_eq!(decoded.id, v1.id);
        assert!(decoded.used);
        assert_eq!(decoded.used_at_ms, None);
    }

    #[test]
    fn deletion_request_value_roundtrip() {
        let val = DeletionRequestValue {
            token: "tok-abc".to_owned(),
            did: "did:plc:test".to_owned(),
            created_at_ms: 1700000000000,
            expires_at_ms: 1700000600000,
        };
        let bytes = val.serialize();
        let decoded = DeletionRequestValue::deserialize(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn report_value_roundtrip() {
        let val = ReportValue {
            id: 42,
            reason_type: "spam".to_owned(),
            reason: Some("bad content".to_owned()),
            subject_json: b"{}".to_vec(),
            reported_by_did: "did:plc:reporter".to_owned(),
            created_at_ms: 1700000000000,
        };
        let bytes = val.serialize();
        let decoded = ReportValue::deserialize(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn notification_history_value_roundtrip() {
        let val = NotificationHistoryValue {
            id: uuid::Uuid::new_v4(),
            channel: 0,
            comms_type: 1,
            recipient: "user@example.com".to_owned(),
            subject: None,
            body: "notification body".to_owned(),
            status: 2,
            created_at_ms: 1700000000000,
        };
        let bytes = val.serialize();
        let decoded = NotificationHistoryValue::deserialize(&bytes).unwrap();
        assert_eq!(val, decoded);
    }

    #[test]
    fn comms_queue_key_roundtrip() {
        let id = uuid::Uuid::new_v4();
        let key = comms_queue_key(id);
        let mut reader = KeyReader::new(&key);
        assert_eq!(reader.tag(), Some(KeyTag::INFRA_COMMS_QUEUE.raw()));
        let id_bytes = reader.bytes().unwrap();
        assert_eq!(uuid::Uuid::from_slice(&id_bytes).unwrap(), id);
        assert!(reader.is_empty());
    }

    #[test]
    fn invite_code_key_roundtrip() {
        let key = invite_code_key("abc-def");
        let mut reader = KeyReader::new(&key);
        assert_eq!(reader.tag(), Some(KeyTag::INFRA_INVITE_CODE.raw()));
        assert_eq!(reader.string(), Some("abc-def".to_owned()));
        assert!(reader.is_empty());
    }

    #[test]
    fn invite_use_key_roundtrip() {
        let user_id = uuid::Uuid::new_v4();
        let key = invite_use_key("code1", user_id);
        let mut reader = KeyReader::new(&key);
        assert_eq!(reader.tag(), Some(KeyTag::INFRA_INVITE_USE.raw()));
        assert_eq!(reader.string(), Some("code1".to_owned()));
        let id_bytes = reader.bytes().unwrap();
        assert_eq!(uuid::Uuid::from_slice(&id_bytes).unwrap(), user_id);
        assert!(reader.is_empty());
    }

    #[test]
    fn comms_history_newest_first_ordering() {
        let user_id = uuid::Uuid::new_v4();
        let id_a = uuid::Uuid::new_v4();
        let id_b = uuid::Uuid::new_v4();
        let key_old = comms_history_key(user_id, 1000, 0, id_a);
        let key_new = comms_history_key(user_id, 2000, 0, id_b);
        assert!(key_new.as_slice() < key_old.as_slice());
    }

    #[test]
    fn account_pref_key_roundtrip() {
        let user_id = uuid::Uuid::new_v4();
        let key = account_pref_key(user_id, "app.bsky.actor.profile");
        let mut reader = KeyReader::new(&key);
        assert_eq!(reader.tag(), Some(KeyTag::INFRA_ACCOUNT_PREF.raw()));
        let id_bytes = reader.bytes().unwrap();
        assert_eq!(uuid::Uuid::from_slice(&id_bytes).unwrap(), user_id);
        assert_eq!(reader.string(), Some("app.bsky.actor.profile".to_owned()));
        assert!(reader.is_empty());
    }

    #[test]
    fn plc_token_key_roundtrip() {
        let user_id = uuid::Uuid::new_v4();
        let key = plc_token_key(user_id, "tok123");
        let mut reader = KeyReader::new(&key);
        assert_eq!(reader.tag(), Some(KeyTag::INFRA_PLC_TOKEN.raw()));
        let id_bytes = reader.bytes().unwrap();
        assert_eq!(uuid::Uuid::from_slice(&id_bytes).unwrap(), user_id);
        assert_eq!(reader.string(), Some("tok123".to_owned()));
        assert!(reader.is_empty());
    }

    #[test]
    fn deserialize_unknown_version_returns_none() {
        let val = QueuedCommsValue {
            id: uuid::Uuid::new_v4(),
            user_id: None,
            channel: 0,
            comms_type: 0,
            recipient: String::new(),
            subject: None,
            body: String::new(),
            metadata: None,
            status: 0,
            error_message: None,
            attempts: 0,
            max_attempts: 3,
            created_at_ms: 0,
            scheduled_for_ms: 0,
            sent_at_ms: None,
        };
        let mut bytes = val.serialize();
        bytes[0] = 99;
        assert!(QueuedCommsValue::deserialize(&bytes).is_none());
    }

    #[test]
    fn channel_u8_roundtrip() {
        use tranquil_db_traits::CommsChannel;
        [
            CommsChannel::Email,
            CommsChannel::Discord,
            CommsChannel::Telegram,
            CommsChannel::Signal,
        ]
        .iter()
        .for_each(|&ch| {
            assert_eq!(u8_to_channel(channel_to_u8(ch)), Some(ch));
        });
    }

    #[test]
    fn comms_type_u8_roundtrip() {
        use tranquil_db_traits::CommsType;
        [
            CommsType::Welcome,
            CommsType::EmailVerification,
            CommsType::PasswordReset,
            CommsType::EmailUpdate,
            CommsType::AccountDeletion,
            CommsType::AdminEmail,
            CommsType::PlcOperation,
            CommsType::TwoFactorCode,
            CommsType::PasskeyRecovery,
            CommsType::LegacyLoginAlert,
            CommsType::MigrationVerification,
            CommsType::ChannelVerification,
            CommsType::ChannelVerified,
        ]
        .iter()
        .for_each(|&ct| {
            assert_eq!(u8_to_comms_type(comms_type_to_u8(ct)), Some(ct));
        });
    }

    #[test]
    fn status_u8_roundtrip() {
        use tranquil_db_traits::CommsStatus;
        [
            CommsStatus::Pending,
            CommsStatus::Processing,
            CommsStatus::Sent,
            CommsStatus::Failed,
        ]
        .iter()
        .for_each(|&s| {
            assert_eq!(u8_to_status(status_to_u8(s)), Some(s));
        });
    }

    #[test]
    fn u8_to_channel_invalid_returns_none() {
        assert!(u8_to_channel(255).is_none());
    }

    #[test]
    fn u8_to_comms_type_invalid_returns_none() {
        assert!(u8_to_comms_type(255).is_none());
    }

    #[test]
    fn u8_to_status_invalid_returns_none() {
        assert!(u8_to_status(255).is_none());
    }
}
