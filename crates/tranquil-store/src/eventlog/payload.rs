use serde::{Deserialize, Serialize};
use tranquil_db_traits::{
    AccountStatus, EventBlockInline, EventBlocks, SequenceNumber, SequencedEvent,
};
use tranquil_types::{CidLink, Did, Handle};

use crate::eventlog::reader::RawEvent;

pub(crate) const PAYLOAD_VERSION_V1: u8 = 1;
const CURRENT_PAYLOAD_VERSION: u8 = PAYLOAD_VERSION_V1;
const LARGE_PAYLOAD_WARNING_THRESHOLD: usize = 4 * 1024 * 1024;

pub(crate) const CID_BYTE_LEN: usize = 36;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventPayload {
    pub did: String,
    pub commit_cid: Option<Vec<u8>>,
    pub prev_cid: Option<Vec<u8>>,
    pub prev_data_cid: Option<Vec<u8>>,
    pub ops: Option<Vec<u8>>,
    pub blobs: Option<Vec<String>>,
    pub blocks: Option<Vec<EventBlockInline>>,
    pub handle: Option<String>,
    pub active: Option<bool>,
    pub status: Option<u8>,
    pub rev: Option<String>,
    pub mutation_set: Option<Vec<u8>>,
}

#[derive(Debug, thiserror::Error)]
pub enum PayloadError {
    #[error("payload too large: {size} bytes exceeds max {max}")]
    TooLarge { size: usize, max: usize },
    #[error("deserialization failed: {0}")]
    DeserializeFailed(postcard::Error),
    #[error("unknown payload version: {0}")]
    UnknownVersion(u8),
    #[error("invalid DID in payload: {0}")]
    InvalidDid(String),
    #[error("invalid timestamp: {0}")]
    InvalidTimestamp(u64),
    #[error("invalid ops DAG-CBOR in payload: {0}")]
    InvalidDagCborOps(String),
    #[error("invalid handle in payload: {0}")]
    InvalidHandle(String),
    #[error("invalid CID length: got {got}, expected {expected}")]
    InvalidCidLength { got: usize, expected: usize },
}

fn cid_link_to_bytes(cid: &CidLink) -> Option<Vec<u8>> {
    let c = cid.to_cid()?;
    let raw = c.to_bytes();
    (raw.len() == CID_BYTE_LEN).then_some(raw)
}

fn bytes_to_cid_link(bytes: &[u8]) -> Result<Option<CidLink>, PayloadError> {
    if bytes.len() != CID_BYTE_LEN {
        return Err(PayloadError::InvalidCidLength {
            got: bytes.len(),
            expected: CID_BYTE_LEN,
        });
    }
    Ok(cid::Cid::read_bytes(bytes)
        .ok()
        .map(|c| CidLink::from_cid(&c)))
}

fn account_status_to_u8(status: &AccountStatus) -> u8 {
    match status {
        AccountStatus::Active => 0,
        AccountStatus::Takendown => 1,
        AccountStatus::Suspended => 2,
        AccountStatus::Deactivated => 3,
        AccountStatus::Deleted => 4,
    }
}

fn u8_to_account_status(tag: u8) -> Option<AccountStatus> {
    match tag {
        0 => Some(AccountStatus::Active),
        1 => Some(AccountStatus::Takendown),
        2 => Some(AccountStatus::Suspended),
        3 => Some(AccountStatus::Deactivated),
        4 => Some(AccountStatus::Deleted),
        _ => None,
    }
}

pub fn encode_payload(event: &SequencedEvent) -> Vec<u8> {
    encode_payload_with_mutations(event, None)
}

pub fn encode_payload_with_mutations(
    event: &SequencedEvent,
    mutation_set: Option<&[u8]>,
) -> Vec<u8> {
    let ops_bytes = event
        .ops
        .as_ref()
        .map(|v| serde_ipld_dagcbor::to_vec(v).expect("serde_json::Value serializes to DAG-CBOR"));

    let payload = EventPayload {
        did: event.did.as_str().to_owned(),
        commit_cid: event.commit_cid.as_ref().and_then(cid_link_to_bytes),
        prev_cid: event.prev_cid.as_ref().and_then(cid_link_to_bytes),
        prev_data_cid: event.prev_data_cid.as_ref().and_then(cid_link_to_bytes),
        ops: ops_bytes,
        blobs: event.blobs.clone(),
        blocks: match event.blocks.as_ref() {
            Some(EventBlocks::Inline(v)) => Some(v.clone()),
            Some(EventBlocks::LegacyCids(_)) | None => None,
        },
        handle: event
            .handle
            .as_ref()
            .map(|h: &Handle| h.as_str().to_owned()),
        active: event.active,
        status: event.status.as_ref().map(account_status_to_u8),
        rev: event.rev.clone(),
        mutation_set: mutation_set.map(|b| b.to_vec()),
    };

    let body = postcard::to_allocvec(&payload).expect("EventPayload serialization is infallible");

    if body.len() > LARGE_PAYLOAD_WARNING_THRESHOLD {
        tracing::warn!(
            size = body.len(),
            did = %event.did,
            "unusually large event payload"
        );
    }

    let mut buf = Vec::with_capacity(1 + body.len());
    buf.push(CURRENT_PAYLOAD_VERSION);
    buf.extend_from_slice(&body);
    buf
}

pub fn decode_payload(bytes: &[u8]) -> Result<EventPayload, PayloadError> {
    let (&version, body) = bytes.split_first().ok_or(PayloadError::DeserializeFailed(
        postcard::Error::DeserializeUnexpectedEnd,
    ))?;

    if version != PAYLOAD_VERSION_V1 {
        return Err(PayloadError::UnknownVersion(version));
    }

    postcard::from_bytes(body).map_err(PayloadError::DeserializeFailed)
}

pub fn validate_payload_size(payload: &[u8], max_payload: u32) -> Result<(), PayloadError> {
    let max = max_payload as usize;
    if payload.len() > max {
        return Err(PayloadError::TooLarge {
            size: payload.len(),
            max,
        });
    }
    Ok(())
}

pub fn to_sequenced_event(
    raw: &RawEvent,
    payload: &EventPayload,
) -> Result<SequencedEvent, PayloadError> {
    let timestamp_secs = raw.timestamp.raw() / 1_000_000;
    let timestamp_secs_i64 = i64::try_from(timestamp_secs)
        .map_err(|_| PayloadError::InvalidTimestamp(raw.timestamp.raw()))?;
    let timestamp_subsec_us =
        u32::try_from(raw.timestamp.raw() % 1_000_000).expect("modulo 1M always fits u32");

    let created_at =
        chrono::DateTime::from_timestamp(timestamp_secs_i64, timestamp_subsec_us * 1_000)
            .unwrap_or_default();

    let did = Did::new(&payload.did).map_err(|_| PayloadError::InvalidDid(payload.did.clone()))?;

    let ops = payload
        .ops
        .as_ref()
        .map(|bytes| {
            serde_ipld_dagcbor::from_slice(bytes)
                .map_err(|e| PayloadError::InvalidDagCborOps(e.to_string()))
        })
        .transpose()?;

    let handle = payload
        .handle
        .as_ref()
        .map(|h| Handle::new(h.as_str()).map_err(|_| PayloadError::InvalidHandle(h.clone())))
        .transpose()?;

    Ok(SequencedEvent {
        seq: SequenceNumber::from_raw(raw.seq.as_i64()),
        did,
        created_at,
        event_type: raw.event_type.to_repo_event_type(),
        commit_cid: payload
            .commit_cid
            .as_deref()
            .map(bytes_to_cid_link)
            .transpose()?
            .flatten(),
        prev_cid: payload
            .prev_cid
            .as_deref()
            .map(bytes_to_cid_link)
            .transpose()?
            .flatten(),
        prev_data_cid: payload
            .prev_data_cid
            .as_deref()
            .map(bytes_to_cid_link)
            .transpose()?
            .flatten(),
        ops,
        blobs: payload.blobs.clone(),
        blocks: payload.blocks.clone().map(EventBlocks::Inline),
        handle,
        active: payload.active,
        status: payload.status.and_then(u8_to_account_status),
        rev: payload.rev.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eventlog::types::{DidHash, EventSequence, EventTypeTag, TimestampMicros};
    use bytes::Bytes;
    use sha2::Digest;
    use tranquil_db_traits::RepoEventType;

    fn test_did() -> Did {
        Did::new("did:plc:testuser1234567890abcdef").unwrap()
    }

    fn test_cid_link() -> CidLink {
        let hash = sha2::Digest::finalize(sha2::Sha256::new());
        let mh = multihash::Multihash::<64>::wrap(0x12, &hash).unwrap();
        let c = cid::Cid::new_v1(0x71, mh);
        CidLink::from_cid(&c)
    }

    #[test]
    fn round_trip_minimal_payload() {
        let event = SequencedEvent {
            seq: SequenceNumber::from_raw(42),
            did: test_did(),
            created_at: chrono::Utc::now(),
            event_type: RepoEventType::Account,
            commit_cid: None,
            prev_cid: None,
            prev_data_cid: None,
            ops: None,
            blobs: None,
            blocks: None,
            handle: None,
            active: Some(true),
            status: Some(AccountStatus::Active),
            rev: None,
        };

        let encoded = encode_payload(&event);
        assert_eq!(encoded[0], CURRENT_PAYLOAD_VERSION);

        let decoded = decode_payload(&encoded).unwrap();
        assert_eq!(decoded.did, event.did.as_str());
        assert_eq!(decoded.active, Some(true));
        assert_eq!(decoded.status, Some(0));
        assert!(decoded.commit_cid.is_none());
    }

    #[test]
    fn round_trip_full_commit_payload() {
        let cid = test_cid_link();
        let ops = serde_json::json!([{"action": "create", "path": "app.bsky.feed.post/abc"}]);

        let event = SequencedEvent {
            seq: SequenceNumber::from_raw(100),
            did: test_did(),
            created_at: chrono::Utc::now(),
            event_type: RepoEventType::Commit,
            commit_cid: Some(cid.clone()),
            prev_cid: Some(cid.clone()),
            prev_data_cid: Some(cid.clone()),
            ops: Some(ops.clone()),
            blobs: Some(vec!["bafkreibtest".to_owned()]),
            blocks: Some(EventBlocks::Inline(vec![EventBlockInline {
                cid_bytes: cid_link_to_bytes(&cid).unwrap(),
                data: b"hello block".to_vec(),
            }])),
            handle: Some(Handle::new("test.bsky.social").unwrap()),
            active: None,
            status: None,
            rev: Some("rev123".to_owned()),
        };

        let encoded = encode_payload(&event);
        let decoded = decode_payload(&encoded).unwrap();

        let raw = RawEvent {
            seq: EventSequence::new(100),
            timestamp: TimestampMicros::now(),
            did_hash: DidHash::from_did(event.did.as_str()),
            event_type: EventTypeTag::COMMIT,
            payload: Bytes::from(encoded),
        };

        let reconstructed = to_sequenced_event(&raw, &decoded).unwrap();
        assert_eq!(reconstructed.did.as_str(), event.did.as_str());
        assert_eq!(reconstructed.commit_cid, event.commit_cid);
        assert_eq!(reconstructed.prev_cid, event.prev_cid);
        assert_eq!(reconstructed.prev_data_cid, event.prev_data_cid);
        assert_eq!(reconstructed.blobs, event.blobs);
        let inline_len = |b: &EventBlocks| match b {
            EventBlocks::Inline(v) => v.len(),
            EventBlocks::LegacyCids(_) => 0,
        };
        assert_eq!(
            reconstructed.blocks.as_ref().map(inline_len),
            event.blocks.as_ref().map(inline_len)
        );
        assert_eq!(
            reconstructed.handle.as_ref().map(|h: &Handle| h.as_str()),
            event.handle.as_ref().map(|h: &Handle| h.as_str())
        );
        assert_eq!(reconstructed.rev, event.rev);
        assert_eq!(reconstructed.event_type, RepoEventType::Commit);

        let reconstructed_ops = reconstructed.ops.unwrap();
        assert_eq!(reconstructed_ops, ops);
    }

    #[test]
    fn unknown_version_rejected() {
        let mut encoded = encode_payload(&SequencedEvent {
            seq: SequenceNumber::from_raw(1),
            did: test_did(),
            created_at: chrono::Utc::now(),
            event_type: RepoEventType::Identity,
            commit_cid: None,
            prev_cid: None,
            prev_data_cid: None,
            ops: None,
            blobs: None,
            blocks: None,
            handle: None,
            active: None,
            status: None,
            rev: None,
        });

        encoded[0] = 99;
        match decode_payload(&encoded) {
            Err(PayloadError::UnknownVersion(99)) => {}
            other => panic!("expected UnknownVersion(99), got {other:?}"),
        }
    }

    #[test]
    fn empty_payload_rejected() {
        match decode_payload(&[]) {
            Err(PayloadError::DeserializeFailed(_)) => {}
            other => panic!("expected DeserializeFailed, got {other:?}"),
        }
    }

    #[test]
    fn validate_payload_size_accepts_within_limit() {
        let data = vec![0u8; 1024];
        assert!(validate_payload_size(&data, 4096).is_ok());
    }

    #[test]
    fn validate_payload_size_rejects_oversized() {
        let limit: u32 = 1024;
        let data = vec![0u8; limit as usize + 1];
        match validate_payload_size(&data, limit) {
            Err(PayloadError::TooLarge { size, max }) => {
                assert_eq!(size, limit as usize + 1);
                assert_eq!(max, limit as usize);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn account_status_round_trip() {
        let statuses = [
            AccountStatus::Active,
            AccountStatus::Takendown,
            AccountStatus::Suspended,
            AccountStatus::Deactivated,
            AccountStatus::Deleted,
        ];

        statuses.iter().for_each(|status| {
            let tag = account_status_to_u8(status);
            let recovered = u8_to_account_status(tag).unwrap();
            assert_eq!(&recovered, status);
        });
    }

    #[test]
    fn invalid_account_status_returns_none() {
        assert!(u8_to_account_status(255).is_none());
    }

    #[test]
    fn cid_bytes_round_trip() {
        let cid = test_cid_link();
        let bytes = cid_link_to_bytes(&cid).unwrap();
        assert_eq!(bytes.len(), CID_BYTE_LEN);
        let recovered = bytes_to_cid_link(&bytes).unwrap().unwrap();
        assert_eq!(cid, recovered);
    }

    #[test]
    fn cid_bytes_wrong_length_rejected() {
        let short = vec![0u8; 10];
        match bytes_to_cid_link(&short) {
            Err(PayloadError::InvalidCidLength {
                got: 10,
                expected: 36,
            }) => {}
            other => panic!("expected InvalidCidLength, got {other:?}"),
        }
    }

    #[test]
    fn event_type_tag_mapping() {
        assert_eq!(
            EventTypeTag::COMMIT.to_repo_event_type(),
            RepoEventType::Commit
        );
        assert_eq!(
            EventTypeTag::IDENTITY.to_repo_event_type(),
            RepoEventType::Identity
        );
        assert_eq!(
            EventTypeTag::ACCOUNT.to_repo_event_type(),
            RepoEventType::Account
        );
        assert_eq!(EventTypeTag::SYNC.to_repo_event_type(), RepoEventType::Sync);
    }

    #[test]
    fn timestamp_microseconds_preserved() {
        let us = 1_700_000_000_123_456u64;
        let raw = RawEvent {
            seq: EventSequence::new(1),
            timestamp: TimestampMicros::new(us),
            did_hash: DidHash::from_did("did:plc:test"),
            event_type: EventTypeTag::COMMIT,
            payload: Bytes::from_static(&[PAYLOAD_VERSION_V1]),
        };

        let payload = EventPayload {
            did: "did:plc:testuser1234567890abcdef".to_owned(),
            commit_cid: None,
            prev_cid: None,
            prev_data_cid: None,
            ops: None,
            blobs: None,
            blocks: None,
            handle: None,
            active: None,
            status: None,
            rev: None,
            mutation_set: None,
        };

        let event = to_sequenced_event(&raw, &payload).unwrap();
        let recovered_us = u64::try_from(event.created_at.timestamp_micros()).unwrap();
        assert_eq!(recovered_us, us);
    }
}
