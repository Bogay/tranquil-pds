use serde::{Deserialize, Serialize};
use tranquil_db_traits::SequenceNumber;

pub const MAX_EVENT_PAYLOAD: u32 = u32::MAX;
pub const DEFAULT_MAX_EVENT_PAYLOAD: u32 = 256 * 1024 * 1024;
pub const DEFAULT_SEGMENT_SIZE: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EventSequence(u64);

impl EventSequence {
    pub const BEFORE_ALL: Self = Self(0);

    pub fn new(seq: u64) -> Self {
        assert!(
            seq > 0,
            "EventSequence must be positive; use BEFORE_ALL for cursor start"
        );
        Self(seq)
    }

    pub fn raw(self) -> u64 {
        self.0
    }

    pub fn next(self) -> Self {
        Self(self.0.checked_add(1).expect("EventSequence overflow"))
    }

    pub fn prev_or_before_all(self) -> Self {
        match self.0 {
            0 | 1 => Self::BEFORE_ALL,
            n => Self(n - 1),
        }
    }

    pub fn as_i64(self) -> i64 {
        i64::try_from(self.0).expect("EventSequence exceeds i64::MAX")
    }

    pub fn from_i64(n: i64) -> Option<Self> {
        match u64::try_from(n) {
            Ok(0) | Err(_) => None,
            Ok(v) => Some(Self(v)),
        }
    }

    pub fn cursor_from_i64(n: i64) -> Option<Self> {
        u64::try_from(n).ok().map(Self)
    }
}

impl From<EventSequence> for SequenceNumber {
    fn from(es: EventSequence) -> Self {
        SequenceNumber::from_raw(es.as_i64())
    }
}

impl TryFrom<SequenceNumber> for EventSequence {
    type Error = &'static str;

    fn try_from(seq: SequenceNumber) -> Result<Self, Self::Error> {
        let raw = seq.as_i64();
        match u64::try_from(raw) {
            Ok(0) => Err("SequenceNumber 0 maps to BEFORE_ALL, not a valid EventSequence"),
            Ok(v) => Ok(Self(v)),
            Err(_) => Err("negative SequenceNumber cannot convert to EventSequence"),
        }
    }
}

impl std::fmt::Display for EventSequence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SegmentId(u32);

impl SegmentId {
    pub fn new(id: u32) -> Self {
        Self(id)
    }

    pub fn raw(self) -> u32 {
        self.0
    }

    pub fn next(self) -> Self {
        Self(self.0.checked_add(1).expect("SegmentId overflow"))
    }
}

impl std::fmt::Display for SegmentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:08}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SegmentOffset(u64);

impl SegmentOffset {
    pub const fn new(offset: u64) -> Self {
        Self(offset)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    pub fn advance(self, delta: u64) -> Self {
        Self(self.0.checked_add(delta).expect("SegmentOffset overflow"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EventLength(u32);

impl EventLength {
    pub fn new(length: u32) -> Self {
        Self(length)
    }

    pub fn raw(self) -> u32 {
        self.0
    }

    pub fn as_u64(self) -> u64 {
        u64::from(self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DidHash(u32);

impl DidHash {
    pub fn from_did(did: &str) -> Self {
        Self(xxhash_rust::xxh3::xxh3_64(did.as_bytes()) as u32)
    }

    pub fn from_raw(hash: u32) -> Self {
        Self(hash)
    }

    pub fn raw(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct EventTypeTag(u8);

impl EventTypeTag {
    pub const COMMIT: Self = Self(1);
    pub const IDENTITY: Self = Self(2);
    pub const ACCOUNT: Self = Self(3);
    pub const SYNC: Self = Self(4);

    pub fn from_raw(tag: u8) -> Option<Self> {
        match tag {
            1..=4 => Some(Self(tag)),
            _ => None,
        }
    }

    pub fn raw(self) -> u8 {
        self.0
    }

    pub fn to_repo_event_type(self) -> tranquil_db_traits::RepoEventType {
        match self {
            Self::COMMIT => tranquil_db_traits::RepoEventType::Commit,
            Self::IDENTITY => tranquil_db_traits::RepoEventType::Identity,
            Self::ACCOUNT => tranquil_db_traits::RepoEventType::Account,
            Self::SYNC => tranquil_db_traits::RepoEventType::Sync,
            _ => unreachable!("EventTypeTag invariant guarantees valid discriminant"),
        }
    }
}

impl<'de> Deserialize<'de> for EventTypeTag {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = u8::deserialize(deserializer)?;
        Self::from_raw(raw)
            .ok_or_else(|| serde::de::Error::custom(format_args!("invalid EventTypeTag: {raw}")))
    }
}

impl std::fmt::Display for EventTypeTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::COMMIT => write!(f, "Commit"),
            Self::IDENTITY => write!(f, "Identity"),
            Self::ACCOUNT => write!(f, "Account"),
            Self::SYNC => write!(f, "Sync"),
            _ => unreachable!("EventTypeTag invariant violated: raw value {}", self.0),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TimestampMicros(u64);

impl TimestampMicros {
    pub fn new(us: u64) -> Self {
        Self(us)
    }

    pub fn raw(self) -> u64 {
        self.0
    }

    pub fn now() -> Self {
        let duration = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before unix epoch");
        Self(
            duration
                .as_secs()
                .saturating_mul(1_000_000)
                .saturating_add(u64::from(duration.subsec_micros())),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_sequence_lifecycle() {
        let seq = EventSequence::new(1);
        assert_eq!(seq.raw(), 1);
        assert_eq!(seq.next(), EventSequence::new(2));
        assert_eq!(seq.as_i64(), 1);
    }

    #[test]
    fn event_sequence_before_all() {
        assert_eq!(EventSequence::BEFORE_ALL.raw(), 0);
    }

    #[test]
    fn event_sequence_prev_or_before_all() {
        assert_eq!(
            EventSequence::BEFORE_ALL.prev_or_before_all(),
            EventSequence::BEFORE_ALL
        );
        assert_eq!(
            EventSequence::new(1).prev_or_before_all(),
            EventSequence::BEFORE_ALL
        );
        assert_eq!(
            EventSequence::new(2).prev_or_before_all(),
            EventSequence::new(1)
        );
        assert_eq!(
            EventSequence::new(100).prev_or_before_all(),
            EventSequence::new(99)
        );
    }

    #[test]
    #[should_panic(expected = "EventSequence must be positive")]
    fn event_sequence_zero_panics() {
        EventSequence::new(0);
    }

    #[test]
    fn event_sequence_i64_round_trip() {
        let seq = EventSequence::new(42);
        let as_i64 = seq.as_i64();
        assert_eq!(EventSequence::from_i64(as_i64), Some(seq));
    }

    #[test]
    fn event_sequence_from_i64_rejects_zero_and_negative() {
        assert_eq!(EventSequence::from_i64(0), None);
        assert_eq!(EventSequence::from_i64(-1), None);
    }

    #[test]
    fn event_sequence_cursor_from_i64_allows_zero() {
        assert_eq!(
            EventSequence::cursor_from_i64(0),
            Some(EventSequence::BEFORE_ALL)
        );
        assert_eq!(
            EventSequence::cursor_from_i64(1),
            Some(EventSequence::new(1))
        );
        assert_eq!(EventSequence::cursor_from_i64(-1), None);
    }

    #[test]
    #[should_panic(expected = "EventSequence overflow")]
    fn event_sequence_overflow_panics() {
        EventSequence::new(u64::MAX).next();
    }

    #[test]
    fn segment_id_display_zero_padded() {
        assert_eq!(SegmentId::new(0).to_string(), "00000000");
        assert_eq!(SegmentId::new(1).to_string(), "00000001");
        assert_eq!(SegmentId::new(99999999).to_string(), "99999999");
    }

    #[test]
    fn segment_id_next_increments() {
        assert_eq!(SegmentId::new(0).next(), SegmentId::new(1));
        assert_eq!(SegmentId::new(99).next(), SegmentId::new(100));
    }

    #[test]
    #[should_panic(expected = "SegmentId overflow")]
    fn segment_id_overflow_panics() {
        SegmentId::new(u32::MAX).next();
    }

    #[test]
    fn segment_offset_advance() {
        let offset = SegmentOffset::new(100);
        assert_eq!(offset.advance(50), SegmentOffset::new(150));
    }

    #[test]
    #[should_panic(expected = "SegmentOffset overflow")]
    fn segment_offset_overflow_panics() {
        SegmentOffset::new(u64::MAX).advance(1);
    }

    #[test]
    fn event_length_valid() {
        let len = EventLength::new(1024);
        assert_eq!(len.raw(), 1024);
        assert_eq!(len.as_u64(), 1024);
    }

    #[test]
    fn event_length_max_accepted() {
        let len = EventLength::new(MAX_EVENT_PAYLOAD);
        assert_eq!(len.raw(), MAX_EVENT_PAYLOAD);
    }

    #[test]
    fn did_hash_deterministic() {
        let hash1 = DidHash::from_did("did:plc:abc123");
        let hash2 = DidHash::from_did("did:plc:abc123");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn did_hash_different_dids_differ() {
        let hash1 = DidHash::from_did("did:plc:abc123");
        let hash2 = DidHash::from_did("did:plc:xyz789");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn event_type_tag_known_variants() {
        assert_eq!(EventTypeTag::COMMIT.raw(), 1);
        assert_eq!(EventTypeTag::IDENTITY.raw(), 2);
        assert_eq!(EventTypeTag::ACCOUNT.raw(), 3);
        assert_eq!(EventTypeTag::SYNC.raw(), 4);
    }

    #[test]
    fn event_type_tag_from_raw_valid() {
        assert_eq!(EventTypeTag::from_raw(1), Some(EventTypeTag::COMMIT));
        assert_eq!(EventTypeTag::from_raw(2), Some(EventTypeTag::IDENTITY));
        assert_eq!(EventTypeTag::from_raw(3), Some(EventTypeTag::ACCOUNT));
        assert_eq!(EventTypeTag::from_raw(4), Some(EventTypeTag::SYNC));
    }

    #[test]
    fn event_type_tag_from_raw_invalid() {
        assert_eq!(EventTypeTag::from_raw(0), None);
        assert_eq!(EventTypeTag::from_raw(5), None);
        assert_eq!(EventTypeTag::from_raw(255), None);
    }

    #[test]
    fn event_type_tag_display() {
        assert_eq!(EventTypeTag::COMMIT.to_string(), "Commit");
        assert_eq!(EventTypeTag::IDENTITY.to_string(), "Identity");
        assert_eq!(EventTypeTag::ACCOUNT.to_string(), "Account");
        assert_eq!(EventTypeTag::SYNC.to_string(), "Sync");
    }

    #[test]
    fn timestamp_micros_round_trip() {
        let ts = TimestampMicros::new(1_700_000_000_000_000);
        assert_eq!(ts.raw(), 1_700_000_000_000_000);
    }

    #[test]
    fn timestamp_micros_now_is_reasonable() {
        let ts = TimestampMicros::now();
        assert!(ts.raw() > 1_700_000_000_000_000);
    }

    #[test]
    fn postcard_round_trip_event_sequence() {
        let seq = EventSequence::new(42);
        let bytes = postcard::to_allocvec(&seq).unwrap();
        let decoded: EventSequence = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(seq, decoded);
    }

    #[test]
    fn postcard_round_trip_segment_id() {
        let id = SegmentId::new(7);
        let bytes = postcard::to_allocvec(&id).unwrap();
        let decoded: SegmentId = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn postcard_round_trip_did_hash() {
        let hash = DidHash::from_did("did:plc:test");
        let bytes = postcard::to_allocvec(&hash).unwrap();
        let decoded: DidHash = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(hash, decoded);
    }

    #[test]
    fn postcard_round_trip_event_type_tag() {
        let tag = EventTypeTag::COMMIT;
        let bytes = postcard::to_allocvec(&tag).unwrap();
        let decoded: EventTypeTag = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(tag, decoded);
    }

    #[test]
    fn postcard_round_trip_timestamp_micros() {
        let ts = TimestampMicros::new(1_700_000_000_000_000);
        let bytes = postcard::to_allocvec(&ts).unwrap();
        let decoded: TimestampMicros = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ts, decoded);
    }

    #[test]
    fn postcard_rejects_invalid_event_type_tag() {
        let bytes = postcard::to_allocvec(&0u8).unwrap();
        assert!(postcard::from_bytes::<EventTypeTag>(&bytes).is_err());

        let bytes = postcard::to_allocvec(&5u8).unwrap();
        assert!(postcard::from_bytes::<EventTypeTag>(&bytes).is_err());

        let bytes = postcard::to_allocvec(&255u8).unwrap();
        assert!(postcard::from_bytes::<EventTypeTag>(&bytes).is_err());
    }

    #[test]
    fn event_sequence_to_sequence_number() {
        let es = EventSequence::new(42);
        let sn: SequenceNumber = es.into();
        assert_eq!(sn.as_i64(), 42);
    }

    #[test]
    fn event_sequence_before_all_to_sequence_number() {
        let sn: SequenceNumber = EventSequence::BEFORE_ALL.into();
        assert_eq!(sn, SequenceNumber::ZERO);
    }

    #[test]
    fn sequence_number_to_event_sequence() {
        let sn = SequenceNumber::from_raw(42);
        let es = EventSequence::try_from(sn).unwrap();
        assert_eq!(es.raw(), 42);
    }

    #[test]
    fn sequence_number_zero_rejects_to_event_sequence() {
        let result = EventSequence::try_from(SequenceNumber::ZERO);
        assert!(result.is_err());
    }

    #[test]
    fn sequence_number_negative_rejects_to_event_sequence() {
        let result = EventSequence::try_from(SequenceNumber::from_raw(-1));
        assert!(result.is_err());
    }

    #[test]
    fn postcard_accepts_max_event_length() {
        let bytes = postcard::to_allocvec(&MAX_EVENT_PAYLOAD).unwrap();
        let decoded: EventLength = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.raw(), MAX_EVENT_PAYLOAD);
    }
}
