use std::cell::Cell;
use std::io;
use std::path::Path;

use crate::io::{FileId, OpenOptions, StorageIO};
use crate::record::{RecordReader, RecordWriter};

use super::payload::{CID_BYTE_LEN, PAYLOAD_VERSION_V1};
use super::segment_file::{
    EVENT_HEADER_SIZE, ReadEventRecord, SEGMENT_HEADER_SIZE, SEGMENT_MAGIC, decode_event_record,
};
use super::types::{DidHash, EventSequence, EventTypeTag, SegmentOffset, TimestampMicros};

pub const SIDECAR_MAGIC: [u8; 4] = *b"TQSC";
pub const SIDECAR_VERSION: u8 = 1;
pub const SIDECAR_HEADER_SIZE: usize = 16;
pub const SIDECAR_ENTRY_SIZE: usize = 64;

const MAX_SIDECAR_ENTRIES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SidecarEntry {
    pub seq: u64,
    pub timestamp: u64,
    pub did_hash: u32,
    pub event_type: u8,
    pub active: u8,
    pub status: u8,
    pub did_offset: u32,
    pub did_len: u16,
    pub commit_cid_offset: u32,
    pub prev_cid_offset: u32,
    pub prev_data_cid_offset: u32,
    pub ops_offset: u32,
    pub ops_len: u32,
    pub rev_offset: u32,
    pub rev_len: u16,
    pub handle_offset: u32,
    pub handle_len: u16,
}

impl SidecarEntry {
    fn encode(&self, buf: &mut [u8; SIDECAR_ENTRY_SIZE]) {
        buf[0..8].copy_from_slice(&self.seq.to_le_bytes());
        buf[8..16].copy_from_slice(&self.timestamp.to_le_bytes());
        buf[16..20].copy_from_slice(&self.did_hash.to_le_bytes());
        buf[20] = self.event_type;
        buf[21] = self.active;
        buf[22] = self.status;
        buf[23] = 0;
        buf[24..28].copy_from_slice(&self.did_offset.to_le_bytes());
        buf[28..30].copy_from_slice(&self.did_len.to_le_bytes());
        buf[30..34].copy_from_slice(&self.commit_cid_offset.to_le_bytes());
        buf[34..38].copy_from_slice(&self.prev_cid_offset.to_le_bytes());
        buf[38..42].copy_from_slice(&self.prev_data_cid_offset.to_le_bytes());
        buf[42..46].copy_from_slice(&self.ops_offset.to_le_bytes());
        buf[46..50].copy_from_slice(&self.ops_len.to_le_bytes());
        buf[50..54].copy_from_slice(&self.rev_offset.to_le_bytes());
        buf[54..56].copy_from_slice(&self.rev_len.to_le_bytes());
        buf[56..60].copy_from_slice(&self.handle_offset.to_le_bytes());
        buf[60..62].copy_from_slice(&self.handle_len.to_le_bytes());
        buf[62..64].copy_from_slice(&[0u8; 2]);
    }

    fn decode(buf: &[u8; SIDECAR_ENTRY_SIZE]) -> Self {
        Self {
            seq: u64::from_le_bytes(buf[0..8].try_into().unwrap()),
            timestamp: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            did_hash: u32::from_le_bytes(buf[16..20].try_into().unwrap()),
            event_type: buf[20],
            active: buf[21],
            status: buf[22],
            did_offset: u32::from_le_bytes(buf[24..28].try_into().unwrap()),
            did_len: u16::from_le_bytes(buf[28..30].try_into().unwrap()),
            commit_cid_offset: u32::from_le_bytes(buf[30..34].try_into().unwrap()),
            prev_cid_offset: u32::from_le_bytes(buf[34..38].try_into().unwrap()),
            prev_data_cid_offset: u32::from_le_bytes(buf[38..42].try_into().unwrap()),
            ops_offset: u32::from_le_bytes(buf[42..46].try_into().unwrap()),
            ops_len: u32::from_le_bytes(buf[46..50].try_into().unwrap()),
            rev_offset: u32::from_le_bytes(buf[50..54].try_into().unwrap()),
            rev_len: u16::from_le_bytes(buf[54..56].try_into().unwrap()),
            handle_offset: u32::from_le_bytes(buf[56..60].try_into().unwrap()),
            handle_len: u16::from_le_bytes(buf[60..62].try_into().unwrap()),
        }
    }

    pub fn seq(&self) -> EventSequence {
        EventSequence::new(self.seq)
    }

    pub fn timestamp(&self) -> TimestampMicros {
        TimestampMicros::new(self.timestamp)
    }

    pub fn did_hash(&self) -> DidHash {
        DidHash::from_raw(self.did_hash)
    }

    pub fn event_type_tag(&self) -> Option<EventTypeTag> {
        EventTypeTag::from_raw(self.event_type)
    }

    pub fn has_ops(&self) -> bool {
        self.ops_offset != 0
    }

    pub fn has_commit_cid(&self) -> bool {
        self.commit_cid_offset != 0
    }

    pub fn cid_byte_len(&self) -> usize {
        CID_BYTE_LEN
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarIndex {
    entries: Vec<SidecarEntry>,
}

impl SidecarIndex {
    pub fn new(entries: Vec<SidecarEntry>) -> Self {
        Self { entries }
    }

    pub fn entries(&self) -> &[SidecarEntry] {
        &self.entries
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn lookup_by_seq(&self, target_seq: EventSequence) -> Option<&SidecarEntry> {
        let target = target_seq.raw();
        self.entries
            .binary_search_by_key(&target, |e| e.seq)
            .ok()
            .map(|idx| &self.entries[idx])
    }

    pub fn first_seq(&self) -> Option<EventSequence> {
        self.entries.first().map(|e| EventSequence::new(e.seq))
    }

    pub fn last_seq(&self) -> Option<EventSequence> {
        self.entries.last().map(|e| EventSequence::new(e.seq))
    }

    pub fn save<S: StorageIO>(&self, io: &S, path: &Path) -> io::Result<()> {
        let tmp_path = path.with_extension("tqs.tmp");
        let fd = io.open(&tmp_path, OpenOptions::read_write())?;

        let result = (|| {
            let data = self.serialize();
            let mut writer = RecordWriter::new(io, fd)?;
            writer.append(&data)?;
            io.truncate(fd, writer.position())?;
            writer.sync()?;
            Ok(())
        })();

        if let Err(e) = result {
            let _ = io.close(fd);
            return Err(e);
        }
        io.close(fd)?;

        if let Err(e) = io.rename(&tmp_path, path) {
            let _ = io.delete(&tmp_path);
            return Err(e);
        }
        if let Some(parent) = path.parent() {
            io.sync_dir(parent)?;
        }
        Ok(())
    }

    pub fn load<S: StorageIO>(io: &S, path: &Path) -> io::Result<Option<Self>> {
        let fd = match io.open(path, OpenOptions::read_only_existing()) {
            Ok(fd) => fd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };

        let reader = match RecordReader::open(io, fd) {
            Ok(r) => r,
            Err(e) => {
                let _ = io.close(fd);
                return Err(e);
            }
        };
        let records = reader.valid_records();
        io.close(fd)?;

        let data = records.into_iter().next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "sidecar file contains no records",
            )
        })?;

        Self::deserialize(&data).map(Some)
    }

    fn serialize(&self) -> Vec<u8> {
        let entry_count = u32::try_from(self.entries.len()).expect("entry count fits u32");
        let total_size = SIDECAR_HEADER_SIZE + self.entries.len() * SIDECAR_ENTRY_SIZE;
        let mut buf = vec![0u8; total_size];

        buf[0..4].copy_from_slice(&SIDECAR_MAGIC);
        buf[4] = SIDECAR_VERSION;
        buf[5..9].copy_from_slice(&entry_count.to_le_bytes());
        buf[9..11].copy_from_slice(&(SIDECAR_ENTRY_SIZE as u16).to_le_bytes());

        self.entries.iter().enumerate().for_each(|(i, entry)| {
            let offset = SIDECAR_HEADER_SIZE + i * SIDECAR_ENTRY_SIZE;
            let entry_buf: &mut [u8; SIDECAR_ENTRY_SIZE] = (&mut buf
                [offset..offset + SIDECAR_ENTRY_SIZE])
                .try_into()
                .unwrap();
            entry.encode(entry_buf);
        });

        buf
    }

    fn deserialize(data: &[u8]) -> io::Result<Self> {
        if data.len() < SIDECAR_HEADER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sidecar data too small for header",
            ));
        }

        if data[0..4] != SIDECAR_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad sidecar magic",
            ));
        }

        if data[4] != SIDECAR_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported sidecar version",
            ));
        }

        let entry_count = u32::from_le_bytes(data[5..9].try_into().unwrap()) as usize;
        let entry_size = u16::from_le_bytes(data[9..11].try_into().unwrap()) as usize;

        if entry_size != SIDECAR_ENTRY_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "sidecar entry size mismatch: got {entry_size}, expected {SIDECAR_ENTRY_SIZE}"
                ),
            ));
        }

        if entry_count > MAX_SIDECAR_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sidecar contains too many entries",
            ));
        }

        let expected_size = SIDECAR_HEADER_SIZE + entry_count * SIDECAR_ENTRY_SIZE;
        if data.len() < expected_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sidecar data truncated",
            ));
        }

        let entries: Vec<SidecarEntry> = (0..entry_count)
            .map(|i| {
                let offset = SIDECAR_HEADER_SIZE + i * SIDECAR_ENTRY_SIZE;
                let entry_buf: &[u8; SIDECAR_ENTRY_SIZE] = (&data
                    [offset..offset + SIDECAR_ENTRY_SIZE])
                    .try_into()
                    .unwrap();
                SidecarEntry::decode(entry_buf)
            })
            .collect();

        let is_sorted = entries.windows(2).all(|pair| pair[0].seq < pair[1].seq);
        if !is_sorted {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sidecar entries not monotonically sorted by seq",
            ));
        }

        Ok(Self { entries })
    }
}

struct FieldSpan {
    offset: usize,
    len: usize,
}

struct PayloadFieldPositions {
    did: FieldSpan,
    commit_cid: Option<FieldSpan>,
    prev_cid: Option<FieldSpan>,
    prev_data_cid: Option<FieldSpan>,
    ops: Option<FieldSpan>,
    handle: Option<FieldSpan>,
    active: Option<bool>,
    status: Option<u8>,
    rev: Option<FieldSpan>,
}

fn read_varint(data: &[u8], pos: usize) -> Option<(usize, usize)> {
    let mut result: usize = 0;
    let mut shift = 0u32;
    let mut current = pos;
    loop {
        let byte = *data.get(current)?;
        current += 1;
        result |= ((byte & 0x7f) as usize) << shift;
        if byte & 0x80 == 0 {
            return Some((result, current));
        }
        shift += 7;
        if shift >= 35 {
            return None;
        }
    }
}

fn read_bytes_span(data: &[u8], pos: usize) -> Option<(FieldSpan, usize)> {
    let (len, after_varint) = read_varint(data, pos)?;
    let end = after_varint.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    Some((
        FieldSpan {
            offset: after_varint,
            len,
        },
        end,
    ))
}

fn read_optional_bytes_span(data: &[u8], pos: usize) -> Option<(Option<FieldSpan>, usize)> {
    let tag = *data.get(pos)?;
    match tag {
        0 => Some((None, pos + 1)),
        1 => {
            let (span, end) = read_bytes_span(data, pos + 1)?;
            Some((Some(span), end))
        }
        _ => None,
    }
}

fn skip_optional_vec_of_strings(data: &[u8], pos: usize) -> Option<usize> {
    let tag = *data.get(pos)?;
    match tag {
        0 => Some(pos + 1),
        1 => {
            let (count, current) = read_varint(data, pos + 1)?;
            (0..count).try_fold(current, |cur, _| {
                let (_, end) = read_bytes_span(data, cur)?;
                Some(end)
            })
        }
        _ => None,
    }
}

fn read_optional_bool(data: &[u8], pos: usize) -> Option<(Option<bool>, usize)> {
    let tag = *data.get(pos)?;
    match tag {
        0 => Some((None, pos + 1)),
        1 => {
            let val = *data.get(pos + 1)?;
            Some((Some(val != 0), pos + 2))
        }
        _ => None,
    }
}

fn read_optional_u8(data: &[u8], pos: usize) -> Option<(Option<u8>, usize)> {
    let tag = *data.get(pos)?;
    match tag {
        0 => Some((None, pos + 1)),
        1 => {
            let val = *data.get(pos + 1)?;
            Some((Some(val), pos + 2))
        }
        _ => None,
    }
}

fn extract_field_positions(postcard_body: &[u8]) -> Option<PayloadFieldPositions> {
    let (did, pos) = read_bytes_span(postcard_body, 0)?;
    let (commit_cid, pos) = read_optional_bytes_span(postcard_body, pos)?;
    let (prev_cid, pos) = read_optional_bytes_span(postcard_body, pos)?;
    let (prev_data_cid, pos) = read_optional_bytes_span(postcard_body, pos)?;
    let (ops, pos) = read_optional_bytes_span(postcard_body, pos)?;
    let pos = skip_optional_vec_of_strings(postcard_body, pos)?;
    let pos = skip_optional_vec_of_strings(postcard_body, pos)?;
    let (handle, pos) = read_optional_bytes_span(postcard_body, pos)?;
    let (active, pos) = read_optional_bool(postcard_body, pos)?;
    let (status, pos) = read_optional_u8(postcard_body, pos)?;
    let (rev, _pos) = read_optional_bytes_span(postcard_body, pos)?;

    Some(PayloadFieldPositions {
        did,
        commit_cid,
        prev_cid,
        prev_data_cid,
        ops,
        handle,
        active,
        status,
        rev,
    })
}

fn to_segment_offset(payload_base: u64, body_field_offset: usize) -> u32 {
    u32::try_from(payload_base + body_field_offset as u64).unwrap_or(0)
}

fn active_to_tag(active: Option<bool>) -> u8 {
    match active {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    }
}

fn status_to_tag(status: Option<u8>) -> u8 {
    match status {
        None => 0,
        Some(v) => v.saturating_add(1),
    }
}

pub fn build_sidecar_from_segment<S: StorageIO>(
    io: &S,
    segment_fd: FileId,
    max_payload: u32,
) -> io::Result<SidecarIndex> {
    let file_size = io.file_size(segment_fd)?;

    if file_size < SEGMENT_HEADER_SIZE as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file too small for segment header",
        ));
    }

    let mut header = [0u8; SEGMENT_HEADER_SIZE];
    io.read_exact_at(segment_fd, 0, &mut header)?;
    if header[..SEGMENT_MAGIC.len()] != SEGMENT_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad segment magic",
        ));
    }

    let offset = Cell::new(SegmentOffset::new(SEGMENT_HEADER_SIZE as u64));

    let entries: Vec<SidecarEntry> = std::iter::from_fn(|| {
        (offset.get().raw() < file_size)
            .then(|| decode_event_record(io, segment_fd, offset.get(), file_size, max_payload))
    })
    .map_while(|result| match result {
        Err(e) => Some(Err(e)),
        Ok(None | Some(ReadEventRecord::Corrupted { .. } | ReadEventRecord::Truncated { .. })) => {
            None
        }
        Ok(Some(ReadEventRecord::Valid { event, next_offset })) => {
            let payload_start = offset.get().raw() + EVENT_HEADER_SIZE as u64;
            offset.set(next_offset);

            match build_sidecar_entry_from_payload(
                &event.payload,
                payload_start,
                event.seq,
                event.timestamp,
                event.did_hash,
                event.event_type,
            ) {
                Some(entry) => Some(Ok(entry)),
                None => {
                    tracing::warn!(
                        seq = %event.seq,
                        "failed to extract field positions for sidecar, skipping rest"
                    );
                    None
                }
            }
        }
    })
    .collect::<io::Result<Vec<_>>>()?;

    Ok(SidecarIndex::new(entries))
}

fn build_sidecar_entry_from_payload(
    payload: &[u8],
    payload_start: u64,
    seq: EventSequence,
    timestamp: TimestampMicros,
    did_hash: DidHash,
    event_type: EventTypeTag,
) -> Option<SidecarEntry> {
    let (&version, postcard_body) = payload.split_first()?;
    if version != PAYLOAD_VERSION_V1 {
        return None;
    }

    let positions = extract_field_positions(postcard_body)?;

    let body_base = payload_start + 1;

    let seg_offset = |span: &FieldSpan| -> u32 { to_segment_offset(body_base, span.offset) };

    Some(SidecarEntry {
        seq: seq.raw(),
        timestamp: timestamp.raw(),
        did_hash: did_hash.raw(),
        event_type: event_type.raw(),
        active: active_to_tag(positions.active),
        status: status_to_tag(positions.status),
        did_offset: seg_offset(&positions.did),
        did_len: u16::try_from(positions.did.len).unwrap_or(u16::MAX),
        commit_cid_offset: positions.commit_cid.as_ref().map_or(0, seg_offset),
        prev_cid_offset: positions.prev_cid.as_ref().map_or(0, seg_offset),
        prev_data_cid_offset: positions.prev_data_cid.as_ref().map_or(0, seg_offset),
        ops_offset: positions.ops.as_ref().map_or(0, seg_offset),
        ops_len: positions
            .ops
            .as_ref()
            .map_or(0, |s| u32::try_from(s.len).unwrap_or(u32::MAX)),
        rev_offset: positions.rev.as_ref().map_or(0, seg_offset),
        rev_len: positions
            .rev
            .as_ref()
            .map_or(0, |s| u16::try_from(s.len).unwrap_or(u16::MAX)),
        handle_offset: positions.handle.as_ref().map_or(0, seg_offset),
        handle_len: positions
            .handle
            .as_ref()
            .map_or(0, |s| u16::try_from(s.len).unwrap_or(u16::MAX)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OpenOptions;
    use crate::eventlog::payload::{encode_payload, encode_payload_with_mutations};
    use crate::eventlog::segment_file::{SegmentWriter, ValidEvent};
    use crate::eventlog::types::{
        DidHash, EventSequence, EventTypeTag, MAX_EVENT_PAYLOAD, SegmentId, TimestampMicros,
    };
    use crate::sim::SimulatedIO;
    use sha2::Digest;
    use std::path::Path;
    use tranquil_db_traits::{AccountStatus, RepoEventType, SequenceNumber, SequencedEvent};
    use tranquil_types::{Did, Handle};

    fn test_did() -> Did {
        Did::new("did:plc:testuser1234567890abcdef").unwrap()
    }

    fn test_cid_link() -> tranquil_types::CidLink {
        let hash = sha2::Digest::finalize(sha2::Sha256::new());
        let mh = multihash::Multihash::<64>::wrap(0x12, &hash).unwrap();
        let c = cid::Cid::new_v1(0x71, mh);
        tranquil_types::CidLink::from_cid(&c)
    }

    fn setup() -> (SimulatedIO, FileId) {
        let sim = SimulatedIO::pristine(42);
        let dir = Path::new("/test");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();
        let fd = sim
            .open(Path::new("/test/segment.tqe"), OpenOptions::read_write())
            .unwrap();
        (sim, fd)
    }

    fn make_commit_event(seq: u64) -> SequencedEvent {
        let cid = test_cid_link();
        let ops = serde_json::json!([{"action": "create", "path": "app.bsky.feed.post/abc"}]);

        SequencedEvent {
            seq: SequenceNumber::from_raw(seq as i64),
            did: test_did(),
            created_at: chrono::Utc::now(),
            event_type: RepoEventType::Commit,
            commit_cid: Some(cid.clone()),
            prev_cid: Some(cid.clone()),
            prev_data_cid: Some(cid),
            ops: Some(ops),
            blobs: Some(vec!["bafkreibtest".to_owned()]),
            blocks: None,
            handle: Some(Handle::new("test.bsky.social").unwrap()),
            active: None,
            status: None,
            rev: Some("rev123".to_owned()),
        }
    }

    fn make_account_event(seq: u64) -> SequencedEvent {
        SequencedEvent {
            seq: SequenceNumber::from_raw(seq as i64),
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
        }
    }

    fn write_events(sim: &SimulatedIO, fd: FileId, events: &[SequencedEvent]) -> Vec<ValidEvent> {
        let mut writer = SegmentWriter::new(
            sim,
            fd,
            SegmentId::new(1),
            EventSequence::new(1),
            MAX_EVENT_PAYLOAD,
        )
        .unwrap();

        let valid_events: Vec<ValidEvent> = events
            .iter()
            .enumerate()
            .map(|(i, event)| {
                let payload = encode_payload(event);
                let event_type = match event.event_type {
                    RepoEventType::Commit => EventTypeTag::COMMIT,
                    RepoEventType::Identity => EventTypeTag::IDENTITY,
                    RepoEventType::Account => EventTypeTag::ACCOUNT,
                    RepoEventType::Sync => EventTypeTag::SYNC,
                };
                let ve = ValidEvent {
                    seq: EventSequence::new((i + 1) as u64),
                    timestamp: TimestampMicros::new((i as u64 + 1) * 1_000_000),
                    did_hash: DidHash::from_did(event.did.as_str()),
                    event_type,
                    payload,
                };
                writer.append_event(sim, &ve).unwrap();
                ve
            })
            .collect();

        writer.sync(sim).unwrap();
        valid_events
    }

    #[test]
    fn entry_encode_decode_round_trip() {
        let entry = SidecarEntry {
            seq: 42,
            timestamp: 1_700_000_000_000_000,
            did_hash: 0xDEADBEEF,
            event_type: 1,
            active: 2,
            status: 1,
            did_offset: 100,
            did_len: 30,
            commit_cid_offset: 200,
            prev_cid_offset: 300,
            prev_data_cid_offset: 400,
            ops_offset: 500,
            ops_len: 1024,
            rev_offset: 600,
            rev_len: 10,
            handle_offset: 700,
            handle_len: 20,
        };

        let mut buf = [0u8; SIDECAR_ENTRY_SIZE];
        entry.encode(&mut buf);
        let decoded = SidecarEntry::decode(&buf);
        assert_eq!(entry, decoded);
    }

    #[test]
    fn sidecar_serialize_deserialize_round_trip() {
        let entries = vec![
            SidecarEntry {
                seq: 1,
                timestamp: 1_000_000,
                did_hash: 100,
                event_type: 1,
                active: 0,
                status: 0,
                did_offset: 50,
                did_len: 30,
                commit_cid_offset: 0,
                prev_cid_offset: 0,
                prev_data_cid_offset: 0,
                ops_offset: 0,
                ops_len: 0,
                rev_offset: 0,
                rev_len: 0,
                handle_offset: 0,
                handle_len: 0,
            },
            SidecarEntry {
                seq: 2,
                timestamp: 2_000_000,
                did_hash: 200,
                event_type: 3,
                active: 2,
                status: 1,
                did_offset: 150,
                did_len: 30,
                commit_cid_offset: 0,
                prev_cid_offset: 0,
                prev_data_cid_offset: 0,
                ops_offset: 0,
                ops_len: 0,
                rev_offset: 0,
                rev_len: 0,
                handle_offset: 0,
                handle_len: 0,
            },
        ];

        let index = SidecarIndex::new(entries.clone());
        let serialized = index.serialize();
        let deserialized = SidecarIndex::deserialize(&serialized).unwrap();
        assert_eq!(index, deserialized);
    }

    #[test]
    fn sidecar_save_load_round_trip() {
        let sim = SimulatedIO::pristine(42);
        let dir = Path::new("/test");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();

        let entries = vec![SidecarEntry {
            seq: 1,
            timestamp: 1_000_000,
            did_hash: 100,
            event_type: 1,
            active: 0,
            status: 0,
            did_offset: 50,
            did_len: 30,
            commit_cid_offset: 0,
            prev_cid_offset: 0,
            prev_data_cid_offset: 0,
            ops_offset: 0,
            ops_len: 0,
            rev_offset: 0,
            rev_len: 0,
            handle_offset: 0,
            handle_len: 0,
        }];

        let index = SidecarIndex::new(entries);
        let path = Path::new("/test/00000001.tqs");
        index.save(&sim, path).unwrap();

        let loaded = SidecarIndex::load(&sim, path).unwrap().unwrap();
        assert_eq!(index, loaded);
    }

    #[test]
    fn sidecar_load_missing_returns_none() {
        let sim = SimulatedIO::pristine(42);
        let dir = Path::new("/test");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();

        let result = SidecarIndex::load(&sim, Path::new("/test/missing.tqs")).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn build_sidecar_from_commit_events() {
        let (sim, fd) = setup();
        let events: Vec<_> = (1u64..=3).map(make_commit_event).collect();
        write_events(&sim, fd, &events);

        let sidecar = build_sidecar_from_segment(&sim, fd, MAX_EVENT_PAYLOAD).unwrap();
        assert_eq!(sidecar.entry_count(), 3);

        sidecar.entries().iter().enumerate().for_each(|(i, entry)| {
            assert_eq!(entry.seq, (i + 1) as u64);
            assert_eq!(entry.event_type, EventTypeTag::COMMIT.raw());
            assert!(entry.did_offset > 0);
            assert!(entry.did_len > 0);
            assert!(entry.commit_cid_offset > 0);
            assert!(entry.prev_cid_offset > 0);
            assert!(entry.prev_data_cid_offset > 0);
            assert!(entry.ops_offset > 0);
            assert!(entry.ops_len > 0);
            assert!(entry.rev_offset > 0);
            assert!(entry.rev_len > 0);
            assert!(entry.handle_offset > 0);
            assert!(entry.handle_len > 0);
        });
    }

    #[test]
    fn build_sidecar_from_account_events() {
        let (sim, fd) = setup();
        let events: Vec<_> = (1u64..=2).map(make_account_event).collect();
        write_events(&sim, fd, &events);

        let sidecar = build_sidecar_from_segment(&sim, fd, MAX_EVENT_PAYLOAD).unwrap();
        assert_eq!(sidecar.entry_count(), 2);

        sidecar.entries().iter().for_each(|entry| {
            assert_eq!(entry.event_type, EventTypeTag::ACCOUNT.raw());
            assert!(entry.did_offset > 0);
            assert_eq!(entry.commit_cid_offset, 0);
            assert_eq!(entry.ops_offset, 0);
            assert_eq!(entry.ops_len, 0);
            assert_eq!(entry.active, 2);
            assert_eq!(entry.status, 1);
        });
    }

    #[test]
    fn build_sidecar_empty_segment() {
        let (sim, fd) = setup();
        SegmentWriter::new(
            &sim,
            fd,
            SegmentId::new(1),
            EventSequence::new(1),
            MAX_EVENT_PAYLOAD,
        )
        .unwrap();
        sim.sync(fd).unwrap();

        let sidecar = build_sidecar_from_segment(&sim, fd, MAX_EVENT_PAYLOAD).unwrap();
        assert_eq!(sidecar.entry_count(), 0);
    }

    #[test]
    fn sidecar_lookup_by_seq() {
        let (sim, fd) = setup();
        let events: Vec<_> = (1u64..=5).map(make_commit_event).collect();
        write_events(&sim, fd, &events);

        let sidecar = build_sidecar_from_segment(&sim, fd, MAX_EVENT_PAYLOAD).unwrap();

        let entry = sidecar.lookup_by_seq(EventSequence::new(3)).unwrap();
        assert_eq!(entry.seq, 3);

        assert!(sidecar.lookup_by_seq(EventSequence::new(99)).is_none());
    }

    #[test]
    fn sidecar_field_offsets_point_to_valid_data() {
        let (sim, fd) = setup();
        let events = vec![make_commit_event(1)];
        write_events(&sim, fd, &events);

        let sidecar = build_sidecar_from_segment(&sim, fd, MAX_EVENT_PAYLOAD).unwrap();
        let entry = &sidecar.entries()[0];

        let file_size = sim.file_size(fd).unwrap();
        let mut did_bytes = vec![0u8; entry.did_len as usize];
        sim.read_exact_at(fd, entry.did_offset as u64, &mut did_bytes)
            .unwrap();
        let did_str = std::str::from_utf8(&did_bytes).unwrap();
        assert_eq!(did_str, "did:plc:testuser1234567890abcdef");

        let mut rev_bytes = vec![0u8; entry.rev_len as usize];
        sim.read_exact_at(fd, entry.rev_offset as u64, &mut rev_bytes)
            .unwrap();
        let rev_str = std::str::from_utf8(&rev_bytes).unwrap();
        assert_eq!(rev_str, "rev123");

        let mut handle_bytes = vec![0u8; entry.handle_len as usize];
        sim.read_exact_at(fd, entry.handle_offset as u64, &mut handle_bytes)
            .unwrap();
        let handle_str = std::str::from_utf8(&handle_bytes).unwrap();
        assert_eq!(handle_str, "test.bsky.social");

        assert!(entry.commit_cid_offset > 0);
        assert!((entry.commit_cid_offset as u64) + CID_BYTE_LEN as u64 <= file_size);
    }

    #[test]
    fn sidecar_build_and_reload() {
        let sim = SimulatedIO::pristine(42);
        let dir = Path::new("/test");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();

        let fd = sim
            .open(Path::new("/test/segment.tqe"), OpenOptions::read_write())
            .unwrap();
        let events: Vec<_> = (1u64..=10).map(make_commit_event).collect();
        write_events(&sim, fd, &events);

        let sidecar = build_sidecar_from_segment(&sim, fd, MAX_EVENT_PAYLOAD).unwrap();
        let path = Path::new("/test/00000001.tqs");
        sidecar.save(&sim, path).unwrap();

        let loaded = SidecarIndex::load(&sim, path).unwrap().unwrap();
        assert_eq!(sidecar, loaded);
        assert_eq!(loaded.entry_count(), 10);
    }

    #[test]
    fn sidecar_with_mutations() {
        let (sim, fd) = setup();
        let event = make_commit_event(1);
        let mutation_bytes = b"mutation-data";
        let payload = encode_payload_with_mutations(&event, Some(mutation_bytes));

        let ve = ValidEvent {
            seq: EventSequence::new(1),
            timestamp: TimestampMicros::new(1_000_000),
            did_hash: DidHash::from_did(event.did.as_str()),
            event_type: EventTypeTag::COMMIT,
            payload,
        };

        let mut writer = SegmentWriter::new(
            &sim,
            fd,
            SegmentId::new(1),
            EventSequence::new(1),
            MAX_EVENT_PAYLOAD,
        )
        .unwrap();
        writer.append_event(&sim, &ve).unwrap();
        writer.sync(&sim).unwrap();

        let sidecar = build_sidecar_from_segment(&sim, fd, MAX_EVENT_PAYLOAD).unwrap();
        assert_eq!(sidecar.entry_count(), 1);
        assert!(sidecar.entries()[0].ops_offset > 0);
    }

    #[test]
    fn extract_positions_minimal_payload() {
        let event = make_account_event(1);
        let encoded = encode_payload(&event);
        let postcard_body = &encoded[1..];

        let positions = extract_field_positions(postcard_body).unwrap();
        assert!(positions.did.len > 0);
        assert!(positions.commit_cid.is_none());
        assert!(positions.ops.is_none());
        assert_eq!(positions.active, Some(true));
        assert_eq!(positions.status, Some(0));
    }

    #[test]
    fn extract_positions_full_payload() {
        let event = make_commit_event(1);
        let encoded = encode_payload(&event);
        let postcard_body = &encoded[1..];

        let positions = extract_field_positions(postcard_body).unwrap();

        let slice = |span: &FieldSpan| &postcard_body[span.offset..span.offset + span.len];

        assert_eq!(
            std::str::from_utf8(slice(&positions.did)).unwrap(),
            "did:plc:testuser1234567890abcdef"
        );

        let commit_cid_span = positions.commit_cid.unwrap();
        let prev_cid_span = positions.prev_cid.unwrap();
        let prev_data_cid_span = positions.prev_data_cid.unwrap();
        assert_eq!(commit_cid_span.len, CID_BYTE_LEN);
        assert_eq!(prev_cid_span.len, CID_BYTE_LEN);
        assert_eq!(prev_data_cid_span.len, CID_BYTE_LEN);
        assert_eq!(slice(&commit_cid_span), slice(&prev_cid_span));
        assert_eq!(slice(&commit_cid_span), slice(&prev_data_cid_span));

        let expected_cid = test_cid_link().to_cid().unwrap().to_bytes();
        assert_eq!(slice(&commit_cid_span), expected_cid.as_slice());

        let ops_span = positions.ops.unwrap();
        let ops_decoded: serde_json::Value =
            serde_ipld_dagcbor::from_slice(slice(&ops_span)).unwrap();
        let expected_ops =
            serde_json::json!([{"action": "create", "path": "app.bsky.feed.post/abc"}]);
        assert_eq!(ops_decoded, expected_ops);

        let handle_span = positions.handle.unwrap();
        assert_eq!(
            std::str::from_utf8(slice(&handle_span)).unwrap(),
            "test.bsky.social"
        );

        assert_eq!(positions.active, None);
        assert_eq!(positions.status, None);

        let rev_span = positions.rev.unwrap();
        assert_eq!(std::str::from_utf8(slice(&rev_span)).unwrap(), "rev123");
    }

    #[test]
    fn bad_magic_rejected() {
        let mut data = vec![0u8; SIDECAR_HEADER_SIZE];
        data[0..4].copy_from_slice(b"NOPE");
        data[4] = SIDECAR_VERSION;

        let result = SidecarIndex::deserialize(&data);
        assert!(result.is_err());
    }

    #[test]
    fn unsorted_entries_rejected() {
        let entries = vec![
            SidecarEntry {
                seq: 2,
                timestamp: 0,
                did_hash: 0,
                event_type: 1,
                active: 0,
                status: 0,
                did_offset: 0,
                did_len: 0,
                commit_cid_offset: 0,
                prev_cid_offset: 0,
                prev_data_cid_offset: 0,
                ops_offset: 0,
                ops_len: 0,
                rev_offset: 0,
                rev_len: 0,
                handle_offset: 0,
                handle_len: 0,
            },
            SidecarEntry {
                seq: 1,
                timestamp: 0,
                did_hash: 0,
                event_type: 1,
                active: 0,
                status: 0,
                did_offset: 0,
                did_len: 0,
                commit_cid_offset: 0,
                prev_cid_offset: 0,
                prev_data_cid_offset: 0,
                ops_offset: 0,
                ops_len: 0,
                rev_offset: 0,
                rev_len: 0,
                handle_offset: 0,
                handle_len: 0,
            },
        ];

        let index = SidecarIndex { entries };
        let serialized = index.serialize();
        let result = SidecarIndex::deserialize(&serialized);
        assert!(result.is_err());
    }
}
