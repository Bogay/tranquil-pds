use std::io;

use crate::io::{FileId, StorageIO};

use super::types::{
    DidHash, EventSequence, EventTypeTag, SegmentId, SegmentOffset, TimestampMicros,
};

pub const SEGMENT_MAGIC: [u8; 4] = *b"TQEV";
pub const SEGMENT_FORMAT_VERSION: u8 = 1;
pub const SEGMENT_HEADER_SIZE: usize = 5;

pub const EVENT_HEADER_SIZE: usize = 8 + 8 + 4 + 1 + 4;
pub const EVENT_RECORD_OVERHEAD: usize = EVENT_HEADER_SIZE + 4;

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidEvent {
    pub seq: EventSequence,
    pub timestamp: TimestampMicros,
    pub did_hash: DidHash,
    pub event_type: EventTypeTag,
    pub payload: Vec<u8>,
}

fn event_record_checksum(header: &[u8; EVENT_HEADER_SIZE], payload: &[u8]) -> u32 {
    let mut hasher = xxhash_rust::xxh3::Xxh3::new();
    hasher.update(header);
    hasher.update(payload);
    hasher.digest() as u32
}

fn encode_header(event: &ValidEvent, payload_len: u32) -> [u8; EVENT_HEADER_SIZE] {
    let mut header = [0u8; EVENT_HEADER_SIZE];
    header[0..8].copy_from_slice(&event.seq.raw().to_le_bytes());
    header[8..16].copy_from_slice(&event.timestamp.raw().to_le_bytes());
    header[16..20].copy_from_slice(&event.did_hash.raw().to_le_bytes());
    header[20] = event.event_type.raw();
    header[21..25].copy_from_slice(&payload_len.to_le_bytes());
    header
}

pub fn encode_event_record<S: StorageIO>(
    io: &S,
    fd: FileId,
    offset: SegmentOffset,
    event: &ValidEvent,
    max_payload: u32,
) -> io::Result<u64> {
    let payload_len = u32::try_from(event.payload.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "event payload exceeds u32::MAX",
        )
    })?;
    if payload_len > max_payload {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("event payload {payload_len} exceeds configured max_payload {max_payload}"),
        ));
    }

    let header = encode_header(event, payload_len);
    let checksum = event_record_checksum(&header, &event.payload);
    let record_size = EVENT_RECORD_OVERHEAD as u64 + u64::from(payload_len);

    let base = offset.raw();
    io.write_all_at(fd, base, &header)?;
    io.write_all_at(fd, base + EVENT_HEADER_SIZE as u64, &event.payload)?;
    io.write_all_at(
        fd,
        base + EVENT_HEADER_SIZE as u64 + u64::from(payload_len),
        &checksum.to_le_bytes(),
    )?;

    Ok(record_size)
}

#[must_use]
#[derive(Debug)]
pub enum ReadEventRecord {
    Valid {
        event: ValidEvent,
        next_offset: SegmentOffset,
    },
    Corrupted {
        offset: SegmentOffset,
    },
    Truncated {
        offset: SegmentOffset,
    },
}

pub fn decode_event_record<S: StorageIO>(
    io: &S,
    fd: FileId,
    offset: SegmentOffset,
    file_size: u64,
    max_payload: u32,
) -> io::Result<Option<ReadEventRecord>> {
    let raw = offset.raw();
    if raw > file_size {
        return Ok(Some(ReadEventRecord::Corrupted { offset }));
    }
    let remaining = file_size - raw;
    if remaining == 0 {
        return Ok(None);
    }

    if remaining < EVENT_HEADER_SIZE as u64 {
        return Ok(Some(ReadEventRecord::Truncated { offset }));
    }

    let mut header = [0u8; EVENT_HEADER_SIZE];
    io.read_exact_at(fd, raw, &mut header)?;

    let seq_raw = u64::from_le_bytes(header[0..8].try_into().unwrap());
    if seq_raw == 0 {
        return Ok(Some(ReadEventRecord::Corrupted { offset }));
    }
    let seq = EventSequence::new(seq_raw);

    let timestamp = TimestampMicros::new(u64::from_le_bytes(header[8..16].try_into().unwrap()));
    let did_hash = DidHash::from_raw(u32::from_le_bytes(header[16..20].try_into().unwrap()));
    let event_type_raw = header[20];
    let event_type = match EventTypeTag::from_raw(event_type_raw) {
        Some(t) => t,
        None => return Ok(Some(ReadEventRecord::Corrupted { offset })),
    };

    let payload_len = u32::from_le_bytes(header[21..25].try_into().unwrap());
    if payload_len > max_payload {
        return Ok(Some(ReadEventRecord::Corrupted { offset }));
    }

    let record_size = EVENT_RECORD_OVERHEAD as u64 + u64::from(payload_len);
    if record_size > remaining {
        return Ok(Some(ReadEventRecord::Truncated { offset }));
    }

    let payload_offset = raw + EVENT_HEADER_SIZE as u64;
    let mut payload = vec![0u8; usize::try_from(payload_len).expect("payload_len fits usize")];
    io.read_exact_at(fd, payload_offset, &mut payload)?;

    let mut checksum_bytes = [0u8; 4];
    io.read_exact_at(
        fd,
        payload_offset + u64::from(payload_len),
        &mut checksum_bytes,
    )?;

    let stored_checksum = u32::from_le_bytes(checksum_bytes);
    let computed_checksum = event_record_checksum(&header, &payload);

    if stored_checksum != computed_checksum {
        return Ok(Some(ReadEventRecord::Corrupted { offset }));
    }

    let next_offset = offset.advance(record_size);

    Ok(Some(ReadEventRecord::Valid {
        event: ValidEvent {
            seq,
            timestamp,
            did_hash,
            event_type,
            payload,
        },
        next_offset,
    }))
}

#[derive(Debug)]
pub enum ValidateEventRecord {
    Valid {
        seq: EventSequence,
        next_offset: SegmentOffset,
    },
    Corrupted,
    Truncated,
}

const CHECKSUM_CHUNK_SIZE: usize = 8 * 1024;

pub fn validate_event_record<S: StorageIO>(
    io: &S,
    fd: FileId,
    offset: SegmentOffset,
    file_size: u64,
    max_payload: u32,
) -> io::Result<Option<ValidateEventRecord>> {
    let raw = offset.raw();
    assert!(
        raw <= file_size,
        "validate offset {raw} past file size {file_size}"
    );
    let remaining = file_size - raw;
    if remaining == 0 {
        return Ok(None);
    }

    if remaining < EVENT_HEADER_SIZE as u64 {
        return Ok(Some(ValidateEventRecord::Truncated));
    }

    let mut header = [0u8; EVENT_HEADER_SIZE];
    io.read_exact_at(fd, raw, &mut header)?;

    let seq_raw = u64::from_le_bytes(header[0..8].try_into().unwrap());
    if seq_raw == 0 {
        return Ok(Some(ValidateEventRecord::Corrupted));
    }
    let seq = EventSequence::new(seq_raw);

    let event_type_raw = header[20];
    if EventTypeTag::from_raw(event_type_raw).is_none() {
        return Ok(Some(ValidateEventRecord::Corrupted));
    }

    let payload_len = u32::from_le_bytes(header[21..25].try_into().unwrap());
    if payload_len > max_payload {
        return Ok(Some(ValidateEventRecord::Corrupted));
    }

    let record_size = EVENT_RECORD_OVERHEAD as u64 + u64::from(payload_len);
    if record_size > remaining {
        return Ok(Some(ValidateEventRecord::Truncated));
    }

    let payload_offset = raw + EVENT_HEADER_SIZE as u64;

    let mut hasher = xxhash_rust::xxh3::Xxh3::new();
    hasher.update(&header);
    let mut chunk = [0u8; CHECKSUM_CHUNK_SIZE];
    (0..u64::from(payload_len))
        .step_by(CHECKSUM_CHUNK_SIZE)
        .map(|chunk_start| {
            let to_read =
                ((u64::from(payload_len) - chunk_start) as usize).min(CHECKSUM_CHUNK_SIZE);
            (payload_offset + chunk_start, to_read)
        })
        .try_for_each(|(pos, to_read)| {
            io.read_exact_at(fd, pos, &mut chunk[..to_read])?;
            hasher.update(&chunk[..to_read]);
            Ok::<_, io::Error>(())
        })?;
    let computed_checksum = hasher.digest() as u32;

    let mut checksum_bytes = [0u8; 4];
    io.read_exact_at(
        fd,
        payload_offset + u64::from(payload_len),
        &mut checksum_bytes,
    )?;
    let stored_checksum = u32::from_le_bytes(checksum_bytes);

    if stored_checksum != computed_checksum {
        return Ok(Some(ValidateEventRecord::Corrupted));
    }

    let next_offset = offset.advance(record_size);
    Ok(Some(ValidateEventRecord::Valid { seq, next_offset }))
}

pub struct SegmentWriter {
    fd: FileId,
    segment_id: SegmentId,
    position: SegmentOffset,
    base_seq: EventSequence,
    last_seq: Option<EventSequence>,
    max_payload: u32,
}

impl SegmentWriter {
    pub fn new<S: StorageIO>(
        io: &S,
        fd: FileId,
        segment_id: SegmentId,
        base_seq: EventSequence,
        max_payload: u32,
    ) -> io::Result<Self> {
        let mut header = [0u8; SEGMENT_HEADER_SIZE];
        header[..4].copy_from_slice(&SEGMENT_MAGIC);
        header[4] = SEGMENT_FORMAT_VERSION;
        io.write_all_at(fd, 0, &header)?;
        Ok(Self {
            fd,
            segment_id,
            position: SegmentOffset::new(SEGMENT_HEADER_SIZE as u64),
            base_seq,
            last_seq: None,
            max_payload,
        })
    }

    pub fn resume<S: StorageIO>(
        io: &S,
        fd: FileId,
        segment_id: SegmentId,
        position: SegmentOffset,
        base_seq: EventSequence,
        last_seq: Option<EventSequence>,
        max_payload: u32,
    ) -> Self {
        assert!(
            position.raw() >= SEGMENT_HEADER_SIZE as u64,
            "resume position {position:?} is before header end"
        );
        #[cfg(debug_assertions)]
        {
            let mut magic = [0u8; 4];
            io.read_exact_at(fd, 0, &mut magic)
                .expect("resume: failed to read segment header");
            assert_eq!(magic, SEGMENT_MAGIC, "resume: bad segment magic");
        }
        #[cfg(not(debug_assertions))]
        let _ = io;
        Self {
            fd,
            segment_id,
            position,
            base_seq,
            last_seq,
            max_payload,
        }
    }

    pub fn max_payload(&self) -> u32 {
        self.max_payload
    }

    pub fn append_event<S: StorageIO>(
        &mut self,
        io: &S,
        event: &ValidEvent,
    ) -> io::Result<SegmentOffset> {
        assert!(
            self.last_seq.is_none_or(|prev| event.seq > prev),
            "non-monotonic sequence: {} after {}",
            event.seq,
            self.last_seq.unwrap()
        );
        let record_offset = self.position;
        let bytes_written =
            encode_event_record(io, self.fd, record_offset, event, self.max_payload)?;
        self.position = self.position.advance(bytes_written);
        self.last_seq = Some(event.seq);
        Ok(record_offset)
    }

    pub fn sync<S: StorageIO>(&self, io: &S) -> io::Result<()> {
        io.sync(self.fd)
    }

    pub fn position(&self) -> SegmentOffset {
        self.position
    }

    pub fn segment_id(&self) -> SegmentId {
        self.segment_id
    }

    pub fn base_seq(&self) -> EventSequence {
        self.base_seq
    }

    pub fn fd(&self) -> FileId {
        self.fd
    }
}

pub struct SegmentReader<'a, S: StorageIO> {
    io: &'a S,
    fd: FileId,
    position: SegmentOffset,
    file_size: u64,
    max_payload: u32,
}

impl<'a, S: StorageIO> SegmentReader<'a, S> {
    pub fn open(io: &'a S, fd: FileId, max_payload: u32) -> io::Result<Self> {
        let file_size = io.file_size(fd)?;
        if file_size < SEGMENT_HEADER_SIZE as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "file too small for segment header",
            ));
        }

        let mut header = [0u8; SEGMENT_HEADER_SIZE];
        io.read_exact_at(fd, 0, &mut header)?;

        if header[..SEGMENT_MAGIC.len()] != SEGMENT_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad segment magic",
            ));
        }
        if header[SEGMENT_MAGIC.len()] != SEGMENT_FORMAT_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported segment format version",
            ));
        }

        Ok(Self {
            io,
            fd,
            position: SegmentOffset::new(SEGMENT_HEADER_SIZE as u64),
            file_size,
            max_payload,
        })
    }

    pub fn max_payload(&self) -> u32 {
        self.max_payload
    }

    pub fn valid_prefix(self) -> io::Result<Vec<ValidEvent>> {
        self.map(|result| {
            result.map(|record| match record {
                ReadEventRecord::Valid { event, .. } => Some(event),
                ReadEventRecord::Corrupted { .. } | ReadEventRecord::Truncated { .. } => None,
            })
        })
        .scan((), |(), result| match result {
            Err(e) => Some(Err(e)),
            Ok(Some(event)) => Some(Ok(event)),
            Ok(None) => None,
        })
        .collect()
    }

    pub fn fd(&self) -> FileId {
        self.fd
    }

    pub fn position(&self) -> SegmentOffset {
        self.position
    }

    pub fn file_size(&self) -> u64 {
        self.file_size
    }
}

impl<S: StorageIO> Iterator for SegmentReader<'_, S> {
    type Item = io::Result<ReadEventRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        match decode_event_record(
            self.io,
            self.fd,
            self.position,
            self.file_size,
            self.max_payload,
        ) {
            Err(e) => {
                self.position = SegmentOffset::new(self.file_size);
                Some(Err(e))
            }
            Ok(None) => None,
            Ok(Some(record)) => {
                match &record {
                    ReadEventRecord::Valid { next_offset, .. } => {
                        self.position = *next_offset;
                    }
                    ReadEventRecord::Corrupted { .. } | ReadEventRecord::Truncated { .. } => {
                        self.position = SegmentOffset::new(self.file_size);
                    }
                }
                Some(Ok(record))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OpenOptions;
    use crate::eventlog::types::MAX_EVENT_PAYLOAD;
    use crate::sim::SimulatedIO;
    use proptest::prelude::*;
    use std::path::Path;

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

    fn test_did_hash(seed: u8) -> DidHash {
        DidHash::from_did(&format!("did:plc:test{seed}"))
    }

    fn test_event(seq: u64, payload: &[u8]) -> ValidEvent {
        ValidEvent {
            seq: EventSequence::new(seq),
            timestamp: TimestampMicros::new(seq * 1_000_000),
            did_hash: test_did_hash(seq as u8),
            event_type: EventTypeTag::COMMIT,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn write_and_read_single_event() {
        let (sim, fd) = setup();
        let mut writer = SegmentWriter::new(
            &sim,
            fd,
            SegmentId::new(1),
            EventSequence::new(1),
            MAX_EVENT_PAYLOAD,
        )
        .unwrap();

        let event = test_event(1, b"test event payload");
        let offset = writer.append_event(&sim, &event).unwrap();
        writer.sync(&sim).unwrap();

        assert_eq!(offset, SegmentOffset::new(SEGMENT_HEADER_SIZE as u64));

        let reader = SegmentReader::open(&sim, fd, MAX_EVENT_PAYLOAD).unwrap();
        let events = reader.valid_prefix().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], event);
    }

    #[test]
    fn write_and_read_multiple_events() {
        let (sim, fd) = setup();
        let mut writer = SegmentWriter::new(
            &sim,
            fd,
            SegmentId::new(1),
            EventSequence::new(1),
            MAX_EVENT_PAYLOAD,
        )
        .unwrap();

        let written: Vec<ValidEvent> = (1u64..=3)
            .map(|i| {
                let event = test_event(i, format!("event {i}").as_bytes());
                writer.append_event(&sim, &event).unwrap();
                event
            })
            .collect();
        writer.sync(&sim).unwrap();

        let reader = SegmentReader::open(&sim, fd, MAX_EVENT_PAYLOAD).unwrap();
        let events = reader.valid_prefix().unwrap();
        assert_eq!(events, written);
    }

    #[test]
    fn empty_segment_has_no_events() {
        let (sim, fd) = setup();
        SegmentWriter::new(
            &sim,
            fd,
            SegmentId::new(1),
            EventSequence::new(1),
            MAX_EVENT_PAYLOAD,
        )
        .unwrap();

        let reader = SegmentReader::open(&sim, fd, MAX_EVENT_PAYLOAD).unwrap();
        let events = reader.valid_prefix().unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn detects_truncated_event() {
        let (sim, fd) = setup();
        let mut writer = SegmentWriter::new(
            &sim,
            fd,
            SegmentId::new(1),
            EventSequence::new(1),
            MAX_EVENT_PAYLOAD,
        )
        .unwrap();
        writer
            .append_event(&sim, &test_event(1, b"complete event"))
            .unwrap();
        writer.sync(&sim).unwrap();

        sim.write_all_at(fd, writer.position().raw(), &[1, 2, 3, 4, 5])
            .unwrap();
        sim.sync(fd).unwrap();

        let mut reader = SegmentReader::open(&sim, fd, MAX_EVENT_PAYLOAD).unwrap();
        let first = reader.next().unwrap().unwrap();
        assert!(matches!(first, ReadEventRecord::Valid { .. }));

        let second = reader.next().unwrap().unwrap();
        assert!(matches!(second, ReadEventRecord::Truncated { .. }));
    }

    #[test]
    fn checksum_detects_corruption() {
        let (sim, fd) = setup();
        let mut writer = SegmentWriter::new(
            &sim,
            fd,
            SegmentId::new(1),
            EventSequence::new(1),
            MAX_EVENT_PAYLOAD,
        )
        .unwrap();
        writer
            .append_event(&sim, &test_event(1, &vec![0xAA; 256]))
            .unwrap();
        writer.sync(&sim).unwrap();

        let corrupt_offset = SEGMENT_HEADER_SIZE as u64 + EVENT_HEADER_SIZE as u64 + 128;
        sim.write_all_at(fd, corrupt_offset, &[0x00]).unwrap();

        let mut reader = SegmentReader::open(&sim, fd, MAX_EVENT_PAYLOAD).unwrap();
        let record = reader.next().unwrap().unwrap();
        assert!(matches!(record, ReadEventRecord::Corrupted { .. }));
    }

    #[test]
    fn crash_before_sync_loses_events() {
        let (sim, fd) = setup();
        let mut writer = SegmentWriter::new(
            &sim,
            fd,
            SegmentId::new(1),
            EventSequence::new(1),
            MAX_EVENT_PAYLOAD,
        )
        .unwrap();
        writer
            .append_event(&sim, &test_event(1, b"synced"))
            .unwrap();
        writer.sync(&sim).unwrap();
        sim.sync_dir(Path::new("/test")).unwrap();

        writer
            .append_event(&sim, &test_event(2, b"not synced"))
            .unwrap();

        sim.crash();

        let fd = sim
            .open(Path::new("/test/segment.tqe"), OpenOptions::read())
            .unwrap();
        let reader = SegmentReader::open(&sim, fd, MAX_EVENT_PAYLOAD).unwrap();
        let events = reader.valid_prefix().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].payload, b"synced");
    }

    #[test]
    fn rejects_oversized_payload() {
        let (sim, fd) = setup();
        const SMALL_MAX: u32 = 1024;
        let mut writer = SegmentWriter::new(
            &sim,
            fd,
            SegmentId::new(1),
            EventSequence::new(1),
            SMALL_MAX,
        )
        .unwrap();
        let result = writer.append_event(&sim, &test_event(1, &vec![0u8; SMALL_MAX as usize + 1]));
        assert!(result.is_err());
    }

    #[test]
    fn reader_rejects_corrupt_header_claiming_oversize() {
        let (sim, fd) = setup();
        const SMALL_MAX: u32 = 1024;
        let mut writer = SegmentWriter::new(
            &sim,
            fd,
            SegmentId::new(1),
            EventSequence::new(1),
            MAX_EVENT_PAYLOAD,
        )
        .unwrap();
        writer
            .append_event(&sim, &test_event(1, &vec![0xAA; 2048]))
            .unwrap();
        writer.sync(&sim).unwrap();

        let mut reader = SegmentReader::open(&sim, fd, SMALL_MAX).unwrap();
        let record = reader.next().unwrap().unwrap();
        assert!(matches!(record, ReadEventRecord::Corrupted { .. }));
    }

    #[test]
    fn reader_with_larger_max_reads_writer_segment() {
        let (sim, fd) = setup();
        const WRITER_MAX: u32 = 16 * 1024;
        const READER_MAX: u32 = 1024 * 1024 * 1024;
        let mut writer = SegmentWriter::new(
            &sim,
            fd,
            SegmentId::new(1),
            EventSequence::new(1),
            WRITER_MAX,
        )
        .unwrap();
        writer
            .append_event(&sim, &test_event(1, &vec![0xCD; 8 * 1024]))
            .unwrap();
        writer.sync(&sim).unwrap();

        let reader = SegmentReader::open(&sim, fd, READER_MAX).unwrap();
        let events = reader.valid_prefix().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].payload.len(), 8 * 1024);
    }

    #[test]
    fn zero_length_payload_round_trips() {
        let (sim, fd) = setup();
        let mut writer = SegmentWriter::new(
            &sim,
            fd,
            SegmentId::new(1),
            EventSequence::new(1),
            MAX_EVENT_PAYLOAD,
        )
        .unwrap();
        let event = ValidEvent {
            seq: EventSequence::new(1),
            timestamp: TimestampMicros::new(1_000_000),
            did_hash: test_did_hash(1),
            event_type: EventTypeTag::IDENTITY,
            payload: vec![],
        };
        writer.append_event(&sim, &event).unwrap();
        writer.sync(&sim).unwrap();

        let reader = SegmentReader::open(&sim, fd, MAX_EVENT_PAYLOAD).unwrap();
        let events = reader.valid_prefix().unwrap();
        assert_eq!(events, vec![event]);
    }

    #[test]
    fn accepts_exact_max_payload() {
        let (sim, fd) = setup();
        const SMALL_MAX: u32 = 4096;
        let mut writer = SegmentWriter::new(
            &sim,
            fd,
            SegmentId::new(1),
            EventSequence::new(1),
            SMALL_MAX,
        )
        .unwrap();
        let result = writer.append_event(&sim, &test_event(1, &vec![0xBB; SMALL_MAX as usize]));
        assert!(result.is_ok());
    }

    #[test]
    fn bad_magic_rejected() {
        let sim = SimulatedIO::pristine(42);
        let dir = Path::new("/test");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();
        let fd = sim
            .open(Path::new("/test/bad.tqe"), OpenOptions::read_write())
            .unwrap();
        sim.write_all_at(fd, 0, b"NOPE\x01").unwrap();

        let result = SegmentReader::open(&sim, fd, MAX_EVENT_PAYLOAD);
        assert!(result.is_err());
    }

    #[test]
    fn encode_decode_round_trip_at_offset() {
        let (sim, fd) = setup();

        sim.write_all_at(fd, 0, &[0u8; 100]).unwrap();

        let offset = SegmentOffset::new(100);
        let event = ValidEvent {
            seq: EventSequence::new(42),
            timestamp: TimestampMicros::new(9_999_999),
            did_hash: test_did_hash(7),
            event_type: EventTypeTag::ACCOUNT,
            payload: b"round trip test data".to_vec(),
        };
        let bytes_written =
            encode_event_record(&sim, fd, offset, &event, MAX_EVENT_PAYLOAD).unwrap();
        let expected_size = EVENT_RECORD_OVERHEAD as u64 + event.payload.len() as u64;
        assert_eq!(bytes_written, expected_size);

        let file_size = sim.file_size(fd).unwrap();
        let record = decode_event_record(&sim, fd, offset, file_size, MAX_EVENT_PAYLOAD)
            .unwrap()
            .unwrap();
        match record {
            ReadEventRecord::Valid { event: decoded, .. } => assert_eq!(decoded, event),
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn resume_writer_continues_at_position() {
        let (sim, fd) = setup();
        let mut writer = SegmentWriter::new(
            &sim,
            fd,
            SegmentId::new(1),
            EventSequence::new(1),
            MAX_EVENT_PAYLOAD,
        )
        .unwrap();
        writer.append_event(&sim, &test_event(1, b"first")).unwrap();
        writer.sync(&sim).unwrap();

        let resume_pos = writer.position();
        let mut writer2 = SegmentWriter::resume(
            &sim,
            fd,
            SegmentId::new(1),
            resume_pos,
            EventSequence::new(1),
            Some(EventSequence::new(1)),
            MAX_EVENT_PAYLOAD,
        );
        writer2
            .append_event(&sim, &test_event(2, b"second"))
            .unwrap();
        writer2.sync(&sim).unwrap();

        let reader = SegmentReader::open(&sim, fd, MAX_EVENT_PAYLOAD).unwrap();
        let events = reader.valid_prefix().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].payload, b"first");
        assert_eq!(events[1].payload, b"second");
    }

    #[test]
    fn all_event_types_round_trip() {
        let (sim, fd) = setup();
        let mut writer = SegmentWriter::new(
            &sim,
            fd,
            SegmentId::new(1),
            EventSequence::new(1),
            MAX_EVENT_PAYLOAD,
        )
        .unwrap();

        let types = [
            EventTypeTag::COMMIT,
            EventTypeTag::IDENTITY,
            EventTypeTag::ACCOUNT,
            EventTypeTag::SYNC,
        ];

        types.iter().enumerate().for_each(|(i, &event_type)| {
            let event = ValidEvent {
                seq: EventSequence::new((i + 1) as u64),
                timestamp: TimestampMicros::new(1_000_000),
                did_hash: test_did_hash(i as u8),
                event_type,
                payload: b"payload".to_vec(),
            };
            writer.append_event(&sim, &event).unwrap();
        });
        writer.sync(&sim).unwrap();

        let reader = SegmentReader::open(&sim, fd, MAX_EVENT_PAYLOAD).unwrap();
        let events = reader.valid_prefix().unwrap();
        assert_eq!(events.len(), 4);
        events
            .iter()
            .zip(types.iter())
            .for_each(|(event, &expected_type)| {
                assert_eq!(event.event_type, expected_type);
            });
    }

    #[test]
    fn seq_zero_detected_as_corrupted() {
        let (sim, fd) = setup();
        SegmentWriter::new(
            &sim,
            fd,
            SegmentId::new(1),
            EventSequence::new(1),
            MAX_EVENT_PAYLOAD,
        )
        .unwrap();

        let mut raw_header = [0u8; EVENT_HEADER_SIZE];
        raw_header[0..8].copy_from_slice(&0u64.to_le_bytes());
        raw_header[8..16].copy_from_slice(&1_000_000u64.to_le_bytes());
        raw_header[16..20].copy_from_slice(&test_did_hash(1).raw().to_le_bytes());
        raw_header[20] = EventTypeTag::COMMIT.raw();
        raw_header[21..25].copy_from_slice(&5u32.to_le_bytes());

        sim.write_all_at(fd, SEGMENT_HEADER_SIZE as u64, &raw_header)
            .unwrap();
        sim.write_all_at(
            fd,
            SEGMENT_HEADER_SIZE as u64 + EVENT_HEADER_SIZE as u64,
            b"hello",
        )
        .unwrap();
        sim.write_all_at(
            fd,
            SEGMENT_HEADER_SIZE as u64 + EVENT_HEADER_SIZE as u64 + 5,
            &[0u8; 4],
        )
        .unwrap();

        let mut reader = SegmentReader::open(&sim, fd, MAX_EVENT_PAYLOAD).unwrap();
        let record = reader.next().unwrap().unwrap();
        assert!(matches!(record, ReadEventRecord::Corrupted { .. }));
    }

    #[test]
    fn writer_accessors() {
        let (sim, fd) = setup();
        let writer = SegmentWriter::new(
            &sim,
            fd,
            SegmentId::new(7),
            EventSequence::new(100),
            MAX_EVENT_PAYLOAD,
        )
        .unwrap();
        assert_eq!(writer.segment_id(), SegmentId::new(7));
        assert_eq!(writer.base_seq(), EventSequence::new(100));
        assert_eq!(
            writer.position(),
            SegmentOffset::new(SEGMENT_HEADER_SIZE as u64)
        );
        assert_eq!(writer.fd(), fd);
    }

    fn run_crash_recovery_seed(seed: u64) {
        let sim = SimulatedIO::new(seed, crate::FaultConfig::aggressive());
        let dir = Path::new("/data");
        let _ = sim.mkdir(dir);
        let _ = sim.sync_dir(dir);

        let written_count =
            if let Ok(fd) = sim.open(Path::new("/data/segment.tqe"), OpenOptions::read_write()) {
                if let Ok(mut writer) = SegmentWriter::new(
                    &sim,
                    fd,
                    SegmentId::new(1),
                    EventSequence::new(1),
                    MAX_EVENT_PAYLOAD,
                ) {
                    let count = (1u64..=20).fold(0u64, |count, i| {
                        let event = ValidEvent {
                            seq: EventSequence::new(i),
                            timestamp: TimestampMicros::new(i * 1_000_000),
                            did_hash: DidHash::from_did(&format!("did:plc:user{i}")),
                            event_type: EventTypeTag::COMMIT,
                            payload: vec![i as u8; ((i as usize) + 1) * 10],
                        };
                        match writer.append_event(&sim, &event) {
                            Ok(_) => count + 1,
                            Err(_) => count,
                        }
                    });
                    let _ = writer.sync(&sim);
                    count
                } else {
                    0
                }
            } else {
                0
            };
        let _ = sim.sync_dir(dir);

        sim.crash();

        if let Ok(fd) = sim.open(Path::new("/data/segment.tqe"), OpenOptions::read())
            && let Ok(reader) = SegmentReader::open(&sim, fd, MAX_EVENT_PAYLOAD)
        {
            let recovered: Vec<_> = reader
                .map_while(|r| match r {
                    Ok(ReadEventRecord::Valid { event, .. }) => Some(event),
                    _ => None,
                })
                .collect();

            assert!(
                recovered.len() as u64 <= written_count,
                "recovered {} events but only wrote {written_count}",
                recovered.len()
            );

            recovered.windows(2).enumerate().for_each(|(i, pair)| {
                assert!(
                    pair[0].seq < pair[1].seq,
                    "event {i} seq {} not less than event {} seq {}",
                    pair[0].seq,
                    i + 1,
                    pair[1].seq,
                );
            });
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        #[test]
        fn sim_crash_recovery_aggressive_faults(seed in 0u64..u64::MAX) {
            run_crash_recovery_seed(seed);
        }
    }

    fn run_bit_flip_detection_seed(seed: u64) {
        let sim = SimulatedIO::pristine(seed);
        let dir = Path::new("/data");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();

        let fd = sim
            .open(Path::new("/data/segment.tqe"), OpenOptions::read_write())
            .unwrap();
        let mut writer = SegmentWriter::new(
            &sim,
            fd,
            SegmentId::new(1),
            EventSequence::new(1),
            MAX_EVENT_PAYLOAD,
        )
        .unwrap();

        let data_len = ((seed % 256) as usize).max(1);
        let event = ValidEvent {
            seq: EventSequence::new(1),
            timestamp: TimestampMicros::new(1_000_000),
            did_hash: DidHash::from_did("did:plc:bitflip"),
            event_type: EventTypeTag::COMMIT,
            payload: vec![0xAA; data_len],
        };
        writer.append_event(&sim, &event).unwrap();
        writer.sync(&sim).unwrap();

        let record_start = SEGMENT_HEADER_SIZE as u64;
        let record_end = record_start + EVENT_RECORD_OVERHEAD as u64 + data_len as u64;
        let flip_pos = record_start + (seed.wrapping_mul(7) % (record_end - record_start));
        let flip_bit = (seed.wrapping_mul(13) % 8) as u8;

        let mut byte_buf = [0u8; 1];
        sim.read_exact_at(fd, flip_pos, &mut byte_buf).unwrap();
        byte_buf[0] ^= 1 << flip_bit;
        sim.write_all_at(fd, flip_pos, &byte_buf).unwrap();

        let mut reader = SegmentReader::open(&sim, fd, MAX_EVENT_PAYLOAD).unwrap();
        let record = reader.next().unwrap().unwrap();
        assert!(
            !matches!(record, ReadEventRecord::Valid { .. }),
            "bit flip at offset {flip_pos} bit {flip_bit} was not detected"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        #[test]
        fn sim_bit_flip_detected_by_checksum(seed in 0u64..u64::MAX) {
            run_bit_flip_detection_seed(seed);
        }
    }
}
