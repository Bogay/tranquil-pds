use std::cell::Cell;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::io::{FileId, OpenOptions, StorageIO};
use crate::record::{RecordReader, RecordWriter};

use super::segment_file::{
    SEGMENT_HEADER_SIZE, SEGMENT_MAGIC, ValidateEventRecord, validate_event_record,
};
use super::types::{EventSequence, SegmentOffset};

pub const DEFAULT_INDEX_INTERVAL: usize = 256;
const MAX_INDEX_ENTRIES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct IndexEntry {
    seq: EventSequence,
    offset: SegmentOffset,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentIndex {
    entries: Vec<IndexEntry>,
}

impl SegmentIndex {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn record(&mut self, seq: EventSequence, offset: SegmentOffset) {
        debug_assert!(
            self.entries.last().is_none_or(|last| seq > last.seq),
            "index entries must be monotonically increasing"
        );
        self.entries.push(IndexEntry { seq, offset });
    }

    pub fn lookup(&self, target_seq: EventSequence) -> Option<SegmentOffset> {
        let idx = self.entries.partition_point(|e| e.seq <= target_seq);
        match idx {
            0 => None,
            i => Some(self.entries[i - 1].offset),
        }
    }

    pub fn first_seq(&self) -> Option<EventSequence> {
        self.entries.first().map(|e| e.seq)
    }

    pub fn last_seq(&self) -> Option<EventSequence> {
        self.entries.last().map(|e| e.seq)
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn save<S: StorageIO>(&self, io: &S, path: &Path) -> io::Result<()> {
        let tmp_path = path.with_extension("tqi.tmp");
        let fd = io.open(&tmp_path, OpenOptions::read_write())?;

        let result = (|| {
            let serialized = postcard::to_allocvec(&self.entries)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            let mut writer = RecordWriter::new(io, fd)?;
            writer.append(&serialized)?;
            io.truncate(fd, writer.position())?;
            writer.sync()?;
            Ok(())
        })();

        if let Err(e) = result {
            let _ = io.close(fd);
            return Err(e);
        }
        io.close(fd)?;

        io.rename(&tmp_path, path)?;

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

        let payload = records.into_iter().next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "index file contains no records")
        })?;

        const MIN_POSTCARD_ENTRY_BYTES: usize = 2;
        if payload.len() / MIN_POSTCARD_ENTRY_BYTES > MAX_INDEX_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "index payload too large",
            ));
        }

        let entries: Vec<IndexEntry> = postcard::from_bytes(&payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        if entries.len() > MAX_INDEX_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "index contains too many entries",
            ));
        }

        let is_sorted = entries.windows(2).all(|pair| pair[0].seq < pair[1].seq);
        if !is_sorted {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "index entries not monotonically sorted",
            ));
        }

        Ok(Some(Self { entries }))
    }
}

impl Default for SegmentIndex {
    fn default() -> Self {
        Self::new()
    }
}

struct ScanState {
    index: SegmentIndex,
    event_count: usize,
    last_seq: Option<EventSequence>,
    last_offset: Option<SegmentOffset>,
}

pub fn rebuild_from_segment<S: StorageIO>(
    io: &S,
    segment_fd: FileId,
    index_interval: usize,
    max_payload: u32,
) -> io::Result<(SegmentIndex, Option<EventSequence>)> {
    assert!(index_interval > 0, "index_interval must be positive");
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
    if header[SEGMENT_MAGIC.len()] != super::segment_file::SEGMENT_FORMAT_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported segment format version",
        ));
    }

    let current_offset = Cell::new(SegmentOffset::new(SEGMENT_HEADER_SIZE as u64));
    let prev_seq: Cell<Option<EventSequence>> = Cell::new(None);

    let mut valid_events = std::iter::from_fn(|| {
        let offset = current_offset.get();
        if offset.raw() >= file_size {
            return None;
        }
        match validate_event_record(io, segment_fd, offset, file_size, max_payload) {
            Err(e) => Some(Err(e)),
            Ok(None) => None,
            Ok(Some(ValidateEventRecord::Valid { seq, next_offset })) => {
                if prev_seq.get().is_some_and(|prev| seq <= prev) {
                    return None;
                }
                prev_seq.set(Some(seq));
                current_offset.set(next_offset);
                Some(Ok((seq, offset)))
            }
            Ok(Some(ValidateEventRecord::Corrupted | ValidateEventRecord::Truncated)) => None,
        }
    });

    let initial = ScanState {
        index: SegmentIndex::new(),
        event_count: 0,
        last_seq: None,
        last_offset: None,
    };

    let state = valid_events.try_fold(initial, |mut state, record| -> io::Result<ScanState> {
        let (seq, record_offset) = record?;

        let should_index = state.event_count == 0 || state.event_count % index_interval == 0;
        if should_index {
            state.index.record(seq, record_offset);
        }

        state.event_count += 1;
        state.last_seq = Some(seq);
        state.last_offset = Some(record_offset);

        Ok(state)
    })?;

    let mut index = state.index;
    if let (Some(seq), Some(offset)) = (state.last_seq, state.last_offset)
        && index.last_seq() != Some(seq)
    {
        index.record(seq, offset);
    }

    let valid_end = current_offset.get().raw();
    if valid_end < file_size {
        io.truncate(segment_fd, valid_end)?;
        io.sync(segment_fd)?;
    }

    Ok((index, state.last_seq))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OpenOptions;
    use crate::eventlog::segment_file::{
        EVENT_HEADER_SIZE, SegmentWriter, ValidEvent, encode_event_record,
    };
    use crate::eventlog::types::{
        DidHash, EventSequence, EventTypeTag, MAX_EVENT_PAYLOAD, SegmentId, SegmentOffset,
        TimestampMicros,
    };
    use crate::sim::SimulatedIO;
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

    fn test_event(seq: u64, payload: &[u8]) -> ValidEvent {
        ValidEvent {
            seq: EventSequence::new(seq),
            timestamp: TimestampMicros::new(seq * 1_000_000),
            did_hash: DidHash::from_did(&format!("did:plc:test{seq}")),
            event_type: EventTypeTag::COMMIT,
            payload: payload.to_vec(),
        }
    }

    fn write_n_events<S: StorageIO>(
        io: &S,
        fd: FileId,
        count: u64,
    ) -> Vec<(EventSequence, SegmentOffset)> {
        let mut writer = SegmentWriter::new(
            io,
            fd,
            SegmentId::new(0),
            EventSequence::new(1),
            MAX_EVENT_PAYLOAD,
        )
        .unwrap();
        let offsets: Vec<_> = (1..=count)
            .map(|i| {
                let event = test_event(i, format!("payload-{i}").as_bytes());
                let offset = writer.append_event(io, &event).unwrap();
                (event.seq, offset)
            })
            .collect();
        writer.sync(io).unwrap();
        offsets
    }

    #[test]
    fn empty_index() {
        let index = SegmentIndex::new();
        assert_eq!(index.entry_count(), 0);
        assert_eq!(index.first_seq(), None);
        assert_eq!(index.last_seq(), None);
        assert_eq!(index.lookup(EventSequence::new(1)), None);
    }

    #[test]
    fn record_and_lookup_single_entry() {
        let mut index = SegmentIndex::new();
        index.record(EventSequence::new(10), SegmentOffset::new(100));

        assert_eq!(index.entry_count(), 1);
        assert_eq!(index.first_seq(), Some(EventSequence::new(10)));
        assert_eq!(index.last_seq(), Some(EventSequence::new(10)));

        assert_eq!(
            index.lookup(EventSequence::new(10)),
            Some(SegmentOffset::new(100))
        );
        assert_eq!(
            index.lookup(EventSequence::new(15)),
            Some(SegmentOffset::new(100))
        );
        assert_eq!(index.lookup(EventSequence::new(5)), None);
    }

    #[test]
    fn lookup_returns_floor_entry() {
        let mut index = SegmentIndex::new();
        index.record(EventSequence::new(1), SegmentOffset::new(100));
        index.record(EventSequence::new(100), SegmentOffset::new(5000));
        index.record(EventSequence::new(200), SegmentOffset::new(10000));

        assert_eq!(
            index.lookup(EventSequence::new(1)),
            Some(SegmentOffset::new(100))
        );
        assert_eq!(
            index.lookup(EventSequence::new(50)),
            Some(SegmentOffset::new(100))
        );
        assert_eq!(
            index.lookup(EventSequence::new(100)),
            Some(SegmentOffset::new(5000))
        );
        assert_eq!(
            index.lookup(EventSequence::new(150)),
            Some(SegmentOffset::new(5000))
        );
        assert_eq!(
            index.lookup(EventSequence::new(200)),
            Some(SegmentOffset::new(10000))
        );
        assert_eq!(
            index.lookup(EventSequence::new(999)),
            Some(SegmentOffset::new(10000))
        );
    }

    #[test]
    fn lookup_before_first_returns_none() {
        let mut index = SegmentIndex::new();
        index.record(EventSequence::new(10), SegmentOffset::new(100));
        index.record(EventSequence::new(20), SegmentOffset::new(200));

        assert_eq!(index.lookup(EventSequence::new(5)), None);
        assert_eq!(index.lookup(EventSequence::new(9)), None);
    }

    #[test]
    fn save_and_load_round_trip() {
        let sim = SimulatedIO::pristine(42);
        let dir = Path::new("/test");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();

        let mut index = SegmentIndex::new();
        index.record(EventSequence::new(1), SegmentOffset::new(5));
        index.record(EventSequence::new(256), SegmentOffset::new(50000));
        index.record(EventSequence::new(512), SegmentOffset::new(100000));

        let path = Path::new("/test/00000001.tqi");
        index.save(&sim, path).unwrap();

        let loaded = SegmentIndex::load(&sim, path).unwrap().unwrap();
        assert_eq!(loaded, index);
    }

    #[test]
    fn load_missing_file_returns_none() {
        let sim = SimulatedIO::pristine(42);
        let dir = Path::new("/test");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();

        let result = SegmentIndex::load(&sim, Path::new("/test/missing.tqi")).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn load_corrupt_file_returns_err() {
        let sim = SimulatedIO::pristine(42);
        let dir = Path::new("/test");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();

        let path = Path::new("/test/corrupt.tqi");
        let fd = sim.open(path, OpenOptions::read_write()).unwrap();
        sim.write_all_at(fd, 0, b"TQST\x02garbage_not_valid_postcard")
            .unwrap();
        sim.sync(fd).unwrap();
        sim.close(fd).unwrap();

        let result = SegmentIndex::load(&sim, path);
        assert!(result.is_err());
    }

    #[test]
    fn save_empty_index_round_trips() {
        let sim = SimulatedIO::pristine(42);
        let dir = Path::new("/test");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();

        let index = SegmentIndex::new();
        let path = Path::new("/test/empty.tqi");
        index.save(&sim, path).unwrap();

        let loaded = SegmentIndex::load(&sim, path).unwrap().unwrap();
        assert_eq!(loaded.entry_count(), 0);
    }

    #[test]
    fn rebuild_empty_segment() {
        let (sim, fd) = setup();
        SegmentWriter::new(
            &sim,
            fd,
            SegmentId::new(0),
            EventSequence::new(1),
            MAX_EVENT_PAYLOAD,
        )
        .unwrap();
        sim.sync(fd).unwrap();

        let (index, last_seq) =
            rebuild_from_segment(&sim, fd, DEFAULT_INDEX_INTERVAL, MAX_EVENT_PAYLOAD).unwrap();
        assert_eq!(index.entry_count(), 0);
        assert_eq!(last_seq, None);
    }

    #[test]
    fn rebuild_single_event() {
        let (sim, fd) = setup();
        let offsets = write_n_events(&sim, fd, 1);
        sim.sync(fd).unwrap();

        let (index, last_seq) =
            rebuild_from_segment(&sim, fd, DEFAULT_INDEX_INTERVAL, MAX_EVENT_PAYLOAD).unwrap();
        assert_eq!(last_seq, Some(EventSequence::new(1)));
        assert_eq!(index.entry_count(), 1);
        assert_eq!(index.first_seq(), Some(EventSequence::new(1)));
        assert_eq!(index.lookup(EventSequence::new(1)), Some(offsets[0].1));
    }

    #[test]
    fn rebuild_indexes_first_and_last() {
        let (sim, fd) = setup();
        let offsets = write_n_events(&sim, fd, 10);
        sim.sync(fd).unwrap();

        let (index, last_seq) =
            rebuild_from_segment(&sim, fd, DEFAULT_INDEX_INTERVAL, MAX_EVENT_PAYLOAD).unwrap();
        assert_eq!(last_seq, Some(EventSequence::new(10)));
        assert_eq!(index.entry_count(), 2);
        assert_eq!(index.first_seq(), Some(EventSequence::new(1)));
        assert_eq!(index.last_seq(), Some(EventSequence::new(10)));
        assert_eq!(index.lookup(EventSequence::new(1)), Some(offsets[0].1));
        assert_eq!(index.lookup(EventSequence::new(10)), Some(offsets[9].1));
    }

    #[test]
    fn rebuild_indexes_at_interval() {
        let (sim, fd) = setup();
        let offsets = write_n_events(&sim, fd, 600);
        sim.sync(fd).unwrap();

        let (index, last_seq) = rebuild_from_segment(&sim, fd, 256, MAX_EVENT_PAYLOAD).unwrap();
        assert_eq!(last_seq, Some(EventSequence::new(600)));
        assert_eq!(index.first_seq(), Some(EventSequence::new(1)));
        assert_eq!(index.last_seq(), Some(EventSequence::new(600)));
        assert_eq!(index.entry_count(), 4);
        assert_eq!(index.lookup(EventSequence::new(1)), Some(offsets[0].1));
        assert_eq!(index.lookup(EventSequence::new(257)), Some(offsets[256].1));
        assert_eq!(index.lookup(EventSequence::new(256)), Some(offsets[0].1));
        assert_eq!(index.lookup(EventSequence::new(513)), Some(offsets[512].1));
        assert_eq!(index.lookup(EventSequence::new(600)), Some(offsets[599].1));
    }

    #[test]
    fn rebuild_truncates_corruption() {
        let (sim, fd) = setup();
        write_n_events(&sim, fd, 5);
        sim.sync(fd).unwrap();

        let file_size_before = sim.file_size(fd).unwrap();

        sim.write_all_at(fd, file_size_before, b"garbage_trailing_data")
            .unwrap();
        sim.sync(fd).unwrap();
        let file_size_with_garbage = sim.file_size(fd).unwrap();
        assert!(file_size_with_garbage > file_size_before);

        let (index, last_seq) =
            rebuild_from_segment(&sim, fd, DEFAULT_INDEX_INTERVAL, MAX_EVENT_PAYLOAD).unwrap();
        assert_eq!(last_seq, Some(EventSequence::new(5)));
        assert_eq!(index.first_seq(), Some(EventSequence::new(1)));

        let file_size_after = sim.file_size(fd).unwrap();
        assert_eq!(file_size_after, file_size_before);
    }

    #[test]
    fn rebuild_truncates_partial_record() {
        let (sim, fd) = setup();
        write_n_events(&sim, fd, 3);
        sim.sync(fd).unwrap();

        let valid_end = sim.file_size(fd).unwrap();

        let partial_header = [0u8; EVENT_HEADER_SIZE - 5];
        sim.write_all_at(fd, valid_end, &partial_header).unwrap();
        sim.sync(fd).unwrap();

        let (_, last_seq) =
            rebuild_from_segment(&sim, fd, DEFAULT_INDEX_INTERVAL, MAX_EVENT_PAYLOAD).unwrap();
        assert_eq!(last_seq, Some(EventSequence::new(3)));
        assert_eq!(sim.file_size(fd).unwrap(), valid_end);
    }

    #[test]
    fn rebuild_truncates_at_non_monotonic_seq() {
        let (sim, fd) = setup();
        let mut writer = SegmentWriter::new(
            &sim,
            fd,
            SegmentId::new(0),
            EventSequence::new(1),
            MAX_EVENT_PAYLOAD,
        )
        .unwrap();

        let event1 = test_event(1, b"first");
        let event2 = test_event(2, b"second");
        writer.append_event(&sim, &event1).unwrap();
        let offset_after_two = {
            writer.append_event(&sim, &event2).unwrap();
            writer.position()
        };
        writer.sync(&sim).unwrap();

        let valid_size_before = offset_after_two.raw();

        let regressed = ValidEvent {
            seq: EventSequence::new(1),
            timestamp: TimestampMicros::new(3_000_000),
            did_hash: DidHash::from_did("did:plc:test3"),
            event_type: EventTypeTag::COMMIT,
            payload: b"regressed".to_vec(),
        };
        encode_event_record(&sim, fd, offset_after_two, &regressed, MAX_EVENT_PAYLOAD).unwrap();
        sim.sync(fd).unwrap();

        let (index, last_seq) =
            rebuild_from_segment(&sim, fd, DEFAULT_INDEX_INTERVAL, MAX_EVENT_PAYLOAD).unwrap();
        assert_eq!(last_seq, Some(EventSequence::new(2)));
        assert_eq!(index.first_seq(), Some(EventSequence::new(1)));
        assert_eq!(index.last_seq(), Some(EventSequence::new(2)));
        assert_eq!(sim.file_size(fd).unwrap(), valid_size_before);
    }

    #[test]
    fn rebuild_interval_one_indexes_every_event() {
        let (sim, fd) = setup();
        let offsets = write_n_events(&sim, fd, 10);
        sim.sync(fd).unwrap();

        let (index, _) = rebuild_from_segment(&sim, fd, 1, MAX_EVENT_PAYLOAD).unwrap();
        assert_eq!(index.entry_count(), 10);

        offsets.iter().enumerate().for_each(|(i, (seq, offset))| {
            assert_eq!(index.lookup(*seq), Some(*offset), "event {i} lookup failed");
        });
    }

    #[test]
    fn rebuild_and_save_load_round_trip() {
        let sim = SimulatedIO::pristine(42);
        let dir = Path::new("/test");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();

        let fd = sim
            .open(Path::new("/test/segment.tqe"), OpenOptions::read_write())
            .unwrap();
        write_n_events(&sim, fd, 300);
        sim.sync(fd).unwrap();

        let (index, last_seq) = rebuild_from_segment(&sim, fd, 256, MAX_EVENT_PAYLOAD).unwrap();
        assert_eq!(last_seq, Some(EventSequence::new(300)));

        let index_path = Path::new("/test/00000000.tqi");
        index.save(&sim, index_path).unwrap();

        let loaded = SegmentIndex::load(&sim, index_path).unwrap().unwrap();
        assert_eq!(loaded, index);
        assert_eq!(loaded.entry_count(), index.entry_count());
        assert_eq!(loaded.first_seq(), index.first_seq());
        assert_eq!(loaded.last_seq(), index.last_seq());
    }

    #[test]
    fn save_overwrites_stale_tmp() {
        let sim = SimulatedIO::pristine(42);
        let dir = Path::new("/test");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();

        let stale_tmp = Path::new("/test/00000000.tqi.tmp");
        let stale_fd = sim.open(stale_tmp, OpenOptions::read_write()).unwrap();
        sim.write_all_at(stale_fd, 0, b"stale_garbage_from_prior_crash_xxxxxxxxxx")
            .unwrap();
        sim.sync(stale_fd).unwrap();
        sim.close(stale_fd).unwrap();

        let mut index = SegmentIndex::new();
        index.record(EventSequence::new(1), SegmentOffset::new(5));

        let path = Path::new("/test/00000000.tqi");
        index.save(&sim, path).unwrap();

        let loaded = SegmentIndex::load(&sim, path).unwrap().unwrap();
        assert_eq!(loaded, index);
    }

    #[test]
    fn rebuild_bad_magic_returns_err() {
        let sim = SimulatedIO::pristine(42);
        let dir = Path::new("/test");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();

        let fd = sim
            .open(Path::new("/test/bad.tqe"), OpenOptions::read_write())
            .unwrap();
        sim.write_all_at(fd, 0, b"NOPE\x01").unwrap();
        sim.sync(fd).unwrap();

        let result = rebuild_from_segment(&sim, fd, DEFAULT_INDEX_INTERVAL, MAX_EVENT_PAYLOAD);
        assert!(result.is_err());
    }

    #[test]
    fn rebuild_no_truncation_when_clean() {
        let (sim, fd) = setup();
        write_n_events(&sim, fd, 5);
        sim.sync(fd).unwrap();

        let size_before = sim.file_size(fd).unwrap();
        rebuild_from_segment(&sim, fd, DEFAULT_INDEX_INTERVAL, MAX_EVENT_PAYLOAD).unwrap();
        let size_after = sim.file_size(fd).unwrap();
        assert_eq!(size_before, size_after);
    }

    #[test]
    fn lookup_at_before_all_returns_none() {
        let mut index = SegmentIndex::new();
        index.record(EventSequence::new(1), SegmentOffset::new(5));

        assert_eq!(index.lookup(EventSequence::BEFORE_ALL), None);
    }
}
