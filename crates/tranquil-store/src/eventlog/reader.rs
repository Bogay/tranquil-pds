use std::cell::Cell;
use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use bytes::Bytes;
use parking_lot::RwLock;
use tracing::warn;

use crate::io::{MappedFile, StorageIO};

use super::manager::SegmentManager;
use super::segment_file::{ReadEventRecord, SEGMENT_HEADER_SIZE, decode_event_record};
use super::segment_index::{DEFAULT_INDEX_INTERVAL, SegmentIndex, rebuild_from_segment};
use super::sidecar::{SidecarIndex, build_sidecar_from_segment};
use super::types::{
    DidHash, EventSequence, EventTypeTag, SegmentId, SegmentOffset, TimestampMicros,
};

const FIRST_EVENT_OFFSET: SegmentOffset = SegmentOffset::new(SEGMENT_HEADER_SIZE as u64);

#[derive(Debug, Clone)]
pub struct SequenceGap {
    pub after_segment: SegmentId,
    pub expected_seq: EventSequence,
    pub actual_seq: EventSequence,
}

#[derive(Debug, Clone)]
pub struct SequenceContiguityResult {
    pub total_segments: u64,
    pub min_seq: Option<EventSequence>,
    pub max_seq: Option<EventSequence>,
    pub gaps: Vec<SequenceGap>,
}

impl SequenceContiguityResult {
    pub fn is_contiguous(&self) -> bool {
        self.gaps.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct RawEvent {
    pub seq: EventSequence,
    pub timestamp: TimestampMicros,
    pub did_hash: DidHash,
    pub event_type: EventTypeTag,
    pub payload: Bytes,
}

#[derive(Debug, Clone, Copy)]
struct SegmentRange {
    id: SegmentId,
    first: EventSequence,
    last: EventSequence,
}

pub struct EventLogReader<S: StorageIO> {
    manager: Arc<SegmentManager<S>>,
    indexes: RwLock<HashMap<SegmentId, Arc<SegmentIndex>>>,
    sidecars: RwLock<HashMap<SegmentId, Arc<SidecarIndex>>>,
    ranges: RwLock<Vec<SegmentRange>>,
    mmaps: RwLock<HashMap<SegmentId, Arc<MappedFile>>>,
    active_segment: RwLock<Option<SegmentId>>,
    use_mmap: bool,
    skip_sealed_checksum: bool,
    max_payload: u32,
}

impl<S: StorageIO> EventLogReader<S> {
    pub fn new(
        manager: Arc<SegmentManager<S>>,
        use_mmap: bool,
        skip_sealed_checksum: bool,
        max_payload: u32,
    ) -> Self {
        Self {
            manager,
            indexes: RwLock::new(HashMap::new()),
            sidecars: RwLock::new(HashMap::new()),
            ranges: RwLock::new(Vec::new()),
            mmaps: RwLock::new(HashMap::new()),
            active_segment: RwLock::new(None),
            use_mmap,
            skip_sealed_checksum,
            max_payload,
        }
    }

    pub fn max_payload(&self) -> u32 {
        self.max_payload
    }

    pub fn set_active_segment(&self, id: SegmentId) {
        *self.active_segment.write() = Some(id);
    }

    pub fn extend_active_range(&self, first_seq: EventSequence, last_seq: EventSequence) {
        debug_assert!(first_seq <= last_seq);
        let active_id = match *self.active_segment.read() {
            Some(id) => id,
            None => return,
        };

        let mut ranges = self.ranges.write();
        match ranges.last_mut() {
            Some(last_range) if last_range.id == active_id => {
                last_range.last = last_seq;
            }
            _ => {
                ranges.push(SegmentRange {
                    id: active_id,
                    first: first_seq,
                    last: last_seq,
                });
            }
        }
    }

    pub fn seed_index(&self, segment_id: SegmentId, index: SegmentIndex) {
        self.indexes.write().insert(segment_id, Arc::new(index));
    }

    pub fn load_index(&self, segment_id: SegmentId) -> io::Result<Arc<SegmentIndex>> {
        if let Some(idx) = self.indexes.read().get(&segment_id) {
            return Ok(Arc::clone(idx));
        }

        let index = match SegmentIndex::load(
            self.manager.io(),
            &self.manager.index_path(segment_id),
        ) {
            Ok(Some(idx)) => idx,
            Ok(None) => self.rebuild_index(segment_id)?,
            Err(e) => {
                warn!(segment = %segment_id, error = %e, "index load failed, rebuilding from segment scan");
                self.rebuild_index(segment_id)?
            }
        };

        let arc = Arc::new(index);
        self.indexes.write().insert(segment_id, Arc::clone(&arc));
        Ok(arc)
    }

    fn rebuild_index(&self, segment_id: SegmentId) -> io::Result<SegmentIndex> {
        let handle = self.manager.open_for_read(segment_id)?;
        let (idx, _) = rebuild_from_segment(
            self.manager.io(),
            handle.fd(),
            DEFAULT_INDEX_INTERVAL,
            self.max_payload,
        )?;
        let _ = idx.save(self.manager.io(), &self.manager.index_path(segment_id));
        Ok(idx)
    }

    pub fn find_segment_for_seq(&self, target_seq: EventSequence) -> Option<SegmentId> {
        let ranges = self.ranges.read();
        let idx = ranges.partition_point(|r| r.last < target_seq);
        ranges
            .get(idx)
            .and_then(|r| (r.first <= target_seq).then_some(r.id))
    }

    pub fn refresh_segment_ranges(&self) -> io::Result<()> {
        let segment_ids = self.manager.list_segments()?;
        let active = *self.active_segment.read();

        let new_ranges: Vec<SegmentRange> = segment_ids
            .iter()
            .filter_map(|&id| {
                let is_active = active.is_some_and(|a| a == id);
                let idx = match is_active {
                    true => {
                        if let Some(cached) = self.indexes.read().get(&id).cloned() {
                            Ok(cached)
                        } else {
                            self.rebuild_index(id).map(|rebuilt| {
                                let arc = Arc::new(rebuilt);
                                self.indexes.write().insert(id, Arc::clone(&arc));
                                arc
                            })
                        }
                    }
                    false => self.load_index(id),
                };
                match idx {
                    Ok(idx) => match (idx.first_seq(), idx.last_seq()) {
                        (Some(first), Some(last)) => Some(SegmentRange { id, first, last }),
                        _ => None,
                    },
                    Err(e) => {
                        warn!(segment = %id, error = %e, "failed to load index for range cache");
                        None
                    }
                }
            })
            .collect();
        *self.ranges.write() = new_ranges;
        Ok(())
    }

    pub fn check_sequence_contiguity(&self) -> SequenceContiguityResult {
        let ranges = self.ranges.read();
        let mut gaps: Vec<SequenceGap> = Vec::new();
        let total_segments = ranges.len() as u64;

        ranges.windows(2).for_each(|pair| {
            let expected_next = pair[0].last.next();
            let actual_next = pair[1].first;
            if actual_next != expected_next {
                gaps.push(SequenceGap {
                    after_segment: pair[0].id,
                    expected_seq: expected_next,
                    actual_seq: actual_next,
                });
            }
        });

        let max_seq = ranges.last().map(|r| r.last);
        let min_seq = ranges.first().map(|r| r.first);

        SequenceContiguityResult {
            total_segments,
            min_seq,
            max_seq,
            gaps,
        }
    }

    fn is_mmap_eligible(&self, segment_id: SegmentId) -> bool {
        self.use_mmap
            && self
                .active_segment
                .read()
                .is_none_or(|active| active != segment_id)
    }

    fn get_mmap(&self, segment_id: SegmentId) -> io::Result<Arc<MappedFile>> {
        if let Some(m) = self.mmaps.read().get(&segment_id) {
            return Ok(Arc::clone(m));
        }

        let handle = self.manager.open_for_read(segment_id)?;
        let mapped = self.manager.io().mmap_file(handle.fd())?;
        let arc = Arc::new(mapped);
        self.mmaps.write().insert(segment_id, Arc::clone(&arc));
        Ok(arc)
    }

    fn scan_events_from_offset(
        &self,
        segment_id: SegmentId,
        start_offset: SegmentOffset,
        start_seq: EventSequence,
        limit: usize,
        events: &mut Vec<RawEvent>,
        predicate: impl FnMut(&EventSequence) -> bool,
    ) -> io::Result<bool> {
        if self.is_mmap_eligible(segment_id) {
            self.scan_mmap(
                segment_id,
                start_offset,
                start_seq,
                limit,
                events,
                predicate,
            )
        } else {
            let handle = self.manager.open_for_read(segment_id)?;
            let file_size = self.manager.io().file_size(handle.fd())?;
            self.scan_direct(
                handle.fd(),
                file_size,
                start_offset,
                start_seq,
                limit,
                events,
                predicate,
            )
        }
    }

    fn scan_mmap(
        &self,
        segment_id: SegmentId,
        start_offset: SegmentOffset,
        start_seq: EventSequence,
        limit: usize,
        events: &mut Vec<RawEvent>,
        mut predicate: impl FnMut(&EventSequence) -> bool,
    ) -> io::Result<bool> {
        let mmap = self.get_mmap(segment_id)?;
        let mmap_bytes = Bytes::from_owner(OwnedMmap(Arc::clone(&mmap)));
        let data: &[u8] = (*mmap).as_ref();
        let file_size = data.len() as u64;
        let skip_checksum = self.skip_sealed_checksum && self.is_mmap_eligible(segment_id);
        let offset = Cell::new(start_offset);
        let collected = Cell::new(0usize);

        let max_payload = self.max_payload;
        std::iter::from_fn(|| {
            let cur = offset.get();
            (cur.raw() < file_size && collected.get() < limit).then(|| {
                decode_mmap_event(
                    data,
                    &mmap_bytes,
                    cur,
                    file_size,
                    segment_id,
                    skip_checksum,
                    max_payload,
                )
            })
        })
        .try_for_each(|result| -> io::Result<()> {
            match result? {
                MmapDecodeResult::Valid(event, next_offset) => {
                    offset.set(next_offset);
                    if event.seq > start_seq && predicate(&event.seq) {
                        events.push(event);
                        collected.set(collected.get() + 1);
                    }
                }
                MmapDecodeResult::Corrupted
                | MmapDecodeResult::Truncated
                | MmapDecodeResult::EndOfSegment => {
                    offset.set(SegmentOffset::new(file_size));
                }
            }
            Ok(())
        })?;
        Ok(collected.get() >= limit)
    }

    #[allow(clippy::too_many_arguments)]
    fn scan_direct(
        &self,
        fd: crate::io::FileId,
        file_size: u64,
        start_offset: SegmentOffset,
        start_seq: EventSequence,
        limit: usize,
        events: &mut Vec<RawEvent>,
        mut predicate: impl FnMut(&EventSequence) -> bool,
    ) -> io::Result<bool> {
        let offset = Cell::new(start_offset);
        let collected = Cell::new(0usize);

        std::iter::from_fn(|| {
            let cur = offset.get();
            (cur.raw() < file_size && collected.get() < limit).then(|| {
                decode_event_record(self.manager.io(), fd, cur, file_size, self.max_payload)
            })
        })
        .try_for_each(|result| -> io::Result<()> {
            match result? {
                Some(ReadEventRecord::Valid { event, next_offset }) => {
                    offset.set(next_offset);
                    if event.seq > start_seq && predicate(&event.seq) {
                        events.push(RawEvent {
                            seq: event.seq,
                            timestamp: event.timestamp,
                            did_hash: event.did_hash,
                            event_type: event.event_type,
                            payload: Bytes::from(event.payload),
                        });
                        collected.set(collected.get() + 1);
                    }
                }
                Some(ReadEventRecord::Corrupted { .. } | ReadEventRecord::Truncated { .. })
                | None => {
                    offset.set(SegmentOffset::new(file_size));
                }
            }
            Ok(())
        })?;
        Ok(collected.get() >= limit)
    }

    pub fn read_events_from(
        &self,
        start_seq: EventSequence,
        limit: usize,
    ) -> io::Result<Vec<RawEvent>> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let ranges = self.ranges.read().clone();
        let start_idx = match start_seq {
            EventSequence::BEFORE_ALL => Some(0),
            seq => {
                let point = ranges.partition_point(|r| r.last <= seq);
                (point < ranges.len()).then_some(point)
            }
        };

        let start_idx = match start_idx {
            Some(idx) => idx,
            None => return Ok(Vec::new()),
        };

        let mut events = Vec::with_capacity(limit.min(1024));
        let done = Cell::new(false);

        ranges[start_idx..]
            .iter()
            .enumerate()
            .take_while(|_| !done.get())
            .try_for_each(|(i, range)| -> io::Result<()> {
                let remaining = limit - events.len();
                let is_first = i == 0;

                let (scan_offset, effective_seq) = match (is_first, start_seq) {
                    (_, EventSequence::BEFORE_ALL) | (false, _) => {
                        (FIRST_EVENT_OFFSET, EventSequence::BEFORE_ALL)
                    }
                    (true, seq) => {
                        let index = self.load_index(range.id)?;
                        (index.lookup(seq).unwrap_or(FIRST_EVENT_OFFSET), seq)
                    }
                };

                done.set(self.scan_events_from_offset(
                    range.id,
                    scan_offset,
                    effective_seq,
                    remaining,
                    &mut events,
                    |_| true,
                )?);
                Ok(())
            })?;

        Ok(events)
    }

    pub fn read_event_at(&self, seq: EventSequence) -> io::Result<Option<RawEvent>> {
        let segment_id = match self.find_segment_for_seq(seq) {
            Some(id) => id,
            None => return Ok(None),
        };

        let index = self.load_index(segment_id)?;
        let scan_offset = index.lookup(seq).unwrap_or(FIRST_EVENT_OFFSET);

        let mut events = Vec::with_capacity(1);
        self.scan_events_from_offset(
            segment_id,
            scan_offset,
            seq.prev_or_before_all(),
            1,
            &mut events,
            |s| *s == seq,
        )?;

        Ok(events.into_iter().next())
    }

    pub fn on_segment_rotated(
        &self,
        sealed_id: SegmentId,
        new_active_id: SegmentId,
    ) -> io::Result<()> {
        self.invalidate_index(sealed_id);
        self.invalidate_mmap(sealed_id);
        self.invalidate_sidecar(sealed_id);
        self.set_active_segment(new_active_id);
        self.refresh_segment_ranges()
    }

    pub fn invalidate_mmap(&self, segment_id: SegmentId) {
        self.mmaps.write().remove(&segment_id);
    }

    pub fn invalidate_index(&self, segment_id: SegmentId) {
        self.indexes.write().remove(&segment_id);
    }

    pub fn invalidate_sidecar(&self, segment_id: SegmentId) {
        self.sidecars.write().remove(&segment_id);
    }

    pub fn load_sidecar(&self, segment_id: SegmentId) -> io::Result<Option<Arc<SidecarIndex>>> {
        if let Some(sc) = self.sidecars.read().get(&segment_id) {
            return Ok(Some(Arc::clone(sc)));
        }

        let sidecar = match SidecarIndex::load(
            self.manager.io(),
            &self.manager.sidecar_path(segment_id),
        ) {
            Ok(Some(sc)) => sc,
            Ok(None) => return Ok(None),
            Err(e) => {
                warn!(segment = %segment_id, error = %e, "sidecar load failed, attempting rebuild");
                match self.rebuild_sidecar(segment_id) {
                    Ok(sc) => sc,
                    Err(rebuild_err) => {
                        warn!(segment = %segment_id, error = %rebuild_err, "sidecar rebuild also failed");
                        return Ok(None);
                    }
                }
            }
        };

        let arc = Arc::new(sidecar);
        self.sidecars.write().insert(segment_id, Arc::clone(&arc));
        Ok(Some(arc))
    }

    fn rebuild_sidecar(&self, segment_id: SegmentId) -> io::Result<SidecarIndex> {
        let handle = self.manager.open_for_read(segment_id)?;
        let sidecar = build_sidecar_from_segment(self.manager.io(), handle.fd(), self.max_payload)?;
        let _ = sidecar.save(self.manager.io(), &self.manager.sidecar_path(segment_id));
        Ok(sidecar)
    }
}

struct OwnedMmap(Arc<MappedFile>);

impl AsRef<[u8]> for OwnedMmap {
    fn as_ref(&self) -> &[u8] {
        (*self.0).as_ref()
    }
}

enum MmapDecodeResult {
    Valid(RawEvent, SegmentOffset),
    Corrupted,
    Truncated,
    EndOfSegment,
}

fn decode_mmap_event(
    data: &[u8],
    mmap_bytes: &Bytes,
    offset: SegmentOffset,
    file_size: u64,
    segment_id: SegmentId,
    skip_checksum: bool,
    max_payload: u32,
) -> io::Result<MmapDecodeResult> {
    use super::segment_file::EVENT_HEADER_SIZE;

    let raw = offset.raw();
    if raw > file_size {
        warn!(
            segment = %segment_id,
            offset = raw,
            file_size,
            "decode offset past file size, index likely corrupt"
        );
        return Ok(MmapDecodeResult::Corrupted);
    }
    let remaining = file_size - raw;
    if remaining == 0 {
        return Ok(MmapDecodeResult::EndOfSegment);
    }

    if remaining < EVENT_HEADER_SIZE as u64 {
        warn!(
            segment = %segment_id,
            offset = raw,
            remaining,
            "truncated record in sealed segment: not enough bytes for header"
        );
        return Ok(MmapDecodeResult::Truncated);
    }

    let base = usize::try_from(raw).expect("file offset exceeds platform address space");
    let header_slice = &data[base..base + EVENT_HEADER_SIZE];

    let seq_raw = u64::from_le_bytes(header_slice[0..8].try_into().unwrap());
    if seq_raw == 0 {
        warn!(
            segment = %segment_id,
            offset = raw,
            "corrupted record in sealed segment: seq == 0"
        );
        return Ok(MmapDecodeResult::Corrupted);
    }
    let seq = EventSequence::new(seq_raw);

    let timestamp =
        TimestampMicros::new(u64::from_le_bytes(header_slice[8..16].try_into().unwrap()));
    let did_hash = DidHash::from_raw(u32::from_le_bytes(header_slice[16..20].try_into().unwrap()));
    let event_type = match EventTypeTag::from_raw(header_slice[20]) {
        Some(t) => t,
        None => {
            warn!(
                segment = %segment_id,
                offset = raw,
                tag = header_slice[20],
                "corrupted record in sealed segment: invalid event type"
            );
            return Ok(MmapDecodeResult::Corrupted);
        }
    };

    let payload_len = u32::from_le_bytes(header_slice[21..25].try_into().unwrap());
    if payload_len > max_payload {
        warn!(
            segment = %segment_id,
            offset = raw,
            payload_len,
            "corrupted record in sealed segment: payload exceeds maximum"
        );
        return Ok(MmapDecodeResult::Corrupted);
    }

    let record_size = super::segment_file::EVENT_RECORD_OVERHEAD as u64 + u64::from(payload_len);
    if record_size > remaining {
        warn!(
            segment = %segment_id,
            offset = raw,
            record_size,
            remaining,
            "truncated record in sealed segment: record extends past file end"
        );
        return Ok(MmapDecodeResult::Truncated);
    }

    let payload_start = base + EVENT_HEADER_SIZE;
    let payload_end = payload_start + usize::try_from(payload_len).expect("payload_len fits usize");

    if !skip_checksum {
        let checksum_start = payload_end;
        let stored_checksum =
            u32::from_le_bytes(data[checksum_start..checksum_start + 4].try_into().unwrap());

        let mut hasher = xxhash_rust::xxh3::Xxh3::new();
        hasher.update(header_slice);
        hasher.update(&data[payload_start..payload_end]);
        let computed = hasher.digest() as u32;

        if stored_checksum != computed {
            warn!(
                segment = %segment_id,
                offset = raw,
                seq = %seq,
                stored = stored_checksum,
                computed,
                "corrupted record in sealed segment: checksum mismatch"
            );
            return Ok(MmapDecodeResult::Corrupted);
        }
    }

    let next_offset = offset.advance(record_size);
    Ok(MmapDecodeResult::Valid(
        RawEvent {
            seq,
            timestamp,
            did_hash,
            event_type,
            payload: mmap_bytes.slice(payload_start..payload_end),
        },
        next_offset,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eventlog::segment_file::EVENT_RECORD_OVERHEAD;
    use crate::eventlog::types::MAX_EVENT_PAYLOAD;
    use crate::eventlog::writer::EventLogWriter;
    use crate::sim::SimulatedIO;
    use std::path::PathBuf;

    fn setup_manager(max_segment_size: u64) -> Arc<SegmentManager<SimulatedIO>> {
        let sim = SimulatedIO::pristine(42);
        Arc::new(SegmentManager::new(sim, PathBuf::from("/segments"), max_segment_size).unwrap())
    }

    fn setup_with_events(
        event_count: u64,
        payload_size: usize,
        max_segment_size: u64,
    ) -> (
        Arc<SegmentManager<SimulatedIO>>,
        EventLogReader<SimulatedIO>,
    ) {
        let mgr = setup_manager(max_segment_size);
        {
            let mut writer =
                EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL, MAX_EVENT_PAYLOAD)
                    .unwrap();
            (1..=event_count).for_each(|i| {
                writer
                    .append(
                        DidHash::from_did(&format!("did:plc:user{i}")),
                        EventTypeTag::COMMIT,
                        vec![0xAA; payload_size],
                    )
                    .unwrap();
            });
            writer.shutdown().unwrap();
        }
        mgr.shutdown();

        let reader = EventLogReader::new(Arc::clone(&mgr), false, false, MAX_EVENT_PAYLOAD);
        reader.refresh_segment_ranges().unwrap();
        (mgr, reader)
    }

    fn setup_multi_segment(
        events_per_segment: u64,
        num_segments: u64,
        payload_size: usize,
    ) -> (
        Arc<SegmentManager<SimulatedIO>>,
        EventLogReader<SimulatedIO>,
    ) {
        let record_size = EVENT_RECORD_OVERHEAD + payload_size;
        let max_segment_size =
            (SEGMENT_HEADER_SIZE + record_size * events_per_segment as usize) as u64;

        let mgr = setup_manager(max_segment_size);
        {
            let mut writer =
                EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL, MAX_EVENT_PAYLOAD)
                    .unwrap();
            let total = events_per_segment * num_segments;
            (1..=total).for_each(|i| {
                writer
                    .append(
                        DidHash::from_did(&format!("did:plc:user{i}")),
                        EventTypeTag::COMMIT,
                        vec![i as u8; payload_size],
                    )
                    .unwrap();
                if i % events_per_segment == 0 && i < total {
                    writer.sync().unwrap();
                    writer.rotate_if_needed().unwrap();
                }
            });
            writer.shutdown().unwrap();
        }
        mgr.shutdown();

        let reader = EventLogReader::new(Arc::clone(&mgr), false, false, MAX_EVENT_PAYLOAD);
        reader.refresh_segment_ranges().unwrap();
        (mgr, reader)
    }

    #[test]
    fn read_events_from_single_segment() {
        let (_, reader) = setup_with_events(10, 50, 64 * 1024);

        let events = reader
            .read_events_from(EventSequence::BEFORE_ALL, 100)
            .unwrap();
        assert_eq!(events.len(), 10);
        events.iter().enumerate().for_each(|(i, e)| {
            assert_eq!(e.seq, EventSequence::new(i as u64 + 1));
            assert_eq!(e.event_type, EventTypeTag::COMMIT);
            assert_eq!(e.payload.len(), 50);
        });
    }

    #[test]
    fn read_events_from_cursor() {
        let (_, reader) = setup_with_events(10, 50, 64 * 1024);

        let events = reader.read_events_from(EventSequence::new(5), 100).unwrap();
        assert_eq!(events.len(), 5);
        assert_eq!(events[0].seq, EventSequence::new(6));
        assert_eq!(events[4].seq, EventSequence::new(10));
    }

    #[test]
    fn read_events_respects_limit() {
        let (_, reader) = setup_with_events(10, 50, 64 * 1024);

        let events = reader
            .read_events_from(EventSequence::BEFORE_ALL, 3)
            .unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].seq, EventSequence::new(1));
        assert_eq!(events[2].seq, EventSequence::new(3));
    }

    #[test]
    fn read_events_empty_on_zero_limit() {
        let (_, reader) = setup_with_events(5, 50, 64 * 1024);
        let events = reader
            .read_events_from(EventSequence::BEFORE_ALL, 0)
            .unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn read_event_at_existing() {
        let (_, reader) = setup_with_events(10, 50, 64 * 1024);

        let event = reader.read_event_at(EventSequence::new(5)).unwrap();
        assert!(event.is_some());
        let event = event.unwrap();
        assert_eq!(event.seq, EventSequence::new(5));
        assert_eq!(event.payload.len(), 50);
    }

    #[test]
    fn read_event_at_missing() {
        let (_, reader) = setup_with_events(5, 50, 64 * 1024);

        let event = reader.read_event_at(EventSequence::new(100)).unwrap();
        assert!(event.is_none());
    }

    #[test]
    fn cross_segment_read() {
        let (_, reader) = setup_multi_segment(3, 3, 50);

        let events = reader
            .read_events_from(EventSequence::BEFORE_ALL, 100)
            .unwrap();
        assert_eq!(events.len(), 9);
        events.iter().enumerate().for_each(|(i, e)| {
            assert_eq!(e.seq, EventSequence::new(i as u64 + 1));
        });
    }

    #[test]
    fn cross_segment_cursor_resumption() {
        let (_, reader) = setup_multi_segment(3, 3, 50);

        let events = reader.read_events_from(EventSequence::new(4), 100).unwrap();
        assert_eq!(events.len(), 5);
        assert_eq!(events[0].seq, EventSequence::new(5));
        assert_eq!(events[4].seq, EventSequence::new(9));
    }

    #[test]
    fn cross_segment_limit_respected() {
        let (_, reader) = setup_multi_segment(3, 3, 50);

        let events = reader
            .read_events_from(EventSequence::BEFORE_ALL, 5)
            .unwrap();
        assert_eq!(events.len(), 5);
        assert_eq!(events[0].seq, EventSequence::new(1));
        assert_eq!(events[4].seq, EventSequence::new(5));
    }

    #[test]
    fn cross_segment_limit_at_boundary() {
        let (_, reader) = setup_multi_segment(3, 3, 50);

        let events = reader.read_events_from(EventSequence::new(2), 5).unwrap();
        assert_eq!(events.len(), 5);
        assert_eq!(events[0].seq, EventSequence::new(3));
        assert_eq!(events[4].seq, EventSequence::new(7));
    }

    #[test]
    fn find_segment_for_seq_locates_correct_segment() {
        let (_, reader) = setup_multi_segment(3, 2, 50);

        assert_eq!(
            reader.find_segment_for_seq(EventSequence::new(1)),
            Some(SegmentId::new(1))
        );
        assert_eq!(
            reader.find_segment_for_seq(EventSequence::new(3)),
            Some(SegmentId::new(1))
        );
        assert_eq!(
            reader.find_segment_for_seq(EventSequence::new(4)),
            Some(SegmentId::new(2))
        );
        assert_eq!(
            reader.find_segment_for_seq(EventSequence::new(6)),
            Some(SegmentId::new(2))
        );
        assert_eq!(reader.find_segment_for_seq(EventSequence::new(100)), None);
    }

    #[test]
    fn index_caching_returns_same_arc() {
        let (_, reader) = setup_with_events(5, 50, 64 * 1024);

        let idx1 = reader.load_index(SegmentId::new(1)).unwrap();
        let idx2 = reader.load_index(SegmentId::new(1)).unwrap();
        assert!(Arc::ptr_eq(&idx1, &idx2));
    }

    #[test]
    fn refresh_after_segment_deletion() {
        let (mgr, reader) = setup_multi_segment(3, 3, 50);

        assert_eq!(
            reader.find_segment_for_seq(EventSequence::new(1)),
            Some(SegmentId::new(1))
        );

        mgr.delete_segment(SegmentId::new(1)).unwrap();
        reader.invalidate_index(SegmentId::new(1));
        reader.invalidate_mmap(SegmentId::new(1));
        reader.refresh_segment_ranges().unwrap();

        assert_eq!(reader.find_segment_for_seq(EventSequence::new(1)), None);
        assert_eq!(
            reader.find_segment_for_seq(EventSequence::new(4)),
            Some(SegmentId::new(2))
        );
    }

    #[test]
    fn mmap_read_matches_direct_read() {
        let (mgr, direct_reader) = setup_with_events(10, 50, 64 * 1024);

        let mmap_reader = EventLogReader::new(Arc::clone(&mgr), true, false, MAX_EVENT_PAYLOAD);
        mmap_reader.refresh_segment_ranges().unwrap();

        let direct_events = direct_reader
            .read_events_from(EventSequence::BEFORE_ALL, 100)
            .unwrap();
        let mmap_events = mmap_reader
            .read_events_from(EventSequence::BEFORE_ALL, 100)
            .unwrap();

        assert_eq!(direct_events.len(), mmap_events.len());
        direct_events
            .iter()
            .zip(mmap_events.iter())
            .for_each(|(d, m)| {
                assert_eq!(d.seq, m.seq);
                assert_eq!(d.timestamp, m.timestamp);
                assert_eq!(d.did_hash, m.did_hash);
                assert_eq!(d.event_type, m.event_type);
                assert_eq!(d.payload, m.payload);
            });
    }

    #[test]
    fn read_event_at_first_and_last() {
        let (_, reader) = setup_with_events(20, 50, 64 * 1024);

        let first = reader
            .read_event_at(EventSequence::new(1))
            .unwrap()
            .unwrap();
        assert_eq!(first.seq, EventSequence::new(1));

        let last = reader
            .read_event_at(EventSequence::new(20))
            .unwrap()
            .unwrap();
        assert_eq!(last.seq, EventSequence::new(20));
    }

    #[test]
    fn empty_reader_returns_empty() {
        let mgr = setup_manager(64 * 1024);
        let reader = EventLogReader::new(Arc::clone(&mgr), false, false, MAX_EVENT_PAYLOAD);
        reader.refresh_segment_ranges().unwrap();

        let events = reader
            .read_events_from(EventSequence::BEFORE_ALL, 100)
            .unwrap();
        assert!(events.is_empty());

        let event = reader.read_event_at(EventSequence::new(1)).unwrap();
        assert!(event.is_none());
    }

    #[test]
    fn cursor_past_end_returns_empty() {
        let (_, reader) = setup_with_events(5, 50, 64 * 1024);
        let events = reader.read_events_from(EventSequence::new(5), 100).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn cross_segment_read_event_at() {
        let (_, reader) = setup_multi_segment(3, 3, 50);

        (1..=9).for_each(|i| {
            let event = reader
                .read_event_at(EventSequence::new(i))
                .unwrap()
                .unwrap();
            assert_eq!(event.seq, EventSequence::new(i));
            assert_eq!(event.payload[0], i as u8);
        });
    }

    #[test]
    fn different_event_types_preserved() {
        let mgr = setup_manager(64 * 1024);
        {
            let mut writer =
                EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL, MAX_EVENT_PAYLOAD)
                    .unwrap();
            let types = [
                EventTypeTag::COMMIT,
                EventTypeTag::IDENTITY,
                EventTypeTag::ACCOUNT,
                EventTypeTag::SYNC,
            ];
            types.iter().enumerate().for_each(|(i, &et)| {
                writer
                    .append(
                        DidHash::from_did(&format!("did:plc:user{i}")),
                        et,
                        vec![0xAA; 32],
                    )
                    .unwrap();
            });
            writer.shutdown().unwrap();
        }
        mgr.shutdown();

        let reader = EventLogReader::new(Arc::clone(&mgr), false, false, MAX_EVENT_PAYLOAD);
        reader.refresh_segment_ranges().unwrap();

        let events = reader
            .read_events_from(EventSequence::BEFORE_ALL, 100)
            .unwrap();
        assert_eq!(events[0].event_type, EventTypeTag::COMMIT);
        assert_eq!(events[1].event_type, EventTypeTag::IDENTITY);
        assert_eq!(events[2].event_type, EventTypeTag::ACCOUNT);
        assert_eq!(events[3].event_type, EventTypeTag::SYNC);
    }

    #[test]
    fn active_segment_excludes_mmap() {
        let (mgr, _) = setup_with_events(10, 50, 64 * 1024);

        let reader = EventLogReader::new(Arc::clone(&mgr), true, false, MAX_EVENT_PAYLOAD);
        reader.set_active_segment(SegmentId::new(1));
        reader.refresh_segment_ranges().unwrap();

        assert!(!reader.is_mmap_eligible(SegmentId::new(1)));
        assert!(reader.is_mmap_eligible(SegmentId::new(2)));
    }

    #[test]
    fn no_active_segment_mmaps_all() {
        let reader: EventLogReader<SimulatedIO> =
            EventLogReader::new(setup_manager(64 * 1024), true, false, MAX_EVENT_PAYLOAD);

        assert!(reader.is_mmap_eligible(SegmentId::new(1)));
        assert!(reader.is_mmap_eligible(SegmentId::new(99)));
    }

    #[test]
    fn corrupt_index_offset_does_not_panic() {
        let mgr = setup_manager(64 * 1024);
        {
            let mut writer =
                EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL, MAX_EVENT_PAYLOAD)
                    .unwrap();
            (1..=5).for_each(|i| {
                writer
                    .append(
                        DidHash::from_did(&format!("did:plc:user{i}")),
                        EventTypeTag::COMMIT,
                        vec![0xAA; 50],
                    )
                    .unwrap();
            });
            writer.shutdown().unwrap();
        }
        mgr.shutdown();

        let mut bad_index = SegmentIndex::new();
        bad_index.record(EventSequence::new(1), SegmentOffset::new(999_999));
        bad_index.record(EventSequence::new(5), SegmentOffset::new(999_999));
        bad_index
            .save(mgr.io(), &mgr.index_path(SegmentId::new(1)))
            .unwrap();

        let reader = EventLogReader::new(Arc::clone(&mgr), false, false, MAX_EVENT_PAYLOAD);
        reader.refresh_segment_ranges().unwrap();

        let events = reader
            .read_events_from(EventSequence::BEFORE_ALL, 100)
            .unwrap();
        assert!(events.is_empty() || events.len() <= 5);

        let event = reader.read_event_at(EventSequence::new(3)).unwrap();
        assert!(event.is_none() || event.is_some_and(|e| e.seq == EventSequence::new(3)));
    }

    #[test]
    fn corrupt_index_offset_mmap_does_not_panic() {
        let mgr = setup_manager(64 * 1024);
        {
            let mut writer =
                EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL, MAX_EVENT_PAYLOAD)
                    .unwrap();
            (1..=5).for_each(|i| {
                writer
                    .append(
                        DidHash::from_did(&format!("did:plc:user{i}")),
                        EventTypeTag::COMMIT,
                        vec![0xAA; 50],
                    )
                    .unwrap();
            });
            writer.shutdown().unwrap();
        }
        mgr.shutdown();

        let mut bad_index = SegmentIndex::new();
        bad_index.record(EventSequence::new(1), SegmentOffset::new(999_999));
        bad_index.record(EventSequence::new(5), SegmentOffset::new(999_999));
        bad_index
            .save(mgr.io(), &mgr.index_path(SegmentId::new(1)))
            .unwrap();

        let reader = EventLogReader::new(Arc::clone(&mgr), true, false, MAX_EVENT_PAYLOAD);
        reader.refresh_segment_ranges().unwrap();

        let events = reader
            .read_events_from(EventSequence::BEFORE_ALL, 100)
            .unwrap();
        assert!(events.is_empty() || events.len() <= 5);
    }

    #[test]
    fn on_segment_rotated_updates_state() {
        let (mgr, _direct_reader) = setup_multi_segment(3, 2, 50);

        let reader = EventLogReader::new(Arc::clone(&mgr), true, false, MAX_EVENT_PAYLOAD);
        reader.refresh_segment_ranges().unwrap();

        assert_eq!(
            reader.find_segment_for_seq(EventSequence::new(1)),
            Some(SegmentId::new(1))
        );

        reader
            .on_segment_rotated(SegmentId::new(1), SegmentId::new(2))
            .unwrap();

        assert!(!reader.is_mmap_eligible(SegmentId::new(2)));
        assert!(reader.is_mmap_eligible(SegmentId::new(1)));

        let events = reader
            .read_events_from(EventSequence::BEFORE_ALL, 100)
            .unwrap();
        assert_eq!(events.len(), 6);
    }
}
