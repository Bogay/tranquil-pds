use std::io;
use std::sync::Arc;

use tracing::warn;

use crate::io::StorageIO;

use super::manager::SegmentManager;
use super::segment_file::{SEGMENT_HEADER_SIZE, SegmentWriter, ValidEvent};
use super::segment_index::{DEFAULT_INDEX_INTERVAL, SegmentIndex, rebuild_from_segment};
use super::types::{
    DidHash, EventSequence, EventTypeTag, MAX_EVENT_PAYLOAD, SegmentId, SegmentOffset,
    TimestampMicros,
};

#[derive(Debug)]
pub struct SyncResult {
    pub synced_through: EventSequence,
    pub segment_id: SegmentId,
    pub position: SegmentOffset,
    pub flushed_events: Vec<ValidEvent>,
}

pub struct EventLogWriter<S: StorageIO> {
    manager: Arc<SegmentManager<S>>,
    active_writer: SegmentWriter,
    active_index: SegmentIndex,
    next_seq: EventSequence,
    synced_seq: EventSequence,
    index_interval: usize,
    event_count_in_segment: usize,
    last_event_offset: Option<SegmentOffset>,
    pending_events: Vec<ValidEvent>,
}

impl<S: StorageIO> EventLogWriter<S> {
    pub fn open(manager: Arc<SegmentManager<S>>, index_interval: usize) -> io::Result<Self> {
        assert!(index_interval > 0, "index_interval must be positive");

        let segments = manager.list_segments()?;

        match segments.last() {
            None => Self::init_fresh(
                manager,
                SegmentId::new(1),
                EventSequence::new(1),
                index_interval,
            ),
            Some(&last_id) => Self::recover_active(manager, &segments, last_id, index_interval),
        }
    }

    fn init_fresh(
        manager: Arc<SegmentManager<S>>,
        segment_id: SegmentId,
        next_seq: EventSequence,
        index_interval: usize,
    ) -> io::Result<Self> {
        let fd = manager.open_for_append(segment_id)?;
        manager.io().truncate(fd, 0)?;
        let writer = SegmentWriter::new(manager.io(), fd, segment_id, next_seq)?;
        writer.sync(manager.io())?;
        manager.io().sync_dir(manager.segments_dir())?;

        Ok(Self {
            manager,
            active_writer: writer,
            active_index: SegmentIndex::new(),
            next_seq,
            synced_seq: next_seq.prev_or_before_all(),
            index_interval,
            event_count_in_segment: 0,
            last_event_offset: None,
            pending_events: Vec::new(),
        })
    }

    fn recover_active(
        manager: Arc<SegmentManager<S>>,
        segments: &[SegmentId],
        active_id: SegmentId,
        index_interval: usize,
    ) -> io::Result<Self> {
        let fd = manager.open_for_append(active_id)?;

        let (index, last_seq_in_active) = match rebuild_from_segment(
            manager.io(),
            fd,
            index_interval,
        ) {
            Ok(result) => result,
            Err(rebuild_err) => {
                let file_size = manager.io().file_size(fd)?;
                if file_size <= SEGMENT_HEADER_SIZE as u64 {
                    manager.io().truncate(fd, 0)?;
                    let prev_segments = &segments[..segments.len().saturating_sub(1)];
                    let next_seq = find_last_seq_from_segments(&manager, prev_segments)?
                        .map_or(EventSequence::new(1), |s| s.next());
                    return Self::init_fresh(
                        Arc::clone(&manager),
                        active_id,
                        next_seq,
                        index_interval,
                    );
                }
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "segment {active_id} rebuild failed ({file_size} bytes on disk): {rebuild_err}"
                    ),
                ));
            }
        };

        let position = SegmentOffset::new(manager.io().file_size(fd)?);

        let prev_segments = &segments[..segments.len().saturating_sub(1)];

        let next_seq = match last_seq_in_active {
            Some(seq) => {
                if let Some(sealed_last) = find_last_seq_from_segments(&manager, prev_segments)?
                    && seq <= sealed_last
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "active segment last seq ({seq}) must exceed sealed segments' \
                             last seq ({sealed_last}): cross-segment corruption detected"
                        ),
                    ));
                }
                seq.next()
            }
            None => find_last_seq_from_segments(&manager, prev_segments)?
                .map_or(EventSequence::new(1), |s| s.next()),
        };

        let synced_seq = next_seq.prev_or_before_all();

        let event_count_in_segment = match (index.first_seq(), index.last_seq()) {
            (Some(first), Some(last)) => {
                debug_assert!(
                    first <= last,
                    "index invariant violated: first_seq {first} > last_seq {last}"
                );
                usize::try_from(last.raw() - first.raw() + 1).expect("event count exceeds usize")
            }
            _ => 0,
        };

        let base_seq = index.first_seq().unwrap_or(next_seq);

        let last_event_offset = index.last_seq().and_then(|seq| index.lookup(seq));

        let writer = SegmentWriter::resume(
            manager.io(),
            fd,
            active_id,
            position,
            base_seq,
            last_seq_in_active,
        );

        if let Err(e) = manager.io().delete(&manager.index_path(active_id))
            && e.kind() != io::ErrorKind::NotFound
        {
            warn!(segment = %active_id, error = %e, "failed to delete stale index");
        }

        Ok(Self {
            manager,
            active_writer: writer,
            active_index: index,
            next_seq,
            synced_seq,
            index_interval,
            event_count_in_segment,
            last_event_offset,
            pending_events: Vec::new(),
        })
    }

    pub fn append(
        &mut self,
        did_hash: DidHash,
        event_type: EventTypeTag,
        payload: Vec<u8>,
    ) -> io::Result<EventSequence> {
        let payload_len = u32::try_from(payload.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "payload exceeds u32::MAX"))?;
        if payload_len > MAX_EVENT_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "payload length {payload_len} exceeds MAX_EVENT_PAYLOAD {MAX_EVENT_PAYLOAD}"
                ),
            ));
        }

        let seq = self.next_seq;
        let timestamp = TimestampMicros::now();

        let event = ValidEvent {
            seq,
            timestamp,
            did_hash,
            event_type,
            payload,
        };

        let offset = self.active_writer.append_event(self.manager.io(), &event)?;

        let should_index = self.event_count_in_segment == 0
            || self
                .event_count_in_segment
                .is_multiple_of(self.index_interval);
        if should_index {
            self.active_index.record(seq, offset);
        }

        self.event_count_in_segment = self
            .event_count_in_segment
            .checked_add(1)
            .expect("event_count_in_segment overflow");
        self.last_event_offset = Some(offset);
        self.next_seq = seq.next();
        self.pending_events.push(event);

        Ok(seq)
    }

    pub fn sync(&mut self) -> io::Result<SyncResult> {
        if !self.pending_events.is_empty() {
            self.active_writer.sync(self.manager.io())?;
        }

        let flushed = std::mem::take(&mut self.pending_events);
        self.synced_seq = flushed.last().map(|e| e.seq).unwrap_or(self.synced_seq);

        Ok(SyncResult {
            synced_through: self.synced_seq,
            segment_id: self.active_writer.segment_id(),
            position: self.active_writer.position(),
            flushed_events: flushed,
        })
    }

    pub fn rotate_if_needed(&mut self) -> io::Result<Option<SegmentId>> {
        if !self.manager.should_rotate(self.active_writer.position()) {
            return Ok(None);
        }

        if !self.pending_events.is_empty() {
            return Ok(None);
        }

        let old_id = self.active_writer.segment_id();

        self.ensure_last_event_indexed();

        self.manager.seal_segment(old_id, &self.active_index)?;

        let (new_id, new_fd) = self.manager.prepare_rotation(old_id)?;

        match SegmentWriter::new::<S>(self.manager.io(), new_fd, new_id, self.next_seq) {
            Ok(writer) => {
                self.active_writer = writer;
                self.active_index = SegmentIndex::new();
                self.event_count_in_segment = 0;
                self.last_event_offset = None;
                self.manager.commit_rotation(new_id, new_fd);
                Ok(Some(old_id))
            }
            Err(e) => {
                self.manager.rollback_rotation(new_id, new_fd);
                Err(e)
            }
        }
    }

    pub fn checkpoint_index(&self) -> io::Result<()> {
        if self.active_index.entry_count() == 0 {
            return Ok(());
        }
        let path = self.manager.index_path(self.active_writer.segment_id());
        self.active_index.save(self.manager.io(), &path)
    }

    pub fn current_seq(&self) -> EventSequence {
        self.next_seq.prev_or_before_all()
    }

    pub fn synced_seq(&self) -> EventSequence {
        self.synced_seq
    }

    pub fn active_segment_id(&self) -> SegmentId {
        self.active_writer.segment_id()
    }

    pub fn active_index_snapshot(&self) -> SegmentIndex {
        self.active_index.clone()
    }

    pub fn position(&self) -> SegmentOffset {
        self.active_writer.position()
    }

    pub fn shutdown(&mut self) -> io::Result<()> {
        let _ = self.sync()?;
        self.ensure_last_event_indexed();
        self.checkpoint_index()
    }

    fn ensure_last_event_indexed(&mut self) {
        let last_written = self.next_seq.prev_or_before_all();
        let needs_final_index = self.last_event_offset.is_some()
            && (self.active_index.last_seq() != Some(last_written));
        if let (true, Some(offset)) = (needs_final_index, self.last_event_offset) {
            self.active_index.record(last_written, offset);
        }
    }
}

fn find_last_seq_from_segments<S: StorageIO>(
    manager: &SegmentManager<S>,
    segments: &[SegmentId],
) -> io::Result<Option<EventSequence>> {
    segments.iter().rev().try_fold(None, |acc, &seg_id| {
        if acc.is_some() {
            return Ok(acc);
        }

        match SegmentIndex::load(manager.io(), &manager.index_path(seg_id)) {
            Ok(Some(idx)) => Ok(idx.last_seq()),
            Err(e) if e.kind() != io::ErrorKind::InvalidData => Err(e),
            _ => {
                let fd = manager.open_for_read(seg_id)?;
                let (_, last_seq) = rebuild_from_segment(manager.io(), fd, DEFAULT_INDEX_INTERVAL)?;
                Ok(last_seq)
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eventlog::segment_file::{EVENT_RECORD_OVERHEAD, SegmentReader};
    use crate::eventlog::segment_index::DEFAULT_INDEX_INTERVAL;
    use crate::sim::SimulatedIO;
    use std::path::{Path, PathBuf};

    fn setup_manager(max_segment_size: u64) -> Arc<SegmentManager<SimulatedIO>> {
        let sim = SimulatedIO::pristine(42);
        Arc::new(SegmentManager::new(sim, PathBuf::from("/segments"), max_segment_size).unwrap())
    }

    fn append_test_event(
        writer: &mut EventLogWriter<SimulatedIO>,
        did_seed: &str,
    ) -> EventSequence {
        writer
            .append(
                DidHash::from_did(did_seed),
                EventTypeTag::COMMIT,
                format!("payload-{did_seed}").into_bytes(),
            )
            .unwrap()
    }

    #[test]
    fn open_fresh_creates_segment() {
        let mgr = setup_manager(64 * 1024);
        let writer = EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL).unwrap();

        assert_eq!(writer.active_segment_id(), SegmentId::new(1));
        assert_eq!(writer.current_seq(), EventSequence::BEFORE_ALL);
        assert_eq!(writer.synced_seq(), EventSequence::BEFORE_ALL);
        assert_eq!(
            writer.position(),
            SegmentOffset::new(SEGMENT_HEADER_SIZE as u64)
        );

        let segments = mgr.list_segments().unwrap();
        assert_eq!(segments, vec![SegmentId::new(1)]);
    }

    #[test]
    fn append_assigns_contiguous_sequences() {
        let mgr = setup_manager(64 * 1024);
        let mut writer = EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL).unwrap();

        let seqs: Vec<EventSequence> = (1..=5)
            .map(|i| append_test_event(&mut writer, &format!("did:plc:user{i}")))
            .collect();

        assert_eq!(seqs, (1..=5).map(EventSequence::new).collect::<Vec<_>>());
        assert_eq!(writer.current_seq(), EventSequence::new(5));
    }

    #[test]
    fn sync_returns_flushed_events() {
        let mgr = setup_manager(64 * 1024);
        let mut writer = EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL).unwrap();

        (1..=3).for_each(|i| {
            append_test_event(&mut writer, &format!("did:plc:user{i}"));
        });

        let result = writer.sync().unwrap();
        assert_eq!(result.synced_through, EventSequence::new(3));
        assert_eq!(result.flushed_events.len(), 3);
        assert_eq!(result.segment_id, SegmentId::new(1));

        result
            .flushed_events
            .iter()
            .enumerate()
            .for_each(|(i, event)| {
                assert_eq!(event.seq, EventSequence::new(i as u64 + 1));
            });

        assert_eq!(writer.synced_seq(), EventSequence::new(3));
    }

    #[test]
    fn sync_without_pending_is_noop() {
        let mgr = setup_manager(64 * 1024);
        let mut writer = EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL).unwrap();

        let result = writer.sync().unwrap();
        assert_eq!(result.synced_through, EventSequence::BEFORE_ALL);
        assert!(result.flushed_events.is_empty());
    }

    #[test]
    fn second_sync_returns_only_new_events() {
        let mgr = setup_manager(64 * 1024);
        let mut writer = EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL).unwrap();

        (1..=3).for_each(|i| {
            append_test_event(&mut writer, &format!("did:plc:user{i}"));
        });
        writer.sync().unwrap();

        (4..=5).for_each(|i| {
            append_test_event(&mut writer, &format!("did:plc:user{i}"));
        });
        let result = writer.sync().unwrap();
        assert_eq!(result.synced_through, EventSequence::new(5));
        assert_eq!(result.flushed_events.len(), 2);
        assert_eq!(result.flushed_events[0].seq, EventSequence::new(4));
        assert_eq!(result.flushed_events[1].seq, EventSequence::new(5));
    }

    #[test]
    fn recovery_preserves_synced_events() {
        let mgr = setup_manager(64 * 1024);

        {
            let mut writer =
                EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL).unwrap();
            (1..=5).for_each(|i| {
                append_test_event(&mut writer, &format!("did:plc:user{i}"));
            });
            writer.sync().unwrap();
        }

        mgr.shutdown();

        let writer = EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL).unwrap();
        assert_eq!(writer.current_seq(), EventSequence::new(5));
        assert_eq!(writer.synced_seq(), EventSequence::new(5));
        assert_eq!(writer.active_segment_id(), SegmentId::new(1));

        let fd = mgr.open_for_read(SegmentId::new(1)).unwrap();
        let events = SegmentReader::open(mgr.io(), fd)
            .unwrap()
            .valid_prefix()
            .unwrap();
        assert_eq!(events.len(), 5);
    }

    #[test]
    fn recovery_loses_unsynced_events() {
        let mgr = setup_manager(64 * 1024);

        {
            let mut writer =
                EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL).unwrap();
            (1..=3).for_each(|i| {
                append_test_event(&mut writer, &format!("did:plc:user{i}"));
            });
            writer.sync().unwrap();
            mgr.io().sync_dir(Path::new("/segments")).unwrap();

            (4..=6).for_each(|i| {
                append_test_event(&mut writer, &format!("did:plc:user{i}"));
            });
        }

        mgr.shutdown();
        mgr.io().crash();

        let writer = EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL).unwrap();
        assert_eq!(writer.current_seq(), EventSequence::new(3));
        assert_eq!(writer.next_seq, EventSequence::new(4));
    }

    #[test]
    fn rotation_creates_new_segment() {
        let payload_size = 100;
        let record_size = EVENT_RECORD_OVERHEAD + payload_size;
        let max_segment_size = SEGMENT_HEADER_SIZE + record_size * 3;

        let mgr = setup_manager(max_segment_size as u64);
        let mut writer = EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL).unwrap();

        (1..=3).for_each(|i| {
            writer
                .append(
                    DidHash::from_did(&format!("did:plc:user{i}")),
                    EventTypeTag::COMMIT,
                    vec![0xAA; payload_size],
                )
                .unwrap();
        });
        writer.sync().unwrap();
        assert!(writer.rotate_if_needed().unwrap().is_some());

        assert_eq!(writer.active_segment_id(), SegmentId::new(2));
        assert_eq!(
            writer.position(),
            SegmentOffset::new(SEGMENT_HEADER_SIZE as u64)
        );

        let segments = mgr.list_segments().unwrap();
        assert_eq!(segments, vec![SegmentId::new(1), SegmentId::new(2)]);
    }

    #[test]
    fn rotation_seals_old_segment() {
        let payload_size = 100;
        let record_size = EVENT_RECORD_OVERHEAD + payload_size;
        let max_segment_size = SEGMENT_HEADER_SIZE + record_size * 2;

        let mgr = setup_manager(max_segment_size as u64);
        let mut writer = EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL).unwrap();

        (1..=2).for_each(|i| {
            writer
                .append(
                    DidHash::from_did(&format!("did:plc:user{i}")),
                    EventTypeTag::COMMIT,
                    vec![0xBB; payload_size],
                )
                .unwrap();
        });
        writer.sync().unwrap();
        writer.rotate_if_needed().unwrap();

        assert!(mgr.is_sealed(SegmentId::new(1)));

        let index = SegmentIndex::load(mgr.io(), &mgr.index_path(SegmentId::new(1)))
            .unwrap()
            .unwrap();
        assert_eq!(index.first_seq(), Some(EventSequence::new(1)));
        assert_eq!(index.last_seq(), Some(EventSequence::new(2)));
    }

    #[test]
    fn sequences_continue_across_rotation() {
        let payload_size = 50;
        let record_size = EVENT_RECORD_OVERHEAD + payload_size;
        let max_segment_size = SEGMENT_HEADER_SIZE + record_size * 2;

        let mgr = setup_manager(max_segment_size as u64);
        let mut writer = EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL).unwrap();

        (1..=2).for_each(|i| {
            writer
                .append(
                    DidHash::from_did(&format!("did:plc:user{i}")),
                    EventTypeTag::COMMIT,
                    vec![0xCC; payload_size],
                )
                .unwrap();
        });
        writer.sync().unwrap();
        writer.rotate_if_needed().unwrap();

        let seq = writer
            .append(
                DidHash::from_did("did:plc:user3"),
                EventTypeTag::COMMIT,
                vec![0xCC; payload_size],
            )
            .unwrap();
        assert_eq!(seq, EventSequence::new(3));
    }

    #[test]
    fn recovery_after_rotation() {
        let payload_size = 50;
        let record_size = EVENT_RECORD_OVERHEAD + payload_size;
        let max_segment_size = SEGMENT_HEADER_SIZE + record_size * 2;

        let mgr = setup_manager(max_segment_size as u64);

        {
            let mut writer =
                EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL).unwrap();
            (1..=2).for_each(|i| {
                writer
                    .append(
                        DidHash::from_did(&format!("did:plc:user{i}")),
                        EventTypeTag::COMMIT,
                        vec![0xDD; payload_size],
                    )
                    .unwrap();
            });
            writer.sync().unwrap();
            writer.rotate_if_needed().unwrap();

            writer
                .append(
                    DidHash::from_did("did:plc:user3"),
                    EventTypeTag::COMMIT,
                    vec![0xDD; payload_size],
                )
                .unwrap();
            writer.sync().unwrap();
        }

        mgr.shutdown();

        let writer = EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL).unwrap();
        assert_eq!(writer.active_segment_id(), SegmentId::new(2));
        assert_eq!(writer.current_seq(), EventSequence::new(3));
        assert_eq!(writer.next_seq, EventSequence::new(4));
    }

    #[test]
    fn recovery_sealed_last_segment() {
        let payload_size = 50;
        let record_size = EVENT_RECORD_OVERHEAD + payload_size;
        let max_segment_size = SEGMENT_HEADER_SIZE + record_size * 2;

        let mgr = setup_manager(max_segment_size as u64);

        {
            let mut writer =
                EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL).unwrap();
            (1..=2).for_each(|i| {
                writer
                    .append(
                        DidHash::from_did(&format!("did:plc:user{i}")),
                        EventTypeTag::COMMIT,
                        vec![0xEE; payload_size],
                    )
                    .unwrap();
            });
            writer.sync().unwrap();
            writer.rotate_if_needed().unwrap();
        }

        mgr.shutdown();
        mgr.io().crash();

        let writer = EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL).unwrap();
        assert_eq!(writer.next_seq, EventSequence::new(3));
    }

    #[test]
    fn recovery_empty_active_after_rotation() {
        let payload_size = 50;
        let record_size = EVENT_RECORD_OVERHEAD + payload_size;
        let max_segment_size = SEGMENT_HEADER_SIZE + record_size * 2;

        let mgr = setup_manager(max_segment_size as u64);

        {
            let mut writer =
                EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL).unwrap();
            (1..=2).for_each(|i| {
                writer
                    .append(
                        DidHash::from_did(&format!("did:plc:user{i}")),
                        EventTypeTag::COMMIT,
                        vec![0xEE; payload_size],
                    )
                    .unwrap();
            });
            writer.sync().unwrap();
            writer.rotate_if_needed().unwrap();
        }

        mgr.shutdown();

        let writer = EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL).unwrap();
        assert_eq!(writer.next_seq, EventSequence::new(3));

        let fd = mgr.open_for_read(SegmentId::new(1)).unwrap();
        let events = SegmentReader::open(mgr.io(), fd)
            .unwrap()
            .valid_prefix()
            .unwrap();
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn checkpoint_creates_index_file() {
        let mgr = setup_manager(64 * 1024);
        let mut writer = EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL).unwrap();

        (1..=10).for_each(|i| {
            append_test_event(&mut writer, &format!("did:plc:user{i}"));
        });
        writer.sync().unwrap();

        writer.checkpoint_index().unwrap();

        let wip = mgr.index_path(SegmentId::new(1));
        let loaded = SegmentIndex::load(mgr.io(), &wip).unwrap();
        assert!(loaded.is_some());
    }

    #[test]
    fn checkpoint_empty_index_is_noop() {
        let mgr = setup_manager(64 * 1024);
        let writer = EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL).unwrap();

        writer.checkpoint_index().unwrap();

        let wip = mgr.index_path(SegmentId::new(1));
        let loaded = SegmentIndex::load(mgr.io(), &wip).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn current_seq_and_synced_seq_diverge_before_sync() {
        let mgr = setup_manager(64 * 1024);
        let mut writer = EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL).unwrap();

        append_test_event(&mut writer, "did:plc:user1");
        append_test_event(&mut writer, "did:plc:user2");

        assert_eq!(writer.current_seq(), EventSequence::new(2));
        assert_eq!(writer.synced_seq(), EventSequence::BEFORE_ALL);

        writer.sync().unwrap();

        assert_eq!(writer.current_seq(), EventSequence::new(2));
        assert_eq!(writer.synced_seq(), EventSequence::new(2));
    }

    #[test]
    fn sparse_index_built_at_intervals() {
        let mgr = setup_manager(64 * 1024);
        let mut writer = EventLogWriter::open(Arc::clone(&mgr), 4).unwrap();

        (1..=10).for_each(|i| {
            append_test_event(&mut writer, &format!("did:plc:user{i}"));
        });
        writer.sync().unwrap();

        assert_eq!(writer.active_index.first_seq(), Some(EventSequence::new(1)));
        assert!(writer.active_index.entry_count() >= 3);
        assert!(writer.active_index.lookup(EventSequence::new(1)).is_some());
        assert!(writer.active_index.lookup(EventSequence::new(5)).is_some());
    }

    #[test]
    fn multi_rotation_and_recovery() {
        let payload_size = 30;
        let record_size = EVENT_RECORD_OVERHEAD + payload_size;
        let max_segment_size = SEGMENT_HEADER_SIZE + record_size * 3;

        let mgr = setup_manager(max_segment_size as u64);

        {
            let mut writer =
                EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL).unwrap();
            (1..=9).for_each(|i| {
                writer
                    .append(
                        DidHash::from_did(&format!("did:plc:user{i}")),
                        EventTypeTag::COMMIT,
                        vec![i as u8; payload_size],
                    )
                    .unwrap();

                if i % 3 == 0 {
                    writer.sync().unwrap();
                    writer.rotate_if_needed().unwrap();
                }
            });
            writer.sync().unwrap();
        }

        mgr.shutdown();

        let writer = EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL).unwrap();
        assert_eq!(writer.next_seq, EventSequence::new(10));

        let segments = mgr.list_segments().unwrap();
        assert!(segments.len() >= 3);
    }

    #[test]
    fn shutdown_syncs_and_checkpoints() {
        let mgr = setup_manager(64 * 1024);
        let mut writer = EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL).unwrap();

        (1..=5).for_each(|i| {
            append_test_event(&mut writer, &format!("did:plc:user{i}"));
        });

        assert_eq!(writer.synced_seq(), EventSequence::BEFORE_ALL);

        writer.shutdown().unwrap();

        assert_eq!(writer.synced_seq(), EventSequence::new(5));

        let wip = mgr.index_path(SegmentId::new(1));
        assert!(SegmentIndex::load(mgr.io(), &wip).unwrap().is_some());
    }

    #[test]
    fn rotation_indexes_last_event() {
        let payload_size = 50;
        let record_size = EVENT_RECORD_OVERHEAD + payload_size;
        let max_segment_size = SEGMENT_HEADER_SIZE + record_size * 5;

        let mgr = setup_manager(max_segment_size as u64);
        let mut writer = EventLogWriter::open(Arc::clone(&mgr), 256).unwrap();

        (1..=5).for_each(|i| {
            writer
                .append(
                    DidHash::from_did(&format!("did:plc:user{i}")),
                    EventTypeTag::COMMIT,
                    vec![0xFF; payload_size],
                )
                .unwrap();
        });
        writer.sync().unwrap();
        writer.rotate_if_needed().unwrap();

        let index = SegmentIndex::load(mgr.io(), &mgr.index_path(SegmentId::new(1)))
            .unwrap()
            .unwrap();

        assert_eq!(index.last_seq(), Some(EventSequence::new(5)));
        assert!(index.lookup(EventSequence::new(5)).is_some());
    }

    #[test]
    fn open_idempotent_on_fresh() {
        let mgr = setup_manager(64 * 1024);

        {
            let _writer = EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL).unwrap();
        }
        mgr.shutdown();

        let writer = EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL).unwrap();
        assert_eq!(writer.active_segment_id(), SegmentId::new(1));
        assert_eq!(writer.current_seq(), EventSequence::BEFORE_ALL);
    }

    #[test]
    fn append_after_recovery_continues_sequence() {
        let mgr = setup_manager(64 * 1024);

        {
            let mut writer =
                EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL).unwrap();
            (1..=3).for_each(|i| {
                append_test_event(&mut writer, &format!("did:plc:user{i}"));
            });
            writer.sync().unwrap();
        }

        mgr.shutdown();

        let mut writer = EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL).unwrap();
        let seq = append_test_event(&mut writer, "did:plc:user4");
        assert_eq!(seq, EventSequence::new(4));
        writer.sync().unwrap();

        let fd = mgr.open_for_read(SegmentId::new(1)).unwrap();
        let events = SegmentReader::open(mgr.io(), fd)
            .unwrap()
            .valid_prefix()
            .unwrap();
        assert_eq!(events.len(), 4);
        assert_eq!(events[3].seq, EventSequence::new(4));
    }

    #[test]
    fn recovery_falls_back_to_scan_when_index_corrupt() {
        let payload_size = 50;
        let record_size = EVENT_RECORD_OVERHEAD + payload_size;
        let max_segment_size = SEGMENT_HEADER_SIZE + record_size * 2;

        let mgr = setup_manager(max_segment_size as u64);

        {
            let mut writer =
                EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL).unwrap();
            (1..=2).for_each(|i| {
                writer
                    .append(
                        DidHash::from_did(&format!("did:plc:user{i}")),
                        EventTypeTag::COMMIT,
                        vec![0xAA; payload_size],
                    )
                    .unwrap();
            });
            writer.sync().unwrap();
            writer.rotate_if_needed().unwrap();

            (3..=4).for_each(|i| {
                writer
                    .append(
                        DidHash::from_did(&format!("did:plc:user{i}")),
                        EventTypeTag::COMMIT,
                        vec![0xAA; payload_size],
                    )
                    .unwrap();
            });
            writer.sync().unwrap();
            writer.rotate_if_needed().unwrap();
        }

        mgr.shutdown();

        let index_path = mgr.index_path(SegmentId::new(1));
        let fd = mgr
            .io()
            .open(&index_path, crate::OpenOptions::read_write())
            .unwrap();
        mgr.io().write_all_at(fd, 0, b"CORRUPT_GARBAGE").unwrap();
        mgr.io().sync(fd).unwrap();
        mgr.io().close(fd).unwrap();

        let index_path_2 = mgr.index_path(SegmentId::new(2));
        let fd2 = mgr
            .io()
            .open(&index_path_2, crate::OpenOptions::read_write())
            .unwrap();
        mgr.io().write_all_at(fd2, 0, b"CORRUPT_GARBAGE").unwrap();
        mgr.io().sync(fd2).unwrap();
        mgr.io().close(fd2).unwrap();

        let writer = EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL).unwrap();
        assert_eq!(writer.next_seq, EventSequence::new(5));
    }

    #[test]
    fn rotation_not_needed_returns_false() {
        let mgr = setup_manager(64 * 1024);
        let mut writer = EventLogWriter::open(Arc::clone(&mgr), DEFAULT_INDEX_INTERVAL).unwrap();

        append_test_event(&mut writer, "did:plc:user1");
        writer.sync().unwrap();

        assert!(writer.rotate_if_needed().unwrap().is_none());
    }
}
