mod bridge;
mod commit_loop;
mod manager;
mod notifier;
mod payload;
mod reader;
mod segment_file;
mod segment_index;
mod sidecar;
mod types;
mod writer;

use std::collections::VecDeque;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::broadcast;
use tracing::warn;
use tranquil_db_traits::{RepoEventType, SequencedEvent};
use tranquil_types::Did;

use crate::blockstore::BlocksSynced;
use crate::fsync_order::PostBlockstoreHook;
use crate::io::StorageIO;

use commit_loop::{CommitThread, FreezeResponse, PendingBytesBudget, WriterNotify, WriterRequest};

pub use bridge::{DeferredBroadcast, EventLogBridge};
pub use manager::{SEGMENT_FILE_EXTENSION, SegmentManager, parse_segment_id, segment_path};
pub use notifier::EventLogNotifier;
pub use payload::{
    EventPayload, PayloadError, decode_payload, encode_payload, encode_payload_with_mutations,
    to_sequenced_event, validate_payload_size,
};
pub use reader::{EventLogReader, RawEvent, SequenceContiguityResult, SequenceGap};
pub use segment_file::{
    EVENT_HEADER_SIZE, EVENT_RECORD_OVERHEAD, ReadEventRecord, SEGMENT_FORMAT_VERSION,
    SEGMENT_HEADER_SIZE, SEGMENT_MAGIC, SegmentReader, SegmentWriter, ValidEvent,
    ValidateEventRecord, decode_event_record, encode_event_record, validate_event_record,
};
pub use segment_index::{DEFAULT_INDEX_INTERVAL, SegmentIndex, rebuild_from_segment};
pub use sidecar::{SidecarEntry, SidecarIndex, build_sidecar_from_segment};
pub use types::{
    DEFAULT_MAX_EVENT_PAYLOAD, DEFAULT_SEGMENT_SIZE, DidHash, EventLength, EventSequence,
    EventTypeTag, MAX_EVENT_PAYLOAD, SegmentId, SegmentOffset, TimestampMicros,
};
pub use writer::{EventLogWriter, SyncResult};

const DEFAULT_BROADCAST_BUFFER: usize = 16384;
pub const DEFAULT_PENDING_BYTES_BUDGET: u64 = 1024 * 1024 * 1024;

pub struct EventWithMutations {
    pub event: SequencedEvent,
    pub mutation_set: Option<Vec<u8>>,
}

pub struct EventLogConfig {
    pub segments_dir: PathBuf,
    pub max_segment_size: u64,
    pub index_interval: usize,
    pub broadcast_buffer: usize,
    pub use_mmap: bool,
    pub skip_sealed_checksum: bool,
    pub pending_bytes_budget: u64,
    pub max_event_payload: u32,
}

impl Default for EventLogConfig {
    fn default() -> Self {
        Self {
            segments_dir: PathBuf::from("eventlog"),
            max_segment_size: DEFAULT_SEGMENT_SIZE,
            index_interval: DEFAULT_INDEX_INTERVAL,
            broadcast_buffer: DEFAULT_BROADCAST_BUFFER,
            use_mmap: true,
            skip_sealed_checksum: false,
            pending_bytes_budget: DEFAULT_PENDING_BYTES_BUDGET,
            max_event_payload: DEFAULT_MAX_EVENT_PAYLOAD,
        }
    }
}

pub struct EventLogSnapshotState {
    pub max_seq: EventSequence,
    pub active_segment_id: SegmentId,
    pub active_segment_position: SegmentOffset,
    pub sealed_segments: Vec<SegmentId>,
}

pub struct EventLogFreezeGuard {
    _resume: Option<flume::Sender<()>>,
}

impl Drop for EventLogFreezeGuard {
    fn drop(&mut self) {
        if let Some(resume) = self._resume.take() {
            let _ = resume.send(());
        }
    }
}

pub struct EventLog<S: StorageIO> {
    commit_thread: CommitThread,
    reader: Arc<EventLogReader<S>>,
    manager: Arc<SegmentManager<S>>,
    broadcast_tx: broadcast::Sender<RawEvent>,
    synced_seq: Arc<AtomicU64>,
    notify: Arc<WriterNotify>,
    pending_bytes: Arc<PendingBytesBudget>,
    next_seq: AtomicU64,
    max_payload: u32,
}

impl<S: StorageIO + 'static> EventLog<S> {
    pub fn open(config: EventLogConfig, io: S) -> io::Result<Self> {
        let max_payload = config.max_event_payload;
        let manager = Arc::new(SegmentManager::new(
            io,
            config.segments_dir,
            config.max_segment_size,
        )?);

        let writer =
            EventLogWriter::open(Arc::clone(&manager), config.index_interval, max_payload)?;
        let synced = writer.synced_seq();
        let initial_next_seq = writer.current_seq().next();

        let reader = Arc::new(EventLogReader::new(
            Arc::clone(&manager),
            config.use_mmap,
            config.skip_sealed_checksum,
            max_payload,
        ));
        reader.set_active_segment(writer.active_segment_id());
        reader.seed_index(writer.active_segment_id(), writer.active_index_snapshot());
        reader.refresh_segment_ranges()?;

        let (broadcast_tx, _) = broadcast::channel(config.broadcast_buffer);

        let synced_seq = Arc::new(AtomicU64::new(synced.raw()));
        let notify = Arc::new(WriterNotify::new(synced.raw()));
        let pending_bytes = Arc::new(PendingBytesBudget::new(config.pending_bytes_budget));

        let commit_thread = CommitThread::spawn(
            writer,
            Arc::clone(&reader),
            broadcast_tx.clone(),
            Arc::clone(&notify),
            Arc::clone(&synced_seq),
            Arc::clone(&pending_bytes),
        )?;

        Ok(Self {
            commit_thread,
            reader,
            manager,
            broadcast_tx,
            synced_seq,
            notify,
            pending_bytes,
            next_seq: AtomicU64::new(initial_next_seq.raw()),
            max_payload,
        })
    }

    pub fn max_payload(&self) -> u32 {
        self.max_payload
    }

    pub fn pending_bytes_in_flight(&self) -> u64 {
        self.pending_bytes.in_flight()
    }

    pub fn pending_bytes_budget(&self) -> u64 {
        self.pending_bytes.budget()
    }

    fn reserve_seq(&self) -> EventSequence {
        let raw = self.next_seq.fetch_add(1, Ordering::Relaxed);
        EventSequence::new(raw)
    }

    fn send_append(&self, event: ValidEvent) -> io::Result<()> {
        self.commit_thread
            .sender()
            .send(WriterRequest::Append(event))
            .map_err(|_| io::Error::other("eventlog writer thread terminated"))
    }

    pub fn append_event(
        &self,
        did: &Did,
        event_type: RepoEventType,
        event: &SequencedEvent,
    ) -> io::Result<EventSequence> {
        let payload = encode_payload(event);
        self.append_raw_payload(did, event_type, payload)
    }

    pub fn append_raw_payload(
        &self,
        did: &Did,
        event_type: RepoEventType,
        payload: Vec<u8>,
    ) -> io::Result<EventSequence> {
        let did_hash = DidHash::from_did(did.as_str());
        let tag = repo_event_type_to_tag(event_type);
        validate_payload_size(&payload, self.max_payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        self.pending_bytes.acquire(payload.len() as u64)?;

        let seq = self.reserve_seq();
        let timestamp = TimestampMicros::now();

        let event = ValidEvent {
            seq,
            timestamp,
            did_hash,
            event_type: tag,
            payload,
        };
        self.send_append(event)?;
        Ok(seq)
    }

    pub fn group_sync(&self, my_seq: EventSequence) -> io::Result<()> {
        self.notify.wait_for_sync(my_seq)
    }

    pub fn sync(&self) -> io::Result<SyncResult> {
        self.sync_data()
    }

    pub fn append_and_sync(
        &self,
        did: &Did,
        event_type: RepoEventType,
        event: &SequencedEvent,
    ) -> io::Result<EventSequence> {
        let seq = self.append_event(did, event_type, event)?;
        self.group_sync(seq)?;
        Ok(seq)
    }

    pub fn append_batch(
        &self,
        events: Vec<(&Did, RepoEventType, &SequencedEvent)>,
    ) -> io::Result<Vec<EventSequence>> {
        events
            .iter()
            .map(|(did, event_type, event)| self.append_event(did, *event_type, event))
            .collect()
    }

    pub fn sync_data(&self) -> io::Result<SyncResult> {
        let (resp_tx, resp_rx) = flume::bounded(1);
        self.commit_thread
            .sender()
            .send(WriterRequest::SyncBarrier { response: resp_tx })
            .map_err(|_| io::Error::other("eventlog writer thread terminated"))?;
        resp_rx
            .recv()
            .map_err(|_| io::Error::other("eventlog writer thread terminated"))?
    }

    pub fn get_events_since(
        &self,
        cursor: EventSequence,
        limit: usize,
    ) -> io::Result<Vec<SequencedEvent>> {
        let raw_events = self.reader.read_events_from(cursor, limit)?;
        raw_events
            .iter()
            .map(|raw| {
                let payload = decode_payload(&raw.payload)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                to_sequenced_event(raw, &payload)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
            })
            .collect()
    }

    pub fn get_events_with_mutations_since(
        &self,
        cursor: EventSequence,
        limit: usize,
    ) -> io::Result<Vec<EventWithMutations>> {
        let raw_events = self.reader.read_events_from(cursor, limit)?;
        raw_events
            .iter()
            .map(|raw| {
                let payload = decode_payload(&raw.payload)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                let mutation_set = payload.mutation_set.clone();
                let event = to_sequenced_event(raw, &payload)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                Ok(EventWithMutations {
                    event,
                    mutation_set,
                })
            })
            .collect()
    }

    pub fn get_event(&self, seq: EventSequence) -> io::Result<Option<SequencedEvent>> {
        self.reader.read_event_at(seq)?.map_or(Ok(None), |raw| {
            let payload = decode_payload(&raw.payload)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let event = to_sequenced_event(&raw, &payload)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            Ok(Some(event))
        })
    }

    pub fn max_seq(&self) -> EventSequence {
        let raw = self.synced_seq.load(Ordering::Acquire);
        match raw {
            0 => EventSequence::BEFORE_ALL,
            n => EventSequence::new(n),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<RawEvent> {
        self.broadcast_tx.subscribe()
    }

    pub fn maybe_rotate(&self) -> io::Result<bool> {
        Ok(false)
    }

    pub fn run_retention(&self, max_age: Duration) -> io::Result<usize> {
        self.run_retention_at(TimestampMicros::now(), max_age)
    }

    pub fn run_retention_at(&self, now: TimestampMicros, max_age: Duration) -> io::Result<usize> {
        let max_age_us = u64::try_from(max_age.as_micros()).unwrap_or(u64::MAX);
        let cutoff_us = now.raw().saturating_sub(max_age_us);

        let sync_result = self.sync_data()?;
        let active_id = sync_result.segment_id;
        let segments = self.manager.list_segments()?;

        let deleted = segments
            .iter()
            .take_while(|&&id| id != active_id)
            .filter(|&&id| self.segment_past_cutoff(id, cutoff_us))
            .copied()
            .collect::<Vec<_>>();

        deleted.iter().try_for_each(|&id| -> io::Result<()> {
            self.manager.delete_segment(id)?;
            self.reader.invalidate_index(id);
            self.reader.invalidate_mmap(id);
            self.reader.invalidate_sidecar(id);
            Ok(())
        })?;

        if !deleted.is_empty() {
            self.reader.refresh_segment_ranges()?;
        }

        Ok(deleted.len())
    }

    fn segment_past_cutoff(&self, id: SegmentId, cutoff_us: u64) -> bool {
        let idx = match self.reader.load_index(id) {
            Ok(idx) => idx,
            Err(e) => {
                warn!(
                    segment_id = id.raw(),
                    error = %e,
                    "eventlog retention: failed to load segment index, keeping segment"
                );
                return false;
            }
        };
        let last_seq = match idx.last_seq() {
            Some(seq) => seq,
            None => return false,
        };
        match self.reader.read_event_at(last_seq) {
            Ok(Some(event)) => event.timestamp.raw() < cutoff_us,
            Ok(None) => {
                warn!(
                    segment_id = id.raw(),
                    last_seq = last_seq.raw(),
                    "eventlog retention: index reports last_seq but read_event_at returned None, keeping segment"
                );
                false
            }
            Err(e) => {
                warn!(
                    segment_id = id.raw(),
                    last_seq = last_seq.raw(),
                    error = %e,
                    "eventlog retention: failed to read last event, keeping segment"
                );
                false
            }
        }
    }

    pub fn segment_count(&self) -> usize {
        self.manager.list_segments().map_or(0, |s| s.len())
    }

    pub fn disk_usage(&self) -> io::Result<u64> {
        let segments = self.manager.list_segments()?;
        segments.iter().try_fold(0u64, |acc, &id| {
            let handle = self.manager.open_for_read(id)?;
            let size = self.manager.io().file_size(handle.fd())?;
            Ok(acc.saturating_add(size))
        })
    }

    pub fn snapshot_state(&self) -> io::Result<EventLogSnapshotState> {
        let (state, _guard) = self.freeze()?;
        Ok(state)
    }

    pub fn freeze(&self) -> io::Result<(EventLogSnapshotState, EventLogFreezeGuard)> {
        let (resp_tx, resp_rx) = flume::bounded(1);
        let (resume_tx, resume_rx) = flume::bounded(1);

        self.commit_thread
            .sender()
            .send(WriterRequest::Freeze {
                response: resp_tx,
                resume: resume_rx,
            })
            .map_err(|_| io::Error::other("eventlog writer thread terminated"))?;

        let freeze_resp: FreezeResponse = resp_rx
            .recv()
            .map_err(|_| io::Error::other("eventlog writer thread terminated"))??;

        let all_segments = self.manager.list_segments()?;
        let sealed_segments: Vec<SegmentId> = all_segments
            .into_iter()
            .filter(|&id| id != freeze_resp.segment_id)
            .collect();

        let state = EventLogSnapshotState {
            max_seq: freeze_resp.synced_through,
            active_segment_id: freeze_resp.segment_id,
            active_segment_position: freeze_resp.position,
            sealed_segments,
        };

        Ok((
            state,
            EventLogFreezeGuard {
                _resume: Some(resume_tx),
            },
        ))
    }

    pub fn segments_dir(&self) -> &std::path::Path {
        self.manager.segments_dir()
    }

    pub fn shutdown(&self) -> io::Result<()> {
        self.commit_thread.shutdown();
        Ok(())
    }

    pub fn subscriber(&self, start_seq: EventSequence) -> EventLogSubscriber<S> {
        EventLogSubscriber::new(
            self.broadcast_tx.subscribe(),
            Arc::clone(&self.reader),
            start_seq,
        )
    }

    pub fn reader(&self) -> &EventLogReader<S> {
        &self.reader
    }

    pub fn manager(&self) -> &Arc<SegmentManager<S>> {
        &self.manager
    }

    fn last_assigned_seq(&self) -> EventSequence {
        let raw = self.next_seq.load(Ordering::Acquire);
        match raw.checked_sub(1) {
            Some(0) | None => EventSequence::BEFORE_ALL,
            Some(n) => EventSequence::new(n),
        }
    }
}

impl<S: StorageIO + Send + Sync + 'static> PostBlockstoreHook for EventLog<S> {
    fn on_blocks_synced(&self, _proof: &BlocksSynced) -> io::Result<()> {
        let target = self.last_assigned_seq();
        if target == EventSequence::BEFORE_ALL {
            return Ok(());
        }
        self.notify.wait_for_sync(target)
    }
}

pub struct EventLogSubscriber<S: StorageIO> {
    rx: broadcast::Receiver<RawEvent>,
    last_seen: EventSequence,
    reader: Arc<EventLogReader<S>>,
    backfill_buffer: VecDeque<RawEvent>,
    consecutive_lags: u32,
    last_lag_time: Option<Instant>,
}

const MAX_CONSECUTIVE_LAGS_BEFORE_WARN: u32 = 3;
const LAG_WINDOW: Duration = Duration::from_secs(10);
const BACKFILL_BATCH_SIZE: usize = 1024;

impl<S: StorageIO> EventLogSubscriber<S> {
    pub fn new(
        rx: broadcast::Receiver<RawEvent>,
        reader: Arc<EventLogReader<S>>,
        start_seq: EventSequence,
    ) -> Self {
        Self {
            rx,
            last_seen: start_seq,
            reader,
            backfill_buffer: VecDeque::new(),
            consecutive_lags: 0,
            last_lag_time: None,
        }
    }

    pub async fn next(&mut self) -> Option<RawEvent> {
        loop {
            if let Some(event) = self.backfill_buffer.pop_front() {
                self.last_seen = event.seq;
                self.consecutive_lags = 0;
                return Some(event);
            }

            match self.rx.recv().await {
                Ok(event) if event.seq > self.last_seen => {
                    self.last_seen = event.seq;
                    self.consecutive_lags = 0;
                    return Some(event);
                }
                Ok(_) => continue,
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!(
                        lagged = n,
                        last_seen = %self.last_seen,
                        "subscriber lagged, backfilling from disk"
                    );
                    self.track_lag();
                    match self.fill_backfill_buffer() {
                        Ok(()) => continue,
                        Err(e) => {
                            warn!(error = %e, "backfill failed");
                            return None;
                        }
                    }
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }

    fn fill_backfill_buffer(&mut self) -> io::Result<()> {
        let events = self
            .reader
            .read_events_from(self.last_seen, BACKFILL_BATCH_SIZE)?;
        events.into_iter().for_each(|event| {
            self.backfill_buffer.push_back(event);
        });
        Ok(())
    }

    fn track_lag(&mut self) {
        let now = Instant::now();
        let in_window = self
            .last_lag_time
            .is_some_and(|t| now.duration_since(t) < LAG_WINDOW);

        if in_window {
            self.consecutive_lags = self.consecutive_lags.saturating_add(1);
        } else {
            self.consecutive_lags = 1;
        }
        self.last_lag_time = Some(now);

        if self.consecutive_lags >= MAX_CONSECUTIVE_LAGS_BEFORE_WARN {
            warn!(
                consecutive_lags = self.consecutive_lags,
                last_seen = %self.last_seen,
                "subscriber repeatedly falling behind"
            );
        }
    }

    pub fn last_seen(&self) -> EventSequence {
        self.last_seen
    }
}

fn valid_event_to_raw(e: ValidEvent) -> RawEvent {
    RawEvent {
        seq: e.seq,
        timestamp: e.timestamp,
        did_hash: e.did_hash,
        event_type: e.event_type,
        payload: bytes::Bytes::from(e.payload),
    }
}

fn repo_event_type_to_tag(event_type: RepoEventType) -> EventTypeTag {
    match event_type {
        RepoEventType::Commit => EventTypeTag::COMMIT,
        RepoEventType::Identity => EventTypeTag::IDENTITY,
        RepoEventType::Account => EventTypeTag::ACCOUNT,
        RepoEventType::Sync => EventTypeTag::SYNC,
    }
}
