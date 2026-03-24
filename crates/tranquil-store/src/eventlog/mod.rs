mod bridge;
mod manager;
mod notifier;
mod payload;
mod reader;
mod segment_file;
mod segment_index;
mod types;
mod writer;

use std::collections::VecDeque;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::broadcast;
use tracing::warn;
use tranquil_db_traits::{RepoEventType, SequencedEvent};
use tranquil_types::Did;

use crate::blockstore::BlocksSynced;
use crate::fsync_order::PostBlockstoreHook;
use crate::io::StorageIO;

pub use bridge::{DeferredBroadcast, EventLogBridge};
pub use manager::SegmentManager;
pub use notifier::EventLogNotifier;
pub use payload::{
    EventPayload, PayloadError, decode_payload, encode_payload, encode_payload_with_mutations,
    to_sequenced_event, validate_payload_size,
};
pub use reader::{EventLogReader, RawEvent};
pub use segment_file::{
    EVENT_HEADER_SIZE, EVENT_RECORD_OVERHEAD, ReadEventRecord, SEGMENT_FORMAT_VERSION,
    SEGMENT_HEADER_SIZE, SEGMENT_MAGIC, SegmentReader, SegmentWriter, ValidEvent,
    ValidateEventRecord, decode_event_record, encode_event_record, validate_event_record,
};
pub use segment_index::{DEFAULT_INDEX_INTERVAL, SegmentIndex, rebuild_from_segment};
pub use types::{
    DEFAULT_SEGMENT_SIZE, DidHash, EventLength, EventSequence, EventTypeTag, MAX_EVENT_PAYLOAD,
    SegmentId, SegmentOffset, TimestampMicros,
};
pub use writer::{EventLogWriter, SyncResult};

const DEFAULT_BROADCAST_BUFFER: usize = 16384;

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
}

impl Default for EventLogConfig {
    fn default() -> Self {
        Self {
            segments_dir: PathBuf::from("eventlog"),
            max_segment_size: DEFAULT_SEGMENT_SIZE,
            index_interval: DEFAULT_INDEX_INTERVAL,
            broadcast_buffer: DEFAULT_BROADCAST_BUFFER,
            use_mmap: true,
        }
    }
}

pub struct EventLog<S: StorageIO> {
    writer: Mutex<EventLogWriter<S>>,
    reader: Arc<EventLogReader<S>>,
    manager: Arc<SegmentManager<S>>,
    broadcast_tx: broadcast::Sender<RawEvent>,
    synced_seq: AtomicU64,
    consecutive_sync_failures: AtomicU32,
}

impl<S: StorageIO> EventLog<S> {
    pub fn open(config: EventLogConfig, io: S) -> io::Result<Self> {
        let manager = Arc::new(SegmentManager::new(
            io,
            config.segments_dir,
            config.max_segment_size,
        )?);

        let writer = EventLogWriter::open(Arc::clone(&manager), config.index_interval)?;
        let synced = writer.synced_seq();

        let reader = Arc::new(EventLogReader::new(Arc::clone(&manager), config.use_mmap));
        reader.set_active_segment(writer.active_segment_id());
        reader.seed_index(writer.active_segment_id(), writer.active_index_snapshot());
        reader.refresh_segment_ranges()?;

        let (broadcast_tx, _) = broadcast::channel(config.broadcast_buffer);

        Ok(Self {
            writer: Mutex::new(writer),
            reader,
            manager,
            broadcast_tx,
            synced_seq: AtomicU64::new(synced.raw()),
            consecutive_sync_failures: AtomicU32::new(0),
        })
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
        validate_payload_size(&payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        self.writer.lock().append(did_hash, tag, payload)
    }

    pub fn sync(&self) -> io::Result<SyncResult> {
        self.sync_and_broadcast()
    }

    pub fn append_and_sync(
        &self,
        did: &Did,
        event_type: RepoEventType,
        event: &SequencedEvent,
    ) -> io::Result<EventSequence> {
        let seq = self.append_event(did, event_type, event)?;
        self.sync_and_broadcast()?;
        Ok(seq)
    }

    pub fn append_batch(
        &self,
        events: Vec<(&Did, RepoEventType, &SequencedEvent)>,
    ) -> io::Result<Vec<EventSequence>> {
        let mut writer = self.writer.lock();
        events
            .iter()
            .map(|(did, event_type, event)| {
                let did_hash = DidHash::from_did(did.as_str());
                let tag = repo_event_type_to_tag(*event_type);
                let payload = encode_payload(event);
                validate_payload_size(&payload)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                writer.append(did_hash, tag, payload)
            })
            .collect()
    }

    pub fn sync_data(&self) -> io::Result<SyncResult> {
        let mut writer = self.writer.lock();
        let result = writer.sync()?;
        self.synced_seq
            .store(result.synced_through.raw(), Ordering::Release);

        if let (Some(first), Some(last)) =
            (result.flushed_events.first(), result.flushed_events.last())
        {
            self.reader.extend_active_range(first.seq, last.seq);
        }
        Ok(result)
    }

    pub fn broadcast_result(&self, result: &SyncResult) {
        result.flushed_events.iter().for_each(|e| {
            let _ = self.broadcast_tx.send(valid_event_to_raw(e));
        });
    }

    pub fn sync_and_broadcast(&self) -> io::Result<SyncResult> {
        let result = self.sync_data()?;
        self.broadcast_result(&result);
        Ok(result)
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
        let (sealed_id, new_active_id) = {
            let mut writer = self.writer.lock();
            match writer.rotate_if_needed()? {
                None => return Ok(false),
                Some(sealed_id) => (sealed_id, writer.active_segment_id()),
            }
        };
        self.reader.on_segment_rotated(sealed_id, new_active_id)?;
        Ok(true)
    }

    pub fn run_retention(&self, max_age: Duration) -> io::Result<usize> {
        let max_age_us = u64::try_from(max_age.as_micros()).unwrap_or(u64::MAX);
        let cutoff_us = TimestampMicros::now().raw().saturating_sub(max_age_us);
        let active_id = self.writer.lock().active_segment_id();
        let segments = self.manager.list_segments()?;

        let deleted = segments
            .iter()
            .take_while(|&&id| id != active_id)
            .filter(|&&id| {
                self.reader
                    .load_index(id)
                    .ok()
                    .and_then(|idx| idx.last_seq())
                    .and_then(|seq| {
                        self.reader
                            .read_event_at(seq)
                            .ok()
                            .flatten()
                            .map(|e| e.timestamp.raw() < cutoff_us)
                    })
                    .unwrap_or(false)
            })
            .copied()
            .collect::<Vec<_>>();

        deleted.iter().try_for_each(|&id| -> io::Result<()> {
            self.manager.delete_segment(id)?;
            self.reader.invalidate_index(id);
            self.reader.invalidate_mmap(id);
            Ok(())
        })?;

        if !deleted.is_empty() {
            self.reader.refresh_segment_ranges()?;
        }

        Ok(deleted.len())
    }

    pub fn segment_count(&self) -> usize {
        self.manager.list_segments().map_or(0, |s| s.len())
    }

    pub fn disk_usage(&self) -> io::Result<u64> {
        let segments = self.manager.list_segments()?;
        segments.iter().try_fold(0u64, |acc, &id| {
            let fd = self.manager.open_for_read(id)?;
            let size = self.manager.io().file_size(fd)?;
            Ok(acc.saturating_add(size))
        })
    }

    pub fn shutdown(&self) -> io::Result<()> {
        self.writer.lock().shutdown()
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

    pub fn consecutive_sync_failures(&self) -> u32 {
        self.consecutive_sync_failures.load(Ordering::Relaxed)
    }
}

impl<S: StorageIO + Send + Sync> PostBlockstoreHook for EventLog<S> {
    fn on_blocks_synced(&self, _proof: &BlocksSynced) -> io::Result<()> {
        match self.sync_and_broadcast() {
            Ok(_) => {
                self.consecutive_sync_failures.store(0, Ordering::Relaxed);
                if let Err(e) = self.maybe_rotate() {
                    warn!(error = %e, "eventlog rotation deferred");
                }
                Ok(())
            }
            Err(e) => {
                let count = self
                    .consecutive_sync_failures
                    .fetch_add(1, Ordering::Relaxed)
                    .saturating_add(1);
                warn!(
                    error = %e,
                    consecutive_failures = count,
                    "eventlog sync failed after blockstore commit"
                );
                Err(e)
            }
        }
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

fn valid_event_to_raw(e: &ValidEvent) -> RawEvent {
    RawEvent {
        seq: e.seq,
        timestamp: e.timestamp,
        did_hash: e.did_hash,
        event_type: e.event_type,
        payload: bytes::Bytes::from(e.payload.clone()),
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
