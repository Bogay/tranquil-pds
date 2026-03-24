use std::io;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use tracing::warn;
use tranquil_db_traits::{DbError, SequenceNumber, SequencedEvent};

use super::notifier::EventLogNotifier;
use super::types::{EventSequence, TimestampMicros};
use super::writer::SyncResult;
use super::{EventLog, EventWithMutations, decode_payload, to_sequenced_event};
use crate::io::StorageIO;

pub struct DeferredBroadcast(SyncResult);

fn io_to_db(e: io::Error) -> DbError {
    DbError::Query(e.to_string())
}

fn seq_to_event(seq: SequenceNumber) -> EventSequence {
    let raw = seq.as_i64();
    if raw < 0 {
        warn!(
            seq = raw,
            "negative SequenceNumber passed to eventlog bridge, treating as BEFORE_ALL"
        );
        return EventSequence::BEFORE_ALL;
    }
    EventSequence::cursor_from_i64(raw).unwrap_or(EventSequence::BEFORE_ALL)
}

fn datetime_to_micros(dt: &DateTime<Utc>) -> u64 {
    let micros = dt.timestamp_micros();
    debug_assert!(micros >= 0, "pre-epoch DateTime passed to eventlog bridge");
    u64::try_from(micros).unwrap_or(0)
}

pub struct EventLogBridge<S: StorageIO> {
    log: Arc<EventLog<S>>,
}

impl<S: StorageIO> EventLogBridge<S> {
    pub fn new(log: Arc<EventLog<S>>) -> Self {
        Self { log }
    }

    pub fn notifier(&self) -> EventLogNotifier<S> {
        EventLogNotifier::new(Arc::clone(&self.log))
    }

    pub fn log(&self) -> &Arc<EventLog<S>> {
        &self.log
    }

    pub fn get_max_seq(&self) -> SequenceNumber {
        let es = self.log.max_seq();
        SequenceNumber::from_raw(es.as_i64())
    }

    pub fn get_events_since_seq(
        &self,
        since: SequenceNumber,
        limit: Option<i64>,
    ) -> Result<Vec<SequencedEvent>, DbError> {
        let cap = limit
            .and_then(|l| usize::try_from(l).ok())
            .unwrap_or(usize::MAX);
        self.get_events_impl(since, cap)
    }

    pub fn get_events_since_cursor(
        &self,
        cursor: SequenceNumber,
        limit: i64,
    ) -> Result<Vec<SequencedEvent>, DbError> {
        let cap = usize::try_from(limit).unwrap_or(usize::MAX);
        self.get_events_impl(cursor, cap)
    }

    fn get_events_impl(
        &self,
        since: SequenceNumber,
        limit: usize,
    ) -> Result<Vec<SequencedEvent>, DbError> {
        let cursor = seq_to_event(since);
        self.log.get_events_since(cursor, limit).map_err(io_to_db)
    }

    pub fn get_event_by_seq(&self, seq: SequenceNumber) -> Result<Option<SequencedEvent>, DbError> {
        let es = EventSequence::from_i64(seq.as_i64())
            .ok_or_else(|| DbError::Query("invalid sequence number".into()))?;
        self.log.get_event(es).map_err(io_to_db)
    }

    pub fn get_events_in_seq_range(
        &self,
        start: SequenceNumber,
        end: SequenceNumber,
    ) -> Result<Vec<SequencedEvent>, DbError> {
        let end_raw = match u64::try_from(end.as_i64()) {
            Ok(v) => v,
            Err(_) => return Ok(Vec::new()),
        };
        let cursor = seq_to_event(start);
        if end_raw <= cursor.raw().saturating_add(1) {
            return Ok(Vec::new());
        }
        let range_size =
            usize::try_from(end_raw.saturating_sub(cursor.raw())).unwrap_or(usize::MAX);
        let raw_events = self
            .log
            .reader()
            .read_events_from(cursor, range_size)
            .map_err(io_to_db)?;

        raw_events
            .iter()
            .take_while(|e| e.seq.raw() < end_raw)
            .map(|raw| {
                let payload =
                    decode_payload(&raw.payload).map_err(|e| DbError::Query(e.to_string()))?;
                to_sequenced_event(raw, &payload).map_err(|e| DbError::Query(e.to_string()))
            })
            .collect()
    }

    pub fn get_min_seq_since(
        &self,
        since: DateTime<Utc>,
    ) -> Result<Option<SequenceNumber>, DbError> {
        let target_us = datetime_to_micros(&since);
        let target_ts = TimestampMicros::new(target_us);
        let reader = self.log.reader();

        let segments = self.log.manager().list_segments().map_err(io_to_db)?;
        if segments.is_empty() {
            return Ok(None);
        }

        let scan_from_seg = self.find_segment_for_timestamp(&segments, target_ts)?;

        let start_seq = match scan_from_seg {
            Some(idx) => reader
                .load_index(segments[idx])
                .map_err(io_to_db)?
                .first_seq()
                .map(|s| s.prev_or_before_all())
                .unwrap_or(EventSequence::BEFORE_ALL),
            None => return Ok(None),
        };

        const SCAN_BATCH: usize = 1024;
        self.scan_for_timestamp(reader, start_seq, target_ts, SCAN_BATCH)
    }

    fn scan_for_timestamp(
        &self,
        reader: &super::EventLogReader<S>,
        cursor: EventSequence,
        target_ts: TimestampMicros,
        batch_size: usize,
    ) -> Result<Option<SequenceNumber>, DbError> {
        let batch = reader
            .read_events_from(cursor, batch_size)
            .map_err(io_to_db)?;
        if batch.is_empty() {
            return Ok(None);
        }
        match batch.iter().find(|e| e.timestamp >= target_ts) {
            Some(e) => Ok(Some(SequenceNumber::from_raw(e.seq.as_i64()))),
            None => {
                let next_cursor = batch.last().map(|e| e.seq).unwrap_or(cursor);
                self.scan_for_timestamp(reader, next_cursor, target_ts, batch_size)
            }
        }
    }

    fn find_segment_for_timestamp(
        &self,
        segments: &[super::SegmentId],
        target_ts: TimestampMicros,
    ) -> Result<Option<usize>, DbError> {
        let reader = self.log.reader();

        let last_seg_idx = segments.len() - 1;
        let last_index = reader
            .load_index(segments[last_seg_idx])
            .map_err(io_to_db)?;

        let last_ts = last_index
            .first_seq()
            .and_then(|seq| reader.read_event_at(seq).ok().flatten())
            .map(|e| e.timestamp);

        match last_ts {
            Some(ts) if ts < target_ts => {
                let tail_ts = last_index
                    .last_seq()
                    .and_then(|seq| reader.read_event_at(seq).ok().flatten())
                    .map(|e| e.timestamp);
                match tail_ts {
                    Some(ts) if ts < target_ts => return Ok(None),
                    _ => return Ok(Some(last_seg_idx)),
                }
            }
            None => return Ok(None),
            _ => {}
        }

        Ok(self
            .binary_search_segment(reader, segments, target_ts, 0, last_seg_idx, None)?
            .map(|r| r.saturating_sub(1)))
    }

    fn binary_search_segment(
        &self,
        reader: &super::EventLogReader<S>,
        segments: &[super::SegmentId],
        target_ts: TimestampMicros,
        lo: usize,
        hi: usize,
        best: Option<usize>,
    ) -> Result<Option<usize>, DbError> {
        if lo > hi {
            return Ok(best);
        }
        let mid = lo + (hi - lo) / 2;
        let seg_ts = reader
            .load_index(segments[mid])
            .map_err(io_to_db)?
            .first_seq()
            .and_then(|seq| reader.read_event_at(seq).ok().flatten())
            .map(|e| e.timestamp);

        match seg_ts {
            Some(ts) if ts < target_ts => {
                self.binary_search_segment(reader, segments, target_ts, mid + 1, hi, best)
            }
            Some(_) => match mid {
                0 => Ok(Some(0)),
                _ => {
                    self.binary_search_segment(reader, segments, target_ts, lo, mid - 1, Some(mid))
                }
            },
            None => self.binary_search_segment(reader, segments, target_ts, mid + 1, hi, best),
        }
    }

    pub fn get_events_with_mutations_since(
        &self,
        since: SequenceNumber,
        limit: usize,
    ) -> Result<Vec<EventWithMutations>, DbError> {
        let cursor = seq_to_event(since);
        self.log
            .get_events_with_mutations_since(cursor, limit)
            .map_err(io_to_db)
    }

    pub fn insert_event(&self, event: &SequencedEvent) -> Result<SequenceNumber, io::Error> {
        let seq = self
            .log
            .append_and_sync(&event.did, event.event_type, event)?;
        Ok(SequenceNumber::from_raw(seq.as_i64()))
    }

    pub fn insert_event_deferred(
        &self,
        event: &SequencedEvent,
    ) -> Result<(SequenceNumber, DeferredBroadcast), io::Error> {
        let seq = self.log.append_event(&event.did, event.event_type, event)?;
        let sync_result = self.log.sync_data()?;
        Ok((
            SequenceNumber::from_raw(seq.as_i64()),
            DeferredBroadcast(sync_result),
        ))
    }

    pub fn insert_event_deferred_raw(
        &self,
        did: &tranquil_types::Did,
        event_type: tranquil_db_traits::RepoEventType,
        payload: Vec<u8>,
    ) -> Result<(SequenceNumber, DeferredBroadcast), io::Error> {
        let seq = self.log.append_raw_payload(did, event_type, payload)?;
        let sync_result = self.log.sync_data()?;
        Ok((
            SequenceNumber::from_raw(seq.as_i64()),
            DeferredBroadcast(sync_result),
        ))
    }

    pub fn complete_broadcast(&self, deferred: DeferredBroadcast) {
        self.log.broadcast_result(&deferred.0);
    }
}
