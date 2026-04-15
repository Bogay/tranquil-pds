use std::path::PathBuf;
use std::time::Duration;

use tranquil_db_traits::{RepoEventType, SequenceNumber, SequencedEvent};
use tranquil_store::SimulatedIO;
use tranquil_store::eventlog::{EventLog, EventLogConfig, TimestampMicros};
use tranquil_types::Did;

fn make_event(seq: u64) -> SequencedEvent {
    SequencedEvent {
        seq: SequenceNumber::from_raw(seq as i64),
        did: Did::new("did:plc:retentiontest1234567").unwrap(),
        created_at: chrono::Utc::now(),
        event_type: RepoEventType::Commit,
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
    }
}

fn append_n(event_log: &EventLog<SimulatedIO>, did: &Did, n: u64) {
    (1..=n).for_each(|i| {
        event_log
            .append_and_sync(did, RepoEventType::Commit, &make_event(i))
            .unwrap();
    });
}

#[test]
fn run_retention_at_deletes_sealed_segments_past_cutoff() {
    let sim = SimulatedIO::pristine(7);
    let config = EventLogConfig {
        segments_dir: PathBuf::from("/segments"),
        max_segment_size: 4 * 1024,
        broadcast_buffer: 16,
        use_mmap: false,
        ..EventLogConfig::default()
    };

    let event_log = EventLog::open(config, sim).unwrap();
    let did = Did::new("did:plc:retentiontest1234567").unwrap();
    append_n(&event_log, &did, 200);

    let segments_before = event_log.segment_count();
    assert!(
        segments_before >= 3,
        "expected at least 3 segments rolled, got {segments_before}"
    );

    let deleted = event_log
        .run_retention_at(TimestampMicros::new(u64::MAX), Duration::from_secs(0))
        .unwrap();

    assert!(
        deleted >= segments_before - 1,
        "expected at least {} segments deleted, got {deleted}",
        segments_before - 1
    );

    let segments_after = event_log.segment_count();
    assert_eq!(
        segments_after,
        segments_before - deleted,
        "segment count should drop by deleted amount"
    );
    assert!(
        segments_after >= 1,
        "active segment must remain, got {segments_after}"
    );
}

#[test]
fn run_retention_at_keeps_recent_events() {
    let sim = SimulatedIO::pristine(8);
    let config = EventLogConfig {
        segments_dir: PathBuf::from("/segments"),
        max_segment_size: 4 * 1024,
        broadcast_buffer: 16,
        use_mmap: false,
        ..EventLogConfig::default()
    };

    let event_log = EventLog::open(config, sim).unwrap();
    let did = Did::new("did:plc:retentiontest1234567").unwrap();
    append_n(&event_log, &did, 50);

    let segments_before = event_log.segment_count();
    let max_seq_before = event_log.max_seq();

    let deleted = event_log
        .run_retention_at(TimestampMicros::new(0), Duration::from_secs(0))
        .unwrap();

    assert_eq!(
        deleted, 0,
        "no segments should be deleted when cutoff is in the past"
    );
    assert_eq!(event_log.segment_count(), segments_before);
    assert_eq!(event_log.max_seq(), max_seq_before);
}

#[test]
fn run_retention_at_idempotent() {
    let sim = SimulatedIO::pristine(9);
    let config = EventLogConfig {
        segments_dir: PathBuf::from("/segments"),
        max_segment_size: 4 * 1024,
        broadcast_buffer: 16,
        use_mmap: false,
        ..EventLogConfig::default()
    };

    let event_log = EventLog::open(config, sim).unwrap();
    let did = Did::new("did:plc:retentiontest1234567").unwrap();
    append_n(&event_log, &did, 200);
    let max_seq = event_log.max_seq();

    let first = event_log
        .run_retention_at(TimestampMicros::new(u64::MAX), Duration::from_secs(0))
        .unwrap();
    assert!(first > 0);

    let second = event_log
        .run_retention_at(TimestampMicros::new(u64::MAX), Duration::from_secs(0))
        .unwrap();
    assert_eq!(second, 0, "second pass should be a no-op");

    assert_eq!(
        event_log.max_seq(),
        max_seq,
        "max_seq must not regress after retention"
    );

    let new_seq = event_log
        .append_and_sync(&did, RepoEventType::Commit, &make_event(201))
        .unwrap();
    let appended = event_log.get_event(new_seq).unwrap();
    assert!(
        appended.is_some(),
        "newly appended event must be readable after retention"
    );
}
