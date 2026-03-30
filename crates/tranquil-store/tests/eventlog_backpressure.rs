use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tranquil_db_traits::RepoEventType;
use tranquil_store::SimulatedIO;
use tranquil_store::eventlog::{EventLog, EventLogConfig};
use tranquil_types::Did;

fn open_log(seed: u64, budget: u64) -> EventLog<SimulatedIO> {
    let sim = SimulatedIO::pristine(seed);
    let config = EventLogConfig {
        segments_dir: PathBuf::from("/segments"),
        max_segment_size: 64 * 1024,
        broadcast_buffer: 16,
        use_mmap: false,
        pending_bytes_budget: budget,
        ..EventLogConfig::default()
    };
    EventLog::open(config, sim).unwrap()
}

fn test_did() -> Did {
    Did::new("did:plc:backpressuretest12").unwrap()
}

#[test]
fn budget_released_on_sync() {
    let log = open_log(101, 64 * 1024);
    let did = test_did();

    log.append_raw_payload(&did, RepoEventType::Commit, vec![0u8; 1024])
        .unwrap();
    log.sync().unwrap();

    assert_eq!(
        log.pending_bytes_in_flight(),
        0,
        "in-flight bytes must drain to zero after sync"
    );
}

#[test]
fn backpressure_blocks_writers_at_budget() {
    let budget = 4096u64;
    let log = Arc::new(open_log(102, budget));
    let did = test_did();

    let (_state, freeze_guard) = log.freeze().unwrap();

    (0..4).for_each(|_| {
        log.append_raw_payload(&did, RepoEventType::Commit, vec![0u8; 1024])
            .unwrap();
    });

    assert_eq!(
        log.pending_bytes_in_flight(),
        budget,
        "in-flight should match budget after filling it"
    );

    let log_blocked = Arc::clone(&log);
    let did_blocked = did.clone();
    let blocked = std::thread::spawn(move || {
        log_blocked
            .append_raw_payload(&did_blocked, RepoEventType::Commit, vec![0u8; 256])
            .unwrap();
    });

    std::thread::sleep(Duration::from_millis(150));
    assert!(
        !blocked.is_finished(),
        "append must block while pending budget is full"
    );

    drop(freeze_guard);

    blocked.join().unwrap();
    log.sync().unwrap();

    assert_eq!(
        log.pending_bytes_in_flight(),
        0,
        "all bytes must release after backpressure clears and sync completes"
    );
}

#[test]
fn oversized_single_event_admitted_alone() {
    let budget = 1024u64;
    let log = open_log(103, budget);
    let did = test_did();

    let oversized = vec![0u8; 8 * 1024];
    log.append_raw_payload(&did, RepoEventType::Commit, oversized)
        .unwrap();
    log.sync().unwrap();

    assert_eq!(log.pending_bytes_in_flight(), 0);
}

#[test]
fn concurrent_writers_share_budget_fairly() {
    let budget = 16 * 1024u64;
    let log = Arc::new(open_log(104, budget));
    let did = test_did();
    let writer_count = 8usize;
    let events_per_writer = 32usize;
    let payload_size = 256usize;

    let handles: Vec<_> = (0..writer_count)
        .map(|_| {
            let log_clone = Arc::clone(&log);
            let did_clone = did.clone();
            std::thread::spawn(move || {
                (0..events_per_writer).for_each(|_| {
                    log_clone
                        .append_raw_payload(
                            &did_clone,
                            RepoEventType::Commit,
                            vec![0u8; payload_size],
                        )
                        .unwrap();
                });
            })
        })
        .collect();

    handles.into_iter().for_each(|h| h.join().unwrap());
    log.sync().unwrap();

    assert!(
        log.pending_bytes_in_flight() <= budget,
        "in-flight ({}) must never exceed budget ({})",
        log.pending_bytes_in_flight(),
        budget
    );
    assert_eq!(
        log.pending_bytes_in_flight(),
        0,
        "all bytes drained after final sync"
    );
}
