use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tranquil_store::eventlog::{
    DidHash, EVENT_RECORD_OVERHEAD, EventLog, EventLogConfig, EventLogReader, EventLogWriter,
    EventSequence, EventTypeTag, MAX_EVENT_PAYLOAD, PayloadError, RawEvent, SEGMENT_HEADER_SIZE,
    SegmentId, SegmentIndex, SegmentManager, SegmentReader, TimestampMicros, ValidEvent,
    decode_payload, encode_payload, to_sequenced_event, validate_payload_size,
};
use tranquil_store::{OpRecord, OpenOptions, SimulatedIO, StorageIO};

fn setup_manager(max_segment_size: u64) -> Arc<SegmentManager<SimulatedIO>> {
    let sim = SimulatedIO::pristine(42);
    Arc::new(SegmentManager::new(sim, PathBuf::from("/segments"), max_segment_size).unwrap())
}

fn append_test_event(writer: &mut EventLogWriter<SimulatedIO>, seq_hint: u64) -> EventSequence {
    writer
        .append(
            DidHash::from_did(&format!("did:plc:prop{seq_hint}")),
            EventTypeTag::COMMIT,
            format!("payload-{seq_hint}").into_bytes(),
        )
        .unwrap()
}

#[test]
fn sequence_assignment_is_contiguous() {
    let n = 100u64;
    let mgr = setup_manager(64 * 1024);
    let mut writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD).unwrap();

    let seqs: Vec<EventSequence> = (1..=n).map(|i| append_test_event(&mut writer, i)).collect();

    seqs.iter().enumerate().for_each(|(i, seq)| {
        assert_eq!(
            seq.raw(),
            i as u64 + 1,
            "event {i} should have seq {}",
            i + 1,
        );
    });
}

#[test]
fn cursor_resumption_returns_correct_suffix() {
    let mgr = setup_manager(64 * 1024);

    {
        let mut writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD).unwrap();
        (1..=1000).for_each(|i| {
            append_test_event(&mut writer, i);
        });
        writer.shutdown().unwrap();
    }
    mgr.shutdown();

    let reader = EventLogReader::new(Arc::clone(&mgr), false, false, MAX_EVENT_PAYLOAD);
    reader.refresh_segment_ranges().unwrap();

    let events = reader
        .read_events_from(EventSequence::new(500), 1000)
        .unwrap();
    assert_eq!(events.len(), 500);
    assert_eq!(events[0].seq, EventSequence::new(501));
    assert_eq!(events[499].seq, EventSequence::new(1000));

    events.windows(2).for_each(|pair| {
        assert_eq!(
            pair[1].seq.raw(),
            pair[0].seq.raw() + 1,
            "gap between {} and {}",
            pair[0].seq,
            pair[1].seq,
        );
    });
}

#[test]
fn cross_segment_read_is_seamless() {
    let payload_size = 50;
    let record_size = EVENT_RECORD_OVERHEAD + payload_size;
    let events_per_segment = 10;
    let max_segment_size = (SEGMENT_HEADER_SIZE + record_size * events_per_segment) as u64;
    let total_events = 100u64;

    let mgr = setup_manager(max_segment_size);

    {
        let mut writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD).unwrap();
        (1..=total_events).for_each(|i| {
            writer
                .append(
                    DidHash::from_did(&format!("did:plc:xseg{i}")),
                    EventTypeTag::COMMIT,
                    vec![i as u8; payload_size],
                )
                .unwrap();

            if i % events_per_segment as u64 == 0 && i < total_events {
                writer.sync().unwrap();
                writer.rotate_if_needed().unwrap();
            }
        });
        writer.shutdown().unwrap();
    }
    mgr.shutdown();

    let reader = EventLogReader::new(Arc::clone(&mgr), false, false, MAX_EVENT_PAYLOAD);
    reader.refresh_segment_ranges().unwrap();

    let events = reader
        .read_events_from(EventSequence::BEFORE_ALL, total_events as usize + 10)
        .unwrap();

    assert_eq!(events.len(), total_events as usize);

    events.iter().enumerate().for_each(|(i, e)| {
        assert_eq!(
            e.seq,
            EventSequence::new(i as u64 + 1),
            "event at index {i} has wrong seq"
        );
    });

    let mut seen = std::collections::HashSet::new();
    events.iter().for_each(|e| {
        assert!(seen.insert(e.seq.raw()), "duplicate seq {}", e.seq,);
    });
}

#[test]
fn retention_deletes_only_old_segments() {
    let payload_size = 50;
    let record_size = EVENT_RECORD_OVERHEAD + payload_size;
    let events_per_segment = 3;
    let max_segment_size = (SEGMENT_HEADER_SIZE + record_size * events_per_segment) as u64;

    let sim = SimulatedIO::pristine(42);
    let mgr =
        Arc::new(SegmentManager::new(sim, PathBuf::from("/segments"), max_segment_size).unwrap());

    let mut writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD).unwrap();

    (1..=15).for_each(|i| {
        writer
            .append(
                DidHash::from_did(&format!("did:plc:ret{i}")),
                EventTypeTag::COMMIT,
                vec![0xAA; payload_size],
            )
            .unwrap();

        if i % events_per_segment as u64 == 0 {
            writer.sync().unwrap();
            writer.rotate_if_needed().unwrap();
        }
    });
    writer.sync().unwrap();

    let segments_before = mgr.list_segments().unwrap();
    assert!(segments_before.len() >= 5);

    let segments_to_delete: Vec<_> = segments_before[..2].to_vec();
    segments_to_delete.iter().for_each(|&id| {
        mgr.delete_segment(id).unwrap();
    });

    let segments_after = mgr.list_segments().unwrap();
    assert_eq!(segments_after.len(), segments_before.len() - 2,);

    segments_to_delete.iter().for_each(|id| {
        assert!(
            !segments_after.contains(id),
            "deleted segment {id} still present"
        );
    });

    segments_after.iter().for_each(|id| {
        assert!(
            !segments_to_delete.contains(id),
            "remaining segment {id} was supposed to be deleted"
        );
    });
}

#[test]
fn did_hash_is_deterministic() {
    let dids = [
        "did:plc:abc123",
        "did:plc:xyz789",
        "did:web:example.com",
        "did:plc:aaaabbbbccccddddeeeeffffggg",
    ];

    dids.iter().for_each(|did| {
        let h1 = DidHash::from_did(did);
        let h2 = DidHash::from_did(did);
        assert_eq!(h1, h2, "DidHash not deterministic for {did}");
    });
}

#[test]
fn payload_round_trip() {
    use bytes::Bytes;
    use tranquil_db_traits::{AccountStatus, RepoEventType, SequenceNumber, SequencedEvent};
    use tranquil_types::{Did, Handle};

    let variants: Vec<(RepoEventType, EventTypeTag, SequencedEvent)> = vec![
        (
            RepoEventType::Commit,
            EventTypeTag::COMMIT,
            SequencedEvent {
                seq: SequenceNumber::from_raw(1),
                did: Did::new("did:plc:testuser1234567890abcdef").unwrap(),
                created_at: chrono::Utc::now(),
                event_type: RepoEventType::Commit,
                commit_cid: None,
                prev_cid: None,
                prev_data_cid: None,
                ops: Some(
                    serde_json::json!([{"action": "create", "path": "app.bsky.feed.post/abc"}]),
                ),
                blobs: Some(vec!["bafkreibtest".to_owned()]),
                blocks: None,
                handle: None,
                active: None,
                status: None,
                rev: Some("rev1".to_owned()),
            },
        ),
        (
            RepoEventType::Identity,
            EventTypeTag::IDENTITY,
            SequencedEvent {
                seq: SequenceNumber::from_raw(2),
                did: Did::new("did:plc:testuser1234567890abcdef").unwrap(),
                created_at: chrono::Utc::now(),
                event_type: RepoEventType::Identity,
                commit_cid: None,
                prev_cid: None,
                prev_data_cid: None,
                ops: None,
                blobs: None,
                blocks: None,
                handle: Some(Handle::new("test.bsky.social").unwrap()),
                active: None,
                status: None,
                rev: None,
            },
        ),
        (
            RepoEventType::Account,
            EventTypeTag::ACCOUNT,
            SequencedEvent {
                seq: SequenceNumber::from_raw(3),
                did: Did::new("did:plc:testuser1234567890abcdef").unwrap(),
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
            },
        ),
        (
            RepoEventType::Sync,
            EventTypeTag::SYNC,
            SequencedEvent {
                seq: SequenceNumber::from_raw(4),
                did: Did::new("did:plc:testuser1234567890abcdef").unwrap(),
                created_at: chrono::Utc::now(),
                event_type: RepoEventType::Sync,
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
            },
        ),
    ];

    variants.iter().for_each(|(event_type, tag, event)| {
        let encoded = encode_payload(event);
        let decoded = decode_payload(&encoded).unwrap();

        let raw = RawEvent {
            seq: EventSequence::new(event.seq.as_i64() as u64),
            timestamp: TimestampMicros::now(),
            did_hash: DidHash::from_did(event.did.as_str()),
            event_type: *tag,
            payload: Bytes::from(encoded),
        };

        let reconstructed = to_sequenced_event(&raw, &decoded).unwrap();
        assert_eq!(reconstructed.did.as_str(), event.did.as_str());
        assert_eq!(reconstructed.event_type, *event_type);
        assert_eq!(reconstructed.rev, event.rev);
        assert_eq!(reconstructed.blobs, event.blobs);
        assert_eq!(reconstructed.active, event.active);
    });
}

#[test]
fn max_payload_accepted() {
    const SMALL_MAX: u32 = 1024 * 1024;
    let payload = vec![0xBB; SMALL_MAX as usize];
    assert!(validate_payload_size(&payload, SMALL_MAX).is_ok());

    let sim = SimulatedIO::pristine(42);
    let dir = Path::new("/test");
    sim.mkdir(dir).unwrap();
    sim.sync_dir(dir).unwrap();

    let fd = sim
        .open(Path::new("/test/segment.tqe"), OpenOptions::read_write())
        .unwrap();
    let mut writer = tranquil_store::eventlog::SegmentWriter::new(
        &sim,
        fd,
        SegmentId::new(1),
        EventSequence::new(1),
        SMALL_MAX,
    )
    .unwrap();

    let event = ValidEvent {
        seq: EventSequence::new(1),
        timestamp: TimestampMicros::new(1_000_000),
        did_hash: DidHash::from_did("did:plc:maxpayload"),
        event_type: EventTypeTag::COMMIT,
        payload: payload.clone(),
    };
    writer.append_event(&sim, &event).unwrap();
    writer.sync(&sim).unwrap();

    let reader = SegmentReader::open(&sim, fd, SMALL_MAX).unwrap();
    let events = reader.valid_prefix().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].payload.len(), SMALL_MAX as usize);
}

#[test]
fn oversized_payload_rejected() {
    const SMALL_MAX: u32 = 1024;
    let payload = vec![0xCC; SMALL_MAX as usize + 1];
    match validate_payload_size(&payload, SMALL_MAX) {
        Err(PayloadError::TooLarge { size, max }) => {
            assert_eq!(size, SMALL_MAX as usize + 1);
            assert_eq!(max, SMALL_MAX as usize);
        }
        other => panic!("expected TooLarge, got {other:?}"),
    }
}

#[test]
fn retention_does_not_break_active_readers() {
    let payload_size = 50;
    let record_size = EVENT_RECORD_OVERHEAD + payload_size;
    let events_per_segment = 5;
    let max_segment_size = (SEGMENT_HEADER_SIZE + record_size * events_per_segment) as u64;

    let sim = SimulatedIO::pristine(42);
    let mgr =
        Arc::new(SegmentManager::new(sim, PathBuf::from("/segments"), max_segment_size).unwrap());

    {
        let mut writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD).unwrap();
        (1..=25).for_each(|i| {
            writer
                .append(
                    DidHash::from_did(&format!("did:plc:active{i}")),
                    EventTypeTag::COMMIT,
                    vec![i as u8; payload_size],
                )
                .unwrap();
            if i % events_per_segment as u64 == 0 {
                writer.sync().unwrap();
                writer.rotate_if_needed().unwrap();
            }
        });
        writer.sync().unwrap();
    }
    mgr.shutdown();

    let reader = EventLogReader::new(Arc::clone(&mgr), false, false, MAX_EVENT_PAYLOAD);
    reader.refresh_segment_ranges().unwrap();

    let first_batch = reader
        .read_events_from(EventSequence::BEFORE_ALL, 10)
        .unwrap();
    assert_eq!(first_batch.len(), 10);

    mgr.delete_segment(SegmentId::new(1)).unwrap();
    reader.invalidate_index(SegmentId::new(1));
    reader.invalidate_mmap(SegmentId::new(1));
    reader.refresh_segment_ranges().unwrap();

    let later_events = reader.read_events_from(EventSequence::new(10), 20).unwrap();
    assert!(!later_events.is_empty());
    later_events.iter().for_each(|e| {
        assert!(e.seq.raw() > 10);
    });
}

#[tokio::test]
async fn subscriber_lag_recovery() {
    let sim = SimulatedIO::pristine(42);
    let config = EventLogConfig {
        segments_dir: PathBuf::from("/segments"),
        max_segment_size: 64 * 1024,
        index_interval: 256,
        broadcast_buffer: 4,
        use_mmap: false,
        ..EventLogConfig::default()
    };

    let event_log = EventLog::open(config, sim).unwrap();
    let mut subscriber = event_log.subscriber(EventSequence::BEFORE_ALL);

    let total_events = 20u64;
    (1..=total_events).for_each(|i| {
        event_log
            .append_and_sync(
                &tranquil_types::Did::new("did:plc:testuser1234567890abcdef").unwrap(),
                tranquil_db_traits::RepoEventType::Commit,
                &tranquil_db_traits::SequencedEvent {
                    seq: tranquil_db_traits::SequenceNumber::from_raw(i as i64),
                    did: tranquil_types::Did::new("did:plc:testuser1234567890abcdef").unwrap(),
                    created_at: chrono::Utc::now(),
                    event_type: tranquil_db_traits::RepoEventType::Commit,
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
                },
            )
            .unwrap();
    });

    let mut received_seqs: Vec<u64> = Vec::new();
    let timeout = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(event) = subscriber.next().await {
            received_seqs.push(event.seq.raw());
            if event.seq.raw() >= total_events {
                break;
            }
        }
    });

    timeout
        .await
        .expect("subscriber timed out before receiving all events");

    assert_eq!(
        received_seqs.len(),
        total_events as usize,
        "subscriber should receive all {total_events} events, got {}",
        received_seqs.len(),
    );

    received_seqs.windows(2).for_each(|pair| {
        assert!(
            pair[1] > pair[0],
            "events must be in order: {} -> {}",
            pair[0],
            pair[1],
        );
    });

    let unique: std::collections::HashSet<u64> = received_seqs.iter().copied().collect();
    assert_eq!(
        unique.len(),
        received_seqs.len(),
        "no duplicate events allowed"
    );
}

#[test]
fn index_checkpoint_accelerates_recovery() {
    let event_count = 50_000u64;
    let sim = SimulatedIO::pristine(42);
    let mgr =
        Arc::new(SegmentManager::new(sim, PathBuf::from("/segments"), 256 * 1024 * 1024).unwrap());

    {
        let mut writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD).unwrap();
        (1..=event_count).for_each(|i| {
            writer
                .append(
                    DidHash::from_did(&format!("did:plc:chk{i}")),
                    EventTypeTag::COMMIT,
                    format!("ckpt-{i}").into_bytes(),
                )
                .unwrap();
        });
        writer.shutdown().unwrap();
    }
    mgr.shutdown();

    let index = SegmentIndex::load(mgr.io(), &mgr.index_path(SegmentId::new(1)))
        .unwrap()
        .unwrap();

    assert!(index.entry_count() > 0);
    assert_eq!(index.first_seq(), Some(EventSequence::new(1)));
    assert_eq!(index.last_seq(), Some(EventSequence::new(event_count)));

    let mid = EventSequence::new(event_count / 2);
    let offset = index.lookup(mid);
    assert!(offset.is_some(), "index should cover midpoint seq {}", mid,);

    let reader_with_index = EventLogReader::new(Arc::clone(&mgr), false, false, MAX_EVENT_PAYLOAD);

    let reads_before = mgr
        .io()
        .op_log()
        .iter()
        .filter(|op| matches!(op, OpRecord::ReadAt { .. }))
        .count();

    reader_with_index.refresh_segment_ranges().unwrap();
    let mid_events = reader_with_index
        .read_events_from(EventSequence::new(event_count / 2), 10)
        .unwrap();
    assert_eq!(mid_events.len(), 10);

    let reads_with_index = mgr
        .io()
        .op_log()
        .iter()
        .filter(|op| matches!(op, OpRecord::ReadAt { .. }))
        .count()
        - reads_before;

    let _ = mgr.io().delete(&mgr.index_path(SegmentId::new(1)));

    let reader_without_index =
        EventLogReader::new(Arc::clone(&mgr), false, false, MAX_EVENT_PAYLOAD);

    let reads_before = mgr
        .io()
        .op_log()
        .iter()
        .filter(|op| matches!(op, OpRecord::ReadAt { .. }))
        .count();

    reader_without_index.refresh_segment_ranges().unwrap();
    let mid_events_no_idx = reader_without_index
        .read_events_from(EventSequence::new(event_count / 2), 10)
        .unwrap();
    assert_eq!(mid_events_no_idx.len(), 10);

    let reads_without_index = mgr
        .io()
        .op_log()
        .iter()
        .filter(|op| matches!(op, OpRecord::ReadAt { .. }))
        .count()
        - reads_before;

    assert!(
        reads_with_index < reads_without_index,
        "read with index ({reads_with_index} reads) should require fewer reads than without ({reads_without_index} reads)"
    );
}

#[test]
fn fsync_ordering_blocks_before_events() {
    use tranquil_store::blockstore::{
        CID_SIZE, DataFileId, DataFileManager, DataFileReader, DataFileWriter,
    };

    fn test_cid(seed: u8) -> [u8; CID_SIZE] {
        let mut cid = [0u8; CID_SIZE];
        cid[0] = 0x01;
        cid[1] = 0x71;
        cid[2] = 0x12;
        cid[3] = 0x20;
        cid[4] = seed;
        cid
    }

    let sim = Arc::new(SimulatedIO::pristine(42));
    let data_dir = Path::new("/blocks");
    sim.mkdir(data_dir).unwrap();
    sim.sync_dir(data_dir).unwrap();
    let seg_dir = Path::new("/segments");

    let block_mgr =
        DataFileManager::with_default_max_size(Arc::clone(&sim), data_dir.to_path_buf());
    let event_mgr = Arc::new(
        SegmentManager::new(Arc::clone(&sim), PathBuf::from("/segments"), 64 * 1024).unwrap(),
    );

    let block_fd = block_mgr.open_for_append(DataFileId::new(0)).unwrap();
    let mut block_writer =
        DataFileWriter::new(block_mgr.io(), block_fd, DataFileId::new(0)).unwrap();
    let cid = test_cid(1);
    let _ = block_writer.append_block(&cid, &[0xAA; 128]).unwrap();
    block_writer.sync().unwrap();
    sim.sync_dir(data_dir).unwrap();

    {
        let mut event_writer =
            EventLogWriter::open(Arc::clone(&event_mgr), 256, MAX_EVENT_PAYLOAD).unwrap();
        event_writer
            .append(
                DidHash::from_did("did:plc:fsyncorder"),
                EventTypeTag::COMMIT,
                b"event-before-sync".to_vec(),
            )
            .unwrap();
    }

    sim.crash();
    event_mgr.shutdown();

    let block_fd = sim
        .open(
            Path::new("/blocks/000000.tqb"),
            OpenOptions::read_only_existing(),
        )
        .unwrap();
    let block_reader = DataFileReader::open(&*sim, block_fd).unwrap();
    let recovered_blocks = block_reader.valid_blocks().unwrap();
    assert_eq!(
        recovered_blocks.len(),
        1,
        "blockstore was synced, block must survive crash"
    );
    assert_eq!(recovered_blocks[0].1, cid, "recovered block CID must match");

    let event_writer =
        EventLogWriter::open(Arc::clone(&event_mgr), 256, MAX_EVENT_PAYLOAD).unwrap();
    assert_eq!(
        event_writer.synced_seq(),
        EventSequence::BEFORE_ALL,
        "crash between blockstore sync and eventlog sync must not persist the event (blocks exist, event does not = orphan, not inconsistency)"
    );

    drop(event_writer);

    {
        let mut event_writer =
            EventLogWriter::open(Arc::clone(&event_mgr), 256, MAX_EVENT_PAYLOAD).unwrap();
        event_writer
            .append(
                DidHash::from_did("did:plc:fsyncorder"),
                EventTypeTag::COMMIT,
                b"event-with-sync".to_vec(),
            )
            .unwrap();
        event_writer.sync().unwrap();
        sim.sync_dir(seg_dir).unwrap();
    }

    event_mgr.shutdown();
    sim.crash();

    let event_writer =
        EventLogWriter::open(Arc::clone(&event_mgr), 256, MAX_EVENT_PAYLOAD).unwrap();
    assert_eq!(
        event_writer.synced_seq(),
        EventSequence::new(1),
        "both stores synced, event must survive crash"
    );
}
