mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rayon::prelude::*;
use tranquil_store::eventlog::{
    DidHash, EVENT_HEADER_SIZE, EVENT_RECORD_OVERHEAD, EventLogWriter, EventSequence, EventTypeTag,
    MAX_EVENT_PAYLOAD, SEGMENT_HEADER_SIZE, SegmentId, SegmentManager, SegmentReader, ValidEvent,
};
use tranquil_store::{
    FaultConfig, OpenOptions, Probability, SimulatedIO, StorageIO, sim_seed_range,
};

use common::Rng;

const SEGMENTS_DIR: &str = "/segments";

fn setup_manager(sim: SimulatedIO, max_segment_size: u64) -> Arc<SegmentManager<SimulatedIO>> {
    Arc::new(SegmentManager::new(sim, PathBuf::from(SEGMENTS_DIR), max_segment_size).unwrap())
}

fn append_test_event(
    writer: &mut EventLogWriter<SimulatedIO>,
    seq_hint: u64,
    seed: u64,
) -> EventSequence {
    writer
        .append(
            DidHash::from_did(&format!("did:plc:sim{seq_hint}")),
            EventTypeTag::COMMIT,
            format!("payload-{seq_hint}").into_bytes(),
        )
        .unwrap_or_else(|e| panic!("seed {seed}: append event {seq_hint} failed: {e}"))
}

fn read_all_events(mgr: &SegmentManager<SimulatedIO>, seed: u64) -> Vec<ValidEvent> {
    mgr.list_segments()
        .unwrap_or_else(|e| panic!("seed {seed}: list_segments failed: {e}"))
        .iter()
        .flat_map(|&seg_id| {
            let fd = mgr
                .open_for_read(seg_id)
                .unwrap_or_else(|e| panic!("seed {seed}: open_for_read({seg_id}) failed: {e}"))
                .fd();
            SegmentReader::open(mgr.io(), fd, MAX_EVENT_PAYLOAD)
                .unwrap_or_else(|e| {
                    panic!(
                        "seed {seed}: SegmentReader::open({seg_id}, MAX_EVENT_PAYLOAD) failed: {e}"
                    )
                })
                .valid_prefix()
                .unwrap_or_else(|e| panic!("seed {seed}: valid_prefix({seg_id}) failed: {e}"))
        })
        .collect()
}

fn small_segment_size(payload_size: usize, events_per_segment: usize) -> u64 {
    let record_size = EVENT_RECORD_OVERHEAD + payload_size;
    (SEGMENT_HEADER_SIZE + record_size * events_per_segment) as u64
}

#[test]
fn crash_during_segment_rotation_old_sealed_new_missing() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let payload_size = 50;
        let events_per_seg = 3usize;
        let max_seg = small_segment_size(payload_size, events_per_seg);

        let sim = SimulatedIO::pristine(seed);
        let mgr = setup_manager(sim, max_seg);

        {
            let mut writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD)
                .unwrap_or_else(|e| panic!("seed {seed}: open writer failed: {e}"));
            (1..=events_per_seg as u64).for_each(|i| {
                writer
                    .append(
                        DidHash::from_did(&format!("did:plc:rot{i}")),
                        EventTypeTag::COMMIT,
                        vec![i as u8; payload_size],
                    )
                    .unwrap_or_else(|e| panic!("seed {seed}: append {i} failed: {e}"));
            });
            writer
                .sync()
                .unwrap_or_else(|e| panic!("seed {seed}: sync failed: {e}"));

            let old_id = writer.active_segment_id();
            let old_index = writer.active_index_snapshot();
            mgr.seal_segment(old_id, &old_index)
                .unwrap_or_else(|e| panic!("seed {seed}: seal_segment failed: {e}"));
        }

        mgr.io()
            .sync_dir(Path::new(SEGMENTS_DIR))
            .unwrap_or_else(|e| panic!("seed {seed}: sync_dir failed: {e}"));
        mgr.shutdown();
        mgr.io().crash();

        let writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD)
            .unwrap_or_else(|e| panic!("seed {seed}: recovery open failed: {e}"));
        assert!(
            writer.synced_seq().raw() >= events_per_seg as u64,
            "seed {seed}: sealed events must survive, got seq {}",
            writer.synced_seq(),
        );
    });
}

#[test]
fn crash_during_segment_rotation_new_file_created_but_not_synced() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let payload_size = 50;
        let events_per_seg = 3usize;
        let max_seg = small_segment_size(payload_size, events_per_seg);

        let sim = SimulatedIO::pristine(seed);
        let mgr = setup_manager(sim, max_seg);

        {
            let mut writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD)
                .unwrap_or_else(|e| panic!("seed {seed}: open writer failed: {e}"));
            (1..=events_per_seg as u64).for_each(|i| {
                writer
                    .append(
                        DidHash::from_did(&format!("did:plc:rot2{i}")),
                        EventTypeTag::COMMIT,
                        vec![i as u8; payload_size],
                    )
                    .unwrap_or_else(|e| panic!("seed {seed}: append {i} failed: {e}"));
            });
            writer
                .sync()
                .unwrap_or_else(|e| panic!("seed {seed}: sync failed: {e}"));
            mgr.io()
                .sync_dir(Path::new(SEGMENTS_DIR))
                .unwrap_or_else(|e| panic!("seed {seed}: sync_dir failed: {e}"));

            writer
                .rotate_if_needed()
                .unwrap_or_else(|e| panic!("seed {seed}: rotate failed: {e}"));
        }

        mgr.shutdown();
        mgr.io().crash();

        let recovery = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD)
        }));

        let Ok(Ok(mut writer)) = recovery else {
            return;
        };

        assert!(
            writer.synced_seq().raw() >= events_per_seg as u64,
            "seed {seed}: sealed segment events must survive rotation crash, got {}",
            writer.synced_seq(),
        );

        let post_seq = writer
            .append(
                DidHash::from_did("did:plc:post_rot"),
                EventTypeTag::COMMIT,
                vec![0xAA; payload_size],
            )
            .unwrap_or_else(|e| panic!("seed {seed}: post-recovery append failed: {e}"));
        assert!(
            post_seq.raw() > events_per_seg as u64,
            "seed {seed}: post-recovery seq must be monotonic"
        );
    });
}

#[test]
fn crash_mid_rotation_with_faults() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let payload_size = 50;
        let events_per_seg = 3usize;
        let max_seg = small_segment_size(payload_size, events_per_seg);

        let sim = SimulatedIO::new(seed, FaultConfig::moderate());
        let mgr = setup_manager(sim, max_seg);

        let write_result = (|| -> std::io::Result<u64> {
            let mut writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD)?;
            (1..=events_per_seg as u64).try_for_each(|i| -> std::io::Result<()> {
                writer.append(
                    DidHash::from_did(&format!("did:plc:frot{i}")),
                    EventTypeTag::COMMIT,
                    vec![i as u8; payload_size],
                )?;
                Ok(())
            })?;
            writer.sync()?;
            mgr.io().sync_dir(Path::new(SEGMENTS_DIR))?;
            let _ = writer.rotate_if_needed();
            Ok(writer.synced_seq().raw())
        })();

        mgr.shutdown();
        mgr.io().crash();

        let recovery = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD)
        }));

        if let Ok(Ok(writer)) = recovery {
            let recovered = writer.synced_seq().raw();
            assert!(
                recovered <= events_per_seg as u64,
                "seed {seed}: recovered {recovered} > written {events_per_seg}"
            );
            let _ = write_result;
        }
    });
}

#[test]
fn segment_deletion_does_not_corrupt_neighbors() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let payload_size = 50;
        let events_per_seg = 3usize;
        let max_seg = small_segment_size(payload_size, events_per_seg);

        let sim = SimulatedIO::pristine(seed);
        let mgr = setup_manager(sim, max_seg);

        let total_events = (events_per_seg * 3) as u64;
        {
            let mut writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD)
                .unwrap_or_else(|e| panic!("seed {seed}: open writer failed: {e}"));
            (1..=total_events).for_each(|i| {
                writer
                    .append(
                        DidHash::from_did(&format!("did:plc:del{i}")),
                        EventTypeTag::COMMIT,
                        vec![i as u8; payload_size],
                    )
                    .unwrap_or_else(|e| panic!("seed {seed}: append {i} failed: {e}"));
                if (i as usize).is_multiple_of(events_per_seg) && (i as usize) < events_per_seg * 3
                {
                    writer
                        .sync()
                        .unwrap_or_else(|e| panic!("seed {seed}: sync failed: {e}"));
                    writer
                        .rotate_if_needed()
                        .unwrap_or_else(|e| panic!("seed {seed}: rotate failed: {e}"));
                }
            });
            writer
                .sync()
                .unwrap_or_else(|e| panic!("seed {seed}: final sync failed: {e}"));
        }

        mgr.delete_segment(SegmentId::new(1))
            .unwrap_or_else(|e| panic!("seed {seed}: delete_segment(1) failed: {e}"));

        let seg2_fd = mgr
            .open_for_read(SegmentId::new(2))
            .unwrap_or_else(|e| panic!("seed {seed}: open_for_read(2) failed: {e}"))
            .fd();
        let seg2_events = SegmentReader::open(mgr.io(), seg2_fd, MAX_EVENT_PAYLOAD)
            .unwrap_or_else(|e| {
                panic!("seed {seed}: SegmentReader::open(2, MAX_EVENT_PAYLOAD) failed: {e}")
            })
            .valid_prefix()
            .unwrap_or_else(|e| panic!("seed {seed}: valid_prefix(2) failed: {e}"));
        assert_eq!(
            seg2_events.len(),
            events_per_seg,
            "seed {seed}: segment 2 must remain readable after segment 1 deleted"
        );

        let seg3_fd = mgr
            .open_for_read(SegmentId::new(3))
            .unwrap_or_else(|e| panic!("seed {seed}: open_for_read(3) failed: {e}"))
            .fd();
        let seg3_events = SegmentReader::open(mgr.io(), seg3_fd, MAX_EVENT_PAYLOAD)
            .unwrap_or_else(|e| {
                panic!("seed {seed}: SegmentReader::open(3, MAX_EVENT_PAYLOAD) failed: {e}")
            })
            .valid_prefix()
            .unwrap_or_else(|e| panic!("seed {seed}: valid_prefix(3) failed: {e}"));
        assert_eq!(
            seg3_events.len(),
            events_per_seg,
            "seed {seed}: segment 3 must remain readable after segment 1 deleted"
        );
    });
}

#[test]
fn sequence_contiguity_across_segments_after_crash() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let payload_size = 50;
        let events_per_seg = 3usize;
        let max_seg = small_segment_size(payload_size, events_per_seg);

        let sim = SimulatedIO::pristine(seed);
        let mgr = setup_manager(sim, max_seg);

        let sealed_events = (events_per_seg * 2) as u64;
        let trailing = 2u64;
        {
            let mut writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD)
                .unwrap_or_else(|e| panic!("seed {seed}: open writer failed: {e}"));
            (1..=sealed_events + trailing).for_each(|i| {
                writer
                    .append(
                        DidHash::from_did(&format!("did:plc:sub{i}")),
                        EventTypeTag::COMMIT,
                        vec![i as u8; payload_size],
                    )
                    .unwrap_or_else(|e| panic!("seed {seed}: append {i} failed: {e}"));
                if (i as usize).is_multiple_of(events_per_seg) && i <= sealed_events {
                    writer
                        .sync()
                        .unwrap_or_else(|e| panic!("seed {seed}: sync failed: {e}"));
                    writer
                        .rotate_if_needed()
                        .unwrap_or_else(|e| panic!("seed {seed}: rotate failed: {e}"));
                }
            });
            mgr.io()
                .sync_dir(Path::new(SEGMENTS_DIR))
                .unwrap_or_else(|e| panic!("seed {seed}: sync_dir failed: {e}"));
        }

        mgr.shutdown();
        mgr.io().crash();

        let writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD)
            .unwrap_or_else(|e| panic!("seed {seed}: recovery open failed: {e}"));

        assert!(
            writer.synced_seq().raw() >= sealed_events,
            "seed {seed}: sealed events must survive, got {}",
            writer.synced_seq(),
        );

        let all_events = read_all_events(&mgr, seed);

        all_events.windows(2).for_each(|pair| {
            assert_eq!(
                pair[1].seq.raw(),
                pair[0].seq.raw() + 1,
                "seed {seed}: non-contiguous sequence {} -> {} across segments",
                pair[0].seq,
                pair[1].seq,
            );
        });
    });
}

#[test]
fn fsync_ordering_unsynced_events_never_durable() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let sim = SimulatedIO::pristine(seed);
        let mgr = setup_manager(sim, 64 * 1024);

        let synced_count = 5u64;
        let unsynced_count = 5u64;
        {
            let mut writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD)
                .unwrap_or_else(|e| panic!("seed {seed}: open writer failed: {e}"));
            (1..=synced_count).for_each(|i| {
                append_test_event(&mut writer, i, seed);
            });
            writer
                .sync()
                .unwrap_or_else(|e| panic!("seed {seed}: sync failed: {e}"));
            mgr.io()
                .sync_dir(Path::new(SEGMENTS_DIR))
                .unwrap_or_else(|e| panic!("seed {seed}: sync_dir failed: {e}"));

            (synced_count + 1..=synced_count + unsynced_count).for_each(|i| {
                append_test_event(&mut writer, i, seed);
            });
        }

        mgr.shutdown();
        mgr.io().crash();

        let writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD)
            .unwrap_or_else(|e| panic!("seed {seed}: recovery open failed: {e}"));
        assert_eq!(
            writer.synced_seq().raw(),
            synced_count,
            "seed {seed}: exactly the synced events must survive, never unsynced"
        );

        let fd = mgr
            .open_for_read(SegmentId::new(1))
            .unwrap_or_else(|e| panic!("seed {seed}: open_for_read(1) failed: {e}"))
            .fd();
        let recovered = SegmentReader::open(mgr.io(), fd, MAX_EVENT_PAYLOAD)
            .unwrap_or_else(|e| {
                panic!("seed {seed}: SegmentReader::open(1, MAX_EVENT_PAYLOAD) failed: {e}")
            })
            .valid_prefix()
            .unwrap_or_else(|e| panic!("seed {seed}: valid_prefix(1) failed: {e}"));
        assert_eq!(
            recovered.len(),
            synced_count as usize,
            "seed {seed}: on-disk events must match synced count"
        );

        recovered.iter().enumerate().for_each(|(i, e)| {
            let expected = format!("payload-{}", i + 1);
            assert_eq!(
                e.payload,
                expected.as_bytes(),
                "seed {seed}: event {} payload mismatch",
                i + 1,
            );
        });
    });
}

#[test]
fn fsync_ordering_proof_sync_before_blockstore_ack() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let sim = SimulatedIO::pristine(seed);
        let mgr = setup_manager(sim, 64 * 1024);

        let event_count = 10u64;

        let mut synced_payloads: Vec<Vec<u8>> = Vec::new();
        {
            let mut writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD)
                .unwrap_or_else(|e| panic!("seed {seed}: open writer failed: {e}"));
            (1..=event_count).for_each(|i| {
                append_test_event(&mut writer, i, seed);
                if i % 3 == 0 {
                    writer
                        .sync()
                        .unwrap_or_else(|e| panic!("seed {seed}: sync failed: {e}"));
                    mgr.io()
                        .sync_dir(Path::new(SEGMENTS_DIR))
                        .unwrap_or_else(|e| panic!("seed {seed}: sync_dir failed: {e}"));

                    synced_payloads = (1..=i)
                        .map(|j| format!("payload-{j}").into_bytes())
                        .collect();
                }
            });
        }

        mgr.shutdown();
        mgr.io().crash();

        let writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD)
            .unwrap_or_else(|e| panic!("seed {seed}: recovery open failed: {e}"));
        let recovered_count = writer.synced_seq().raw() as usize;

        assert_eq!(
            recovered_count,
            synced_payloads.len(),
            "seed {seed}: recovered {recovered_count} but expected exactly {} (synced+dir_synced)",
            synced_payloads.len(),
        );

        let fd = mgr
            .open_for_read(SegmentId::new(1))
            .unwrap_or_else(|e| panic!("seed {seed}: open_for_read(1) failed: {e}"))
            .fd();
        let recovered = SegmentReader::open(mgr.io(), fd, MAX_EVENT_PAYLOAD)
            .unwrap_or_else(|e| {
                panic!("seed {seed}: SegmentReader::open(1, MAX_EVENT_PAYLOAD) failed: {e}")
            })
            .valid_prefix()
            .unwrap_or_else(|e| panic!("seed {seed}: valid_prefix(1) failed: {e}"));

        assert_eq!(
            recovered.len(),
            synced_payloads.len(),
            "seed {seed}: on-disk event count must match synced count"
        );

        recovered
            .iter()
            .zip(synced_payloads.iter())
            .for_each(|(e, expected)| {
                assert_eq!(
                    &e.payload, expected,
                    "seed {seed}: recovered event payload must match synced payload"
                );
            });
    });
}

#[test]
fn group_sync_crash_after_append_before_sync() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let sim = SimulatedIO::pristine(seed);
        let mgr = setup_manager(sim, 64 * 1024);

        let mut rng = Rng::new(seed);
        let pre_sync_count = (rng.range_u32(8) as u64) + 2;
        let post_append_count = (rng.range_u32(5) as u64) + 1;

        {
            let mut writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD)
                .unwrap_or_else(|e| panic!("seed {seed}: open writer failed: {e}"));
            (1..=pre_sync_count).for_each(|i| {
                append_test_event(&mut writer, i, seed);
            });
            writer
                .sync()
                .unwrap_or_else(|e| panic!("seed {seed}: sync failed: {e}"));
            mgr.io()
                .sync_dir(Path::new(SEGMENTS_DIR))
                .unwrap_or_else(|e| panic!("seed {seed}: sync_dir failed: {e}"));

            (pre_sync_count + 1..=pre_sync_count + post_append_count).for_each(|i| {
                append_test_event(&mut writer, i, seed);
            });
        }

        mgr.shutdown();
        mgr.io().crash();

        let writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD)
            .unwrap_or_else(|e| panic!("seed {seed}: recovery open failed: {e}"));
        assert_eq!(
            writer.synced_seq().raw(),
            pre_sync_count,
            "seed {seed}: only pre-sync events survive when crash happens after append but before group sync"
        );
    });
}

#[test]
fn group_sync_crash_mid_sync_partial_fsync() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let fault_config = FaultConfig {
            sync_failure_probability: Probability::new(0.3),
            partial_write_probability: Probability::new(0.1),
            ..FaultConfig::none()
        };
        let sim = SimulatedIO::new(seed, fault_config);
        let mgr = setup_manager(sim, 64 * 1024);

        let event_count = 10u64;
        let write_result = (|| -> std::io::Result<u64> {
            let mut writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD)?;
            (1..=event_count).try_for_each(|i| -> std::io::Result<()> {
                writer.append(
                    DidHash::from_did(&format!("did:plc:gsync{i}")),
                    EventTypeTag::COMMIT,
                    format!("gsync-{i}").into_bytes(),
                )?;
                if i % 3 == 0 {
                    let _ = writer.sync();
                    let _ = mgr.io().sync_dir(Path::new(SEGMENTS_DIR));
                }
                Ok(())
            })?;
            let _ = writer.sync();
            Ok(writer.synced_seq().raw())
        })();
        let _ = write_result;

        mgr.shutdown();
        mgr.io().crash();

        let recovery = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD)
        }));

        let Ok(Ok(writer)) = recovery else {
            return;
        };

        let recovered = writer.synced_seq().raw();
        assert!(
            recovered <= event_count,
            "seed {seed}: recovered {recovered} exceeds written {event_count}"
        );

        if recovered == 0 {
            return;
        }

        let fd = mgr
            .open_for_read(SegmentId::new(1))
            .unwrap_or_else(|e| panic!("seed {seed}: open_for_read(1) failed: {e}"))
            .fd();
        let events = SegmentReader::open(mgr.io(), fd, MAX_EVENT_PAYLOAD)
            .unwrap_or_else(|e| {
                panic!("seed {seed}: SegmentReader::open(1, MAX_EVENT_PAYLOAD) failed: {e}")
            })
            .valid_prefix()
            .unwrap_or_else(|e| panic!("seed {seed}: valid_prefix(1) failed: {e}"));

        events.iter().enumerate().for_each(|(i, e)| {
            assert_eq!(
                e.seq,
                EventSequence::new(i as u64 + 1),
                "seed {seed}: recovered events must be contiguous starting from 1"
            );
        });
    });
}

#[test]
fn group_sync_no_double_sync_no_skipped_events() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let sim = SimulatedIO::pristine(seed);
        let mgr = setup_manager(sim, 64 * 1024);

        let batch_count = 4u64;
        let events_per_batch = 3u64;
        let total = batch_count * events_per_batch;

        {
            let mut writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD)
                .unwrap_or_else(|e| panic!("seed {seed}: open writer failed: {e}"));
            (0..batch_count).for_each(|batch| {
                let start = batch * events_per_batch + 1;
                let end = start + events_per_batch;
                (start..end).for_each(|i| {
                    append_test_event(&mut writer, i, seed);
                });

                let result = writer
                    .sync()
                    .unwrap_or_else(|e| panic!("seed {seed} batch {batch}: sync failed: {e}"));
                assert_eq!(
                    result.flushed_events.len(),
                    events_per_batch as usize,
                    "seed {seed} batch {batch}: sync must flush exactly one batch"
                );
                result.flushed_events.iter().enumerate().for_each(|(j, e)| {
                    let expected_seq = start + j as u64;
                    assert_eq!(
                        e.seq,
                        EventSequence::new(expected_seq),
                        "seed {seed} batch {batch}: flushed event {j} has wrong seq"
                    );
                });
            });
            mgr.io()
                .sync_dir(Path::new(SEGMENTS_DIR))
                .unwrap_or_else(|e| panic!("seed {seed}: sync_dir failed: {e}"));
        }

        mgr.shutdown();
        mgr.io().crash();

        let writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD)
            .unwrap_or_else(|e| panic!("seed {seed}: recovery open failed: {e}"));
        assert_eq!(
            writer.synced_seq().raw(),
            total,
            "seed {seed}: all batch-synced events must survive"
        );

        let fd = mgr
            .open_for_read(SegmentId::new(1))
            .unwrap_or_else(|e| panic!("seed {seed}: open_for_read(1) failed: {e}"))
            .fd();
        let events = SegmentReader::open(mgr.io(), fd, MAX_EVENT_PAYLOAD)
            .unwrap_or_else(|e| {
                panic!("seed {seed}: SegmentReader::open(1, MAX_EVENT_PAYLOAD) failed: {e}")
            })
            .valid_prefix()
            .unwrap_or_else(|e| panic!("seed {seed}: valid_prefix(1) failed: {e}"));
        assert_eq!(events.len(), total as usize);

        events.iter().enumerate().for_each(|(i, e)| {
            assert_eq!(
                e.seq,
                EventSequence::new(i as u64 + 1),
                "seed {seed}: event at position {i} has wrong sequence"
            );
            let expected_payload = format!("payload-{}", i + 1);
            assert_eq!(
                e.payload,
                expected_payload.as_bytes(),
                "seed {seed}: event {} payload mismatch (duplicate or skip)",
                i + 1,
            );
        });
    });
}

#[test]
fn group_sync_contention_under_faults() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let fault_config = FaultConfig {
            partial_write_probability: Probability::new(0.05),
            sync_failure_probability: Probability::new(0.10),
            dir_sync_failure_probability: Probability::new(0.05),
            ..FaultConfig::none()
        };
        let sim = SimulatedIO::new(seed, fault_config);
        let mgr = setup_manager(sim, 64 * 1024);

        let mut rng = Rng::new(seed);
        let event_count = (rng.range_u32(15) as u64) + 5;
        let sync_interval = (rng.range_u32(4) as u64) + 1;

        let write_ok = (|| -> std::io::Result<()> {
            let mut writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD)?;
            (1..=event_count).try_for_each(|i| -> std::io::Result<()> {
                writer.append(
                    DidHash::from_did(&format!("did:plc:cont{i}")),
                    EventTypeTag::COMMIT,
                    format!("contention-{i}").into_bytes(),
                )?;
                if i % sync_interval == 0 && writer.sync().is_ok() {
                    let _ = mgr.io().sync_dir(Path::new(SEGMENTS_DIR));
                }
                Ok(())
            })?;
            if writer.sync().is_ok() {
                let _ = mgr.io().sync_dir(Path::new(SEGMENTS_DIR));
            }
            Ok(())
        })();
        let _ = write_ok;

        mgr.shutdown();
        mgr.io().crash();

        let recovery = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD)
        }));

        let Ok(Ok(writer)) = recovery else {
            return;
        };

        let recovered = writer.synced_seq().raw();
        assert!(
            recovered <= event_count,
            "seed {seed}: recovered {recovered} > written {event_count}"
        );

        if recovered == 0 {
            return;
        }

        let all_events = read_all_events(&mgr, seed);

        assert!(
            !all_events.is_empty(),
            "seed {seed}: recovered {recovered} but found no events on disk"
        );

        all_events.iter().enumerate().for_each(|(i, e)| {
            assert_eq!(
                e.seq,
                EventSequence::new(i as u64 + 1),
                "seed {seed}: event at position {i} has wrong seq {}, expected {}",
                e.seq,
                i + 1,
            );
        });
    });
}

#[test]
fn multi_rotation_crash_at_each_phase() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let payload_size = 50;
        let events_per_seg = 3usize;
        let max_seg = small_segment_size(payload_size, events_per_seg);

        let crash_phase = seed % 4;

        let sim = SimulatedIO::pristine(seed);
        let mgr = setup_manager(sim, max_seg);

        let total_sealed = (events_per_seg * 2) as u64;
        let write_result = (|| -> std::io::Result<()> {
            let mut writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD)?;

            (1..=total_sealed).for_each(|i| {
                writer
                    .append(
                        DidHash::from_did(&format!("did:plc:mrot{i}")),
                        EventTypeTag::COMMIT,
                        vec![i as u8; payload_size],
                    )
                    .unwrap_or_else(|e| panic!("seed {seed}: append sealed {i} failed: {e}"));
                if (i as usize).is_multiple_of(events_per_seg) {
                    writer
                        .sync()
                        .unwrap_or_else(|e| panic!("seed {seed}: sync sealed failed: {e}"));
                    writer
                        .rotate_if_needed()
                        .unwrap_or_else(|e| panic!("seed {seed}: rotate sealed failed: {e}"));
                }
            });
            mgr.io().sync_dir(Path::new(SEGMENTS_DIR))?;

            match crash_phase {
                0 => {
                    writer
                        .append(
                            DidHash::from_did("did:plc:crash0"),
                            EventTypeTag::COMMIT,
                            vec![0xFF; payload_size],
                        )
                        .unwrap_or_else(|e| panic!("seed {seed} phase 0: append failed: {e}"));
                }
                1 => {
                    writer
                        .append(
                            DidHash::from_did("did:plc:crash1"),
                            EventTypeTag::COMMIT,
                            vec![0xFF; payload_size],
                        )
                        .unwrap_or_else(|e| panic!("seed {seed} phase 1: append failed: {e}"));
                    writer.sync()?;
                }
                2 => {
                    (1..=events_per_seg as u64).for_each(|i| {
                        writer
                            .append(
                                DidHash::from_did(&format!("did:plc:crash2_{i}")),
                                EventTypeTag::COMMIT,
                                vec![0xFF; payload_size],
                            )
                            .unwrap_or_else(|e| {
                                panic!("seed {seed} phase 2: append {i} failed: {e}")
                            });
                    });
                    writer.sync()?;
                    let _ = writer.rotate_if_needed();
                }
                _ => {
                    (1..=events_per_seg as u64).for_each(|i| {
                        writer
                            .append(
                                DidHash::from_did(&format!("did:plc:crash3_{i}")),
                                EventTypeTag::COMMIT,
                                vec![0xFF; payload_size],
                            )
                            .unwrap_or_else(|e| {
                                panic!("seed {seed} phase 3: append {i} failed: {e}")
                            });
                    });
                    writer.sync()?;
                    writer.rotate_if_needed()?;
                    mgr.io().sync_dir(Path::new(SEGMENTS_DIR))?;
                }
            }

            Ok(())
        })();
        let _ = write_result;

        mgr.shutdown();
        mgr.io().crash();

        let recovery = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD)
        }));

        let Ok(Ok(mut writer)) = recovery else {
            return;
        };

        let min_expected = match crash_phase {
            0 => total_sealed,
            1 => total_sealed + 1,
            _ => total_sealed + events_per_seg as u64,
        };
        assert!(
            writer.synced_seq().raw() >= min_expected,
            "seed {seed} phase {crash_phase}: expected >= {min_expected} durable events, got {}",
            writer.synced_seq(),
        );

        let post_seqs: Vec<EventSequence> = (0..3)
            .map(|i| {
                writer
                    .append(
                        DidHash::from_did(&format!("did:plc:post{i}")),
                        EventTypeTag::COMMIT,
                        vec![0xBB; payload_size],
                    )
                    .unwrap_or_else(|e| {
                        panic!(
                            "seed {seed} phase {crash_phase}: post-recovery append {i} failed: {e}"
                        )
                    })
            })
            .collect();

        post_seqs.windows(2).for_each(|pair| {
            assert_eq!(
                pair[1].raw(),
                pair[0].raw() + 1,
                "seed {seed} phase {crash_phase}: post-recovery seqs not contiguous"
            );
        });
    });
}

#[test]
fn aggressive_faults_group_sync_recovery() {
    let fault_config = FaultConfig {
        partial_write_probability: Probability::new(0.15),
        sync_failure_probability: Probability::new(0.10),
        dir_sync_failure_probability: Probability::new(0.05),
        misdirected_write_probability: Probability::new(0.05),
        ..FaultConfig::none()
    };

    sim_seed_range().into_par_iter().for_each(|seed| {
        let sim = SimulatedIO::new(seed, fault_config);
        let mgr = setup_manager(sim, 64 * 1024);

        let event_count = 20u64;
        let pristine_sim = SimulatedIO::pristine(seed);
        let pristine_mgr = setup_manager(pristine_sim, 64 * 1024);

        {
            let mut writer =
                EventLogWriter::open(Arc::clone(&pristine_mgr), 256, MAX_EVENT_PAYLOAD)
                    .unwrap_or_else(|e| panic!("seed {seed}: open pristine writer failed: {e}"));
            (1..=event_count).for_each(|i| {
                writer
                    .append(
                        DidHash::from_did(&format!("did:plc:agg{i}")),
                        EventTypeTag::COMMIT,
                        format!("aggressive-{i}").into_bytes(),
                    )
                    .unwrap_or_else(|e| panic!("seed {seed}: pristine append {i} failed: {e}"));
                if i % 5 == 0 {
                    writer
                        .sync()
                        .unwrap_or_else(|e| panic!("seed {seed}: pristine sync failed: {e}"));
                }
            });
            writer
                .sync()
                .unwrap_or_else(|e| panic!("seed {seed}: pristine final sync failed: {e}"));
        }
        pristine_mgr.shutdown();

        let pristine_fd = pristine_mgr
            .open_for_read(SegmentId::new(1))
            .unwrap_or_else(|e| panic!("seed {seed}: pristine open_for_read(1) failed: {e}"))
            .fd();
        let pristine_events = SegmentReader::open(
            pristine_mgr.io(),
            pristine_fd,
            MAX_EVENT_PAYLOAD,
        )
        .unwrap_or_else(|e| {
            panic!("seed {seed}: pristine SegmentReader::open(1, MAX_EVENT_PAYLOAD) failed: {e}")
        })
        .valid_prefix()
        .unwrap_or_else(|e| panic!("seed {seed}: pristine valid_prefix(1) failed: {e}"));

        let _ = (|| -> std::io::Result<()> {
            let mut writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD)?;
            (1..=event_count).try_for_each(|i| -> std::io::Result<()> {
                writer.append(
                    DidHash::from_did(&format!("did:plc:agg{i}")),
                    EventTypeTag::COMMIT,
                    format!("aggressive-{i}").into_bytes(),
                )?;
                if i % 5 == 0 {
                    let _ = writer.sync();
                    let _ = mgr.io().sync_dir(Path::new(SEGMENTS_DIR));
                }
                Ok(())
            })?;
            let _ = writer.sync();
            Ok(())
        })();

        mgr.shutdown();
        mgr.io().crash();

        let Ok(writer) = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD) else {
            return;
        };

        let recovered_count = writer.synced_seq().raw();
        assert!(
            recovered_count <= event_count,
            "seed {seed}: recovered {recovered_count} > written {event_count}"
        );

        if recovered_count == 0 {
            return;
        }

        let Ok(handle) = mgr.open_for_read(SegmentId::new(1)) else {
            return;
        };
        let fd = handle.fd();
        let Ok(reader) = SegmentReader::open(mgr.io(), fd, MAX_EVENT_PAYLOAD) else {
            return;
        };
        let Ok(recovered_events) = reader.valid_prefix() else {
            return;
        };

        let is_prefix = recovered_events
            .iter()
            .zip(pristine_events.iter())
            .all(|(r, p)| {
                r.seq == p.seq
                    && r.did_hash == p.did_hash
                    && r.event_type == p.event_type
                    && r.payload == p.payload
            });

        assert!(
            is_prefix,
            "seed {seed}: recovered events must be a prefix of pristine"
        );
    });
}

#[test]
fn sync_synced_seq_must_match_durable_valid_prefix() {
    let asserted = std::sync::atomic::AtomicU64::new(0);
    let range = sim_seed_range();
    let total = range.end - range.start;
    range.into_par_iter().for_each(|seed| {
        let fault_config = FaultConfig {
            partial_write_probability: Probability::new(0.05),
            torn_page_probability: Probability::new(0.01),
            misdirected_write_probability: Probability::new(0.01),
            sync_failure_probability: Probability::new(0.03),
            sync_reorder_window: tranquil_store::SyncReorderWindow(4),
            ..FaultConfig::none()
        };
        let sim = SimulatedIO::new(seed, fault_config);
        let mgr = setup_manager(sim, 64 * 1024);

        let Ok(mut writer) = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD) else {
            return;
        };

        let event_count = 10u64;
        (1..=event_count).for_each(|i| {
            let _ = append_test_event(&mut writer, i, seed);
        });

        let synced_through = match writer.sync() {
            Ok(r) => r.synced_through.raw(),
            Err(_) => return,
        };
        let _ = mgr.io().sync_dir(Path::new(SEGMENTS_DIR));

        if synced_through == 0 {
            return;
        }

        let Ok(handle) = mgr.open_for_read(SegmentId::new(1)) else {
            return;
        };
        let Ok(reader) = SegmentReader::open(mgr.io(), handle.fd(), MAX_EVENT_PAYLOAD) else {
            return;
        };
        let Ok(valid) = reader.valid_prefix() else {
            return;
        };

        let durable_max = valid.last().map(|e| e.seq.raw()).unwrap_or(0);

        asserted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        assert!(
            synced_through <= durable_max,
            "seed {seed}: sync acked seq {synced_through} but durable valid prefix only reaches {durable_max}, events written: {event_count}, valid_prefix.len()={}",
            valid.len()
        );
    });

    let asserted = asserted.load(std::sync::atomic::Ordering::Relaxed);
    if total >= 50 {
        assert!(
            asserted * 2 >= total,
            "fewer than half of {total} seeds reached the durability assertion: {asserted}"
        );
    }
}

#[test]
fn reopen_recovers_from_torn_segment_header() {
    let sim = SimulatedIO::pristine(0);
    let mgr = setup_manager(sim, 64 * 1024);

    {
        let mut writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD).unwrap();
        (1..=3).for_each(|i| {
            let _ = append_test_event(&mut writer, i, 0);
        });
        writer.sync().unwrap();
    }
    mgr.shutdown();

    let path = mgr.segment_path(SegmentId::new(1));
    let fd = mgr
        .io()
        .open(&path, OpenOptions::read_write_existing())
        .unwrap();
    mgr.io().write_all_at(fd, 0, &[0u8; 4]).unwrap();
    mgr.io().sync(fd).unwrap();
    mgr.io().sync_dir(Path::new(SEGMENTS_DIR)).unwrap();
    mgr.io().close(fd).unwrap();

    let writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD)
        .expect("reopen with torn header on highest-numbered segment must succeed");
    assert_eq!(writer.active_segment_id(), SegmentId::new(1));
}

#[test]
fn partial_valid_sync_poisons_writer_and_acks_only_valid_prefix() {
    let sim = SimulatedIO::pristine(0);
    let mgr = setup_manager(sim, 64 * 1024);
    let mut writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD).unwrap();

    let payload = b"payload-x".to_vec();
    let payload_size = payload.len();
    let record_size = EVENT_RECORD_OVERHEAD + payload_size;

    (1..=5u64).for_each(|i| {
        writer
            .append(
                DidHash::from_did(&format!("did:plc:user{i}")),
                EventTypeTag::COMMIT,
                payload.clone(),
            )
            .unwrap();
    });

    let event_3_start = SEGMENT_HEADER_SIZE + 2 * record_size;
    let event_3_checksum_offset = event_3_start + EVENT_HEADER_SIZE + payload_size;

    let segment_path = mgr.segment_path(SegmentId::new(1));
    let corrupt_fd = mgr
        .io()
        .open(&segment_path, OpenOptions::read_write_existing())
        .unwrap();
    mgr.io()
        .write_all_at(corrupt_fd, event_3_checksum_offset as u64, &[0xFFu8; 4])
        .unwrap();
    mgr.io().close(corrupt_fd).unwrap();

    let result = writer.sync().unwrap();
    assert_eq!(
        result.synced_through,
        EventSequence::new(2),
        "sync must ack only events 1..=2 with corrupt event 3"
    );
    assert_eq!(result.flushed_events.len(), 2);
    assert!(
        writer.is_poisoned(),
        "writer must be poisoned after partial sync"
    );

    let append_after_poison = writer.append(
        DidHash::from_did("did:plc:after"),
        EventTypeTag::COMMIT,
        payload.clone(),
    );
    assert!(
        append_after_poison.is_err(),
        "append must fail on poisoned writer"
    );

    let sync_after_poison = writer.sync();
    assert!(
        sync_after_poison.is_err(),
        "sync must fail on poisoned writer"
    );

    drop(writer);
    let recovered = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD).unwrap();
    assert_eq!(
        recovered.synced_seq(),
        EventSequence::new(2),
        "reopen must observe synced_seq matching disk's valid prefix"
    );

    let valid = read_all_events(&mgr, 0);
    assert_eq!(valid.len(), 2);
    assert_eq!(valid[0].seq, EventSequence::new(1));
    assert_eq!(valid[1].seq, EventSequence::new(2));
}
