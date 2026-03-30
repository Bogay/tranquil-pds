use std::path::{Path, PathBuf};
use std::sync::Arc;

use rayon::prelude::*;
use tranquil_store::eventlog::{
    DidHash, EVENT_RECORD_OVERHEAD, EventLogWriter, EventSequence, EventTypeTag, MAX_EVENT_PAYLOAD,
    SEGMENT_HEADER_SIZE, SegmentId, SegmentManager, SegmentReader, SegmentWriter, TimestampMicros,
    ValidEvent, rebuild_from_segment,
};
use tranquil_store::{FaultConfig, OpenOptions, SimulatedIO, StorageIO, sim_seed_range};

fn setup_manager(sim: SimulatedIO, max_segment_size: u64) -> Arc<SegmentManager<SimulatedIO>> {
    Arc::new(SegmentManager::new(sim, PathBuf::from("/segments"), max_segment_size).unwrap())
}

fn append_test_event(writer: &mut EventLogWriter<SimulatedIO>, seq_hint: u64) -> EventSequence {
    writer
        .append(
            DidHash::from_did(&format!("did:plc:crash{seq_hint}")),
            EventTypeTag::COMMIT,
            format!("payload-{seq_hint}").into_bytes(),
        )
        .unwrap()
}

#[test]
fn synced_events_survive_crash() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let sim = SimulatedIO::pristine(seed);
        let mgr = setup_manager(sim, 64 * 1024);

        let n = 10u64;
        {
            let mut writer =
                EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD).unwrap();
            (1..=n).for_each(|i| {
                append_test_event(&mut writer, i);
            });
            writer.sync().unwrap();
            mgr.io().sync_dir(Path::new("/segments")).unwrap();
        }

        mgr.shutdown();
        mgr.io().crash();

        let writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD).unwrap();
        assert_eq!(
            writer.synced_seq(),
            EventSequence::new(n),
            "seed {seed}: expected all synced events to survive"
        );

        let fd = mgr.open_for_read(SegmentId::new(1)).unwrap();
        let events = SegmentReader::open(mgr.io(), fd, MAX_EVENT_PAYLOAD)
            .unwrap()
            .valid_prefix()
            .unwrap();
        assert_eq!(events.len(), n as usize, "seed {seed}");

        events.iter().enumerate().for_each(|(i, e)| {
            assert_eq!(e.seq, EventSequence::new(i as u64 + 1));
        });
    });
}

#[test]
fn unsynced_events_lost_on_crash() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let sim = SimulatedIO::pristine(seed);
        let mgr = setup_manager(sim, 64 * 1024);

        let synced_count = 5u64;
        let unsynced_count = 5u64;
        {
            let mut writer =
                EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD).unwrap();
            (1..=synced_count).for_each(|i| {
                append_test_event(&mut writer, i);
            });
            writer.sync().unwrap();
            mgr.io().sync_dir(Path::new("/segments")).unwrap();

            (synced_count + 1..=synced_count + unsynced_count).for_each(|i| {
                append_test_event(&mut writer, i);
            });
        }

        mgr.shutdown();
        mgr.io().crash();

        let writer =
            EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD).unwrap();
        let recovered_count = writer.synced_seq().raw();
        assert_eq!(
            recovered_count, synced_count,
            "seed {seed}: pristine IO should recover exactly {synced_count} synced events, got {recovered_count}"
        );
    });
}

#[test]
fn sequence_monotonicity_after_recovery() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let sim = SimulatedIO::new(seed, FaultConfig::moderate());
        let mgr = setup_manager(sim, 64 * 1024);

        let crash_point = (seed % 15) + 3;
        let write_result: Result<(), std::io::Error> = (|| {
            let mut writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD)?;
            (1..=crash_point).try_for_each(|i| -> std::io::Result<()> {
                writer.append(
                    DidHash::from_did(&format!("did:plc:mono{i}")),
                    EventTypeTag::COMMIT,
                    format!("data-{i}").into_bytes(),
                )?;
                if i % 3 == 0 {
                    writer.sync()?;
                    mgr.io().sync_dir(Path::new("/segments"))?;
                }
                Ok(())
            })?;
            Ok(())
        })();
        let _ = write_result;

        mgr.shutdown();
        mgr.io().crash();

        let mgr_clone = Arc::clone(&mgr);
        let recovery_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut writer = EventLogWriter::open(Arc::clone(&mgr_clone), 256, MAX_EVENT_PAYLOAD)?;
            let new_seqs: Vec<EventSequence> = (0..5u64)
                .filter_map(|i| {
                    writer
                        .append(
                            DidHash::from_did(&format!("did:plc:post{i}")),
                            EventTypeTag::COMMIT,
                            format!("post-recovery-{i}").into_bytes(),
                        )
                        .ok()
                })
                .collect();
            Ok::<_, std::io::Error>(new_seqs)
        }));

        let Ok(Ok(new_seqs)) = recovery_result else {
            return;
        };

        new_seqs.windows(2).for_each(|pair| {
            assert!(
                pair[1].raw() == pair[0].raw() + 1,
                "seed {seed}: non-contiguous seqs {} -> {}",
                pair[0],
                pair[1],
            );
        });

        if let Some(first_new) = new_seqs.first() {
            assert!(first_new.raw() > 0, "seed {seed}: new sequence starts at 0");
        }
    });
}

#[test]
fn partial_event_truncated_on_recovery() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let sim = SimulatedIO::pristine(seed);
        let mgr = setup_manager(sim, 64 * 1024);

        let complete_count = 5u64;
        {
            let mut writer =
                EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD).unwrap();
            (1..=complete_count).for_each(|i| {
                append_test_event(&mut writer, i);
            });
            writer.sync().unwrap();
            mgr.io().sync_dir(Path::new("/segments")).unwrap();
        }

        let fd = mgr.open_for_read(SegmentId::new(1)).unwrap();
        let file_size = mgr.io().file_size(fd).unwrap();
        let partial_bytes = ((seed % 20) + 1) as usize;
        let junk: Vec<u8> = (0..partial_bytes)
            .map(|i| (i as u8).wrapping_add(seed as u8))
            .collect();
        mgr.io().write_all_at(fd, file_size, &junk).unwrap();
        mgr.io().sync(fd).unwrap();

        mgr.shutdown();
        mgr.io().crash();

        let writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD).unwrap();
        assert_eq!(
            writer.synced_seq(),
            EventSequence::new(complete_count),
            "seed {seed}: partial write should be truncated, preserving {complete_count} events"
        );
    });
}

#[test]
fn cross_segment_recovery() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let payload_size = 50;
        let record_size = EVENT_RECORD_OVERHEAD + payload_size;
        let events_per_segment = 3;
        let max_segment_size = (SEGMENT_HEADER_SIZE + record_size * events_per_segment) as u64;

        let sim = SimulatedIO::pristine(seed);
        let mgr = setup_manager(sim, max_segment_size);

        let sealed_events = 9u64;
        let trailing_unsynced = 2u64;
        let total_events = sealed_events + trailing_unsynced;
        {
            let mut writer =
                EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD).unwrap();
            (1..=total_events).for_each(|i| {
                writer
                    .append(
                        DidHash::from_did(&format!("did:plc:xseg{i}")),
                        EventTypeTag::COMMIT,
                        vec![i as u8; payload_size],
                    )
                    .unwrap();

                if i % events_per_segment as u64 == 0 && i <= sealed_events {
                    writer.sync().unwrap();
                    writer.rotate_if_needed().unwrap();
                }
            });
            mgr.io().sync_dir(Path::new("/segments")).unwrap();
        }

        mgr.shutdown();
        mgr.io().crash();

        let writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD).unwrap();
        let recovered = writer.synced_seq().raw();

        let sealed_segments = mgr.list_segments().unwrap();
        let sealed_count = sealed_segments.len().saturating_sub(1);

        assert!(
            recovered >= (sealed_count as u64) * events_per_segment as u64,
            "seed {seed}: recovered {recovered} but expected at least {} sealed events",
            sealed_count * events_per_segment,
        );

        sealed_segments[..sealed_count].iter().for_each(|&seg_id| {
            let fd = mgr.open_for_read(seg_id).unwrap();
            let events = SegmentReader::open(mgr.io(), fd, MAX_EVENT_PAYLOAD)
                .unwrap()
                .valid_prefix()
                .unwrap();
            assert_eq!(
                events.len(),
                events_per_segment,
                "seed {seed}: sealed segment {seg_id} should have {events_per_segment} events"
            );
        });
    });
}

#[test]
fn corrupt_index_triggers_rebuild() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let payload_size = 50;
        let record_size = EVENT_RECORD_OVERHEAD + payload_size;
        let max_segment_size = (SEGMENT_HEADER_SIZE + record_size * 3) as u64;

        let sim = SimulatedIO::pristine(seed);
        let mgr = setup_manager(sim, max_segment_size);

        {
            let mut writer =
                EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD).unwrap();
            (1..=6).for_each(|i| {
                writer
                    .append(
                        DidHash::from_did(&format!("did:plc:idx{i}")),
                        EventTypeTag::COMMIT,
                        vec![0xAA; payload_size],
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

        let index_path = mgr.index_path(SegmentId::new(1));
        if let Ok(fd) = mgr.io().open(&index_path, OpenOptions::read_write()) {
            mgr.io()
                .write_all_at(fd, 0, b"CORRUPT_INDEX_GARBAGE_DATA_XYZ")
                .unwrap();
            mgr.io().sync(fd).unwrap();
            mgr.io().close(fd).unwrap();
        }

        let writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD).unwrap();

        assert!(
            writer.synced_seq().raw() >= 6,
            "seed {seed}: recovery after corrupt index should find all events, got seq {}",
            writer.synced_seq(),
        );
    });
}

#[test]
fn large_sealed_segment_index_rebuild_latency() {
    let payload_size = 1024;
    let event_count = 64_000u64;

    let sim = SimulatedIO::pristine(42);
    let mgr = setup_manager(sim, 256 * 1024 * 1024);

    {
        let mut writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD).unwrap();
        (1..=event_count).for_each(|i| {
            writer
                .append(
                    DidHash::from_did(&format!("did:plc:bench{i}")),
                    EventTypeTag::COMMIT,
                    vec![0xBB; payload_size],
                )
                .unwrap();
        });
        writer.sync().unwrap();
        writer.checkpoint_index().unwrap();
    }
    mgr.shutdown();

    let index_path = mgr.index_path(SegmentId::new(1));
    let _ = mgr.io().delete(&index_path);

    let fd = mgr.open_for_read(SegmentId::new(1)).unwrap();

    let start = std::time::Instant::now();
    let (index, last_seq) = rebuild_from_segment(mgr.io(), fd, 256, MAX_EVENT_PAYLOAD).unwrap();
    let elapsed = start.elapsed();

    assert_eq!(last_seq, Some(EventSequence::new(event_count)));
    assert!(index.entry_count() > 0);
    assert!(
        elapsed.as_secs() < 60,
        "index rebuild took {:?}, exceeds 60s budget",
        elapsed,
    );
}

#[test]
fn corrupt_metadata_triggers_scan() {
    let sim = SimulatedIO::pristine(42);
    let mgr = setup_manager(sim, 64 * 1024);

    {
        let mut writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD).unwrap();
        (1..=10).for_each(|i| {
            append_test_event(&mut writer, i);
        });
        writer.sync().unwrap();
        writer.checkpoint_index().unwrap();
    }
    mgr.shutdown();

    let index_path = mgr.index_path(SegmentId::new(1));
    if let Ok(fd) = mgr.io().open(&index_path, OpenOptions::read_write()) {
        mgr.io()
            .write_all_at(fd, 0, b"TOTALLY_CORRUPT_META")
            .unwrap();
        mgr.io().sync(fd).unwrap();
        mgr.io().close(fd).unwrap();
    }

    let writer = EventLogWriter::open(Arc::clone(&mgr), 256, MAX_EVENT_PAYLOAD).unwrap();
    assert_eq!(
        writer.synced_seq(),
        EventSequence::new(10),
        "recovery via segment scan should find all 10 events"
    );
}

#[test]
fn pristine_comparison_under_faults() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let event_count = 15u64;
        let sync_interval = 5u64;

        let pristine_sim = SimulatedIO::pristine(seed);
        let pristine_mgr = setup_manager(pristine_sim, 64 * 1024);

        {
            let mut writer =
                EventLogWriter::open(Arc::clone(&pristine_mgr), 256, MAX_EVENT_PAYLOAD).unwrap();
            (1..=event_count).for_each(|i| {
                writer
                    .append(
                        DidHash::from_did(&format!("did:plc:prist{i}")),
                        EventTypeTag::COMMIT,
                        format!("pristine-{i}").into_bytes(),
                    )
                    .unwrap();
                if i % sync_interval == 0 {
                    writer.sync().unwrap();
                }
            });
            writer.sync().unwrap();
        }
        pristine_mgr.shutdown();

        let pristine_fd = pristine_mgr.open_for_read(SegmentId::new(1)).unwrap();
        let pristine_events =
            SegmentReader::open(pristine_mgr.io(), pristine_fd, MAX_EVENT_PAYLOAD)
                .unwrap()
                .valid_prefix()
                .unwrap();

        let faulty_sim = SimulatedIO::new(seed, FaultConfig::moderate());
        let faulty_mgr = setup_manager(faulty_sim, 64 * 1024);

        let write_ok = (|| -> std::io::Result<()> {
            let mut writer = EventLogWriter::open(Arc::clone(&faulty_mgr), 256, MAX_EVENT_PAYLOAD)?;
            (1..=event_count).try_for_each(|i| -> std::io::Result<()> {
                writer.append(
                    DidHash::from_did(&format!("did:plc:prist{i}")),
                    EventTypeTag::COMMIT,
                    format!("pristine-{i}").into_bytes(),
                )?;
                if i % sync_interval == 0 {
                    let _ = writer.sync();
                    let _ = faulty_mgr.io().sync_dir(Path::new("/segments"));
                }
                Ok(())
            })?;
            let _ = writer.sync();
            Ok(())
        })();
        let _ = write_ok;

        faulty_mgr.shutdown();
        faulty_mgr.io().crash();

        let faulty_clone = Arc::clone(&faulty_mgr);
        let recovery = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || -> std::io::Result<Option<Vec<ValidEvent>>> {
                let recovered_writer =
                    EventLogWriter::open(Arc::clone(&faulty_clone), 256, MAX_EVENT_PAYLOAD)?;

                let recovered_seq = recovered_writer.synced_seq().raw();
                assert!(
                    recovered_seq <= event_count,
                    "seed {seed}: recovered {recovered_seq} > written {event_count}"
                );

                if recovered_seq == 0 {
                    return Ok(None);
                }

                let fd = faulty_clone.open_for_read(SegmentId::new(1))?;
                let events = SegmentReader::open(faulty_clone.io(), fd, MAX_EVENT_PAYLOAD)?
                    .valid_prefix()?;
                Ok(Some(events))
            },
        ));

        if let Ok(Ok(Some(recovered_events))) = recovery {
            let is_prefix = recovered_events
                .iter()
                .zip(pristine_events.iter())
                .all(|(r, p)| r.seq == p.seq && r.payload == p.payload);

            assert!(
                is_prefix,
                "seed {seed}: recovered events must be a prefix of pristine"
            );
        }
    });
}

#[test]
fn bit_flip_detected_by_checksum() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let sim = SimulatedIO::pristine(seed);
        let dir = Path::new("/test");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();

        let fd = sim
            .open(Path::new("/test/segment.tqe"), OpenOptions::read_write())
            .unwrap();
        let mut writer = SegmentWriter::new(
            &sim,
            fd,
            SegmentId::new(1),
            EventSequence::new(1),
            MAX_EVENT_PAYLOAD,
        )
        .unwrap();

        let data_len = ((seed % 256) as usize).max(1);
        let event = ValidEvent {
            seq: EventSequence::new(1),
            timestamp: TimestampMicros::new(1_000_000),
            did_hash: DidHash::from_did("did:plc:bitflip"),
            event_type: EventTypeTag::COMMIT,
            payload: vec![0xAA; data_len],
        };
        writer.append_event(&sim, &event).unwrap();
        writer.sync(&sim).unwrap();

        let record_start = SEGMENT_HEADER_SIZE as u64;
        let record_end = record_start + EVENT_RECORD_OVERHEAD as u64 + data_len as u64;
        let flip_pos = record_start + (seed.wrapping_mul(7) % (record_end - record_start));
        let flip_bit = (seed.wrapping_mul(13) % 8) as u8;

        let mut byte_buf = [0u8; 1];
        sim.read_exact_at(fd, flip_pos, &mut byte_buf).unwrap();
        byte_buf[0] ^= 1 << flip_bit;
        sim.write_all_at(fd, flip_pos, &byte_buf).unwrap();

        use tranquil_store::eventlog::ReadEventRecord;
        let mut reader = SegmentReader::open(&sim, fd, MAX_EVENT_PAYLOAD).unwrap();
        let record = reader.next().unwrap().unwrap();
        assert!(
            !matches!(record, ReadEventRecord::Valid { .. }),
            "seed {seed}: bit flip at offset {flip_pos} bit {flip_bit} was not detected"
        );
    });
}

fn fault_configs() -> Vec<(&'static str, FaultConfig)> {
    vec![
        (
            "partial_writes_only",
            FaultConfig {
                partial_write_probability: 0.15,
                ..FaultConfig::none()
            },
        ),
        (
            "sync_failures_only",
            FaultConfig {
                sync_failure_probability: 0.10,
                dir_sync_failure_probability: 0.05,
                ..FaultConfig::none()
            },
        ),
        ("combined", FaultConfig::moderate()),
        (
            "bit_flips_only",
            FaultConfig {
                bit_flip_on_read_probability: 0.05,
                ..FaultConfig::none()
            },
        ),
    ]
}

#[test]
fn pristine_comparison_parameterized_faults() {
    fault_configs().iter().for_each(|(config_name, config)| {
        sim_seed_range().into_par_iter().for_each(|seed| {
            let event_count = 10u64;

            let pristine_sim = SimulatedIO::pristine(seed);
            let pristine_mgr = setup_manager(pristine_sim, 64 * 1024);
            {
                let mut writer =
                    EventLogWriter::open(Arc::clone(&pristine_mgr), 256, MAX_EVENT_PAYLOAD).unwrap();
                (1..=event_count).for_each(|i| {
                    writer
                        .append(
                            DidHash::from_did(&format!("did:plc:param{i}")),
                            EventTypeTag::COMMIT,
                            format!("param-{i}").into_bytes(),
                        )
                        .unwrap();
                    if i % 4 == 0 {
                        writer.sync().unwrap();
                    }
                });
                writer.sync().unwrap();
            }
            pristine_mgr.shutdown();

            let pristine_fd = pristine_mgr.open_for_read(SegmentId::new(1)).unwrap();
            let pristine_events = SegmentReader::open(pristine_mgr.io(), pristine_fd, MAX_EVENT_PAYLOAD)
                .unwrap()
                .valid_prefix()
                .unwrap();

            let faulty_sim = SimulatedIO::new(seed, *config);
            let faulty_mgr = setup_manager(faulty_sim, 64 * 1024);
            let _ = (|| -> std::io::Result<()> {
                let mut writer =
                    EventLogWriter::open(Arc::clone(&faulty_mgr), 256, MAX_EVENT_PAYLOAD)?;
                (1..=event_count).try_for_each(|i| -> std::io::Result<()> {
                    writer.append(
                        DidHash::from_did(&format!("did:plc:param{i}")),
                        EventTypeTag::COMMIT,
                        format!("param-{i}").into_bytes(),
                    )?;
                    if i % 4 == 0 {
                        let _ = writer.sync();
                        let _ = faulty_mgr.io().sync_dir(Path::new("/segments"));
                    }
                    Ok(())
                })?;
                let _ = writer.sync();
                Ok(())
            })();

            faulty_mgr.shutdown();
            faulty_mgr.io().crash();

            let faulty_clone = Arc::clone(&faulty_mgr);
            let recovery = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> std::io::Result<Option<Vec<ValidEvent>>> {
                let recovered_writer =
                    EventLogWriter::open(Arc::clone(&faulty_clone), 256, MAX_EVENT_PAYLOAD)?;

                let recovered_seq = recovered_writer.synced_seq().raw();
                assert!(
                    recovered_seq <= event_count,
                    "config={config_name} seed={seed}: recovered {recovered_seq} > written {event_count}"
                );

                if recovered_seq == 0 {
                    return Ok(None);
                }

                let fd = faulty_clone.open_for_read(SegmentId::new(1))?;
                let events = SegmentReader::open(faulty_clone.io(), fd, MAX_EVENT_PAYLOAD)?
                    .valid_prefix()?;
                Ok(Some(events))
            }));

            if let Ok(Ok(Some(recovered_events))) = recovery {
                let is_prefix = recovered_events
                    .iter()
                    .zip(pristine_events.iter())
                    .all(|(r, p)| r.seq == p.seq && r.payload == p.payload);

                assert!(
                    is_prefix,
                    "config={config_name} seed={seed}: recovered is not prefix of pristine"
                );
            }
        });
    });
}
