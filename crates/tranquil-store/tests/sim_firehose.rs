mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use rayon::prelude::*;
use tranquil_store::eventlog::{EventLog, EventLogConfig, EventSequence};
use tranquil_store::{FaultConfig, SimulatedIO, sim_seed_range};

use common::with_runtime;
use tranquil_db_traits::{RepoEventType, SequenceNumber, SequencedEvent};
use tranquil_types::Did;

fn open_sim_eventlog(
    dir: &std::path::Path,
    sim: &Arc<SimulatedIO>,
) -> Arc<EventLog<Arc<SimulatedIO>>> {
    Arc::new(
        EventLog::open(
            EventLogConfig {
                segments_dir: dir.join("segments"),
                max_segment_size: 4096,
                ..EventLogConfig::default()
            },
            Arc::clone(sim),
        )
        .unwrap(),
    )
}

fn append_seq(el: &EventLog<Arc<SimulatedIO>>, idx: u32) {
    let did = Did::from(format!("did:plc:firehose{}", idx % 16));
    let event = SequencedEvent {
        seq: SequenceNumber::from_raw(0),
        did: did.clone(),
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
        rev: Some(tranquil_types::Tid::from(format!("rev{idx}"))),
    };
    el.append_event(&did, RepoEventType::Commit, &event)
        .unwrap();
}

fn drain_replay(el: &EventLog<Arc<SimulatedIO>>, batch: usize) -> Result<Vec<u64>, String> {
    let mut cursor = EventSequence::BEFORE_ALL;
    let mut seqs: Vec<u64> = Vec::new();
    loop {
        let events = el
            .get_events_since(cursor, batch)
            .map_err(|e| e.to_string())?;
        if events.is_empty() {
            return Ok(seqs);
        }
        events.iter().for_each(|e| {
            let raw = e.seq.as_u64().expect("event seq is non-negative");
            seqs.push(raw);
            cursor = EventSequence::new(raw);
        });
    }
}

#[test]
fn sim_firehose_replay_recovers_after_crash() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("segments")).unwrap();
        let n = ((seed % 400) + 50) as u32;

        let sim = Arc::new(SimulatedIO::new(seed, FaultConfig::read_corruption()));
        sim.set_pristine_mode(true);

        let synced: u64 = {
            let el = open_sim_eventlog(dir.path(), &sim);
            (1..=n).for_each(|i| append_seq(&el, i));
            let result = el.sync().unwrap();
            let synced = result.synced_through.raw();
            el.shutdown().unwrap();
            synced
        };
        assert_eq!(synced, n as u64, "seed={seed} all appends must sync clean");

        sim.crash();

        sim.set_pristine_mode(true);
        let el = open_sim_eventlog(dir.path(), &sim);
        let expected: Vec<u64> = (1..=synced).collect();

        let clean = drain_replay(&el, 64).unwrap();
        assert_eq!(
            clean, expected,
            "seed={seed} clean replay after crash must return every synced event in order"
        );

        sim.set_pristine_mode(false);
        if let Ok(faulted) = drain_replay(&el, 32) {
            assert!(
                faulted.windows(2).all(|w| w[1] > w[0]),
                "seed={seed} replayed seqs must be strictly increasing under read corruption"
            );
            assert!(
                faulted.iter().all(|&s| s >= 1 && s <= synced),
                "seed={seed} replay must never fabricate a seq outside the synced range"
            );
            assert!(
                faulted.len() as u64 <= synced,
                "seed={seed} replay under corruption must never return more events than were synced"
            );
        }

        sim.set_pristine_mode(true);
        let recovered = drain_replay(&el, 64).unwrap();
        assert_eq!(
            recovered, expected,
            "seed={seed} after read faults clear, full replay must be intact"
        );
        el.shutdown().unwrap();
    });
}

#[test]
fn sim_blockstore_quiesce_under_concurrent_writers_and_reopen() {
    use tranquil_store::blockstore::{CidBytes, TranquilBlockStore};

    with_runtime(|| {
        let seed_range = match tranquil_store::sim_single_seed() {
            Some(s) => s..s + 1,
            None => 0..64u64,
        };
        seed_range.into_par_iter().for_each(|seed| {
            let dir = tempfile::TempDir::new().unwrap();
            let cfg = common::default_blockstore_config(dir.path());
            let acked = Arc::new(AtomicU32::new(0));
            let base = (seed as u32).wrapping_mul(100_000);

            {
                let store = TranquilBlockStore::open(cfg.clone()).unwrap();
                let stop = AtomicBool::new(false);

                std::thread::scope(|s| {
                    let writer = s.spawn(|| {
                        let mut next = base;
                        while !stop.load(Ordering::Relaxed) {
                            let batch: Vec<(CidBytes, Vec<u8>)> = (next..next + 4)
                                .map(|i| (common::test_cid(i), common::block_data(i)))
                                .collect();
                            if store.put_blocks_blocking(batch).is_ok() {
                                acked.fetch_max(next + 4, Ordering::Relaxed);
                            }
                            next += 4;
                        }
                    });

                    let mut waited_ms = 0;
                    while acked.load(Ordering::Relaxed) <= base && waited_ms < 5_000 {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                        waited_ms += 1;
                    }
                    let (_snapshot, guard) = store.quiesce().unwrap();
                    let acked_at_quiesce = acked.load(Ordering::Relaxed);
                    assert!(
                        acked_at_quiesce > base,
                        "seed={seed} writer must ack at least one batch before quiesce, otherwise the snapshot assertion has no teeth"
                    );
                    (base..acked_at_quiesce).for_each(|i| {
                        assert!(
                            store.get_block_sync(&common::test_cid(i)).unwrap().is_some(),
                            "seed={seed} block {i} acked before quiesce must be readable in the quiesced snapshot"
                        );
                    });
                    drop(guard);
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    stop.store(true, Ordering::Relaxed);
                    writer.join().unwrap();
                });
            }

            let store = TranquilBlockStore::open(cfg).unwrap();
            let acked_count = acked.load(Ordering::Relaxed);
            (base..acked_count).for_each(|i| {
                assert!(
                    store.get_block_sync(&common::test_cid(i)).unwrap().is_some(),
                    "seed={seed} acked block {i} must survive quiesce + clean reopen"
                );
            });
        });
    });
}
