mod common;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};

use rayon::prelude::*;
use tranquil_store::RealIO;
use tranquil_store::archival::{
    ArchivalDestination, ArchivalSidecar, ContinuousArchiver, LocalArchivalDestination,
};
use tranquil_store::eventlog::{EventLog, EventLogConfig, SegmentId};
use tranquil_store::sim_seed_range;

use tranquil_db_traits::{RepoEventType, SequenceNumber, SequencedEvent};
use tranquil_types::Did;

struct FlakyDestination {
    inner: LocalArchivalDestination,
    calls: AtomicU32,
    fail_at: u32,
}

impl ArchivalDestination for FlakyDestination {
    fn store_segment(&self, segment_id: SegmentId, data: &[u8]) -> std::io::Result<()> {
        let n = self.calls.fetch_add(1, Ordering::Relaxed) + 1;
        if n == self.fail_at {
            return Err(std::io::Error::other("simulated archival crash"));
        }
        self.inner.store_segment(segment_id, data)
    }
}

fn build_segments(segments_dir: &std::path::Path, n_events: u32) {
    std::fs::create_dir_all(segments_dir).unwrap();
    let el = EventLog::open(
        EventLogConfig {
            segments_dir: segments_dir.to_path_buf(),
            max_segment_size: 256,
            ..EventLogConfig::default()
        },
        RealIO::new(),
    )
    .unwrap();
    (0..n_events).for_each(|i| {
        let did = Did::from(format!("did:plc:archive{}", i % 8));
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
            rev: Some(tranquil_types::Tid::from(format!("rev{i}"))),
        };
        el.append_event(&did, RepoEventType::Commit, &event)
            .unwrap();
        if i % 64 == 63 {
            el.sync().unwrap();
        }
    });
    el.sync().unwrap();
    el.shutdown().unwrap();
}

fn tqe_files(dir: &std::path::Path) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == "tqe"))
                .map(|p| {
                    (
                        p.file_name().unwrap().to_string_lossy().into_owned(),
                        std::fs::read(&p).unwrap(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn sim_archival_sidecar_recovers_after_midpass_crash() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let dir = tempfile::TempDir::new().unwrap();
        let segments_dir = dir.path().join("segments");
        let archive_dir = dir.path().join("archive");
        let sidecar_path = dir.path().join("archival_sidecar.json");

        build_segments(&segments_dir, 800);

        let source = tqe_files(&segments_dir);
        assert!(
            source.len() >= 4,
            "seed={seed} need several segments to archive, got {}",
            source.len()
        );
        let mut sealed: Vec<(String, Vec<u8>)> = source.into_iter().collect();
        sealed.pop();
        let sealed: BTreeMap<String, Vec<u8>> = sealed.into_iter().collect();

        let fail_at = ((seed % 3) + 1) as u32;
        {
            let dest = FlakyDestination {
                inner: LocalArchivalDestination::new(archive_dir.clone()).unwrap(),
                calls: AtomicU32::new(0),
                fail_at,
            };
            let archiver =
                ContinuousArchiver::new(segments_dir.clone(), sidecar_path.clone(), Box::new(dest));
            let _ = archiver.run_pass();
        }

        let recovered = {
            let dest = LocalArchivalDestination::new(archive_dir.clone()).unwrap();
            let archiver =
                ContinuousArchiver::new(segments_dir.clone(), sidecar_path.clone(), Box::new(dest));
            archiver.run_pass().unwrap()
        };
        assert!(
            recovered.segments_archived as usize <= sealed.len(),
            "seed={seed} recovery pass cannot archive more than the sealed set"
        );

        let archived = tqe_files(&archive_dir);
        assert_eq!(
            archived, sealed,
            "seed={seed} after a mid-pass crash and resume, every sealed segment must be archived exactly once with matching content"
        );

        let final_state = ArchivalSidecar::new(sidecar_path.clone()).load().unwrap();
        let highest_sealed: SegmentId = {
            let mut ids: Vec<SegmentId> = sealed
                .keys()
                .map(|name| {
                    let stem = name.trim_end_matches(".tqe");
                    SegmentId::new(stem.parse::<u32>().unwrap())
                })
                .collect();
            ids.sort();
            *ids.last().unwrap()
        };
        assert_eq!(
            final_state.last_archived_segment,
            Some(highest_sealed),
            "seed={seed} sidecar last_archived_segment must equal the highest sealed segment after recovery"
        );

        let idempotent = {
            let dest = LocalArchivalDestination::new(archive_dir.clone()).unwrap();
            let archiver =
                ContinuousArchiver::new(segments_dir.clone(), sidecar_path.clone(), Box::new(dest));
            archiver.run_pass().unwrap()
        };
        assert_eq!(
            idempotent.segments_archived, 0,
            "seed={seed} a pass after full archival must archive nothing"
        );
    });
}
