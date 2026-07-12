mod common;

use std::sync::Arc;

use rayon::prelude::*;
use tranquil_store::RealIO;
use tranquil_store::eventlog::{EventLog, EventLogConfig};
use tranquil_store::metastore::record_ops::{ListRecordsQuery, RecordWrite};
use tranquil_store::metastore::repo_meta::RepoStatus;
use tranquil_store::metastore::{Metastore, MetastoreConfig};
use tranquil_store::sim_seed_range;

use common::{test_cid_link, test_did, test_handle, test_uuid};
use tranquil_db_traits::{RepoEventType, SequenceNumber, SequencedEvent};
use tranquil_types::{Did, Handle, Nsid, Rkey};
use uuid::Uuid;

const CACHE_SIZE: u64 = 16 * 1024 * 1024;

fn open_metastore(dir: &std::path::Path) -> Metastore {
    Metastore::open(
        &dir.join("metastore"),
        MetastoreConfig {
            cache_size_bytes: CACHE_SIZE,
        },
    )
    .unwrap()
}

fn seed_one_repo(ms: &Metastore, user_id: Uuid, did: &Did, handle: &Handle) {
    ms.repo_ops()
        .create_repo(
            ms.database(),
            user_id,
            did,
            handle,
            &test_cid_link(7),
            "rev0",
        )
        .unwrap();
}

#[test]
fn sim_blob_lifecycle_survives_restart() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let dir = tempfile::TempDir::new().unwrap();
        let user_id = test_uuid(seed);
        let did = test_did(seed);
        let handle = test_handle(seed);
        let blob_count = ((seed % 6) + 2) as u8;
        let cids: Vec<_> = (0..blob_count)
            .map(|i| test_cid_link(i.wrapping_add(40)))
            .collect();
        let takedown_at = (seed % blob_count as u64) as usize;

        {
            let ms = open_metastore(dir.path());
            seed_one_repo(&ms, user_id, &did, &handle);
            let blob_ops = ms.blob_ops();
            cids.iter().enumerate().for_each(|(i, cid)| {
                blob_ops
                    .insert_blob(
                        cid,
                        "image/png",
                        100 + i as i64,
                        user_id,
                        &format!("blobs/{i}"),
                    )
                    .unwrap();
            });
            blob_ops
                .update_blob_takedown(&cids[takedown_at], Some("mod-takedown"))
                .unwrap();
            ms.persist().unwrap();
        }

        let ms = open_metastore(dir.path());
        let blob_ops = ms.blob_ops();
        cids.iter().enumerate().for_each(|(i, cid)| {
            let meta = blob_ops.get_blob_metadata(cid).unwrap();
            assert!(
                meta.is_some(),
                "seed={seed} blob {i} metadata must survive restart"
            );
            assert_eq!(meta.unwrap().size_bytes, 100 + i as i64);
            let with_td = blob_ops.get_blob_with_takedown(cid).unwrap().unwrap();
            if i == takedown_at {
                assert_eq!(
                    with_td.takedown_ref.as_deref(),
                    Some("mod-takedown"),
                    "seed={seed} takedown must survive restart"
                );
            } else {
                assert!(
                    with_td.takedown_ref.is_none(),
                    "seed={seed} blob {i} must not gain a takedown"
                );
            }
        });
    });
}

#[test]
fn sim_repo_status_transitions_survive_restart() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let dir = tempfile::TempDir::new().unwrap();
        let user_id = test_uuid(seed);
        let did = test_did(seed);
        let handle = test_handle(seed);

        {
            let ms = open_metastore(dir.path());
            seed_one_repo(&ms, user_id, &did, &handle);
            ms.persist().unwrap();
        }

        let want_takedown = seed.is_multiple_of(2);
        let want_deactivate = seed.is_multiple_of(3);

        {
            let ms = open_metastore(dir.path());
            ms.repo_ops()
                .update_repo_status(
                    ms.database(),
                    &did,
                    Some(want_takedown),
                    want_takedown.then_some("mod-ref-9"),
                    Some(want_deactivate),
                )
                .unwrap();
            ms.persist().unwrap();
        }

        let ms = open_metastore(dir.path());
        let (_, meta) = ms.repo_ops().get_repo_meta(user_id).unwrap().unwrap();
        let expected = match (want_takedown, want_deactivate) {
            (true, _) => RepoStatus::Takendown,
            (false, true) => RepoStatus::Deactivated,
            (false, false) => RepoStatus::Active,
        };
        assert!(
            std::mem::discriminant(&meta.status) == std::mem::discriminant(&expected),
            "seed={seed} status must survive restart: want {expected:?}, got {:?}",
            meta.status
        );
        if want_takedown {
            assert_eq!(
                meta.takedown_ref.as_deref(),
                Some("mod-ref-9"),
                "seed={seed} takedown_ref must survive restart"
            );
        }
        assert_eq!(
            meta.deactivated_at_ms.is_some(),
            want_deactivate,
            "seed={seed} deactivation must survive restart"
        );
    });
}

#[test]
fn sim_handle_change_survives_restart() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let dir = tempfile::TempDir::new().unwrap();
        let user_id = test_uuid(seed);
        let did = test_did(seed);
        let old_handle = test_handle(seed);
        let new_handle = test_handle(seed.wrapping_add(1_000_000));

        {
            let ms = open_metastore(dir.path());
            seed_one_repo(&ms, user_id, &did, &old_handle);
            ms.repo_ops()
                .update_handle(ms.database(), user_id, &new_handle)
                .unwrap();
            ms.persist().unwrap();
        }

        let ms = open_metastore(dir.path());
        let repo_ops = ms.repo_ops();
        assert_eq!(
            repo_ops.lookup_handle(&new_handle).unwrap(),
            Some(user_id),
            "seed={seed} new handle must resolve after restart"
        );
        assert_eq!(
            repo_ops.lookup_handle(&old_handle).unwrap(),
            None,
            "seed={seed} old handle index must be cleared after restart"
        );
        let (_, meta) = repo_ops.get_repo_meta(user_id).unwrap().unwrap();
        assert_eq!(
            meta.handle,
            new_handle.as_str().to_ascii_lowercase(),
            "seed={seed} repo_meta handle must reflect the change"
        );
    });
}

#[test]
fn sim_list_records_range_scan_survives_restart() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let dir = tempfile::TempDir::new().unwrap();
        let user_id = test_uuid(seed);
        let did = test_did(seed);
        let handle = test_handle(seed);
        let collection = Nsid::from("app.bsky.feed.post".to_string());
        let count = ((seed % 30) + 10) as usize;

        let rkeys: Vec<Rkey> = (0..count)
            .map(|i| Rkey::from(format!("3k{i:04}")))
            .collect();

        {
            let ms = open_metastore(dir.path());
            seed_one_repo(&ms, user_id, &did, &handle);
            let user_hash = ms.user_hashes().get(&user_id).unwrap();
            let cids: Vec<_> = (0..count).map(|i| test_cid_link((i % 200) as u8)).collect();
            let writes: Vec<RecordWrite<'_>> = (0..count)
                .map(|i| RecordWrite {
                    collection: &collection,
                    rkey: &rkeys[i],
                    cid: &cids[i],
                })
                .collect();
            let mut batch = ms.database().batch();
            ms.record_ops()
                .upsert_records(&mut batch, user_hash, &writes)
                .unwrap();
            batch.commit().unwrap();
            ms.persist().unwrap();
        }

        let ms = open_metastore(dir.path());
        let record_ops = ms.record_ops();

        let ascending = record_ops
            .list_records(&ListRecordsQuery {
                user_id,
                collection: &collection,
                cursor: None,
                limit: 10_000,
                reverse: true,
                rkey_start: None,
                rkey_end: None,
            })
            .unwrap();
        let asc_keys: Vec<String> = ascending
            .iter()
            .map(|r| r.rkey.as_str().to_owned())
            .collect();
        let mut expected_asc: Vec<String> = rkeys.iter().map(|r| r.as_str().to_owned()).collect();
        expected_asc.sort();
        assert_eq!(
            asc_keys, expected_asc,
            "seed={seed} ascending full scan must return every record in order after restart"
        );

        let descending = record_ops
            .list_records(&ListRecordsQuery {
                user_id,
                collection: &collection,
                cursor: None,
                limit: 10_000,
                reverse: false,
                rkey_start: None,
                rkey_end: None,
            })
            .unwrap();
        let desc_keys: Vec<String> = descending
            .iter()
            .map(|r| r.rkey.as_str().to_owned())
            .collect();
        let expected_desc: Vec<String> = expected_asc.iter().rev().cloned().collect();
        assert_eq!(
            desc_keys, expected_desc,
            "seed={seed} reverse:false scan must return records in descending order"
        );

        let lo = &rkeys[count / 4];
        let hi = &rkeys[count - count / 4];
        let bounded = record_ops
            .list_records(&ListRecordsQuery {
                user_id,
                collection: &collection,
                cursor: None,
                limit: 10_000,
                reverse: true,
                rkey_start: Some(lo),
                rkey_end: Some(hi),
            })
            .unwrap();
        let bounded_keys: Vec<String> =
            bounded.iter().map(|r| r.rkey.as_str().to_owned()).collect();
        let expected_bounded: Vec<String> = expected_asc
            .iter()
            .filter(|k| k.as_str() >= lo.as_str() && k.as_str() <= hi.as_str())
            .cloned()
            .collect();
        assert_eq!(
            bounded_keys, expected_bounded,
            "seed={seed} inclusive rkey bounds must scope the scan correctly after restart"
        );

        let page_size = 7usize;
        let mut paged: Vec<String> = Vec::new();
        let mut cursor: Option<Rkey> = None;
        loop {
            let page = record_ops
                .list_records(&ListRecordsQuery {
                    user_id,
                    collection: &collection,
                    cursor: cursor.as_ref(),
                    limit: page_size,
                    reverse: true,
                    rkey_start: None,
                    rkey_end: None,
                })
                .unwrap();
            if page.is_empty() {
                break;
            }
            cursor = Some(page.last().unwrap().rkey.clone());
            paged.extend(page.iter().map(|r| r.rkey.as_str().to_owned()));
        }
        assert_eq!(
            paged, expected_asc,
            "seed={seed} cursor pagination must cover every record exactly once in order"
        );
    });
}

#[test]
fn sim_major_compact_preserves_data() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let dir = tempfile::TempDir::new().unwrap();
        let user_id = test_uuid(seed);
        let did = test_did(seed);
        let handle = test_handle(seed);
        let collection = Nsid::from("app.bsky.feed.post".to_string());
        let count = ((seed % 40) + 20) as usize;
        let rkeys: Vec<Rkey> = (0..count)
            .map(|i| Rkey::from(format!("3k{i:04}")))
            .collect();
        let cids: Vec<_> = (0..count).map(|i| test_cid_link((i % 200) as u8)).collect();
        let blob_cid = test_cid_link(123);
        let expected: Vec<(String, _)> = rkeys
            .iter()
            .zip(cids.iter())
            .map(|(r, c)| (r.as_str().to_owned(), c.clone()))
            .collect();

        {
            let ms = open_metastore(dir.path());
            seed_one_repo(&ms, user_id, &did, &handle);
            let user_hash = ms.user_hashes().get(&user_id).unwrap();
            let writes: Vec<RecordWrite<'_>> = (0..count)
                .map(|i| RecordWrite {
                    collection: &collection,
                    rkey: &rkeys[i],
                    cid: &cids[i],
                })
                .collect();
            let mut batch = ms.database().batch();
            ms.record_ops()
                .upsert_records(&mut batch, user_hash, &writes)
                .unwrap();
            batch.commit().unwrap();
            ms.blob_ops()
                .insert_blob(&blob_cid, "image/png", 4096, user_id, "blobs/c")
                .unwrap();
            ms.persist().unwrap();

            ms.major_compact().unwrap();

            let after = ms
                .record_ops()
                .list_records(&ListRecordsQuery {
                    user_id,
                    collection: &collection,
                    cursor: None,
                    limit: 10_000,
                    reverse: true,
                    rkey_start: None,
                    rkey_end: None,
                })
                .unwrap();
            let after_pairs: Vec<(String, _)> = after
                .iter()
                .map(|r| (r.rkey.as_str().to_owned(), r.record_cid.clone()))
                .collect();
            assert_eq!(
                after_pairs, expected,
                "seed={seed} every record rkey and cid must survive major_compact"
            );
            ms.persist().unwrap();
        }

        let ms = open_metastore(dir.path());
        let after_restart = ms
            .record_ops()
            .list_records(&ListRecordsQuery {
                user_id,
                collection: &collection,
                cursor: None,
                limit: 10_000,
                reverse: true,
                rkey_start: None,
                rkey_end: None,
            })
            .unwrap();
        let after_restart_pairs: Vec<(String, _)> = after_restart
            .iter()
            .map(|r| (r.rkey.as_str().to_owned(), r.record_cid.clone()))
            .collect();
        assert_eq!(
            after_restart_pairs, expected,
            "seed={seed} every record rkey and cid must survive major_compact + restart"
        );
        assert!(
            ms.blob_ops()
                .get_blob_metadata(&blob_cid)
                .unwrap()
                .is_some(),
            "seed={seed} blob must survive major_compact + restart"
        );
    });
}

fn open_eventlog(dir: &std::path::Path, max_segment_size: u64) -> Arc<EventLog<RealIO>> {
    std::fs::create_dir_all(dir.join("segments")).unwrap();
    Arc::new(
        EventLog::open(
            EventLogConfig {
                segments_dir: dir.join("segments"),
                max_segment_size,
                ..EventLogConfig::default()
            },
            RealIO::new(),
        )
        .unwrap(),
    )
}

fn append_n_events(el: &EventLog<RealIO>, n: u32) {
    (0..n).for_each(|i| {
        let did = Did::from(format!("did:plc:contiguity{i}"));
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
}

#[test]
fn sim_check_sequence_contiguity_clean_after_restart() {
    let dir = tempfile::TempDir::new().unwrap();
    {
        let el = open_eventlog(dir.path(), 512);
        append_n_events(&el, 200);
        el.shutdown().unwrap();
    }
    let el = open_eventlog(dir.path(), 512);
    el.reader().refresh_segment_ranges().unwrap();
    let result = el.reader().check_sequence_contiguity();
    assert!(
        result.is_contiguous(),
        "a synced, restart-recovered eventlog must report no sequence gaps: {} gap(s)",
        result.gaps.len()
    );
}

#[test]
fn sim_check_sequence_contiguity_detects_missing_sealed_segment() {
    let dir = tempfile::TempDir::new().unwrap();
    let el = open_eventlog(dir.path(), 256);
    append_n_events(&el, 800);

    let segments_dir = dir.path().join("segments");
    let mut segments: Vec<_> = std::fs::read_dir(&segments_dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "tqe"))
        .collect();
    segments.sort();
    assert!(
        segments.len() >= 4,
        "test needs at least 4 segments so the victim has a sealed neighbour on both sides, got {}",
        segments.len()
    );

    el.reader().refresh_segment_ranges().unwrap();
    assert!(
        el.reader().check_sequence_contiguity().is_contiguous(),
        "a freshly written log must be contiguous before any segment is dropped"
    );

    let victim = &segments[1];
    std::fs::remove_file(victim).unwrap();

    el.reader().refresh_segment_ranges().unwrap();
    let result = el.reader().check_sequence_contiguity();
    assert!(
        !result.is_contiguous(),
        "a sealed segment missing between two surviving ones must surface a sequence gap"
    );
    assert!(
        !result.gaps.is_empty(),
        "check_sequence_contiguity must report the gap left by the missing sealed segment"
    );
    el.shutdown().unwrap();
}

#[test]
fn sim_check_sequence_contiguity_gap_persists_across_reopen() {
    let dir = tempfile::TempDir::new().unwrap();
    let max_seq_before = {
        let el = open_eventlog(dir.path(), 256);
        append_n_events(&el, 800);
        let m = el.max_seq().raw();
        el.shutdown().unwrap();
        m
    };

    let segments_dir = dir.path().join("segments");
    let mut segments: Vec<_> = std::fs::read_dir(&segments_dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "tqe"))
        .collect();
    segments.sort();
    assert!(
        segments.len() >= 4,
        "test needs at least 4 segments so the victim has a sealed neighbour on both sides, got {}",
        segments.len()
    );

    std::fs::remove_file(&segments[1]).unwrap();

    let el = open_eventlog(dir.path(), 256);
    el.reader().refresh_segment_ranges().unwrap();
    let result = el.reader().check_sequence_contiguity();
    assert!(
        !result.is_contiguous(),
        "a restart that recovers a log with a missing sealed segment must still report the gap, not silently hide the hole"
    );
    assert!(
        !result.gaps.is_empty(),
        "check_sequence_contiguity must report the gap after reopen"
    );
    assert_eq!(
        el.max_seq().raw(),
        max_seq_before,
        "reopen must recover the active-segment tail past the hole, not truncate the log at the gap"
    );
    el.shutdown().unwrap();
}
