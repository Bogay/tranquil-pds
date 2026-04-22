mod common;

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use rayon::prelude::*;
use tranquil_store::blockstore::hash_index::{BlockIndex, CheckpointPositions};
use tranquil_store::blockstore::{
    BLOCK_RECORD_OVERHEAD, BlockLocation, BlockOffset, BlockStoreConfig, BlockStoreReader,
    CidBytes, CommitEpoch, DEFAULT_MAX_FILE_SIZE, DataFileId, DataFileManager, DataFileWriter,
    GroupCommitConfig, HINT_RECORD_SIZE, HintFileWriter, HintOffset, TranquilBlockStore,
    WallClockMs, WriteCursor, hint_file_path,
};
use tranquil_store::{FaultConfig, OpenOptions, SimulatedIO, StorageIO, sim_seed_range};

use common::{Rng, advance_epoch, block_data, test_cid, with_runtime};

struct SimHarness {
    sim: Arc<SimulatedIO>,
    data_dir: &'static Path,
}

impl SimHarness {
    fn pristine(seed: u64) -> Self {
        let sim = Arc::new(SimulatedIO::pristine(seed));
        let data_dir = Path::new("/data");
        sim.mkdir(data_dir).unwrap();
        sim.sync_dir(data_dir).unwrap();
        Self { sim, data_dir }
    }

    fn ensure_data_file(&self, file_id: DataFileId) -> BlockOffset {
        let manager = DataFileManager::with_default_max_size(
            Arc::clone(&self.sim),
            self.data_dir.to_path_buf(),
        );
        let handle = manager.open_for_append(file_id).unwrap();
        let fd = handle.fd();
        let file_size = self.sim.file_size(fd).unwrap();
        match file_size {
            0 => {
                let w = DataFileWriter::new(&*self.sim, fd, file_id).unwrap();
                w.sync().unwrap();
                self.sim.sync_dir(self.data_dir).unwrap();
                w.position()
            }
            n => BlockOffset::new(n),
        }
    }

    fn write_blocks_with_hints(
        &self,
        file_id: DataFileId,
        start_pos: BlockOffset,
        seeds: std::ops::Range<u16>,
        data_size: usize,
        sync: bool,
    ) -> (BlockOffset, Vec<(CidBytes, BlockLocation)>) {
        let path = self.data_dir.join(format!("{file_id}.tqb"));
        let fd = self.sim.open(&path, OpenOptions::read_write()).unwrap();
        let mut writer = DataFileWriter::resume(&*self.sim, fd, file_id, start_pos);

        let hint_path = hint_file_path(self.data_dir, file_id);
        let hint_fd = self
            .sim
            .open(&hint_path, OpenOptions::read_write())
            .unwrap();
        let hint_size = self.sim.file_size(hint_fd).unwrap();
        let mut hint_writer =
            HintFileWriter::resume(&*self.sim, hint_fd, HintOffset::new(hint_size));

        let entries: Vec<_> = seeds
            .map(|seed| {
                let cid = test_cid(seed as u32);
                let data = vec![seed as u8; data_size];
                let loc = writer.append_block(&cid, &data).unwrap();
                hint_writer.append_hint(&cid, &loc).unwrap();
                (cid, loc)
            })
            .collect();

        if sync {
            writer.sync().unwrap();
            hint_writer.sync().unwrap();
            self.sim.sync_dir(self.data_dir).unwrap();
        }

        let pos = writer.position();
        let _ = self.sim.close(hint_fd);
        let _ = self.sim.close(fd);
        (pos, entries)
    }

    fn index_entries(
        index: &BlockIndex,
        entries: &[(CidBytes, BlockLocation)],
        cursor: WriteCursor,
    ) {
        index
            .batch_put(
                entries,
                &[],
                cursor,
                CommitEpoch::zero(),
                WallClockMs::new(0),
            )
            .unwrap();
        let positions = CheckpointPositions::single(
            cursor.file_id,
            HintOffset::new(entries.len() as u64 * HINT_RECORD_SIZE as u64),
        );
        index
            .write_checkpoint_with_positions(CommitEpoch::zero(), &positions)
            .unwrap();
    }

    fn make_reader(&self, index: Arc<BlockIndex>) -> BlockStoreReader<Arc<SimulatedIO>> {
        let manager = Arc::new(DataFileManager::with_default_max_size(
            Arc::clone(&self.sim),
            self.data_dir.to_path_buf(),
        ));
        BlockStoreReader::new(index, manager)
    }
}

#[test]
fn sim_crash_during_data_file_write_before_fsync() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let h = SimHarness::pristine(seed);
        let file_id = DataFileId::new(0);
        let start_pos = h.ensure_data_file(file_id);

        let mut rng = Rng::new(seed);
        let block_count = (rng.range_u32(20) + 5) as u16;

        let _ = h.write_blocks_with_hints(file_id, start_pos, 0..block_count, 64, false);
        h.sim.crash();

        let index_dir = tempfile::TempDir::new().unwrap();
        let rebuilt = BlockIndex::open(index_dir.path()).unwrap();
        rebuilt
            .rebuild_from_data_files(&*h.sim, h.data_dir)
            .unwrap();

        (0..block_count).for_each(|i| {
            let cid = test_cid(i as u32);
            assert!(
                rebuilt.get(&cid).is_none(),
                "seed={seed} unsynced block {i} must not appear in index after crash before fsync"
            );
        });
    });
}

#[test]
fn sim_crash_after_fsync_before_index_update() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let h = SimHarness::pristine(seed);
        let file_id = DataFileId::new(0);
        let start_pos = h.ensure_data_file(file_id);

        let mut rng = Rng::new(seed);
        let block_count = (rng.range_u32(20) + 5) as u16;

        let (_end_pos, entries) =
            h.write_blocks_with_hints(file_id, start_pos, 0..block_count, 64, true);

        h.sim.crash();

        let index_dir = tempfile::TempDir::new().unwrap();
        let rebuilt = BlockIndex::open(index_dir.path()).unwrap();
        rebuilt.rebuild_from_hints(&*h.sim, h.data_dir).unwrap();

        let idx = Arc::new(rebuilt);
        let reader = h.make_reader(Arc::clone(&idx));

        entries.iter().for_each(|(cid, _)| {
            assert!(
                idx.get(cid).is_some(),
                "seed={seed} synced block must be recoverable from hints after crash before index update"
            );
            let data = reader.get(cid).unwrap();
            assert!(data.is_some(), "seed={seed} synced block must be readable");
        });
    });
}

#[test]
fn sim_crash_after_index_update() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let h = SimHarness::pristine(seed);
        let file_id = DataFileId::new(0);
        let start_pos = h.ensure_data_file(file_id);

        let mut rng = Rng::new(seed);
        let block_count = (rng.range_u32(20) + 5) as u16;

        let (end_pos, entries) =
            h.write_blocks_with_hints(file_id, start_pos, 0..block_count, 64, true);

        let index_dir = tempfile::TempDir::new().unwrap();
        let index = BlockIndex::open(index_dir.path()).unwrap();
        SimHarness::index_entries(
            &index,
            &entries,
            WriteCursor {
                file_id,
                offset: end_pos,
            },
        );
        drop(index);

        h.sim.crash();

        let reopened = BlockIndex::open(index_dir.path()).unwrap();
        let idx = Arc::new(reopened);
        let reader = h.make_reader(Arc::clone(&idx));

        entries.iter().for_each(|(cid, _)| {
            assert!(
                idx.get(cid).is_some(),
                "seed={seed} fully committed block must survive crash after index update"
            );
            let data = reader.get(cid).unwrap();
            assert!(data.is_some(), "seed={seed} block must be readable");
        });
    });
}

#[test]
fn sim_partial_index_crash_recovers_via_cursor() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let h = SimHarness::pristine(seed);
        let file_id = DataFileId::new(0);
        let start_pos = h.ensure_data_file(file_id);

        let mut rng = Rng::new(seed);
        let block_count = (rng.range_u32(20) + 5) as u16;
        let indexed_count = (rng.range_u32(block_count as u32 - 1) + 1) as u16;

        let (_end_pos, entries) =
            h.write_blocks_with_hints(file_id, start_pos, 0..block_count, 64, true);

        let indexed = &entries[..indexed_count as usize];
        let cursor_end = indexed
            .last()
            .map(|(_, loc)| loc.offset.advance(BLOCK_RECORD_OVERHEAD as u64 + loc.length.as_u64()))
            .unwrap_or(start_pos);

        let index_dir = tempfile::TempDir::new().unwrap();
        let index = BlockIndex::open(index_dir.path()).unwrap();
        SimHarness::index_entries(
            &index,
            indexed,
            WriteCursor {
                file_id,
                offset: cursor_end,
            },
        );
        drop(index);

        h.sim.crash();

        let rebuilt_dir = tempfile::TempDir::new().unwrap();
        let rebuilt = BlockIndex::open(rebuilt_dir.path()).unwrap();
        rebuilt.rebuild_from_hints(&*h.sim, h.data_dir).unwrap();

        let idx = Arc::new(rebuilt);
        let reader = h.make_reader(Arc::clone(&idx));

        (0..block_count).for_each(|i| {
            let cid = test_cid(i as u32);
            assert!(
                idx.get(&cid).is_some(),
                "seed={seed} synced block {i} must be recovered (indexed={indexed_count}, total={block_count})"
            );
            let data = reader.get(&cid).unwrap();
            assert!(data.is_some(), "seed={seed} block {i} must be readable");
            assert_eq!(
                data.unwrap()[0],
                i as u8,
                "seed={seed} block {i} content mismatch"
            );
        });
    });
}

#[test]
fn sim_no_acknowledged_block_lost() {
    with_runtime(|| {
        sim_seed_range().into_par_iter().for_each(|seed| {
            let dir = tempfile::TempDir::new().unwrap();
            let config = BlockStoreConfig {
                data_dir: dir.path().join("data"),
                index_dir: dir.path().join("index"),
                max_file_size: DEFAULT_MAX_FILE_SIZE,
                group_commit: GroupCommitConfig::default(),
                shard_count: 1,
            };

            let block_count = ((seed % 30) + 5) as u32;
            let blocks: Vec<(CidBytes, Vec<u8>)> = (0..block_count)
                .map(|i| (test_cid(i), block_data(i)))
                .collect();

            let acked_cids: Vec<CidBytes> = blocks.iter().map(|(cid, _)| *cid).collect();

            {
                let store = TranquilBlockStore::open(config.clone()).unwrap();
                store.put_blocks_blocking(blocks).unwrap();
            }

            let store = TranquilBlockStore::open(config).unwrap();

            acked_cids.iter().enumerate().for_each(|(idx, cid)| {
                let data = store.get_block_sync(cid).unwrap();
                assert!(
                    data.is_some(),
                    "seed={seed} acknowledged block {idx} must be durable after reopen"
                );
                let expected = block_data(idx as u32);
                assert_eq!(
                    &data.unwrap()[..],
                    &expected[..],
                    "seed={seed} block {idx} content mismatch"
                );
            });
        });
    });
}

#[test]
fn sim_hint_rebuild_matches_normal_index() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let h = SimHarness::pristine(seed);
        let file_id = DataFileId::new(0);
        let start_pos = h.ensure_data_file(file_id);

        let mut rng = Rng::new(seed);
        let block_count = (rng.range_u32(40) + 10) as u16;

        let (end_pos, entries) =
            h.write_blocks_with_hints(file_id, start_pos, 0..block_count, 64, true);

        let normal_dir = tempfile::TempDir::new().unwrap();
        let normal_index = BlockIndex::open(normal_dir.path()).unwrap();
        SimHarness::index_entries(
            &normal_index,
            &entries,
            WriteCursor {
                file_id,
                offset: end_pos,
            },
        );

        let normal_snapshot: HashMap<CidBytes, BlockLocation> = entries
            .iter()
            .filter_map(|(cid, _)| normal_index.get(cid).map(|entry| (*cid, entry.location)))
            .collect();
        drop(normal_index);

        let hint_dir = tempfile::TempDir::new().unwrap();
        let hint_rebuilt = BlockIndex::open(hint_dir.path()).unwrap();
        hint_rebuilt
            .rebuild_from_hints(&*h.sim, h.data_dir)
            .unwrap();

        entries.iter().for_each(|(cid, _)| {
            let rebuilt_entry = hint_rebuilt.get(cid);
            assert!(
                rebuilt_entry.is_some(),
                "seed={seed} hint-rebuilt index must contain all blocks"
            );
            let rebuilt_loc = rebuilt_entry.unwrap().location;
            let normal_loc = normal_snapshot.get(cid).unwrap();
            assert_eq!(
                rebuilt_loc.file_id, normal_loc.file_id,
                "seed={seed} file_id mismatch"
            );
            assert_eq!(
                rebuilt_loc.offset, normal_loc.offset,
                "seed={seed} offset mismatch"
            );
            assert_eq!(
                rebuilt_loc.length, normal_loc.length,
                "seed={seed} length mismatch"
            );
        });

        let data_dir2 = tempfile::TempDir::new().unwrap();
        let data_rebuilt = BlockIndex::open(data_dir2.path()).unwrap();
        data_rebuilt
            .rebuild_from_data_files(&*h.sim, h.data_dir)
            .unwrap();

        entries.iter().for_each(|(cid, _)| {
            let data_entry = data_rebuilt.get(cid);
            assert!(
                data_entry.is_some(),
                "seed={seed} data-file-rebuilt index must contain all blocks"
            );
            let data_loc = data_entry.unwrap().location;
            let normal_loc = normal_snapshot.get(cid).unwrap();
            assert_eq!(
                data_loc.file_id, normal_loc.file_id,
                "seed={seed} data-rebuild file_id mismatch"
            );
            assert_eq!(
                data_loc.offset, normal_loc.offset,
                "seed={seed} data-rebuild offset mismatch"
            );
            assert_eq!(
                data_loc.length, normal_loc.length,
                "seed={seed} data-rebuild length mismatch"
            );
        });
    });
}

#[test]
fn sim_concurrent_reads_during_compaction() {
    with_runtime(|| {
        sim_seed_range().into_par_iter().for_each(|seed| {
            let dir = tempfile::TempDir::new().unwrap();
            let small_file_size = 512u64;
            let config = BlockStoreConfig {
                data_dir: dir.path().join("data"),
                index_dir: dir.path().join("index"),
                max_file_size: small_file_size,
                group_commit: GroupCommitConfig::default(),
                shard_count: 1,
            };

            let store = TranquilBlockStore::open(config).unwrap();

            let initial_count = ((seed % 10) + 5) as u32;
            let blocks: Vec<(CidBytes, Vec<u8>)> = (0..initial_count)
                .map(|i| (test_cid(i), block_data(i)))
                .collect();
            store.put_blocks_blocking(blocks).unwrap();

            let delete_count =
                ((seed % initial_count as u64) + 1).min(initial_count as u64 - 1) as u32;
            let deleted_cids: Vec<CidBytes> = (0..delete_count).map(test_cid).collect();
            store
                .apply_commit_blocking(vec![], deleted_cids.clone())
                .unwrap();
            advance_epoch(&store);

            let live_cids: Vec<CidBytes> = (delete_count..initial_count).map(test_cid).collect();

            let data_files = store.list_data_files().unwrap();
            let sealed_files: Vec<DataFileId> = data_files
                .iter()
                .copied()
                .take(data_files.len().saturating_sub(1))
                .collect();

            let read_store = store.clone();
            let read_cids = live_cids.clone();
            let reader_handle = std::thread::spawn(move || {
                (0..50).for_each(|_| {
                    read_cids.iter().for_each(|cid| {
                        let _ = read_store.get_block_sync(cid);
                    });
                });
            });

            sealed_files.iter().for_each(|&fid| {
                let _ = store.compact_file(fid, 0);
            });

            reader_handle.join().unwrap();

            live_cids.iter().for_each(|cid| {
                let data = store.get_block_sync(cid).unwrap();
                assert!(
                    data.is_some(),
                    "seed={seed} live block must survive compaction"
                );
                let expected_seed = u32::from_le_bytes([cid[4], cid[5], cid[6], cid[7]]);
                assert_eq!(
                    &data.unwrap()[..4],
                    &expected_seed.to_le_bytes(),
                    "seed={seed} block content mismatch after compaction"
                );
            });
        });
    });
}

#[test]
fn sim_aggressive_faults_data_integrity() {
    sim_seed_range().into_par_iter().for_each(|seed| {
        let fault_config = FaultConfig::aggressive();

        let sim = Arc::new(SimulatedIO::new(seed, fault_config));
        let data_dir = Path::new("/data");
        let Ok(()) = sim.mkdir(data_dir).and_then(|()| sim.sync_dir(data_dir)) else {
            return;
        };

        let file_id = DataFileId::new(0);
        let manager =
            DataFileManager::with_default_max_size(Arc::clone(&sim), data_dir.to_path_buf());

        let Ok(handle) = manager.open_for_append(file_id) else {
            return;
        };
        let fd = handle.fd();

        let writer_result = DataFileWriter::new(&*sim, fd, file_id);
        let Ok(writer) = writer_result else { return };
        let Ok(()) = writer.sync() else { return };
        let Ok(()) = sim.sync_dir(data_dir) else {
            return;
        };
        let start_pos = writer.position();
        let _ = writer;
        let _ = handle;

        let mut rng = Rng::new(seed);
        let block_count = (rng.range_u32(15) + 5) as u16;
        let sync_at = (rng.range_u32(block_count as u32) + 1) as u16;

        let _ = (|| -> Option<()> {
            let path = data_dir.join(format!("{file_id}.tqb"));
            let fd = sim.open(&path, OpenOptions::read_write()).ok()?;
            let mut writer = DataFileWriter::resume(&*sim, fd, file_id, start_pos);

            let hint_path = hint_file_path(data_dir, file_id);
            let hint_fd = sim.open(&hint_path, OpenOptions::read_write()).ok()?;
            let hint_size = sim.file_size(hint_fd).ok()?;
            let mut hint_writer =
                HintFileWriter::resume(&*sim, hint_fd, HintOffset::new(hint_size));

            (0..sync_at).try_for_each(|i| {
                let cid = test_cid(i as u32);
                let data = vec![i as u8; 64];
                let loc = writer.append_block(&cid, &data).ok()?;
                hint_writer.append_hint(&cid, &loc).ok()?;
                Some(())
            })?;

            writer.sync().ok()?;
            hint_writer.sync().ok()?;
            sim.sync_dir(data_dir).ok()?;

            let _ = (sync_at..block_count).try_for_each(|i| {
                let cid = test_cid(i as u32);
                let data = vec![i as u8; 64];
                let _ = writer.append_block(&cid, &data).ok()?;
                Some(())
            });

            let _ = sim.close(hint_fd);
            let _ = sim.close(fd);
            Some(())
        })();

        sim.crash();

        let index_dir = tempfile::TempDir::new().unwrap();
        let Ok(rebuilt) = BlockIndex::open(index_dir.path()) else {
            return;
        };

        let all_data_files =
            tranquil_store::blockstore::list_files_by_extension(&*sim, data_dir, "tqb");
        if let Ok(files) = all_data_files {
            files.iter().for_each(|&fid| {
                let path = data_dir.join(format!("{fid}.tqb"));
                let Ok(fd) = sim.open(&path, OpenOptions::read_only_existing()) else {
                    return;
                };
                let file_size = sim.file_size(fd).unwrap_or(0);
                let mut offset =
                    BlockOffset::new(tranquil_store::blockstore::BLOCK_HEADER_SIZE as u64);
                let mut entries = Vec::new();
                while let Ok(Some(tranquil_store::blockstore::ReadBlockRecord::Valid {
                    offset: blk_off,
                    cid_bytes,
                    data,
                })) =
                    tranquil_store::blockstore::decode_block_record(&*sim, fd, offset, file_size)
                {
                    let length = tranquil_store::blockstore::BlockLength::new(
                        u32::try_from(data.len()).unwrap(),
                    );
                    let loc = BlockLocation {
                        file_id: fid,
                        offset: blk_off,
                        length,
                    };
                    entries.push((cid_bytes, loc));
                    offset = blk_off.advance(BLOCK_RECORD_OVERHEAD as u64 + length.as_u64());
                }
                if !entries.is_empty() {
                    let cursor = WriteCursor {
                        file_id: fid,
                        offset: entries
                            .last()
                            .map(|(_, loc)| {
                                loc.offset
                                    .advance(BLOCK_RECORD_OVERHEAD as u64 + loc.length.as_u64())
                            })
                            .unwrap_or(offset),
                    };
                    rebuilt
                        .batch_put(
                            &entries,
                            &[],
                            cursor,
                            CommitEpoch::zero(),
                            WallClockMs::new(0),
                        )
                        .ok();
                }
                let _ = sim.close(fd);
            });
        }

        let idx = Arc::new(rebuilt);
        let reader_manager = Arc::new(DataFileManager::with_default_max_size(
            Arc::clone(&sim),
            data_dir.to_path_buf(),
        ));
        let reader = BlockStoreReader::new(Arc::clone(&idx), reader_manager);

        (sync_at..block_count).for_each(|i| {
            let cid = test_cid(i as u32);
            if idx.get(&cid).is_some()
                && let Ok(Some(data)) = reader.get(&cid)
            {
                assert_eq!(
                    data[0], i as u8,
                    "seed={seed} unsynced-but-recovered block {i} data mismatch"
                );
            }
        });
    });
}

#[test]
fn sim_multi_file_rotation_crash_recovery() {
    with_runtime(|| {
        sim_seed_range().into_par_iter().for_each(|seed| {
            let dir = tempfile::TempDir::new().unwrap();
            let small_file_size = 512u64;
            let config = BlockStoreConfig {
                data_dir: dir.path().join("data"),
                index_dir: dir.path().join("index"),
                max_file_size: small_file_size,
                group_commit: GroupCommitConfig::default(),
                shard_count: 1,
            };

            let block_count = ((seed % 25) + 10) as u32;
            let all_cids: Vec<CidBytes> = (0..block_count).map(test_cid).collect();

            {
                let store = TranquilBlockStore::open(config.clone()).unwrap();
                (0..block_count)
                    .try_for_each(|i| store.put_blocks_blocking(vec![(test_cid(i), block_data(i))]))
                    .unwrap();

                let files = store.list_data_files().unwrap();
                assert!(
                    files.len() > 1,
                    "seed={seed} expected multiple data files from rotation, got {}",
                    files.len()
                );
            }

            let store = TranquilBlockStore::open(config).unwrap();

            all_cids.iter().enumerate().for_each(|(idx, cid)| {
                let data = store.get_block_sync(cid).unwrap();
                assert!(
                    data.is_some(),
                    "seed={seed} block {idx} must survive reopen across rotated files"
                );
                let expected = block_data(idx as u32);
                assert_eq!(
                    &data.unwrap()[..],
                    &expected[..],
                    "seed={seed} block {idx} content mismatch after rotation recovery"
                );
            });
        });
    });
}
