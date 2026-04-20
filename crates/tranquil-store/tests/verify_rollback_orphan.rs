mod common;

use std::sync::Arc;

use tranquil_store::OpenOptions;
use tranquil_store::RealIO;
use tranquil_store::StorageIO;
use tranquil_store::blockstore::BlockLength;
use tranquil_store::blockstore::{
    BlockLocation, BlockOffset, BlockStoreConfig, DataFileId, DataFileManager, DataFileWriter,
    GroupCommitConfig, HintFileWriter, HintOffset, TranquilBlockStore, hint_file_path,
};

use common::{test_cid, with_runtime};

fn fresh_store_dir() -> (tempfile::TempDir, BlockStoreConfig) {
    let dir = tempfile::TempDir::new().unwrap();
    let data_dir = dir.path().join("data");
    let index_dir = dir.path().join("index");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::create_dir_all(&index_dir).unwrap();
    let config = BlockStoreConfig {
        data_dir,
        index_dir,
        max_file_size: 8192,
        group_commit: GroupCommitConfig::default(),
        shard_count: 1,
    };
    (dir, config)
}

fn hint_file_size(path: &std::path::Path) -> u64 {
    let io = RealIO::new();
    let fd = io.open(path, OpenOptions::read_write()).unwrap();
    let size = io.file_size(fd).unwrap();
    let _ = io.close(fd);
    size
}

#[test]
fn rollback_rotation_does_not_leave_orphan_data_file() {
    with_runtime(|| {
        let (_dir, config) = fresh_store_dir();
        let data_dir = config.data_dir.clone();

        {
            let store = TranquilBlockStore::open(config.clone()).unwrap();
            store
                .put_blocks_blocking(vec![(test_cid(1), vec![0x11; 64])])
                .unwrap();
            drop(store);
        }

        let orphan_cid = test_cid(99_999);
        {
            let io: Arc<RealIO> = Arc::new(RealIO::new());
            let manager = DataFileManager::new(Arc::clone(&io), data_dir.clone(), 4096);
            let (next_id, next_fd) = manager.prepare_rotation(DataFileId::new(0)).unwrap();
            manager.commit_rotation(next_id, next_fd);

            let mut writer = DataFileWriter::new(&*io, next_fd, next_id).unwrap();
            let _ = writer.append_block(&orphan_cid, &vec![0xAB; 256]).unwrap();
            writer.sync().unwrap();
            io.sync_dir(&data_dir).unwrap();

            let _ = io.delete(&hint_file_path(&data_dir, next_id));
            manager.rollback_rotation(next_id, next_fd);
        }

        let store = TranquilBlockStore::open(config).unwrap();
        assert!(
            store.get_block_sync(&orphan_cid).unwrap().is_none(),
            "rollback_rotation must delete the uncommitted data file; otherwise recovery's \
             backup-restore branch resurrects rejected blocks"
        );
    });
}

#[test]
fn truncated_old_hint_drops_rejected_entry_on_reopen() {
    with_runtime(|| {
        let (_dir, config) = fresh_store_dir();
        let data_dir = config.data_dir.clone();
        let old_file_id = DataFileId::new(0);
        let old_hint_path = hint_file_path(&data_dir, old_file_id);

        let keep_cid = test_cid(1);
        {
            let store = TranquilBlockStore::open(config.clone()).unwrap();
            store
                .put_blocks_blocking(vec![(keep_cid, vec![0x11; 64])])
                .unwrap();
            drop(store);
        }

        let hint_len_before = hint_file_size(&old_hint_path);
        let rejected_cid = test_cid(42_424);
        {
            let io: Arc<RealIO> = Arc::new(RealIO::new());
            let fd = io.open(&old_hint_path, OpenOptions::read_write()).unwrap();
            let mut writer = HintFileWriter::resume(&*io, fd, HintOffset::new(hint_len_before));
            writer
                .append_hint(
                    &rejected_cid,
                    &BlockLocation {
                        file_id: old_file_id,
                        offset: BlockOffset::new(4096),
                        length: BlockLength::new(64),
                    },
                )
                .unwrap();
            writer.sync().unwrap();
            io.truncate(fd, hint_len_before).unwrap();
            io.sync(fd).unwrap();
            let _ = io.close(fd);
        }

        let store = TranquilBlockStore::open(config).unwrap();
        assert!(
            store.get_block_sync(&rejected_cid).unwrap().is_none(),
            "after rollback_batch truncates state.hint_fd, the rejected hint is gone and reopen is clean"
        );
        assert!(
            store.get_block_sync(&keep_cid).unwrap().is_some(),
            "legitimate pre-batch block remains readable after rollback"
        );
    });
}
