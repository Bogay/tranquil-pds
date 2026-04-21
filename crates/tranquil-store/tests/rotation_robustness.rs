mod common;

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

use tranquil_store::blockstore::{
    BlockStoreConfig, DataFileId, DataFileManager, DataFileWriter, GroupCommitConfig,
    TranquilBlockStore,
};
use tranquil_store::{FileId, MappedFile, OpenOptions, RealIO, SimulatedIO, StorageIO};

use common::{test_cid, with_runtime};

struct FailSpec {
    target_path: Mutex<Option<PathBuf>>,
    armed: AtomicBool,
    tripped: AtomicBool,
}

impl FailSpec {
    fn new() -> Self {
        Self {
            target_path: Mutex::new(None),
            armed: AtomicBool::new(false),
            tripped: AtomicBool::new(false),
        }
    }

    fn arm_fail_first_sync_on(&self, path: &Path) {
        *self.target_path.lock().unwrap() = Some(path.to_path_buf());
        self.tripped.store(false, Ordering::SeqCst);
        self.armed.store(true, Ordering::SeqCst);
    }

    fn fired(&self) -> bool {
        self.tripped.load(Ordering::SeqCst)
    }
}

struct FailingIO {
    inner: RealIO,
    spec: Arc<FailSpec>,
    fd_to_path: Mutex<HashMap<FileId, PathBuf>>,
}

impl FailingIO {
    fn new(spec: Arc<FailSpec>) -> Self {
        Self {
            inner: RealIO::new(),
            spec,
            fd_to_path: Mutex::new(HashMap::new()),
        }
    }
}

impl StorageIO for FailingIO {
    fn open(&self, path: &Path, opts: OpenOptions) -> io::Result<FileId> {
        let fd = self.inner.open(path, opts)?;
        self.fd_to_path.lock().unwrap().insert(fd, path.to_path_buf());
        Ok(fd)
    }

    fn close(&self, fd: FileId) -> io::Result<()> {
        self.fd_to_path.lock().unwrap().remove(&fd);
        self.inner.close(fd)
    }

    fn read_at(&self, fd: FileId, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read_at(fd, offset, buf)
    }

    fn write_at(&self, fd: FileId, offset: u64, buf: &[u8]) -> io::Result<usize> {
        self.inner.write_at(fd, offset, buf)
    }

    fn sync(&self, fd: FileId) -> io::Result<()> {
        let should_fail = self.spec.armed.load(Ordering::SeqCst)
            && !self.spec.tripped.load(Ordering::SeqCst)
            && match (
                self.fd_to_path.lock().unwrap().get(&fd).cloned(),
                self.spec.target_path.lock().unwrap().clone(),
            ) {
                (Some(fd_path), Some(target)) => fd_path == target,
                _ => false,
            };
        match should_fail {
            true => {
                self.spec.tripped.store(true, Ordering::SeqCst);
                Err(io::Error::other("injected sync failure on target path"))
            }
            false => self.inner.sync(fd),
        }
    }

    fn file_size(&self, fd: FileId) -> io::Result<u64> {
        self.inner.file_size(fd)
    }

    fn truncate(&self, fd: FileId, size: u64) -> io::Result<()> {
        self.inner.truncate(fd, size)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.inner.rename(from, to)
    }

    fn delete(&self, path: &Path) -> io::Result<()> {
        self.inner.delete(path)
    }

    fn mkdir(&self, path: &Path) -> io::Result<()> {
        self.inner.mkdir(path)
    }

    fn sync_dir(&self, path: &Path) -> io::Result<()> {
        self.inner.sync_dir(path)
    }

    fn list_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        self.inner.list_dir(path)
    }

    fn mmap_file(&self, fd: FileId) -> io::Result<MappedFile> {
        self.inner.mmap_file(fd)
    }
}

#[test]
fn post_rotation_sync_failure_deletes_new_rotation_files() {
    with_runtime(|| {
        let dir = tempfile::TempDir::new().unwrap();
        let data_dir = dir.path().join("data");
        let index_dir = dir.path().join("index");

        let spec = Arc::new(FailSpec::new());
        let spec_for_factory = Arc::clone(&spec);

        let config = BlockStoreConfig {
            data_dir: data_dir.clone(),
            index_dir,
            max_file_size: 256,
            group_commit: GroupCommitConfig::default(),
            shard_count: 1,
        };

        let store = TranquilBlockStore::<FailingIO>::open_with_io(config, move || {
            FailingIO::new(Arc::clone(&spec_for_factory))
        })
        .unwrap();

        store
            .put_blocks_blocking(vec![(test_cid(1), vec![0xAA; 300])])
            .expect("priming put succeeds");

        let rotated_data_path = data_dir.join("000002.tqb");
        let rotated_hint_path = data_dir.join("000002.tqh");

        spec.arm_fail_first_sync_on(&rotated_data_path);

        let result = store.put_blocks_blocking(vec![(test_cid(2), vec![0xBB; 300])]);
        assert!(
            result.is_err(),
            "put_blocks_blocking should surface the injected post-rotation sync failure"
        );
        assert!(
            spec.fired(),
            "injector never observed a sync on the rotated data file; timing changed"
        );

        assert!(
            !rotated_data_path.exists(),
            "rotation rollback must delete the new data file after a post-write sync failure; \
             leaked file at {rotated_data_path:?}"
        );
        assert!(
            !rotated_hint_path.exists(),
            "rotation rollback must delete the new hint file after a post-write sync failure; \
             leaked file at {rotated_hint_path:?}"
        );
    });
}

#[test]
fn concurrent_reader_survives_evict_handle() {
    let sim: Arc<SimulatedIO> = Arc::new(SimulatedIO::pristine(0x13579bdf));
    let data_dir = Path::new("/data");
    sim.mkdir(data_dir).unwrap();
    sim.sync_dir(data_dir).unwrap();

    let manager = Arc::new(DataFileManager::new(
        Arc::clone(&sim),
        data_dir.to_path_buf(),
        1 << 20,
    ));

    let file_id = DataFileId::new(0);
    let write_handle = manager.open_for_append(file_id).unwrap();
    {
        let mut writer = DataFileWriter::new(&*sim, write_handle.fd(), file_id).unwrap();
        let _ = writer.append_block(&test_cid(1), &vec![0x11; 128]).unwrap();
        writer.sync().unwrap();
    }
    drop(write_handle);

    let ready_to_evict = Arc::new(std::sync::Barrier::new(2));
    let evict_done = Arc::new(std::sync::Barrier::new(2));

    let reader_manager = Arc::clone(&manager);
    let reader_io = Arc::clone(&sim);
    let reader_ready = Arc::clone(&ready_to_evict);
    let reader_done = Arc::clone(&evict_done);

    let reader = std::thread::spawn(move || {
        let read_handle = reader_manager.open_for_read(file_id).unwrap();
        reader_ready.wait();
        reader_done.wait();
        reader_io.file_size(read_handle.fd())
    });

    ready_to_evict.wait();
    manager.evict_handle(file_id);
    evict_done.wait();

    let read_result = reader.join().unwrap();
    assert!(
        read_result.is_ok(),
        "read against a FileId obtained before evict_handle must still succeed; \
         evict_handle closed the underlying fd while the reader held it. error: {:?}",
        read_result.err()
    );
}
