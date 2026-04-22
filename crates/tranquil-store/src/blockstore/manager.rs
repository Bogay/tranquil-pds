use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::RwLock;

use crate::io::{FileId, OpenOptions, StorageIO};

use super::list_files_by_extension;
use super::types::{BlockOffset, DataFileId};

pub const DEFAULT_MAX_FILE_SIZE: u64 = 256 * 1024 * 1024;

pub(crate) const DATA_FILE_EXTENSION: &str = "tqb";

pub struct CachedHandle<S: StorageIO> {
    fd: FileId,
    io: Arc<S>,
    writable: bool,
}

impl<S: StorageIO> CachedHandle<S> {
    pub fn fd(&self) -> FileId {
        self.fd
    }

    pub fn is_writable(&self) -> bool {
        self.writable
    }
}

impl<S: StorageIO> Drop for CachedHandle<S> {
    fn drop(&mut self) {
        let _ = self.io.close(self.fd);
    }
}

pub struct DataFileManager<S: StorageIO> {
    io: Arc<S>,
    data_dir: PathBuf,
    max_file_size: u64,
    handles: RwLock<HashMap<DataFileId, Arc<CachedHandle<S>>>>,
}

impl<S: StorageIO> DataFileManager<S> {
    pub fn new(io: S, data_dir: PathBuf, max_file_size: u64) -> Self {
        Self {
            io: Arc::new(io),
            data_dir,
            max_file_size,
            handles: RwLock::new(HashMap::new()),
        }
    }

    pub fn with_default_max_size(io: S, data_dir: PathBuf) -> Self {
        Self::new(io, data_dir, DEFAULT_MAX_FILE_SIZE)
    }

    pub fn io(&self) -> &S {
        self.io.as_ref()
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn max_file_size(&self) -> u64 {
        self.max_file_size
    }

    pub fn data_file_path(&self, file_id: DataFileId) -> PathBuf {
        self.data_dir
            .join(format!("{file_id}.{DATA_FILE_EXTENSION}"))
    }

    pub fn open_for_append(&self, file_id: DataFileId) -> io::Result<Arc<CachedHandle<S>>> {
        {
            let cache = self.handles.read();
            if let Some(entry) = cache.get(&file_id)
                && entry.writable
            {
                return Ok(Arc::clone(entry));
            }
        }
        let path = self.data_file_path(file_id);
        let fd = self.io.open(&path, OpenOptions::read_write())?;
        let mut cache = self.handles.write();
        match cache.get(&file_id).cloned() {
            Some(entry) if entry.writable => {
                let _ = self.io.close(fd);
                Ok(entry)
            }
            _ => {
                let handle = Arc::new(CachedHandle {
                    fd,
                    io: Arc::clone(&self.io),
                    writable: true,
                });
                cache.insert(file_id, Arc::clone(&handle));
                Ok(handle)
            }
        }
    }

    pub fn open_for_read(&self, file_id: DataFileId) -> io::Result<Arc<CachedHandle<S>>> {
        if let Some(entry) = self.handles.read().get(&file_id) {
            return Ok(Arc::clone(entry));
        }
        let path = self.data_file_path(file_id);
        let fd = self.io.open(&path, OpenOptions::read_only_existing())?;
        let mut cache = self.handles.write();
        match cache.get(&file_id).cloned() {
            Some(entry) => {
                let _ = self.io.close(fd);
                Ok(entry)
            }
            None => {
                let handle = Arc::new(CachedHandle {
                    fd,
                    io: Arc::clone(&self.io),
                    writable: false,
                });
                cache.insert(file_id, Arc::clone(&handle));
                Ok(handle)
            }
        }
    }

    pub fn prepare_rotation(
        &self,
        current: DataFileId,
    ) -> io::Result<(DataFileId, Arc<CachedHandle<S>>)> {
        let next = current.next();
        let path = self.data_file_path(next);
        let fd = self.io.open(&path, OpenOptions::read_write())?;
        let handle = Arc::new(CachedHandle {
            fd,
            io: Arc::clone(&self.io),
            writable: true,
        });
        Ok((next, handle))
    }

    pub fn commit_rotation(&self, file_id: DataFileId, handle: &Arc<CachedHandle<S>>) {
        self.handles.write().insert(file_id, Arc::clone(handle));
    }

    pub fn rollback_rotation(&self, file_id: DataFileId) {
        self.handles.write().remove(&file_id);
        let _ = self.io.delete(&self.data_file_path(file_id));
    }

    pub fn should_rotate(&self, position: BlockOffset) -> bool {
        position.raw() >= self.max_file_size
    }

    pub fn list_files(&self) -> io::Result<Vec<DataFileId>> {
        list_files_by_extension(&*self.io, &self.data_dir, DATA_FILE_EXTENSION)
    }

    pub fn evict_handle(&self, file_id: DataFileId) {
        self.handles.write().remove(&file_id);
    }

    pub fn delete_data_file(&self, file_id: DataFileId) -> io::Result<()> {
        self.evict_handle(file_id);
        let path = self.data_file_path(file_id);
        self.io.delete(&path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blockstore::data_file::{BLOCK_HEADER_SIZE, DataFileReader, DataFileWriter};
    use crate::blockstore::test_cid;
    use crate::sim::SimulatedIO;

    fn setup_manager(max_file_size: u64) -> DataFileManager<SimulatedIO> {
        let sim = SimulatedIO::pristine(42);
        let dir = Path::new("/data");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();
        DataFileManager::new(sim, dir.to_path_buf(), max_file_size)
    }

    #[test]
    fn open_for_append_creates_file() {
        let mgr = setup_manager(1024);
        let handle = mgr.open_for_append(DataFileId::new(0)).unwrap();
        assert_eq!(mgr.io().file_size(handle.fd()).unwrap(), 0);
    }

    #[test]
    fn open_for_read_missing_file_errors() {
        let mgr = setup_manager(1024);
        assert!(mgr.open_for_read(DataFileId::new(99)).is_err());
    }

    #[test]
    fn handle_cache_returns_same_fd() {
        let mgr = setup_manager(1024);
        let h1 = mgr.open_for_append(DataFileId::new(0)).unwrap();
        let h2 = mgr.open_for_append(DataFileId::new(0)).unwrap();
        assert_eq!(h1.fd(), h2.fd());
    }

    #[test]
    fn open_for_read_uses_cache_from_append() {
        let mgr = setup_manager(1024);
        let h_write = mgr.open_for_append(DataFileId::new(0)).unwrap();
        let h_read = mgr.open_for_read(DataFileId::new(0)).unwrap();
        assert_eq!(h_write.fd(), h_read.fd());
    }

    #[test]
    fn rotation_lifecycle_prepare_commit() {
        let mgr = setup_manager(1024);
        let _h0 = mgr.open_for_append(DataFileId::new(0)).unwrap();
        let (next_id, next_handle) = mgr.prepare_rotation(DataFileId::new(0)).unwrap();
        assert_eq!(next_id, DataFileId::new(1));
        assert_eq!(mgr.io().file_size(next_handle.fd()).unwrap(), 0);
        mgr.io().sync_dir(mgr.data_dir()).unwrap();
        mgr.commit_rotation(next_id, &next_handle);
        assert_eq!(mgr.open_for_read(next_id).unwrap().fd(), next_handle.fd());
    }

    #[test]
    fn rotation_rollback_cleans_handle_and_deletes_file() {
        let mgr = setup_manager(1024);
        let _h0 = mgr.open_for_append(DataFileId::new(0)).unwrap();
        let (next_id, next_handle) = mgr.prepare_rotation(DataFileId::new(0)).unwrap();
        mgr.commit_rotation(next_id, &next_handle);

        assert_eq!(mgr.open_for_read(next_id).unwrap().fd(), next_handle.fd());
        drop(next_handle);
        mgr.rollback_rotation(next_id);

        let reopen = mgr.open_for_read(next_id);
        assert!(
            reopen.is_err_and(|e| e.kind() == io::ErrorKind::NotFound),
            "rollback_rotation must delete the data file so recovery cannot resurrect uncommitted bytes"
        );
    }

    #[test]
    fn should_rotate_respects_threshold() {
        let mgr = setup_manager(1024);
        assert!(!mgr.should_rotate(BlockOffset::new(100)));
        assert!(!mgr.should_rotate(BlockOffset::new(1023)));
        assert!(mgr.should_rotate(BlockOffset::new(1024)));
        assert!(mgr.should_rotate(BlockOffset::new(2000)));
    }

    #[test]
    fn list_files_finds_data_files() {
        let mgr = setup_manager(1024);
        let _h0 = mgr.open_for_append(DataFileId::new(0)).unwrap();
        let _h3 = mgr.open_for_append(DataFileId::new(3)).unwrap();

        let files = mgr.list_files().unwrap();
        assert_eq!(files, vec![DataFileId::new(0), DataFileId::new(3)]);
    }

    #[test]
    fn list_files_ignores_non_data_files() {
        let mgr = setup_manager(1024);
        let _h0 = mgr.open_for_append(DataFileId::new(0)).unwrap();
        mgr.io()
            .open(Path::new("/data/notes.txt"), OpenOptions::read_write())
            .unwrap();

        let files = mgr.list_files().unwrap();
        assert_eq!(files, vec![DataFileId::new(0)]);
    }

    #[test]
    fn data_file_path_format() {
        let mgr = setup_manager(1024);
        assert_eq!(
            mgr.data_file_path(DataFileId::new(0)),
            Path::new("/data/000000.tqb")
        );
        assert_eq!(
            mgr.data_file_path(DataFileId::new(42)),
            Path::new("/data/000042.tqb")
        );
    }

    #[test]
    fn rotate_and_write_across_files() {
        let mgr = setup_manager(1024);
        let h0 = mgr.open_for_append(DataFileId::new(0)).unwrap();
        let mut writer0 = DataFileWriter::new(mgr.io(), h0.fd(), DataFileId::new(0)).unwrap();
        let _ = writer0
            .append_block(&test_cid(1), b"first file data")
            .unwrap();
        writer0.sync().unwrap();

        let (id1, h1) = mgr.prepare_rotation(DataFileId::new(0)).unwrap();
        mgr.io().sync_dir(mgr.data_dir()).unwrap();
        mgr.commit_rotation(id1, &h1);
        let mut writer1 = DataFileWriter::new(mgr.io(), h1.fd(), id1).unwrap();
        let _ = writer1
            .append_block(&test_cid(2), b"second file data")
            .unwrap();
        writer1.sync().unwrap();

        let h0_read = mgr.open_for_read(DataFileId::new(0)).unwrap();
        let blocks0 = DataFileReader::open(mgr.io(), h0_read.fd())
            .unwrap()
            .valid_blocks()
            .unwrap();
        assert_eq!(blocks0.len(), 1);
        assert_eq!(blocks0[0].2, b"first file data");

        let h1_read = mgr.open_for_read(id1).unwrap();
        let blocks1 = DataFileReader::open(mgr.io(), h1_read.fd())
            .unwrap()
            .valid_blocks()
            .unwrap();
        assert_eq!(blocks1.len(), 1);
        assert_eq!(blocks1[0].2, b"second file data");
    }

    #[test]
    fn read_cache_hit_from_writable_entry() {
        let mgr = setup_manager(1024);
        let h_write = mgr.open_for_append(DataFileId::new(0)).unwrap();
        DataFileWriter::new(mgr.io(), h_write.fd(), DataFileId::new(0)).unwrap();

        let h_read = mgr.open_for_read(DataFileId::new(0)).unwrap();
        assert_eq!(h_write.fd(), h_read.fd());
    }

    #[test]
    fn read_only_cache_upgraded_on_append() {
        let mgr = setup_manager(1024);

        let raw_fd = mgr
            .io()
            .open(
                &mgr.data_file_path(DataFileId::new(0)),
                OpenOptions::read_write(),
            )
            .unwrap();
        DataFileWriter::new(mgr.io(), raw_fd, DataFileId::new(0)).unwrap();
        mgr.io().sync(raw_fd).unwrap();
        mgr.io().sync_dir(mgr.data_dir()).unwrap();
        mgr.io().close(raw_fd).unwrap();

        let h_read = mgr.open_for_read(DataFileId::new(0)).unwrap();
        let _reader = DataFileReader::open(mgr.io(), h_read.fd()).unwrap();

        let h_append = mgr.open_for_append(DataFileId::new(0)).unwrap();
        assert_ne!(h_read.fd(), h_append.fd());

        let mut writer = DataFileWriter::resume(
            mgr.io(),
            h_append.fd(),
            DataFileId::new(0),
            BlockOffset::new(BLOCK_HEADER_SIZE as u64),
        );
        let _ = writer
            .append_block(&test_cid(1), b"written after upgrade")
            .unwrap();
        writer.sync().unwrap();

        let blocks = DataFileReader::open(mgr.io(), h_append.fd())
            .unwrap()
            .valid_blocks()
            .unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].2, b"written after upgrade");
    }
}
