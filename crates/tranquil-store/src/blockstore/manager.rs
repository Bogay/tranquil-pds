use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

use parking_lot::RwLock;

use crate::io::{FileId, OpenOptions, StorageIO};

use super::list_files_by_extension;
use super::types::{BlockOffset, DataFileId};

pub const DEFAULT_MAX_FILE_SIZE: u64 = 256 * 1024 * 1024;

pub(crate) const DATA_FILE_EXTENSION: &str = "tqb";

struct CachedHandle {
    fd: FileId,
    writable: bool,
}

pub struct DataFileManager<S: StorageIO> {
    io: S,
    data_dir: PathBuf,
    max_file_size: u64,
    handles: RwLock<HashMap<DataFileId, CachedHandle>>,
}

impl<S: StorageIO> DataFileManager<S> {
    pub fn new(io: S, data_dir: PathBuf, max_file_size: u64) -> Self {
        Self {
            io,
            data_dir,
            max_file_size,
            handles: RwLock::new(HashMap::new()),
        }
    }

    pub fn with_default_max_size(io: S, data_dir: PathBuf) -> Self {
        Self::new(io, data_dir, DEFAULT_MAX_FILE_SIZE)
    }

    pub fn io(&self) -> &S {
        &self.io
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

    pub fn open_for_append(&self, file_id: DataFileId) -> io::Result<FileId> {
        {
            let cache = self.handles.read();
            if let Some(entry) = cache.get(&file_id)
                && entry.writable
            {
                return Ok(entry.fd);
            }
        }
        let path = self.data_file_path(file_id);
        let fd = self.io.open(&path, OpenOptions::read_write())?;
        let mut cache = self.handles.write();
        match cache.get(&file_id) {
            Some(entry) if entry.writable => {
                let _ = self.io.close(fd);
                Ok(entry.fd)
            }
            Some(entry) => {
                let old_fd = entry.fd;
                cache.insert(file_id, CachedHandle { fd, writable: true });
                let _ = self.io.close(old_fd);
                Ok(fd)
            }
            None => {
                cache.insert(file_id, CachedHandle { fd, writable: true });
                Ok(fd)
            }
        }
    }

    pub fn open_for_read(&self, file_id: DataFileId) -> io::Result<FileId> {
        if let Some(entry) = self.handles.read().get(&file_id) {
            return Ok(entry.fd);
        }
        let path = self.data_file_path(file_id);
        let fd = self.io.open(&path, OpenOptions::read_only_existing())?;
        let mut cache = self.handles.write();
        match cache.get(&file_id) {
            Some(entry) => {
                let _ = self.io.close(fd);
                Ok(entry.fd)
            }
            None => {
                cache.insert(
                    file_id,
                    CachedHandle {
                        fd,
                        writable: false,
                    },
                );
                Ok(fd)
            }
        }
    }

    pub fn prepare_rotation(&self, current: DataFileId) -> io::Result<(DataFileId, FileId)> {
        let next = current.next();
        let path = self.data_file_path(next);
        let fd = self.io.open(&path, OpenOptions::read_write())?;
        Ok((next, fd))
    }

    pub fn commit_rotation(&self, file_id: DataFileId, fd: FileId) {
        self.handles
            .write()
            .insert(file_id, CachedHandle { fd, writable: true });
    }

    pub fn rollback_rotation(&self, file_id: DataFileId, fd: FileId) {
        let _ = self.io.close(fd);
        self.handles.write().remove(&file_id);
    }

    pub fn should_rotate(&self, position: BlockOffset) -> bool {
        position.raw() >= self.max_file_size
    }

    pub fn list_files(&self) -> io::Result<Vec<DataFileId>> {
        list_files_by_extension(&self.io, &self.data_dir, DATA_FILE_EXTENSION)
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
        let fd = mgr.open_for_append(DataFileId::new(0)).unwrap();
        assert_eq!(mgr.io().file_size(fd).unwrap(), 0);
    }

    #[test]
    fn open_for_read_missing_file_errors() {
        let mgr = setup_manager(1024);
        assert!(mgr.open_for_read(DataFileId::new(99)).is_err());
    }

    #[test]
    fn handle_cache_returns_same_fd() {
        let mgr = setup_manager(1024);
        let fd1 = mgr.open_for_append(DataFileId::new(0)).unwrap();
        let fd2 = mgr.open_for_append(DataFileId::new(0)).unwrap();
        assert_eq!(fd1, fd2);
    }

    #[test]
    fn open_for_read_uses_cache_from_append() {
        let mgr = setup_manager(1024);
        let fd_write = mgr.open_for_append(DataFileId::new(0)).unwrap();
        let fd_read = mgr.open_for_read(DataFileId::new(0)).unwrap();
        assert_eq!(fd_write, fd_read);
    }

    #[test]
    fn rotation_lifecycle_prepare_commit() {
        let mgr = setup_manager(1024);
        let _fd0 = mgr.open_for_append(DataFileId::new(0)).unwrap();
        let (next_id, next_fd) = mgr.prepare_rotation(DataFileId::new(0)).unwrap();
        assert_eq!(next_id, DataFileId::new(1));
        assert_eq!(mgr.io().file_size(next_fd).unwrap(), 0);
        mgr.io().sync_dir(mgr.data_dir()).unwrap();
        mgr.commit_rotation(next_id, next_fd);
        assert_eq!(mgr.open_for_read(next_id).unwrap(), next_fd);
    }

    #[test]
    fn rotation_rollback_cleans_handle() {
        let mgr = setup_manager(1024);
        let _fd0 = mgr.open_for_append(DataFileId::new(0)).unwrap();
        let (next_id, next_fd) = mgr.prepare_rotation(DataFileId::new(0)).unwrap();
        mgr.commit_rotation(next_id, next_fd);

        assert_eq!(mgr.open_for_read(next_id).unwrap(), next_fd);
        mgr.rollback_rotation(next_id, next_fd);

        let reopened_fd = mgr.open_for_read(next_id).unwrap();
        assert_ne!(
            reopened_fd, next_fd,
            "rollback should have closed the cached fd"
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
        let _fd0 = mgr.open_for_append(DataFileId::new(0)).unwrap();
        let _fd3 = mgr.open_for_append(DataFileId::new(3)).unwrap();

        let files = mgr.list_files().unwrap();
        assert_eq!(files, vec![DataFileId::new(0), DataFileId::new(3)]);
    }

    #[test]
    fn list_files_ignores_non_data_files() {
        let mgr = setup_manager(1024);
        let _fd0 = mgr.open_for_append(DataFileId::new(0)).unwrap();
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
        let fd0 = mgr.open_for_append(DataFileId::new(0)).unwrap();
        let mut writer0 = DataFileWriter::new(mgr.io(), fd0, DataFileId::new(0)).unwrap();
        let _ = writer0
            .append_block(&test_cid(1), b"first file data")
            .unwrap();
        writer0.sync().unwrap();

        let (id1, fd1) = mgr.prepare_rotation(DataFileId::new(0)).unwrap();
        mgr.io().sync_dir(mgr.data_dir()).unwrap();
        mgr.commit_rotation(id1, fd1);
        let mut writer1 = DataFileWriter::new(mgr.io(), fd1, id1).unwrap();
        let _ = writer1
            .append_block(&test_cid(2), b"second file data")
            .unwrap();
        writer1.sync().unwrap();

        let fd0_read = mgr.open_for_read(DataFileId::new(0)).unwrap();
        let blocks0 = DataFileReader::open(mgr.io(), fd0_read)
            .unwrap()
            .valid_blocks()
            .unwrap();
        assert_eq!(blocks0.len(), 1);
        assert_eq!(blocks0[0].2, b"first file data");

        let fd1_read = mgr.open_for_read(id1).unwrap();
        let blocks1 = DataFileReader::open(mgr.io(), fd1_read)
            .unwrap()
            .valid_blocks()
            .unwrap();
        assert_eq!(blocks1.len(), 1);
        assert_eq!(blocks1[0].2, b"second file data");
    }

    #[test]
    fn read_cache_hit_from_writable_entry() {
        let mgr = setup_manager(1024);
        let fd_write = mgr.open_for_append(DataFileId::new(0)).unwrap();
        DataFileWriter::new(mgr.io(), fd_write, DataFileId::new(0)).unwrap();

        let fd_read = mgr.open_for_read(DataFileId::new(0)).unwrap();
        assert_eq!(fd_write, fd_read);
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

        let fd_read = mgr.open_for_read(DataFileId::new(0)).unwrap();
        let _reader = DataFileReader::open(mgr.io(), fd_read).unwrap();

        let fd_append = mgr.open_for_append(DataFileId::new(0)).unwrap();
        assert_ne!(fd_read, fd_append);

        let mut writer = DataFileWriter::resume(
            mgr.io(),
            fd_append,
            DataFileId::new(0),
            BlockOffset::new(BLOCK_HEADER_SIZE as u64),
        );
        let _ = writer
            .append_block(&test_cid(1), b"written after upgrade")
            .unwrap();
        writer.sync().unwrap();

        let blocks = DataFileReader::open(mgr.io(), fd_append)
            .unwrap()
            .valid_blocks()
            .unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].2, b"written after upgrade");
    }
}
