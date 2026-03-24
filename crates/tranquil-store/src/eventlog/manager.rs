use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::RwLock;

use crate::io::{FileId, OpenOptions, StorageIO};

use super::segment_file::SEGMENT_HEADER_SIZE;
use super::segment_index::SegmentIndex;
use super::types::{SegmentId, SegmentOffset};

pub(crate) const SEGMENT_FILE_EXTENSION: &str = "tqe";
pub(crate) const INDEX_FILE_EXTENSION: &str = "tqi";

struct CachedSegmentHandle {
    fd: FileId,
    sealed: bool,
    writable: bool,
}

pub struct SegmentManager<S: StorageIO> {
    io: S,
    segments_dir: PathBuf,
    max_segment_size: u64,
    handles: RwLock<HashMap<SegmentId, CachedSegmentHandle>>,
    retention_epoch: AtomicU64,
}

impl<S: StorageIO> SegmentManager<S> {
    pub fn new(io: S, segments_dir: PathBuf, max_segment_size: u64) -> io::Result<Self> {
        assert!(
            max_segment_size > SEGMENT_HEADER_SIZE as u64,
            "max_segment_size ({max_segment_size}) must exceed SEGMENT_HEADER_SIZE ({SEGMENT_HEADER_SIZE})"
        );
        io.mkdir(&segments_dir)?;
        Ok(Self {
            io,
            segments_dir,
            max_segment_size,
            handles: RwLock::new(HashMap::new()),
            retention_epoch: AtomicU64::new(0),
        })
    }

    pub fn io(&self) -> &S {
        &self.io
    }

    pub fn segments_dir(&self) -> &Path {
        &self.segments_dir
    }

    pub fn max_segment_size(&self) -> u64 {
        self.max_segment_size
    }

    pub fn segment_path(&self, id: SegmentId) -> PathBuf {
        self.segments_dir
            .join(format!("{id}.{SEGMENT_FILE_EXTENSION}"))
    }

    pub fn index_path(&self, id: SegmentId) -> PathBuf {
        self.segments_dir
            .join(format!("{id}.{INDEX_FILE_EXTENSION}"))
    }

    pub fn list_segments(&self) -> io::Result<Vec<SegmentId>> {
        let entries = self.io.list_dir(&self.segments_dir)?;
        let mut ids: Vec<SegmentId> = entries
            .iter()
            .filter_map(|path| {
                let stem = path.file_stem()?.to_str()?;
                let ext = path.extension()?.to_str()?;
                (ext == SEGMENT_FILE_EXTENSION)
                    .then(|| stem.parse::<u32>().ok().map(SegmentId::new))?
            })
            .collect();
        ids.sort();
        Ok(ids)
    }

    pub fn open_for_read(&self, id: SegmentId) -> io::Result<FileId> {
        if let Some(entry) = self.handles.read().get(&id) {
            return Ok(entry.fd);
        }
        let path = self.segment_path(id);
        let fd = self.io.open(&path, OpenOptions::read_only_existing())?;
        let mut cache = self.handles.write();
        match cache.get(&id) {
            Some(entry) => {
                let _ = self.io.close(fd);
                Ok(entry.fd)
            }
            None => {
                cache.insert(
                    id,
                    CachedSegmentHandle {
                        fd,
                        sealed: false,
                        writable: false,
                    },
                );
                Ok(fd)
            }
        }
    }

    pub fn open_for_append(&self, id: SegmentId) -> io::Result<FileId> {
        {
            let cache = self.handles.read();
            if let Some(entry) = cache.get(&id) {
                if entry.sealed {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("cannot append to sealed segment {id}"),
                    ));
                }
                if entry.writable {
                    return Ok(entry.fd);
                }
            }
        }
        let path = self.segment_path(id);
        let fd = self.io.open(&path, OpenOptions::read_write())?;
        let mut cache = self.handles.write();
        match cache.get(&id) {
            Some(entry) if entry.sealed => {
                let _ = self.io.close(fd);
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("cannot append to sealed segment {id}"),
                ))
            }
            Some(entry) if entry.writable => {
                let _ = self.io.close(fd);
                Ok(entry.fd)
            }
            Some(entry) => {
                let old_fd = entry.fd;
                cache.insert(
                    id,
                    CachedSegmentHandle {
                        fd,
                        sealed: false,
                        writable: true,
                    },
                );
                let _ = self.io.close(old_fd);
                Ok(fd)
            }
            None => {
                cache.insert(
                    id,
                    CachedSegmentHandle {
                        fd,
                        sealed: false,
                        writable: true,
                    },
                );
                Ok(fd)
            }
        }
    }

    pub fn should_rotate(&self, position: SegmentOffset) -> bool {
        position.raw() >= self.max_segment_size
    }

    pub fn prepare_rotation(&self, current_id: SegmentId) -> io::Result<(SegmentId, FileId)> {
        let next = current_id.next();
        let path = self.segment_path(next);
        let fd = self.io.open(&path, OpenOptions::read_write())?;
        self.io.truncate(fd, 0)?;
        self.io.sync_dir(&self.segments_dir)?;
        Ok((next, fd))
    }

    pub fn commit_rotation(&self, new_id: SegmentId, fd: FileId) {
        self.handles.write().insert(
            new_id,
            CachedSegmentHandle {
                fd,
                sealed: false,
                writable: true,
            },
        );
    }

    pub fn seal_segment(&self, id: SegmentId, index: &SegmentIndex) -> io::Result<()> {
        let path = self.index_path(id);
        index.save(&self.io, &path)?;
        let mut cache = self.handles.write();
        let entry = cache.get_mut(&id).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("seal_segment: segment {id} not in handle cache"),
            )
        })?;
        entry.sealed = true;
        Ok(())
    }

    pub fn is_sealed(&self, id: SegmentId) -> bool {
        self.handles
            .read()
            .get(&id)
            .is_some_and(|entry| entry.sealed)
    }

    pub fn rollback_rotation(&self, new_id: SegmentId, fd: FileId) {
        let _ = self.io.close(fd);
        self.handles.write().remove(&new_id);
        let _ = self.io.delete(&self.segment_path(new_id));
    }

    pub fn delete_segment(&self, id: SegmentId) -> io::Result<()> {
        {
            let mut cache = self.handles.write();
            if let Some(entry) = cache.remove(&id) {
                let _ = self.io.close(entry.fd);
            }
        }
        match self.io.delete(&self.index_path(id)) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        self.io.delete(&self.segment_path(id))?;
        self.io.sync_dir(&self.segments_dir)?;
        self.retention_epoch.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn oldest_segment(&self) -> io::Result<Option<SegmentId>> {
        self.list_segments().map(|segs| segs.into_iter().next())
    }

    pub fn retention_epoch(&self) -> u64 {
        self.retention_epoch.load(Ordering::Relaxed)
    }

    pub fn shutdown(&self) {
        self.handles.write().drain().for_each(|(_, handle)| {
            let _ = self.io.close(handle.fd);
        });
    }
}

impl<S: StorageIO> Drop for SegmentManager<S> {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eventlog::segment_file::{SegmentWriter, ValidEvent};
    use crate::eventlog::segment_index::{DEFAULT_INDEX_INTERVAL, rebuild_from_segment};
    use crate::eventlog::types::{
        DidHash, EventSequence, EventTypeTag, SegmentOffset, TimestampMicros,
    };
    use crate::sim::SimulatedIO;

    fn setup_manager(max_segment_size: u64) -> SegmentManager<SimulatedIO> {
        let sim = SimulatedIO::pristine(42);
        SegmentManager::new(sim, PathBuf::from("/segments"), max_segment_size).unwrap()
    }

    fn test_event(seq: u64, payload: &[u8]) -> ValidEvent {
        ValidEvent {
            seq: EventSequence::new(seq),
            timestamp: TimestampMicros::new(seq * 1_000_000),
            did_hash: DidHash::from_did(&format!("did:plc:test{seq}")),
            event_type: EventTypeTag::COMMIT,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn new_creates_directory() {
        let sim = SimulatedIO::pristine(42);
        let mgr = SegmentManager::new(sim, PathBuf::from("/eventlog/segments"), 1024).unwrap();
        let entries = mgr.io().list_dir(Path::new("/eventlog/segments")).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn segment_path_format() {
        let mgr = setup_manager(1024);
        assert_eq!(
            mgr.segment_path(SegmentId::new(0)),
            Path::new("/segments/00000000.tqe")
        );
        assert_eq!(
            mgr.segment_path(SegmentId::new(42)),
            Path::new("/segments/00000042.tqe")
        );
    }

    #[test]
    fn index_path_format() {
        let mgr = setup_manager(1024);
        assert_eq!(
            mgr.index_path(SegmentId::new(0)),
            Path::new("/segments/00000000.tqi")
        );
        assert_eq!(
            mgr.index_path(SegmentId::new(7)),
            Path::new("/segments/00000007.tqi")
        );
    }

    #[test]
    fn open_for_append_creates_file() {
        let mgr = setup_manager(1024);
        let fd = mgr.open_for_append(SegmentId::new(1)).unwrap();
        assert_eq!(mgr.io().file_size(fd).unwrap(), 0);
    }

    #[test]
    fn open_for_read_missing_file_errors() {
        let mgr = setup_manager(1024);
        assert!(mgr.open_for_read(SegmentId::new(99)).is_err());
    }

    #[test]
    fn handle_cache_returns_same_fd() {
        let mgr = setup_manager(1024);
        let fd1 = mgr.open_for_append(SegmentId::new(1)).unwrap();
        let fd2 = mgr.open_for_append(SegmentId::new(1)).unwrap();
        assert_eq!(fd1, fd2);
    }

    #[test]
    fn open_for_read_uses_cache_from_append() {
        let mgr = setup_manager(1024);
        let fd_write = mgr.open_for_append(SegmentId::new(1)).unwrap();
        let fd_read = mgr.open_for_read(SegmentId::new(1)).unwrap();
        assert_eq!(fd_write, fd_read);
    }

    #[test]
    fn list_segments_finds_segment_files() {
        let mgr = setup_manager(1024);
        mgr.open_for_append(SegmentId::new(1)).unwrap();
        mgr.open_for_append(SegmentId::new(3)).unwrap();

        let segments = mgr.list_segments().unwrap();
        assert_eq!(segments, vec![SegmentId::new(1), SegmentId::new(3)]);
    }

    #[test]
    fn list_segments_ignores_non_segment_files() {
        let mgr = setup_manager(1024);
        mgr.open_for_append(SegmentId::new(1)).unwrap();
        mgr.io()
            .open(Path::new("/segments/notes.txt"), OpenOptions::read_write())
            .unwrap();

        let segments = mgr.list_segments().unwrap();
        assert_eq!(segments, vec![SegmentId::new(1)]);
    }

    #[test]
    fn list_segments_ignores_index_files() {
        let mgr = setup_manager(1024);
        mgr.open_for_append(SegmentId::new(1)).unwrap();
        mgr.io()
            .open(
                Path::new("/segments/00000001.tqi"),
                OpenOptions::read_write(),
            )
            .unwrap();

        let segments = mgr.list_segments().unwrap();
        assert_eq!(segments, vec![SegmentId::new(1)]);
    }

    #[test]
    fn list_segments_sorted_ascending() {
        let mgr = setup_manager(1024);
        mgr.open_for_append(SegmentId::new(5)).unwrap();
        mgr.open_for_append(SegmentId::new(1)).unwrap();
        mgr.open_for_append(SegmentId::new(3)).unwrap();

        let segments = mgr.list_segments().unwrap();
        assert_eq!(
            segments,
            vec![SegmentId::new(1), SegmentId::new(3), SegmentId::new(5)]
        );
    }

    #[test]
    fn should_rotate_respects_threshold() {
        let mgr = setup_manager(1024);
        assert!(!mgr.should_rotate(SegmentOffset::new(100)));
        assert!(!mgr.should_rotate(SegmentOffset::new(1023)));
        assert!(mgr.should_rotate(SegmentOffset::new(1024)));
        assert!(mgr.should_rotate(SegmentOffset::new(2000)));
    }

    #[test]
    fn rotation_lifecycle_prepare_commit() {
        let mgr = setup_manager(1024);
        let _fd0 = mgr.open_for_append(SegmentId::new(1)).unwrap();
        let (next_id, next_fd) = mgr.prepare_rotation(SegmentId::new(1)).unwrap();
        assert_eq!(next_id, SegmentId::new(2));
        assert_eq!(mgr.io().file_size(next_fd).unwrap(), 0);
        mgr.commit_rotation(next_id, next_fd);
        assert_eq!(mgr.open_for_read(next_id).unwrap(), next_fd);
    }

    #[test]
    fn rotation_rollback_cleans_up() {
        let mgr = setup_manager(1024);
        let _fd0 = mgr.open_for_append(SegmentId::new(1)).unwrap();
        let (next_id, next_fd) = mgr.prepare_rotation(SegmentId::new(1)).unwrap();
        mgr.commit_rotation(next_id, next_fd);

        assert_eq!(mgr.open_for_read(next_id).unwrap(), next_fd);
        mgr.rollback_rotation(next_id, next_fd);

        let segments = mgr.list_segments().unwrap();
        assert_eq!(segments, vec![SegmentId::new(1)]);
    }

    #[test]
    fn seal_segment_persists_index_and_marks_sealed() {
        let mgr = setup_manager(64 * 1024);
        let fd = mgr.open_for_append(SegmentId::new(1)).unwrap();
        let mut writer =
            SegmentWriter::new(mgr.io(), fd, SegmentId::new(1), EventSequence::new(1)).unwrap();

        (1u64..=10).for_each(|i| {
            writer
                .append_event(mgr.io(), &test_event(i, format!("payload-{i}").as_bytes()))
                .unwrap();
        });
        writer.sync(mgr.io()).unwrap();

        let (index, _) = rebuild_from_segment(mgr.io(), fd, DEFAULT_INDEX_INTERVAL).unwrap();

        assert!(!mgr.is_sealed(SegmentId::new(1)));
        mgr.seal_segment(SegmentId::new(1), &index).unwrap();
        assert!(mgr.is_sealed(SegmentId::new(1)));

        let loaded = SegmentIndex::load(mgr.io(), &mgr.index_path(SegmentId::new(1)))
            .unwrap()
            .unwrap();
        assert_eq!(loaded, index);
    }

    #[test]
    fn delete_segment_removes_files_and_handle() {
        let mgr = setup_manager(64 * 1024);
        let fd = mgr.open_for_append(SegmentId::new(1)).unwrap();
        let mut writer =
            SegmentWriter::new(mgr.io(), fd, SegmentId::new(1), EventSequence::new(1)).unwrap();
        writer
            .append_event(mgr.io(), &test_event(1, b"will be deleted"))
            .unwrap();
        writer.sync(mgr.io()).unwrap();

        let (index, _) = rebuild_from_segment(mgr.io(), fd, DEFAULT_INDEX_INTERVAL).unwrap();
        mgr.seal_segment(SegmentId::new(1), &index).unwrap();

        let epoch_before = mgr.retention_epoch();
        mgr.delete_segment(SegmentId::new(1)).unwrap();
        assert_eq!(mgr.retention_epoch(), epoch_before + 1);

        assert!(mgr.list_segments().unwrap().is_empty());
        assert!(mgr.open_for_read(SegmentId::new(1)).is_err());
    }

    #[test]
    fn oldest_segment_returns_first() {
        let mgr = setup_manager(1024);
        assert_eq!(mgr.oldest_segment().unwrap(), None);

        mgr.open_for_append(SegmentId::new(3)).unwrap();
        mgr.open_for_append(SegmentId::new(1)).unwrap();
        mgr.open_for_append(SegmentId::new(5)).unwrap();

        assert_eq!(mgr.oldest_segment().unwrap(), Some(SegmentId::new(1)));
    }

    #[test]
    fn retention_epoch_starts_at_zero() {
        let mgr = setup_manager(1024);
        assert_eq!(mgr.retention_epoch(), 0);
    }

    #[test]
    fn rotate_and_write_across_segments() {
        let mgr = setup_manager(1024);

        let fd1 = mgr.open_for_append(SegmentId::new(1)).unwrap();
        let mut writer1 =
            SegmentWriter::new(mgr.io(), fd1, SegmentId::new(1), EventSequence::new(1)).unwrap();
        writer1
            .append_event(mgr.io(), &test_event(1, b"first segment"))
            .unwrap();
        writer1.sync(mgr.io()).unwrap();

        let (id2, fd2) = mgr.prepare_rotation(SegmentId::new(1)).unwrap();
        mgr.commit_rotation(id2, fd2);

        let mut writer2 = SegmentWriter::new(mgr.io(), fd2, id2, EventSequence::new(2)).unwrap();
        writer2
            .append_event(mgr.io(), &test_event(2, b"second segment"))
            .unwrap();
        writer2.sync(mgr.io()).unwrap();

        let fd1_read = mgr.open_for_read(SegmentId::new(1)).unwrap();
        let events1 = crate::eventlog::SegmentReader::open(mgr.io(), fd1_read)
            .unwrap()
            .valid_prefix()
            .unwrap();
        assert_eq!(events1.len(), 1);
        assert_eq!(events1[0].payload, b"first segment");

        let fd2_read = mgr.open_for_read(id2).unwrap();
        let events2 = crate::eventlog::SegmentReader::open(mgr.io(), fd2_read)
            .unwrap()
            .valid_prefix()
            .unwrap();
        assert_eq!(events2.len(), 1);
        assert_eq!(events2[0].payload, b"second segment");
    }

    #[test]
    fn seal_then_append_errors() {
        let mgr = setup_manager(64 * 1024);
        let fd = mgr.open_for_append(SegmentId::new(1)).unwrap();
        SegmentWriter::new(mgr.io(), fd, SegmentId::new(1), EventSequence::new(1)).unwrap();

        let index = SegmentIndex::new();
        mgr.seal_segment(SegmentId::new(1), &index).unwrap();

        let result = mgr.open_for_append(SegmentId::new(1));
        assert!(result.is_err());
    }

    #[test]
    fn accessors() {
        let mgr = setup_manager(999);
        assert_eq!(mgr.max_segment_size(), 999);
        assert_eq!(mgr.segments_dir(), Path::new("/segments"));
    }

    #[test]
    fn multiple_deletions_increment_epoch() {
        let mgr = setup_manager(1024);
        mgr.open_for_append(SegmentId::new(1)).unwrap();
        mgr.open_for_append(SegmentId::new(2)).unwrap();
        mgr.open_for_append(SegmentId::new(3)).unwrap();

        assert_eq!(mgr.retention_epoch(), 0);
        mgr.delete_segment(SegmentId::new(1)).unwrap();
        assert_eq!(mgr.retention_epoch(), 1);
        mgr.delete_segment(SegmentId::new(2)).unwrap();
        assert_eq!(mgr.retention_epoch(), 2);
    }

    #[test]
    fn open_for_read_does_not_infer_sealed_from_index_file() {
        let mgr = setup_manager(64 * 1024);
        let fd = mgr.open_for_append(SegmentId::new(1)).unwrap();
        let mut writer =
            SegmentWriter::new(mgr.io(), fd, SegmentId::new(1), EventSequence::new(1)).unwrap();
        writer
            .append_event(mgr.io(), &test_event(1, b"sealed test"))
            .unwrap();
        writer.sync(mgr.io()).unwrap();

        let (index, _) = rebuild_from_segment(mgr.io(), fd, DEFAULT_INDEX_INTERVAL).unwrap();
        mgr.seal_segment(SegmentId::new(1), &index).unwrap();

        mgr.handles.write().remove(&SegmentId::new(1));

        let _read_fd = mgr.open_for_read(SegmentId::new(1)).unwrap();
        assert!(!mgr.is_sealed(SegmentId::new(1)));
    }

    #[test]
    fn open_for_read_unsealed_allows_append() {
        let mgr = setup_manager(1024);
        let _fd = mgr.open_for_append(SegmentId::new(1)).unwrap();

        mgr.handles.write().remove(&SegmentId::new(1));

        let _read_fd = mgr.open_for_read(SegmentId::new(1)).unwrap();
        assert!(!mgr.is_sealed(SegmentId::new(1)));
    }

    #[test]
    fn shutdown_clears_handles() {
        let mgr = setup_manager(1024);
        mgr.open_for_append(SegmentId::new(1)).unwrap();
        mgr.open_for_append(SegmentId::new(2)).unwrap();

        mgr.shutdown();
        assert!(mgr.handles.read().is_empty());
    }

    #[test]
    #[should_panic(expected = "max_segment_size")]
    fn rejects_max_segment_size_too_small() {
        let sim = SimulatedIO::pristine(42);
        let _ = SegmentManager::new(sim, PathBuf::from("/segments"), 5);
    }

    #[test]
    fn prepare_rotation_truncates_stale_file() {
        let mgr = setup_manager(1024);
        let _fd0 = mgr.open_for_append(SegmentId::new(1)).unwrap();

        let stale_path = mgr.segment_path(SegmentId::new(2));
        let stale_fd = mgr
            .io()
            .open(&stale_path, OpenOptions::read_write())
            .unwrap();
        mgr.io().write_all_at(stale_fd, 0, &[0xDE; 4096]).unwrap();
        mgr.io().sync(stale_fd).unwrap();
        assert_eq!(mgr.io().file_size(stale_fd).unwrap(), 4096);
        mgr.io().close(stale_fd).unwrap();

        let (next_id, next_fd) = mgr.prepare_rotation(SegmentId::new(1)).unwrap();
        assert_eq!(next_id, SegmentId::new(2));
        assert_eq!(mgr.io().file_size(next_fd).unwrap(), 0);
    }

    #[test]
    fn open_for_append_upgrades_read_only_handle() {
        let mgr = setup_manager(1024);
        let fd_append = mgr.open_for_append(SegmentId::new(1)).unwrap();

        mgr.handles.write().remove(&SegmentId::new(1));

        let fd_read = mgr.open_for_read(SegmentId::new(1)).unwrap();
        assert_ne!(fd_read, fd_append);
        assert!(!mgr.handles.read().get(&SegmentId::new(1)).unwrap().writable);

        let fd_upgraded = mgr.open_for_append(SegmentId::new(1)).unwrap();
        assert_ne!(fd_upgraded, fd_read);
        assert!(mgr.handles.read().get(&SegmentId::new(1)).unwrap().writable);
    }

    #[test]
    fn seal_uncached_segment_returns_error() {
        let mgr = setup_manager(1024);
        let index = SegmentIndex::new();
        let result = mgr.seal_segment(SegmentId::new(99), &index);
        assert!(result.is_err());
    }
}
