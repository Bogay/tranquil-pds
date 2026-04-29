use std::cell::Cell;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

pub enum MappedFile {
    Mmap(memmap2::Mmap),
    Buffer(Vec<u8>),
}

impl AsRef<[u8]> for MappedFile {
    fn as_ref(&self) -> &[u8] {
        match self {
            MappedFile::Mmap(m) => m.as_ref(),
            MappedFile::Buffer(b) => b.as_ref(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FileId(u64);

impl FileId {
    #[cfg(any(test, feature = "test-harness"))]
    pub(crate) fn new(id: u64) -> Self {
        Self(id)
    }

    pub fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct OpenOptions {
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub truncate: bool,
}

impl OpenOptions {
    pub fn read() -> Self {
        Self {
            read: true,
            write: false,
            create: false,
            truncate: false,
        }
    }

    pub fn write() -> Self {
        Self {
            read: false,
            write: true,
            create: true,
            truncate: false,
        }
    }

    pub fn read_write() -> Self {
        Self {
            read: true,
            write: true,
            create: true,
            truncate: false,
        }
    }

    pub fn read_only_existing() -> Self {
        Self {
            read: true,
            write: false,
            create: false,
            truncate: false,
        }
    }

    pub fn read_write_existing() -> Self {
        Self {
            read: true,
            write: true,
            create: false,
            truncate: false,
        }
    }
}

pub trait StorageIO: Send + Sync {
    fn open(&self, path: &Path, opts: OpenOptions) -> io::Result<FileId>;
    fn close(&self, fd: FileId) -> io::Result<()>;
    fn read_at(&self, fd: FileId, offset: u64, buf: &mut [u8]) -> io::Result<usize>;
    fn write_at(&self, fd: FileId, offset: u64, buf: &[u8]) -> io::Result<usize>;
    fn sync(&self, fd: FileId) -> io::Result<()>;
    fn file_size(&self, fd: FileId) -> io::Result<u64>;
    fn truncate(&self, fd: FileId, size: u64) -> io::Result<()>;
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
    fn delete(&self, path: &Path) -> io::Result<()>;
    fn mkdir(&self, path: &Path) -> io::Result<()>;
    fn sync_dir(&self, path: &Path) -> io::Result<()>;
    fn list_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>>;

    fn barrier(&self) -> io::Result<()> {
        Ok(())
    }

    fn write_all_at(&self, fd: FileId, offset: u64, buf: &[u8]) -> io::Result<()> {
        let written = Cell::new(0usize);
        std::iter::from_fn(|| (written.get() < buf.len()).then_some(()))
            .try_fold(offset, |pos, ()| {
                let w = written.get();
                let n = self.write_at(fd, pos, &buf[w..])?;
                match n {
                    0 => Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write returned 0 bytes",
                    )),
                    n => {
                        written.set(w + n);
                        Ok(pos + n as u64)
                    }
                }
            })
            .map(|_| ())
    }

    fn read_exact_at(&self, fd: FileId, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let total = buf.len();
        let progress = Cell::new(0usize);
        std::iter::from_fn(|| (progress.get() < total).then_some(()))
            .try_fold(offset, |pos, ()| {
                let r = progress.get();
                let n = self.read_at(fd, pos, &mut buf[r..])?;
                match n {
                    0 => Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "unexpected eof",
                    )),
                    n => {
                        progress.set(r + n);
                        Ok(pos + n as u64)
                    }
                }
            })
            .map(|_| ())
    }

    fn mmap_file(&self, fd: FileId) -> io::Result<MappedFile> {
        let size = self.file_size(fd)?;
        let mut buf = vec![0u8; size as usize];
        self.read_exact_at(fd, 0, &mut buf)?;
        Ok(MappedFile::Buffer(buf))
    }
}

impl<S: StorageIO> StorageIO for Arc<S> {
    fn open(&self, path: &Path, opts: OpenOptions) -> io::Result<FileId> {
        (**self).open(path, opts)
    }
    fn close(&self, fd: FileId) -> io::Result<()> {
        (**self).close(fd)
    }
    fn read_at(&self, fd: FileId, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        (**self).read_at(fd, offset, buf)
    }
    fn write_at(&self, fd: FileId, offset: u64, buf: &[u8]) -> io::Result<usize> {
        (**self).write_at(fd, offset, buf)
    }
    fn sync(&self, fd: FileId) -> io::Result<()> {
        (**self).sync(fd)
    }
    fn file_size(&self, fd: FileId) -> io::Result<u64> {
        (**self).file_size(fd)
    }
    fn truncate(&self, fd: FileId, size: u64) -> io::Result<()> {
        (**self).truncate(fd, size)
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        (**self).rename(from, to)
    }
    fn delete(&self, path: &Path) -> io::Result<()> {
        (**self).delete(path)
    }
    fn mkdir(&self, path: &Path) -> io::Result<()> {
        (**self).mkdir(path)
    }
    fn sync_dir(&self, path: &Path) -> io::Result<()> {
        (**self).sync_dir(path)
    }
    fn list_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        (**self).list_dir(path)
    }
    fn barrier(&self) -> io::Result<()> {
        (**self).barrier()
    }
    fn mmap_file(&self, fd: FileId) -> io::Result<MappedFile> {
        (**self).mmap_file(fd)
    }
}

pub struct RealIO {
    next_id: AtomicU64,
    fds: Mutex<HashMap<FileId, Arc<fs::File>>>,
}

impl RealIO {
    pub fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            fds: Mutex::new(HashMap::new()),
        }
    }

    fn lookup(&self, id: FileId) -> io::Result<Arc<fs::File>> {
        self.fds
            .lock()
            .map_err(|_| io::Error::other("fd table lock poisoned"))?
            .get(&id)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown file id"))
    }
}

impl Default for RealIO {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageIO for RealIO {
    fn open(&self, path: &Path, opts: OpenOptions) -> io::Result<FileId> {
        let file = fs::OpenOptions::new()
            .read(opts.read)
            .write(opts.write)
            .create(opts.create)
            .truncate(opts.truncate)
            .open(path)?;

        let id = FileId(self.next_id.fetch_add(1, Ordering::Relaxed));

        self.fds
            .lock()
            .map_err(|_| io::Error::other("fd table lock poisoned"))?
            .insert(id, Arc::new(file));

        Ok(id)
    }

    fn close(&self, id: FileId) -> io::Result<()> {
        self.fds
            .lock()
            .map_err(|_| io::Error::other("fd table lock poisoned"))?
            .remove(&id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown file id"))?;
        Ok(())
    }

    fn read_at(&self, id: FileId, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.lookup(id)?.read_at(buf, offset)
    }

    fn write_at(&self, id: FileId, offset: u64, buf: &[u8]) -> io::Result<usize> {
        self.lookup(id)?.write_at(buf, offset)
    }

    fn sync(&self, id: FileId) -> io::Result<()> {
        self.lookup(id)?.sync_data()
    }

    fn file_size(&self, id: FileId) -> io::Result<u64> {
        self.lookup(id)?.metadata().map(|m| m.len())
    }

    fn truncate(&self, id: FileId, size: u64) -> io::Result<()> {
        self.lookup(id)?.set_len(size)
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        fs::rename(from, to)
    }

    fn delete(&self, path: &Path) -> io::Result<()> {
        fs::remove_file(path)
    }

    fn mkdir(&self, path: &Path) -> io::Result<()> {
        fs::create_dir_all(path)
    }

    fn sync_dir(&self, path: &Path) -> io::Result<()> {
        fs::File::open(path)?.sync_all()
    }

    fn list_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        fs::read_dir(path)?
            .map(|entry| entry.map(|e| e.path()))
            .collect()
    }

    fn mmap_file(&self, fd: FileId) -> io::Result<MappedFile> {
        let file = self.lookup(fd)?;
        let mmap = unsafe { memmap2::Mmap::map(&*file)? };
        Ok(MappedFile::Mmap(mmap))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_io_round_trip() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("test.dat");
        let io = RealIO::new();

        let fd = io.open(&path, OpenOptions::read_write()).unwrap();

        let data = b"hello tranquil-store";
        let written = io.write_at(fd, 0, data).unwrap();
        assert_eq!(written, data.len());

        io.sync(fd).unwrap();

        let mut buf = vec![0u8; data.len()];
        let read = io.read_at(fd, 0, &mut buf).unwrap();
        assert_eq!(read, data.len());
        assert_eq!(&buf, data);

        assert_eq!(io.file_size(fd).unwrap(), data.len() as u64);

        io.truncate(fd, 5).unwrap();
        assert_eq!(io.file_size(fd).unwrap(), 5);

        io.close(fd).unwrap();
    }

    #[test]
    fn real_io_write_all_at() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("writeall.dat");
        let io = RealIO::new();
        let fd = io.open(&path, OpenOptions::read_write()).unwrap();

        let data = b"complete write via write_all_at";
        io.write_all_at(fd, 0, data).unwrap();
        io.sync(fd).unwrap();

        let mut buf = vec![0u8; data.len()];
        io.read_exact_at(fd, 0, &mut buf).unwrap();
        assert_eq!(&buf, data);

        io.close(fd).unwrap();
    }

    #[test]
    fn real_io_rename_and_delete() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path_a = tmp.path().join("a.dat");
        let path_b = tmp.path().join("b.dat");
        let io = RealIO::new();

        let fd = io.open(&path_a, OpenOptions::read_write()).unwrap();
        io.write_all_at(fd, 0, b"data").unwrap();
        io.sync(fd).unwrap();
        io.close(fd).unwrap();

        io.rename(&path_a, &path_b).unwrap();
        assert!(!path_a.exists());
        assert!(path_b.exists());

        io.delete(&path_b).unwrap();
        assert!(!path_b.exists());
    }

    #[test]
    fn real_io_mkdir_and_sync_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("subdir");
        let io = RealIO::new();

        io.mkdir(&dir).unwrap();
        assert!(dir.is_dir());

        io.sync_dir(&dir).unwrap();
    }

    #[test]
    fn concurrent_read_write_no_deadlock() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("concurrent.dat");
        let io = Arc::new(RealIO::new());
        let fd = io.open(&path, OpenOptions::read_write()).unwrap();

        io.write_all_at(fd, 0, &vec![0u8; 4096]).unwrap();
        io.sync(fd).unwrap();

        let handles: Vec<_> = (0..4)
            .map(|i| {
                let io = Arc::clone(&io);
                std::thread::spawn(move || {
                    let offset = (i * 1024) as u64;
                    let data = vec![i as u8; 1024];
                    io.write_all_at(fd, offset, &data).unwrap();

                    let mut buf = vec![0u8; 1024];
                    io.read_exact_at(fd, offset, &mut buf).unwrap();
                })
            })
            .collect();

        handles.into_iter().for_each(|h| h.join().unwrap());
        io.close(fd).unwrap();
    }
}
