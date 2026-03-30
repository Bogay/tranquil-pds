use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::io::{FileId, OpenOptions, StorageIO};

#[derive(Debug, Clone, Copy)]
pub struct FaultConfig {
    pub partial_write_probability: f64,
    pub bit_flip_on_read_probability: f64,
    pub sync_failure_probability: f64,
    pub dir_sync_failure_probability: f64,
    pub misdirected_write_probability: f64,
    pub io_error_probability: f64,
}

impl FaultConfig {
    pub fn none() -> Self {
        Self {
            partial_write_probability: 0.0,
            bit_flip_on_read_probability: 0.0,
            sync_failure_probability: 0.0,
            dir_sync_failure_probability: 0.0,
            misdirected_write_probability: 0.0,
            io_error_probability: 0.0,
        }
    }

    pub fn moderate() -> Self {
        Self {
            partial_write_probability: 0.05,
            bit_flip_on_read_probability: 0.01,
            sync_failure_probability: 0.03,
            dir_sync_failure_probability: 0.02,
            misdirected_write_probability: 0.01,
            io_error_probability: 0.02,
        }
    }

    pub fn aggressive() -> Self {
        Self {
            partial_write_probability: 0.15,
            bit_flip_on_read_probability: 0.05,
            sync_failure_probability: 0.10,
            dir_sync_failure_probability: 0.05,
            misdirected_write_probability: 0.05,
            io_error_probability: 0.08,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct StorageId(u64);

struct SimStorage {
    buffered: Vec<u8>,
    durable: Vec<u8>,
    dir_entry_durable: bool,
}

struct SimFd {
    storage_id: StorageId,
    readable: bool,
    writable: bool,
}

#[derive(Debug, Clone)]
pub enum OpRecord {
    Open {
        fd: FileId,
        path: PathBuf,
    },
    Close {
        fd: FileId,
    },
    ReadAt {
        fd: FileId,
        offset: u64,
        len: usize,
    },
    WriteAt {
        fd: FileId,
        offset: u64,
        data: Vec<u8>,
        actual_written: usize,
    },
    Sync {
        fd: FileId,
        succeeded: bool,
    },
    Truncate {
        fd: FileId,
        size: u64,
    },
    Rename {
        from: PathBuf,
        to: PathBuf,
    },
    Delete {
        path: PathBuf,
    },
    Mkdir {
        path: PathBuf,
    },
    SyncDir {
        path: PathBuf,
    },
}

struct SimState {
    storage: HashMap<StorageId, SimStorage>,
    paths: HashMap<PathBuf, StorageId>,
    fds: HashMap<FileId, SimFd>,
    dirs_durable: HashSet<PathBuf>,
    op_log: Vec<OpRecord>,
    rng_counter: u64,
    next_fd_id: u64,
    next_storage_id: u64,
}

impl SimState {
    fn next_random(&mut self, seed: u64) -> f64 {
        let counter = self.rng_counter;
        self.rng_counter += 1;
        let mixed = splitmix64(seed.wrapping_add(counter));
        (mixed >> 11) as f64 / (1u64 << 53) as f64
    }

    fn next_random_usize(&mut self, seed: u64, max: usize) -> usize {
        if max == 0 {
            return 0;
        }
        let counter = self.rng_counter;
        self.rng_counter += 1;
        let mixed = splitmix64(seed.wrapping_add(counter));
        (mixed as usize) % max
    }

    fn should_fault(&mut self, seed: u64, probability: f64) -> bool {
        probability > 0.0 && self.next_random(seed) < probability
    }

    fn alloc_fd_id(&mut self) -> FileId {
        let id = self.next_fd_id;
        self.next_fd_id += 1;
        FileId::new(id)
    }

    fn alloc_storage_id(&mut self) -> StorageId {
        let id = self.next_storage_id;
        self.next_storage_id += 1;
        StorageId(id)
    }

    fn require_open(&self, id: FileId) -> io::Result<StorageId> {
        let fd_info = self
            .fds
            .get(&id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown file id"))?;
        if !self.storage.contains_key(&fd_info.storage_id) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "underlying storage removed",
            ));
        }
        Ok(fd_info.storage_id)
    }

    fn require_readable(&self, id: FileId) -> io::Result<StorageId> {
        let sid = self.require_open(id)?;
        if !self.fds[&id].readable {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "file not opened for reading",
            ));
        }
        Ok(sid)
    }

    fn require_writable(&self, id: FileId) -> io::Result<StorageId> {
        let sid = self.require_open(id)?;
        if !self.fds[&id].writable {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "file not opened for writing",
            ));
        }
        Ok(sid)
    }
}

pub struct SimulatedIO {
    state: Mutex<SimState>,
    fault_config: FaultConfig,
    rng_seed: u64,
}

impl SimulatedIO {
    pub fn new(seed: u64, fault_config: FaultConfig) -> Self {
        Self {
            state: Mutex::new(SimState {
                storage: HashMap::new(),
                paths: HashMap::new(),
                fds: HashMap::new(),
                dirs_durable: HashSet::new(),
                op_log: Vec::new(),
                rng_counter: 0,
                next_fd_id: 1,
                next_storage_id: 1,
            }),
            fault_config,
            rng_seed: seed,
        }
    }

    pub fn pristine(seed: u64) -> Self {
        Self::new(seed, FaultConfig::none())
    }

    pub fn crash(&self) {
        let mut state = self.state.lock().unwrap();

        state.fds.clear();

        let orphaned: Vec<StorageId> = state
            .storage
            .iter()
            .filter(|(_, s)| !s.dir_entry_durable)
            .map(|(sid, _)| *sid)
            .collect();

        orphaned.iter().for_each(|sid| {
            state.storage.remove(sid);
        });

        let live_sids: HashSet<StorageId> = state.storage.keys().copied().collect();
        state.paths.retain(|_, sid| live_sids.contains(sid));

        state
            .storage
            .values_mut()
            .for_each(|s| s.buffered = s.durable.clone());
    }

    pub fn op_log(&self) -> Vec<OpRecord> {
        self.state.lock().unwrap().op_log.clone()
    }

    pub fn durable_contents(&self, fd: FileId) -> io::Result<Vec<u8>> {
        let state = self.state.lock().unwrap();
        let sid = state.require_open(fd)?;
        Ok(state.storage.get(&sid).unwrap().durable.clone())
    }

    pub fn buffered_contents(&self, fd: FileId) -> io::Result<Vec<u8>> {
        let state = self.state.lock().unwrap();
        let sid = state.require_open(fd)?;
        Ok(state.storage.get(&sid).unwrap().buffered.clone())
    }

    pub fn last_sync_persisted(&self) -> bool {
        let state = self.state.lock().unwrap();
        state
            .op_log
            .iter()
            .rev()
            .find_map(|op| match op {
                OpRecord::Sync { succeeded, .. } => Some(*succeeded),
                _ => None,
            })
            .unwrap_or(false)
    }
}

impl StorageIO for SimulatedIO {
    fn open(&self, path: &Path, opts: OpenOptions) -> io::Result<FileId> {
        let mut state = self.state.lock().unwrap();
        let seed = self.rng_seed;

        if state.should_fault(seed, self.fault_config.io_error_probability) {
            return Err(io::Error::other("simulated EIO on open"));
        }

        let path_buf = path.to_path_buf();
        let fd_id = state.alloc_fd_id();

        match state.paths.get(&path_buf).copied() {
            Some(sid) => {
                if opts.truncate {
                    state.storage.get_mut(&sid).unwrap().buffered.clear();
                }
                state.fds.insert(
                    fd_id,
                    SimFd {
                        storage_id: sid,
                        readable: opts.read,
                        writable: opts.write,
                    },
                );
            }
            None => {
                if !opts.create {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "file not found and create not set",
                    ));
                }

                let sid = state.alloc_storage_id();
                state.storage.insert(
                    sid,
                    SimStorage {
                        buffered: Vec::new(),
                        durable: Vec::new(),
                        dir_entry_durable: false,
                    },
                );
                state.paths.insert(path_buf.clone(), sid);
                state.fds.insert(
                    fd_id,
                    SimFd {
                        storage_id: sid,
                        readable: opts.read,
                        writable: opts.write,
                    },
                );
            }
        };

        state.op_log.push(OpRecord::Open {
            fd: fd_id,
            path: path_buf,
        });
        Ok(fd_id)
    }

    fn close(&self, id: FileId) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        let fd_info = state
            .fds
            .remove(&id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown file id"))?;

        let sid = fd_info.storage_id;
        let unlinked = !state.paths.values().any(|s| *s == sid);
        let no_remaining_fds = !state.fds.values().any(|f| f.storage_id == sid);

        if unlinked && no_remaining_fds {
            state.storage.remove(&sid);
        }

        state.op_log.push(OpRecord::Close { fd: id });
        Ok(())
    }

    fn read_at(&self, id: FileId, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let mut state = self.state.lock().unwrap();
        let sid = state.require_readable(id)?;
        let seed = self.rng_seed;

        if state.should_fault(seed, self.fault_config.io_error_probability) {
            return Err(io::Error::other("simulated EIO on read"));
        }

        let storage = state.storage.get(&sid).unwrap();

        let off = usize::try_from(offset)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "offset exceeds usize"))?;
        if off >= storage.buffered.len() {
            state.op_log.push(OpRecord::ReadAt {
                fd: id,
                offset,
                len: 0,
            });
            return Ok(0);
        }

        let available = storage.buffered.len().saturating_sub(off);
        let to_read = buf.len().min(available);
        buf[..to_read].copy_from_slice(&storage.buffered[off..off + to_read]);

        if state.should_fault(seed, self.fault_config.bit_flip_on_read_probability) && to_read > 0 {
            let flip_pos = state.next_random_usize(seed, to_read);
            let flip_bit = state.next_random_usize(seed, 8);
            buf[flip_pos] ^= 1 << flip_bit;
        }

        state.op_log.push(OpRecord::ReadAt {
            fd: id,
            offset,
            len: to_read,
        });
        Ok(to_read)
    }

    fn write_at(&self, id: FileId, offset: u64, buf: &[u8]) -> io::Result<usize> {
        let mut state = self.state.lock().unwrap();
        let sid = state.require_writable(id)?;
        let seed = self.rng_seed;

        if state.should_fault(seed, self.fault_config.io_error_probability) {
            return Err(io::Error::other("simulated EIO on write"));
        }

        let actual_len = if buf.len() > 1
            && state.should_fault(seed, self.fault_config.partial_write_probability)
        {
            let partial = state.next_random_usize(seed, buf.len());
            partial.max(1)
        } else {
            buf.len()
        };

        let misdirected = state.should_fault(seed, self.fault_config.misdirected_write_probability);
        let write_offset = if misdirected {
            let drift = state.next_random_usize(seed, 64) as u64;
            if state.next_random(seed) < 0.5 {
                offset.saturating_sub(drift)
            } else {
                offset.saturating_add(drift)
            }
        } else {
            offset
        };

        let storage = state.storage.get_mut(&sid).unwrap();

        let off = usize::try_from(write_offset)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "offset exceeds usize"))?;
        let end = off.saturating_add(actual_len);
        if end > storage.buffered.len() {
            storage.buffered.resize(end, 0);
        }
        storage.buffered[off..end].copy_from_slice(&buf[..actual_len]);

        state.op_log.push(OpRecord::WriteAt {
            fd: id,
            offset,
            data: buf[..actual_len].to_vec(),
            actual_written: actual_len,
        });
        Ok(actual_len)
    }

    fn sync(&self, id: FileId) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        let sid = state.require_open(id)?;
        let seed = self.rng_seed;

        if state.should_fault(seed, self.fault_config.io_error_probability) {
            return Err(io::Error::other("simulated EIO on sync"));
        }

        let sync_succeeded = !state.should_fault(seed, self.fault_config.sync_failure_probability);

        let storage = state.storage.get_mut(&sid).unwrap();

        if sync_succeeded {
            storage.durable = storage.buffered.clone();
        }

        state.op_log.push(OpRecord::Sync {
            fd: id,
            succeeded: sync_succeeded,
        });
        Ok(())
    }

    fn file_size(&self, id: FileId) -> io::Result<u64> {
        let state = self.state.lock().unwrap();
        let sid = state.require_open(id)?;
        Ok(state.storage.get(&sid).unwrap().buffered.len() as u64)
    }

    fn truncate(&self, id: FileId, size: u64) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        let sid = state.require_open(id)?;
        let storage = state.storage.get_mut(&sid).unwrap();

        let target = usize::try_from(size)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "size exceeds usize"))?;
        storage.buffered.resize(target, 0);

        state.op_log.push(OpRecord::Truncate { fd: id, size });
        Ok(())
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        let from_buf = from.to_path_buf();
        let to_buf = to.to_path_buf();

        let sid = state
            .paths
            .remove(&from_buf)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "source file not found"))?;

        let storage = state.storage.get_mut(&sid).unwrap();
        storage.dir_entry_durable = false;

        state.paths.insert(to_buf.clone(), sid);

        state.op_log.push(OpRecord::Rename {
            from: from_buf,
            to: to_buf,
        });
        Ok(())
    }

    fn delete(&self, path: &Path) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        let path_buf = path.to_path_buf();

        let sid = state
            .paths
            .remove(&path_buf)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "file not found"))?;

        let has_open_fds = state.fds.values().any(|fd_info| fd_info.storage_id == sid);

        if !has_open_fds {
            state.storage.remove(&sid);
        }

        state.op_log.push(OpRecord::Delete { path: path_buf });
        Ok(())
    }

    fn mkdir(&self, path: &Path) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        state.op_log.push(OpRecord::Mkdir {
            path: path.to_path_buf(),
        });
        Ok(())
    }

    fn sync_dir(&self, path: &Path) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        let seed = self.rng_seed;

        if state.should_fault(seed, self.fault_config.io_error_probability) {
            return Err(io::Error::other("simulated EIO on sync_dir"));
        }

        let dir_path = path.to_path_buf();
        let actually_persisted =
            !state.should_fault(seed, self.fault_config.dir_sync_failure_probability);

        if actually_persisted {
            state.dirs_durable.insert(dir_path.clone());

            let sids_in_dir: Vec<StorageId> = state
                .paths
                .iter()
                .filter(|(p, _)| p.parent().map(|parent| parent == path).unwrap_or(false))
                .map(|(_, sid)| *sid)
                .collect();

            sids_in_dir.iter().for_each(|sid| {
                if let Some(storage) = state.storage.get_mut(sid) {
                    storage.dir_entry_durable = true;
                }
            });
        }

        state.op_log.push(OpRecord::SyncDir { path: dir_path });
        Ok(())
    }

    fn list_dir(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        let state = self.state.lock().unwrap();
        let entries: Vec<PathBuf> = state
            .paths
            .keys()
            .filter(|p| p.parent() == Some(path))
            .cloned()
            .collect();
        Ok(entries)
    }
}

pub fn sim_seed_count() -> u64 {
    std::env::var("TRANQUIL_SIM_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_000)
}

pub fn sim_single_seed() -> Option<u64> {
    std::env::var("TRANQUIL_SIM_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
}

pub fn sim_seed_range() -> std::ops::Range<u64> {
    match sim_single_seed() {
        Some(seed) => seed..seed + 1,
        None => 0..sim_seed_count(),
    }
}

pub fn sim_proptest_cases() -> u32 {
    u32::try_from(sim_seed_count()).unwrap_or(u32::MAX)
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e3779b97f4a7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pristine_round_trip() {
        let sim = SimulatedIO::pristine(42);
        let path = Path::new("/test/file.dat");
        let fd = sim.open(path, OpenOptions::read_write()).unwrap();

        let data = b"hello simulation";
        sim.write_at(fd, 0, data).unwrap();

        let mut buf = vec![0u8; data.len()];
        sim.read_at(fd, 0, &mut buf).unwrap();
        assert_eq!(&buf, data);
    }

    #[test]
    fn crash_resets_to_durable() {
        let sim = SimulatedIO::pristine(42);
        let dir = Path::new("/test");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();

        let path = Path::new("/test/file.dat");
        let fd = sim.open(path, OpenOptions::read_write()).unwrap();
        sim.write_at(fd, 0, b"durable data").unwrap();
        sim.sync(fd).unwrap();
        sim.sync_dir(dir).unwrap();

        sim.write_at(fd, 0, b"volatile!!!!").unwrap();
        sim.crash();

        let fd = sim.open(path, OpenOptions::read()).unwrap();
        let mut buf = vec![0u8; 12];
        sim.read_at(fd, 0, &mut buf).unwrap();
        assert_eq!(&buf, b"durable data");
    }

    #[test]
    fn crash_with_no_sync_loses_everything() {
        let sim = SimulatedIO::pristine(42);
        let dir = Path::new("/test");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();

        let path = Path::new("/test/file.dat");
        let fd = sim.open(path, OpenOptions::read_write()).unwrap();
        sim.write_at(fd, 0, b"never synced").unwrap();

        sim.sync_dir(dir).unwrap();
        sim.crash();

        let fd = sim.open(path, OpenOptions::read()).unwrap();
        assert_eq!(sim.file_size(fd).unwrap(), 0);
    }

    #[test]
    fn crash_without_dir_sync_loses_file() {
        let sim = SimulatedIO::pristine(42);
        let path = Path::new("/test/file.dat");
        let fd = sim.open(path, OpenOptions::read_write()).unwrap();

        sim.write_at(fd, 0, b"data").unwrap();
        sim.sync(fd).unwrap();

        sim.crash();

        let result = sim.open(path, OpenOptions::read());
        assert!(result.is_err());
    }

    #[test]
    fn dir_sync_makes_file_durable() {
        let sim = SimulatedIO::pristine(42);
        let dir = Path::new("/test");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();

        let path = Path::new("/test/file.dat");
        let fd = sim.open(path, OpenOptions::read_write()).unwrap();
        sim.write_at(fd, 0, b"persistent").unwrap();
        sim.sync(fd).unwrap();
        sim.sync_dir(dir).unwrap();

        sim.crash();

        let fd = sim.open(path, OpenOptions::read()).unwrap();
        let mut buf = vec![0u8; 10];
        sim.read_at(fd, 0, &mut buf).unwrap();
        assert_eq!(&buf, b"persistent");
    }

    #[test]
    fn read_only_rejects_write() {
        let sim = SimulatedIO::pristine(42);
        let path = Path::new("/test/file.dat");
        let fd = sim.open(path, OpenOptions::read_write()).unwrap();
        sim.write_at(fd, 0, b"data").unwrap();

        let fd2 = sim.open(path, OpenOptions::read()).unwrap();
        assert_ne!(fd, fd2);
        let result = sim.write_at(fd2, 0, b"nope");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn write_only_rejects_read() {
        let sim = SimulatedIO::pristine(42);
        let path = Path::new("/test/file.dat");
        let fd = sim.open(path, OpenOptions::write()).unwrap();
        sim.write_at(fd, 0, b"data").unwrap();

        let mut buf = vec![0u8; 4];
        let result = sim.read_at(fd, 0, &mut buf);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn open_without_create_fails_for_missing_file() {
        let sim = SimulatedIO::pristine(42);
        let result = sim.open(Path::new("/nonexistent"), OpenOptions::read());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn truncate_on_open() {
        let sim = SimulatedIO::pristine(42);
        let path = Path::new("/test/file.dat");
        let fd = sim.open(path, OpenOptions::read_write()).unwrap();
        sim.write_at(fd, 0, b"existing data").unwrap();

        let opts = OpenOptions {
            read: true,
            write: true,
            create: true,
            truncate: true,
        };
        let fd2 = sim.open(path, opts).unwrap();
        assert_eq!(sim.file_size(fd2).unwrap(), 0);
    }

    #[test]
    fn rename_makes_entry_non_durable() {
        let sim = SimulatedIO::pristine(42);
        let dir = Path::new("/test");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();

        let path_a = Path::new("/test/a.dat");
        let fd = sim.open(path_a, OpenOptions::read_write()).unwrap();
        sim.write_at(fd, 0, b"data").unwrap();
        sim.sync(fd).unwrap();
        sim.sync_dir(dir).unwrap();

        let path_b = Path::new("/test/b.dat");
        sim.rename(path_a, path_b).unwrap();

        sim.crash();

        let result_a = sim.open(path_a, OpenOptions::read());
        let result_b = sim.open(path_b, OpenOptions::read());
        assert!(result_a.is_err());
        assert!(result_b.is_err());
    }

    #[test]
    fn durable_contents_accessible() {
        let sim = SimulatedIO::pristine(42);
        let dir = Path::new("/test");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();

        let path = Path::new("/test/file.dat");
        let fd = sim.open(path, OpenOptions::read_write()).unwrap();
        sim.write_at(fd, 0, b"synced").unwrap();
        sim.sync(fd).unwrap();
        sim.sync_dir(dir).unwrap();
        sim.write_at(fd, 6, b" unsynced").unwrap();

        let durable = sim.durable_contents(fd).unwrap();
        assert_eq!(&durable, b"synced");

        let buffered = sim.buffered_contents(fd).unwrap();
        assert_eq!(&buffered, b"synced unsynced");
    }

    #[test]
    fn op_log_records_operations() {
        let sim = SimulatedIO::pristine(42);
        let dir = Path::new("/test");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();

        let path = Path::new("/test/file.dat");
        let fd = sim.open(path, OpenOptions::read_write()).unwrap();
        sim.write_at(fd, 0, b"data").unwrap();
        sim.sync(fd).unwrap();
        sim.close(fd).unwrap();

        let log = sim.op_log();
        assert_eq!(log.len(), 6);
        assert!(matches!(log[0], OpRecord::Mkdir { .. }));
        assert!(matches!(log[1], OpRecord::SyncDir { .. }));
        assert!(matches!(log[2], OpRecord::Open { .. }));
        assert!(matches!(log[3], OpRecord::WriteAt { .. }));
        assert!(matches!(
            log[4],
            OpRecord::Sync {
                succeeded: true,
                ..
            }
        ));
        assert!(matches!(log[5], OpRecord::Close { .. }));
    }

    #[test]
    fn multiple_fds_independent_permissions() {
        let sim = SimulatedIO::pristine(42);
        let path = Path::new("/test/file.dat");
        let fd_rw = sim.open(path, OpenOptions::read_write()).unwrap();
        sim.write_at(fd_rw, 0, b"shared data").unwrap();

        let fd_ro = sim.open(path, OpenOptions::read()).unwrap();
        assert_ne!(fd_rw, fd_ro);

        let mut buf = vec![0u8; 11];
        sim.read_at(fd_ro, 0, &mut buf).unwrap();
        assert_eq!(&buf, b"shared data");

        sim.write_at(fd_rw, 0, b"mutated!!!!").unwrap();
        sim.read_at(fd_ro, 0, &mut buf).unwrap();
        assert_eq!(&buf, b"mutated!!!!");

        let result = sim.write_at(fd_ro, 0, b"nope");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn last_sync_persisted_tracks_truth() {
        let sim = SimulatedIO::pristine(42);
        let path = Path::new("/test/file.dat");
        let fd = sim.open(path, OpenOptions::read_write()).unwrap();
        sim.write_at(fd, 0, b"data").unwrap();
        sim.sync(fd).unwrap();
        assert!(sim.last_sync_persisted());
    }
}
