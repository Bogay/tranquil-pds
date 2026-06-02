use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::Duration;

use crate::clock::{Clock, SimClock};
use crate::io::{FileId, OpenOptions, StorageIO};

pub const TORN_PAGE_BYTES: usize = 4096;
pub const SECTOR_BYTES: usize = 512;

const BASE_IO_SERVICE_NS: u64 = 1_000;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Probability(f64);

impl Probability {
    pub const ZERO: Self = Self(0.0);

    pub fn new(p: f64) -> Self {
        assert!(
            p.is_finite() && (0.0..=1.0).contains(&p),
            "probability out of range: {p}"
        );
        Self(p)
    }

    pub fn raw(self) -> f64 {
        self.0
    }

    pub fn is_nonzero(self) -> bool {
        self.0 > 0.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyncReorderWindow(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LatencyNs(pub u64);

#[derive(Debug, Clone, Copy)]
pub struct FaultConfig {
    pub partial_write_probability: Probability,
    pub bit_flip_on_read_probability: Probability,
    pub sync_failure_probability: Probability,
    pub dir_sync_failure_probability: Probability,
    pub misdirected_write_probability: Probability,
    pub io_error_probability: Probability,
    pub torn_page_probability: Probability,
    pub misdirected_read_probability: Probability,
    pub delayed_io_error_probability: Probability,
    pub sync_reorder_window: SyncReorderWindow,
    pub latency_distribution_ns: LatencyNs,
}

impl FaultConfig {
    pub fn none() -> Self {
        Self {
            partial_write_probability: Probability::ZERO,
            bit_flip_on_read_probability: Probability::ZERO,
            sync_failure_probability: Probability::ZERO,
            dir_sync_failure_probability: Probability::ZERO,
            misdirected_write_probability: Probability::ZERO,
            io_error_probability: Probability::ZERO,
            torn_page_probability: Probability::ZERO,
            misdirected_read_probability: Probability::ZERO,
            delayed_io_error_probability: Probability::ZERO,
            sync_reorder_window: SyncReorderWindow(0),
            latency_distribution_ns: LatencyNs(0),
        }
    }

    pub fn moderate() -> Self {
        Self {
            partial_write_probability: Probability::new(0.05),
            bit_flip_on_read_probability: Probability::new(0.01),
            sync_failure_probability: Probability::new(0.03),
            dir_sync_failure_probability: Probability::new(0.02),
            misdirected_write_probability: Probability::new(0.01),
            io_error_probability: Probability::new(0.02),
            torn_page_probability: Probability::new(0.01),
            misdirected_read_probability: Probability::new(0.005),
            delayed_io_error_probability: Probability::new(0.01),
            sync_reorder_window: SyncReorderWindow(4),
            latency_distribution_ns: LatencyNs(50_000),
        }
    }

    pub fn aggressive() -> Self {
        Self {
            partial_write_probability: Probability::new(0.15),
            bit_flip_on_read_probability: Probability::new(0.05),
            sync_failure_probability: Probability::new(0.10),
            dir_sync_failure_probability: Probability::new(0.05),
            misdirected_write_probability: Probability::new(0.05),
            io_error_probability: Probability::new(0.08),
            torn_page_probability: Probability::new(0.05),
            misdirected_read_probability: Probability::new(0.02),
            delayed_io_error_probability: Probability::new(0.05),
            sync_reorder_window: SyncReorderWindow(8),
            latency_distribution_ns: LatencyNs(250_000),
        }
    }

    pub fn torn_pages_only() -> Self {
        Self {
            torn_page_probability: Probability::new(0.25),
            ..Self::none()
        }
    }

    pub fn misdirected_only() -> Self {
        Self {
            misdirected_write_probability: Probability::new(0.25),
            ..Self::none()
        }
    }

    pub fn fsyncgate_only() -> Self {
        Self {
            delayed_io_error_probability: Probability::new(0.05),
            ..Self::none()
        }
    }

    pub fn recoverable() -> Self {
        Self {
            misdirected_write_probability: Probability::ZERO,
            misdirected_read_probability: Probability::ZERO,
            bit_flip_on_read_probability: Probability::ZERO,
            ..Self::moderate()
        }
    }

    pub fn read_faults() -> Self {
        Self {
            misdirected_read_probability: Probability::new(0.05),
            bit_flip_on_read_probability: Probability::new(0.05),
            io_error_probability: Probability::new(0.01),
            ..Self::none()
        }
    }

    pub fn read_corruption() -> Self {
        Self {
            misdirected_read_probability: Probability::new(0.05),
            bit_flip_on_read_probability: Probability::new(0.05),
            ..Self::none()
        }
    }

    pub fn injects_errors(&self) -> bool {
        self.partial_write_probability.is_nonzero()
            || self.bit_flip_on_read_probability.is_nonzero()
            || self.sync_failure_probability.is_nonzero()
            || self.dir_sync_failure_probability.is_nonzero()
            || self.misdirected_write_probability.is_nonzero()
            || self.io_error_probability.is_nonzero()
            || self.torn_page_probability.is_nonzero()
            || self.misdirected_read_probability.is_nonzero()
            || self.delayed_io_error_probability.is_nonzero()
            || self.sync_reorder_window.0 > 0
    }

    pub fn scale_probabilities(self, factor: f64) -> Self {
        let scale = |p: Probability| Probability::new((p.raw() * factor).clamp(0.0, 1.0));
        Self {
            partial_write_probability: scale(self.partial_write_probability),
            bit_flip_on_read_probability: scale(self.bit_flip_on_read_probability),
            sync_failure_probability: scale(self.sync_failure_probability),
            dir_sync_failure_probability: scale(self.dir_sync_failure_probability),
            misdirected_write_probability: scale(self.misdirected_write_probability),
            io_error_probability: scale(self.io_error_probability),
            torn_page_probability: scale(self.torn_page_probability),
            misdirected_read_probability: scale(self.misdirected_read_probability),
            delayed_io_error_probability: scale(self.delayed_io_error_probability),
            sync_reorder_window: self.sync_reorder_window,
            latency_distribution_ns: self.latency_distribution_ns,
        }
    }

    pub fn uniform_density(density: f64) -> Self {
        assert!(
            density.is_finite() && (0.0..=1.0).contains(&density),
            "fault density out of range: {density}"
        );
        let p = Probability::new(density);
        Self {
            partial_write_probability: p,
            bit_flip_on_read_probability: p,
            sync_failure_probability: p,
            dir_sync_failure_probability: p,
            misdirected_write_probability: p,
            io_error_probability: p,
            torn_page_probability: p,
            misdirected_read_probability: p,
            delayed_io_error_probability: p,
            sync_reorder_window: SyncReorderWindow(0),
            latency_distribution_ns: LatencyNs(0),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct StorageId(u64);

struct SimStorage {
    buffered: Vec<u8>,
    durable: Vec<u8>,
    dir_entry_durable: bool,
    io_poisoned: bool,
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
    Barrier,
}

struct PendingSync {
    storage_id: StorageId,
    snapshot: Vec<u8>,
}

struct PendingDelete {
    path: PathBuf,
    storage_id: StorageId,
    was_dir_durable: bool,
}

struct SimState {
    storage: HashMap<StorageId, SimStorage>,
    paths: HashMap<PathBuf, StorageId>,
    fds: HashMap<FileId, SimFd>,
    dirs_durable: HashSet<PathBuf>,
    op_log: Vec<OpRecord>,
    next_fd_id: u64,
    next_storage_id: u64,
    pending_syncs: VecDeque<PendingSync>,
    pending_deletes: Vec<PendingDelete>,
}

const TAG_OPEN_IO: u64 = 100;
const TAG_READ_IO: u64 = 101;
const TAG_READ_MISDIR: u64 = 102;
const TAG_READ_DRIFT_SECTORS: u64 = 103;
const TAG_READ_DRIFT_DIR: u64 = 104;
const TAG_READ_BITFLIP: u64 = 105;
const TAG_READ_FLIP_POS: u64 = 106;
const TAG_READ_FLIP_BIT: u64 = 107;
const TAG_WRITE_IO: u64 = 110;
const TAG_WRITE_TORN: u64 = 111;
const TAG_WRITE_TORN_SECTORS: u64 = 112;
const TAG_WRITE_PARTIAL: u64 = 113;
const TAG_WRITE_PARTIAL_LEN: u64 = 114;
const TAG_WRITE_MISDIR: u64 = 115;
const TAG_WRITE_DRIFT_SECTORS: u64 = 116;
const TAG_WRITE_DRIFT_DIR: u64 = 117;
const TAG_SYNC_IO: u64 = 120;
const TAG_SYNC_FAILURE: u64 = 121;
const TAG_SYNC_DELAYED: u64 = 122;
const TAG_SYNCDIR_IO: u64 = 130;
const TAG_SYNCDIR_FAILURE: u64 = 131;
const TAG_LATENCY: u64 = 140;

fn path_stream(path: &Path) -> u64 {
    let key = path.file_name().unwrap_or(path.as_os_str());
    key.to_string_lossy()
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325, |h, b| {
            (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
        })
}

impl SimState {
    fn fault_hash(seed: u64, stream: u64, key: u64, tag: u64) -> u64 {
        let h = splitmix64(seed ^ 0x9E37_79B9_7F4A_7C15);
        let h = splitmix64(h ^ stream.wrapping_mul(0xD6E8_FEB8_6659_FD93));
        let h = splitmix64(h ^ key);
        splitmix64(h ^ tag)
    }

    fn fault_unit(seed: u64, stream: u64, key: u64, tag: u64) -> f64 {
        (Self::fault_hash(seed, stream, key, tag) >> 11) as f64 / (1u64 << 53) as f64
    }

    fn fault_below(seed: u64, stream: u64, key: u64, tag: u64, probability: Probability) -> bool {
        probability.is_nonzero() && Self::fault_unit(seed, stream, key, tag) < probability.raw()
    }

    fn fault_usize(seed: u64, stream: u64, key: u64, tag: u64, max: usize) -> usize {
        if max == 0 {
            0
        } else {
            (Self::fault_hash(seed, stream, key, tag) as usize) % max
        }
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
    pristine_mode: AtomicBool,
    write_crash_armed: AtomicBool,
    write_crash_countdown: AtomicI64,
    write_crashed: AtomicBool,
    rng_seed: u64,
    clock: SimClock,
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
                next_fd_id: 1,
                next_storage_id: 1,
                pending_syncs: VecDeque::new(),
                pending_deletes: Vec::new(),
            }),
            fault_config,
            pristine_mode: AtomicBool::new(false),
            write_crash_armed: AtomicBool::new(false),
            write_crash_countdown: AtomicI64::new(-1),
            write_crashed: AtomicBool::new(false),
            rng_seed: seed,
            clock: SimClock::new(seed),
        }
    }

    pub fn arm_write_crash(&self, after_writes: i64) {
        self.write_crashed.store(false, Ordering::Relaxed);
        self.write_crash_countdown
            .store(after_writes, Ordering::Relaxed);
        self.write_crash_armed.store(true, Ordering::Relaxed);
    }

    fn write_crash_fired(&self) -> bool {
        if !self.write_crash_armed.load(Ordering::Relaxed) {
            return false;
        }
        if self.write_crashed.load(Ordering::Relaxed) {
            return true;
        }
        if self.write_crash_countdown.fetch_sub(1, Ordering::Relaxed) <= 0 {
            self.write_crashed.store(true, Ordering::Relaxed);
            return true;
        }
        false
    }

    pub fn clock(&self) -> SimClock {
        self.clock.clone()
    }

    fn effective_fault_config(&self) -> FaultConfig {
        if self.pristine_mode.load(Ordering::Relaxed) {
            FaultConfig::none()
        } else {
            self.fault_config
        }
    }

    pub fn set_pristine_mode(&self, on: bool) {
        self.pristine_mode.store(on, Ordering::Relaxed);
    }

    pub fn pristine_mode(&self) -> bool {
        self.pristine_mode.load(Ordering::Relaxed)
    }

    fn jitter(&self, stream: u64, key: u64) {
        let max_ns = self.effective_fault_config().latency_distribution_ns.0;
        let extra_ns = match max_ns {
            0 => 0,
            max => SimState::fault_hash(self.rng_seed, stream, key, TAG_LATENCY) % max,
        };
        self.clock
            .advance(Duration::from_nanos(BASE_IO_SERVICE_NS + extra_ns));
    }

    pub fn pristine(seed: u64) -> Self {
        Self::new(seed, FaultConfig::none())
    }

    pub fn crash(&self) -> Vec<PathBuf> {
        let mut state = self.state.lock().unwrap();

        self.write_crash_armed.store(false, Ordering::Relaxed);
        self.write_crashed.store(false, Ordering::Relaxed);
        self.write_crash_countdown.store(-1, Ordering::Relaxed);

        state.fds.clear();
        state.pending_syncs.clear();

        let pending = std::mem::take(&mut state.pending_deletes);
        pending.into_iter().for_each(|pd| {
            if pd.was_dir_durable && state.storage.contains_key(&pd.storage_id) {
                state.paths.insert(pd.path, pd.storage_id);
            }
        });

        let orphaned: HashSet<StorageId> = state
            .storage
            .iter()
            .filter(|(_, s)| !s.dir_entry_durable)
            .map(|(sid, _)| *sid)
            .collect();

        let removed_paths: Vec<PathBuf> = state
            .paths
            .iter()
            .filter(|(_, sid)| orphaned.contains(sid))
            .map(|(path, _)| path.clone())
            .collect();

        orphaned.iter().for_each(|sid| {
            state.storage.remove(sid);
        });

        let live_sids: HashSet<StorageId> = state.storage.keys().copied().collect();
        state.paths.retain(|_, sid| live_sids.contains(sid));

        state.storage.values_mut().for_each(|s| {
            s.buffered = s.durable.clone();
            s.io_poisoned = false;
        });

        removed_paths
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

pub struct PristineGuard {
    sim: Arc<SimulatedIO>,
    prev: bool,
}

impl PristineGuard {
    pub fn new(sim: Arc<SimulatedIO>, on: bool) -> Self {
        let prev = sim.pristine_mode();
        sim.set_pristine_mode(on || prev);
        Self { sim, prev }
    }
}

impl Drop for PristineGuard {
    fn drop(&mut self) {
        self.sim.set_pristine_mode(self.prev);
    }
}

impl StorageIO for SimulatedIO {
    fn open(&self, path: &Path, opts: OpenOptions) -> io::Result<FileId> {
        let fault = self.effective_fault_config();
        let mut state = self.state.lock().unwrap();
        let seed = self.rng_seed;

        let open_stream = path_stream(path);
        let existing_size = state
            .paths
            .get(path)
            .and_then(|sid| state.storage.get(sid))
            .map(|s| s.buffered.len() as u64)
            .unwrap_or(0);
        if SimState::fault_below(
            seed,
            open_stream,
            existing_size,
            TAG_OPEN_IO,
            fault.io_error_probability,
        ) {
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
                        io_poisoned: false,
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
        let pending_deleted = state.pending_deletes.iter().any(|pd| pd.storage_id == sid);

        if unlinked && no_remaining_fds && !pending_deleted {
            state.storage.remove(&sid);
        }

        state.op_log.push(OpRecord::Close { fd: id });
        Ok(())
    }

    fn read_at(&self, id: FileId, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let fault = self.effective_fault_config();
        let mut state = self.state.lock().unwrap();
        let sid = state.require_readable(id)?;
        let seed = self.rng_seed;
        let stream = sid.0;
        self.jitter(stream, offset);

        if state.storage.get(&sid).is_some_and(|s| s.io_poisoned) {
            return Err(io::Error::other("simulated EIO after delayed sync fault"));
        }

        if SimState::fault_below(
            seed,
            stream,
            offset,
            TAG_READ_IO,
            fault.io_error_probability,
        ) {
            return Err(io::Error::other("simulated EIO on read"));
        }

        let read_offset = if SimState::fault_below(
            seed,
            stream,
            offset,
            TAG_READ_MISDIR,
            fault.misdirected_read_probability,
        ) {
            let drift_sectors =
                SimState::fault_usize(seed, stream, offset, TAG_READ_DRIFT_SECTORS, 8) + 1;
            let drift = (drift_sectors * SECTOR_BYTES) as u64;
            if SimState::fault_unit(seed, stream, offset, TAG_READ_DRIFT_DIR) < 0.5 {
                offset.saturating_sub(drift)
            } else {
                offset.saturating_add(drift)
            }
        } else {
            offset
        };

        let storage = state.storage.get(&sid).unwrap();

        let off = usize::try_from(read_offset)
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

        if to_read > 0
            && SimState::fault_below(
                seed,
                stream,
                offset,
                TAG_READ_BITFLIP,
                fault.bit_flip_on_read_probability,
            )
        {
            let flip_pos = SimState::fault_usize(seed, stream, offset, TAG_READ_FLIP_POS, to_read);
            let flip_bit = SimState::fault_usize(seed, stream, offset, TAG_READ_FLIP_BIT, 8);
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
        let fault = self.effective_fault_config();
        let mut state = self.state.lock().unwrap();
        let sid = state.require_writable(id)?;
        let seed = self.rng_seed;
        let stream = sid.0;
        self.jitter(stream, offset);

        if self.write_crash_fired() {
            return Err(io::Error::other("simulated crash mid-commit"));
        }

        if state.storage.get(&sid).is_some_and(|s| s.io_poisoned) {
            return Err(io::Error::other("simulated EIO after delayed sync fault"));
        }

        if SimState::fault_below(
            seed,
            stream,
            offset,
            TAG_WRITE_IO,
            fault.io_error_probability,
        ) {
            return Err(io::Error::other("simulated EIO on write"));
        }

        let torn_len = if buf.len() > 1
            && SimState::fault_below(
                seed,
                stream,
                offset,
                TAG_WRITE_TORN,
                fault.torn_page_probability,
            ) {
            let page_base = (offset as usize) - ((offset as usize) % TORN_PAGE_BYTES);
            let page_end = page_base + TORN_PAGE_BYTES;
            let cap = page_end.saturating_sub(offset as usize).min(buf.len());
            let max_sectors = cap / SECTOR_BYTES;
            (max_sectors >= 2).then(|| {
                let n = SimState::fault_usize(
                    seed,
                    stream,
                    offset,
                    TAG_WRITE_TORN_SECTORS,
                    max_sectors - 1,
                ) + 1;
                n * SECTOR_BYTES
            })
        } else {
            None
        };

        let actual_len = match torn_len {
            Some(n) => n,
            None if buf.len() > 1
                && SimState::fault_below(
                    seed,
                    stream,
                    offset,
                    TAG_WRITE_PARTIAL,
                    fault.partial_write_probability,
                ) =>
            {
                let partial =
                    SimState::fault_usize(seed, stream, offset, TAG_WRITE_PARTIAL_LEN, buf.len());
                partial.max(1)
            }
            None => buf.len(),
        };

        let misdirected = SimState::fault_below(
            seed,
            stream,
            offset,
            TAG_WRITE_MISDIR,
            fault.misdirected_write_probability,
        );
        let write_offset = if misdirected {
            let drift_sectors =
                SimState::fault_usize(seed, stream, offset, TAG_WRITE_DRIFT_SECTORS, 8) + 1;
            let drift = (drift_sectors * SECTOR_BYTES) as u64;
            if SimState::fault_unit(seed, stream, offset, TAG_WRITE_DRIFT_DIR) < 0.5 {
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
        let fault = self.effective_fault_config();
        let mut state = self.state.lock().unwrap();
        let sid = state.require_open(id)?;
        let seed = self.rng_seed;
        let stream = sid.0;
        let fsize = state
            .storage
            .get(&sid)
            .map(|s| s.buffered.len() as u64)
            .unwrap_or(0);
        self.jitter(stream, fsize);

        if self.write_crashed.load(Ordering::Relaxed) {
            return Err(io::Error::other("simulated crash mid-commit"));
        }

        if state.storage.get(&sid).is_some_and(|s| s.io_poisoned) {
            return Err(io::Error::other("simulated EIO after delayed sync fault"));
        }

        if SimState::fault_below(seed, stream, fsize, TAG_SYNC_IO, fault.io_error_probability) {
            return Err(io::Error::other("simulated EIO on sync"));
        }

        if SimState::fault_below(
            seed,
            stream,
            fsize,
            TAG_SYNC_FAILURE,
            fault.sync_failure_probability,
        ) {
            state.op_log.push(OpRecord::Sync {
                fd: id,
                succeeded: false,
            });
            return Err(io::Error::other("simulated dropped fsync"));
        }

        let poison_after = SimState::fault_below(
            seed,
            stream,
            fsize,
            TAG_SYNC_DELAYED,
            fault.delayed_io_error_probability,
        );
        let reorder_window = fault.sync_reorder_window.0 as usize;

        let evicted = if reorder_window > 0 {
            let snapshot = state.storage.get(&sid).unwrap().buffered.clone();
            state.pending_syncs.push_back(PendingSync {
                storage_id: sid,
                snapshot,
            });
            if state.pending_syncs.len() > reorder_window {
                state.pending_syncs.pop_front()
            } else {
                None
            }
        } else {
            None
        };

        if let Some(PendingSync {
            storage_id: old_sid,
            snapshot,
        }) = evicted
            && let Some(old) = state.storage.get_mut(&old_sid)
        {
            old.durable = snapshot;
        }

        let storage = state.storage.get_mut(&sid).unwrap();

        if reorder_window == 0 {
            storage.durable = storage.buffered.clone();
        }
        if poison_after {
            storage.io_poisoned = true;
        }

        state.op_log.push(OpRecord::Sync {
            fd: id,
            succeeded: true,
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

        let was_dir_durable = state
            .storage
            .get(&sid)
            .map(|s| s.dir_entry_durable)
            .unwrap_or(false);

        state.pending_deletes.push(PendingDelete {
            path: path_buf.clone(),
            storage_id: sid,
            was_dir_durable,
        });

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

    fn barrier(&self) -> io::Result<()> {
        self.jitter(0, 0);
        let mut state = self.state.lock().unwrap();
        let drained: Vec<PendingSync> = state.pending_syncs.drain(..).collect();
        drained.into_iter().for_each(|p| {
            if let Some(storage) = state.storage.get_mut(&p.storage_id) {
                storage.durable = p.snapshot;
            }
        });
        state.op_log.push(OpRecord::Barrier);
        Ok(())
    }

    fn sync_dir(&self, path: &Path) -> io::Result<()> {
        let fault = self.effective_fault_config();
        let mut state = self.state.lock().unwrap();
        let seed = self.rng_seed;

        let dir_stream = path_stream(path);
        let dir_entries = state
            .paths
            .keys()
            .filter(|p| p.parent() == Some(path))
            .count() as u64;

        if SimState::fault_below(
            seed,
            dir_stream,
            dir_entries,
            TAG_SYNCDIR_IO,
            fault.io_error_probability,
        ) {
            return Err(io::Error::other("simulated EIO on sync_dir"));
        }

        let dir_path = path.to_path_buf();
        let actually_persisted = !SimState::fault_below(
            seed,
            dir_stream,
            dir_entries,
            TAG_SYNCDIR_FAILURE,
            fault.dir_sync_failure_probability,
        );

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

            let drained = std::mem::take(&mut state.pending_deletes);
            let (committed, remaining): (Vec<_>, Vec<_>) = drained
                .into_iter()
                .partition(|pd| pd.path.parent() == Some(path));
            state.pending_deletes = remaining;
            committed.into_iter().for_each(|pd| {
                let has_fds = state.fds.values().any(|f| f.storage_id == pd.storage_id);
                if !has_fds {
                    state.storage.remove(&pd.storage_id);
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

pub(crate) fn splitmix64(mut x: u64) -> u64 {
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
    fn delete_without_dir_sync_reverts_on_crash() {
        let sim = SimulatedIO::pristine(42);
        let dir = Path::new("/test");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();

        let path = Path::new("/test/file.dat");
        let fd = sim.open(path, OpenOptions::read_write()).unwrap();
        sim.write_at(fd, 0, b"durable data").unwrap();
        sim.sync(fd).unwrap();
        sim.sync_dir(dir).unwrap();
        sim.close(fd).unwrap();

        sim.delete(path).unwrap();
        sim.crash();

        let fd = sim.open(path, OpenOptions::read()).unwrap();
        let mut buf = vec![0u8; 12];
        sim.read_at(fd, 0, &mut buf).unwrap();
        assert_eq!(&buf, b"durable data");
    }

    #[test]
    fn delete_commits_after_dir_sync() {
        let sim = SimulatedIO::pristine(42);
        let dir = Path::new("/test");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();

        let path = Path::new("/test/file.dat");
        let fd = sim.open(path, OpenOptions::read_write()).unwrap();
        sim.write_at(fd, 0, b"data").unwrap();
        sim.sync(fd).unwrap();
        sim.sync_dir(dir).unwrap();
        sim.close(fd).unwrap();

        sim.delete(path).unwrap();
        sim.sync_dir(dir).unwrap();
        sim.crash();

        let result = sim.open(path, OpenOptions::read());
        assert!(result.is_err());
    }

    #[test]
    fn delete_of_never_durable_file_stays_gone_on_crash() {
        let sim = SimulatedIO::pristine(42);
        let path = Path::new("/test/file.dat");
        let fd = sim.open(path, OpenOptions::read_write()).unwrap();
        sim.write_at(fd, 0, b"volatile").unwrap();
        sim.sync(fd).unwrap();
        sim.close(fd).unwrap();

        sim.delete(path).unwrap();
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
    fn torn_page_truncates_within_page() {
        let fc = FaultConfig {
            torn_page_probability: Probability::new(1.0),
            ..FaultConfig::none()
        };
        let sim = SimulatedIO::new(123, fc);
        let path = Path::new("/test/file.dat");
        let fd = sim.open(path, OpenOptions::read_write()).unwrap();
        let data = vec![0xAAu8; TORN_PAGE_BYTES + 1024];
        let written = sim.write_at(fd, 0, &data).unwrap();
        assert!(written >= 1);
        assert!(written <= TORN_PAGE_BYTES);
    }

    #[test]
    fn delayed_io_error_poisons_storage_after_sync() {
        let fc = FaultConfig {
            delayed_io_error_probability: Probability::new(1.0),
            ..FaultConfig::none()
        };
        let sim = SimulatedIO::new(7, fc);
        let path = Path::new("/test/file.dat");
        let fd = sim.open(path, OpenOptions::read_write()).unwrap();
        sim.write_at(fd, 0, b"hello").unwrap();
        sim.sync(fd).unwrap();

        let err = sim.write_at(fd, 5, b"world").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        let err2 = sim.sync(fd).unwrap_err();
        assert_eq!(err2.kind(), io::ErrorKind::Other);
        let mut buf = [0u8; 5];
        let err3 = sim.read_at(fd, 0, &mut buf).unwrap_err();
        assert_eq!(err3.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn misdirected_read_reads_wrong_offset() {
        let fc = FaultConfig {
            misdirected_read_probability: Probability::new(1.0),
            ..FaultConfig::none()
        };
        let sim = SimulatedIO::new(1, fc);
        let path = Path::new("/test/file.dat");
        let fd = sim.open(path, OpenOptions::read_write()).unwrap();
        let data: Vec<u8> = (0..2048u32).flat_map(|n| n.to_le_bytes()).collect();
        sim.write_at(fd, 0, &data).unwrap();
        sim.sync(fd).unwrap();

        let mut drifted_hit = false;
        for _ in 0..32 {
            let mut buf = [0u8; 16];
            let target_off = 4096u64;
            let expected = &data[target_off as usize..target_off as usize + 16];
            if sim.read_at(fd, target_off, &mut buf).unwrap() == 16 && buf != expected {
                drifted_hit = true;
                break;
            }
        }
        assert!(
            drifted_hit,
            "misdirected read never drifted away from target"
        );
    }

    #[test]
    fn sync_reorder_window_defers_durability() {
        let fc = FaultConfig {
            sync_reorder_window: SyncReorderWindow(2),
            ..FaultConfig::none()
        };
        let sim = SimulatedIO::new(42, fc);
        let dir = Path::new("/test");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();

        let a = Path::new("/test/a.dat");
        let fd_a = sim.open(a, OpenOptions::read_write()).unwrap();
        sim.write_at(fd_a, 0, b"A").unwrap();
        sim.sync(fd_a).unwrap();
        assert!(sim.durable_contents(fd_a).unwrap().is_empty());

        let b = Path::new("/test/b.dat");
        let fd_b = sim.open(b, OpenOptions::read_write()).unwrap();
        sim.write_at(fd_b, 0, b"B").unwrap();
        sim.sync(fd_b).unwrap();
        assert!(sim.durable_contents(fd_a).unwrap().is_empty());
        assert!(sim.durable_contents(fd_b).unwrap().is_empty());

        let c = Path::new("/test/c.dat");
        let fd_c = sim.open(c, OpenOptions::read_write()).unwrap();
        sim.write_at(fd_c, 0, b"C").unwrap();
        sim.sync(fd_c).unwrap();
        assert_eq!(sim.durable_contents(fd_a).unwrap(), b"A");
        assert!(sim.durable_contents(fd_b).unwrap().is_empty());
        assert!(sim.durable_contents(fd_c).unwrap().is_empty());
    }

    #[test]
    fn sync_reorder_commits_at_sync_time_snapshot_not_current_buffer() {
        let fc = FaultConfig {
            sync_reorder_window: SyncReorderWindow(1),
            ..FaultConfig::none()
        };
        let sim = SimulatedIO::new(42, fc);
        let dir = Path::new("/test");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();

        let a = Path::new("/test/a.dat");
        let fd_a = sim.open(a, OpenOptions::read_write()).unwrap();
        sim.write_at(fd_a, 0, b"first").unwrap();
        sim.sync(fd_a).unwrap();
        sim.write_at(fd_a, 0, b"second").unwrap();

        let b = Path::new("/test/b.dat");
        let fd_b = sim.open(b, OpenOptions::read_write()).unwrap();
        sim.write_at(fd_b, 0, b"b").unwrap();
        sim.sync(fd_b).unwrap();

        assert_eq!(
            sim.durable_contents(fd_a).unwrap(),
            b"first",
            "reordered sync must commit buffered-at-sync-call, not current buffered"
        );
    }

    #[test]
    fn crash_drops_pending_reordered_syncs() {
        let fc = FaultConfig {
            sync_reorder_window: SyncReorderWindow(4),
            ..FaultConfig::none()
        };
        let sim = SimulatedIO::new(42, fc);
        let dir = Path::new("/test");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();

        let path = Path::new("/test/file.dat");
        let fd = sim.open(path, OpenOptions::read_write()).unwrap();
        sim.sync_dir(dir).unwrap();
        sim.write_at(fd, 0, b"pending").unwrap();
        sim.sync(fd).unwrap();
        sim.crash();

        let fd2 = sim.open(path, OpenOptions::read()).unwrap();
        assert_eq!(sim.file_size(fd2).unwrap(), 0);
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
