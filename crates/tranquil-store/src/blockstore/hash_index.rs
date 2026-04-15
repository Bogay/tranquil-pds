use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

use parking_lot::RwLock;

use super::data_file::CID_SIZE;
use super::group_commit::ShardHintPositions;
use super::types::{
    BlockLength, BlockLocation, BlockOffset, CidBytes, CollectionResult, CommitEpoch, DataFileId,
    HintOffset, IndexEntry, LivenessInfo, RefCount, ShardId, WallClockMs, WriteCursor,
};

pub struct PositionUpdate<'a> {
    pub hint_positions: &'a ShardHintPositions,
    pub shard_id: ShardId,
    pub file_id: DataFileId,
    pub offset: HintOffset,
}

const EMPTY_CID: [u8; CID_SIZE] = [0u8; CID_SIZE];

fn is_empty(cid: &[u8; CID_SIZE]) -> bool {
    *cid == EMPTY_CID
}

fn is_occupied(cid: &[u8; CID_SIZE]) -> bool {
    !is_empty(cid)
}

fn fibonacci_hash(cid: &[u8; CID_SIZE], shift: u32) -> usize {
    let hash_bytes: [u8; 8] = cid[4..12].try_into().unwrap();
    let hash = u64::from_le_bytes(hash_bytes);
    (hash.wrapping_mul(11_400_714_819_323_198_485u64) >> shift) as usize
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Slot {
    pub cid: [u8; CID_SIZE],
    pub file_id: DataFileId,
    pub offset: BlockOffset,
    pub length: BlockLength,
    pub refcount: RefCount,
    pub gc_since_ms: WallClockMs,
    pub gc_epoch: CommitEpoch,
}

const _: () = assert!(std::mem::size_of::<Slot>() == 72);
const _: () = assert!(std::mem::size_of::<Slot>() == 36 + 4 + 8 + 4 + 4 + 8 + 8);
const _: () = assert!(!std::mem::needs_drop::<Slot>());
const _: () = assert!(std::mem::align_of::<Slot>() == 8);
#[cfg(not(target_endian = "little"))]
compile_error!(
    "checkpoint format uses native-endian slot serialization; only little-endian targets are supported"
);

impl Slot {
    const EMPTY: Self = Self {
        cid: EMPTY_CID,
        file_id: DataFileId::new(0),
        offset: BlockOffset::new(0),
        length: BlockLength::from_raw(0),
        refcount: RefCount::new(0),
        gc_since_ms: WallClockMs::new(0),
        gc_epoch: CommitEpoch::new(0),
    };

    fn to_location(self) -> BlockLocation {
        BlockLocation {
            file_id: self.file_id,
            offset: self.offset,
            length: self.length,
        }
    }

    fn to_index_entry(self) -> IndexEntry {
        IndexEntry {
            location: self.to_location(),
            refcount: self.refcount,
        }
    }

    fn from_location(cid: [u8; CID_SIZE], location: BlockLocation) -> Self {
        Self {
            cid,
            file_id: location.file_id,
            offset: location.offset,
            length: location.length,
            refcount: RefCount::one(),
            gc_since_ms: WallClockMs::new(0),
            gc_epoch: CommitEpoch::zero(),
        }
    }
}

#[derive(Debug)]
pub struct CapacityExhausted;

const MAX_SLOTS: usize = 1 << 30;

pub struct HashTable {
    slots: Vec<Slot>,
    capacity: usize,
    count: usize,
    shift: u32,
    write_cursor: Option<WriteCursor>,
}

impl HashTable {
    pub fn with_capacity(min_capacity: usize) -> Self {
        let capacity = min_capacity
            .max(64)
            .checked_next_power_of_two()
            .expect("capacity overflow");
        assert!(
            capacity <= MAX_SLOTS,
            "requested capacity {min_capacity} rounds to {capacity} which exceeds MAX_SLOTS {MAX_SLOTS}"
        );
        let shift = 64 - capacity.trailing_zeros();
        Self {
            slots: vec![Slot::EMPTY; capacity],
            capacity,
            count: 0,
            shift,
            write_cursor: None,
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    fn needs_grow(&self) -> bool {
        (self.count + 1) * 10 > self.capacity * 7
    }

    fn slot_index(&self, cid: &[u8; CID_SIZE]) -> usize {
        fibonacci_hash(cid, self.shift)
    }

    fn probe_distance(&self, slot_idx: usize, home: usize) -> usize {
        (slot_idx.wrapping_sub(home)) & (self.capacity - 1)
    }

    pub fn get(&self, cid: &[u8; CID_SIZE]) -> Option<&Slot> {
        let home = self.slot_index(cid);
        let mut idx = home;
        let mut dist = 0usize;

        loop {
            let slot = &self.slots[idx];

            if is_empty(&slot.cid) {
                return None;
            }

            let slot_home = self.slot_index(&slot.cid);
            let slot_dist = self.probe_distance(idx, slot_home);
            if slot_dist < dist {
                return None;
            }
            if slot.cid == *cid {
                return Some(slot);
            }

            dist += 1;
            idx = (idx + 1) & (self.capacity - 1);

            if dist >= self.capacity {
                return None;
            }
        }
    }

    pub fn get_mut(&mut self, cid: &[u8; CID_SIZE]) -> Option<&mut Slot> {
        let home = self.slot_index(cid);
        let mut idx = home;
        let mut dist = 0usize;

        loop {
            let slot_cid = self.slots[idx].cid;

            if is_empty(&slot_cid) {
                return None;
            }

            let slot_home = self.slot_index(&slot_cid);
            let slot_dist = self.probe_distance(idx, slot_home);
            if slot_dist < dist {
                return None;
            }
            if slot_cid == *cid {
                return Some(&mut self.slots[idx]);
            }

            dist += 1;
            idx = (idx + 1) & (self.capacity - 1);

            if dist >= self.capacity {
                return None;
            }
        }
    }

    pub fn contains(&self, cid: &[u8; CID_SIZE]) -> bool {
        self.get(cid).is_some()
    }

    pub fn contains_live(&self, cid: &[u8; CID_SIZE]) -> bool {
        self.get(cid).is_some_and(|s| !s.refcount.is_zero())
    }

    pub fn insert(&mut self, new_slot: Slot) -> Result<Option<Slot>, CapacityExhausted> {
        if is_empty(&new_slot.cid) {
            tracing::error!("attempted to insert all-zero CID into hash table");
            return Ok(None);
        }
        if self.needs_grow() {
            self.grow()?;
        }
        Ok(self.insert_probing(new_slot))
    }

    fn insert_probing(&mut self, mut new_slot: Slot) -> Option<Slot> {
        let home = self.slot_index(&new_slot.cid);
        let mut idx = home;
        let mut dist = 0usize;

        loop {
            let slot_cid = self.slots[idx].cid;

            if is_empty(&slot_cid) {
                self.slots[idx] = new_slot;
                self.count += 1;
                return None;
            }

            if slot_cid == new_slot.cid {
                let old = self.slots[idx];
                self.slots[idx] = new_slot;
                return Some(old);
            }

            let slot_home = self.slot_index(&slot_cid);
            let slot_dist = self.probe_distance(idx, slot_home);
            if slot_dist < dist {
                std::mem::swap(&mut self.slots[idx], &mut new_slot);
                dist = slot_dist;
            }

            dist += 1;
            idx = (idx + 1) & (self.capacity - 1);
        }
    }

    pub fn insert_or_increment(
        &mut self,
        cid: &[u8; CID_SIZE],
        location: BlockLocation,
    ) -> Result<RefCount, CapacityExhausted> {
        if is_empty(cid) {
            tracing::error!("attempted to insert all-zero CID into hash table");
            return Ok(RefCount::new(0));
        }
        if self.needs_grow() {
            self.grow()?;
        }
        Ok(self.insert_or_increment_probing(cid, location))
    }

    pub fn insert_if_absent(
        &mut self,
        cid: &[u8; CID_SIZE],
        location: BlockLocation,
    ) -> Result<bool, CapacityExhausted> {
        if is_empty(cid) {
            return Ok(false);
        }
        match self.get(cid) {
            Some(_) => Ok(false),
            None => {
                if self.needs_grow() {
                    self.grow()?;
                }
                self.insert_probing(Slot::from_location(*cid, location));
                Ok(true)
            }
        }
    }

    fn insert_or_increment_probing(
        &mut self,
        cid: &[u8; CID_SIZE],
        location: BlockLocation,
    ) -> RefCount {
        let home = self.slot_index(cid);
        let mut idx = home;
        let mut dist = 0usize;

        loop {
            let slot_cid = self.slots[idx].cid;

            if is_empty(&slot_cid) {
                self.slots[idx] = Slot::from_location(*cid, location);
                self.count += 1;
                return RefCount::one();
            }

            if slot_cid == *cid {
                let slot = &mut self.slots[idx];
                slot.refcount = slot.refcount.saturating_increment();
                if slot.gc_since_ms > WallClockMs::new(0) {
                    slot.gc_since_ms = WallClockMs::new(0);
                    slot.gc_epoch = CommitEpoch::zero();
                }
                return slot.refcount;
            }

            let slot_home = self.slot_index(&slot_cid);
            let slot_dist = self.probe_distance(idx, slot_home);
            if slot_dist < dist {
                let mut displaced = Slot::from_location(*cid, location);
                std::mem::swap(&mut self.slots[idx], &mut displaced);
                self.count += 1;
                self.relocate_displaced(displaced, idx, slot_dist);
                return RefCount::one();
            }

            dist += 1;
            idx = (idx + 1) & (self.capacity - 1);
        }
    }

    fn relocate_displaced(&mut self, mut entry: Slot, from_idx: usize, mut dist: usize) {
        dist += 1;
        let mut idx = (from_idx + 1) & (self.capacity - 1);

        loop {
            if is_empty(&self.slots[idx].cid) {
                self.slots[idx] = entry;
                return;
            }

            let slot_home = self.slot_index(&self.slots[idx].cid);
            let slot_dist = self.probe_distance(idx, slot_home);
            if slot_dist < dist {
                std::mem::swap(&mut self.slots[idx], &mut entry);
                dist = slot_dist;
            }

            dist += 1;
            idx = (idx + 1) & (self.capacity - 1);
        }
    }

    #[must_use]
    pub fn decrement(
        &mut self,
        cid: &[u8; CID_SIZE],
        epoch: CommitEpoch,
        now: WallClockMs,
    ) -> Option<RefCount> {
        let slot = self.get_mut(cid)?;
        match slot.refcount.is_zero() {
            true => {
                tracing::warn!(?cid, "decrement on zero-refcount entry, skipping");
                Some(RefCount::new(0))
            }
            false => {
                slot.refcount = slot.refcount.decrement();
                if slot.refcount.is_zero() {
                    slot.gc_since_ms = now;
                    slot.gc_epoch = epoch;
                }
                Some(slot.refcount)
            }
        }
    }

    pub fn relocate(
        &mut self,
        cid: &[u8; CID_SIZE],
        new_location: BlockLocation,
        refcount: RefCount,
    ) -> Result<bool, CapacityExhausted> {
        if is_empty(cid) {
            return Ok(false);
        }
        if self.needs_grow() {
            self.grow()?;
        }

        let home = self.slot_index(cid);
        let mut idx = home;
        let mut dist = 0usize;

        loop {
            let slot_cid = self.slots[idx].cid;

            if is_empty(&slot_cid) {
                let mut slot = Slot::from_location(*cid, new_location);
                slot.refcount = refcount;
                self.slots[idx] = slot;
                self.count += 1;
                return Ok(false);
            }

            if slot_cid == *cid {
                let slot = &mut self.slots[idx];
                slot.file_id = new_location.file_id;
                slot.offset = new_location.offset;
                slot.length = new_location.length;
                return Ok(true);
            }

            let slot_home = self.slot_index(&slot_cid);
            let slot_dist = self.probe_distance(idx, slot_home);
            if slot_dist < dist {
                let mut displaced = Slot::from_location(*cid, new_location);
                displaced.refcount = refcount;
                std::mem::swap(&mut self.slots[idx], &mut displaced);
                self.count += 1;
                self.relocate_displaced(displaced, idx, slot_dist);
                return Ok(false);
            }

            dist += 1;
            idx = (idx + 1) & (self.capacity - 1);
        }
    }

    #[must_use]
    pub fn remove(&mut self, cid: &[u8; CID_SIZE]) -> bool {
        let home = self.slot_index(cid);
        let mut idx = home;
        let mut dist = 0usize;

        loop {
            let slot_cid = self.slots[idx].cid;

            if is_empty(&slot_cid) {
                return false;
            }

            let slot_home = self.slot_index(&slot_cid);
            let slot_dist = self.probe_distance(idx, slot_home);
            if slot_dist < dist {
                return false;
            }
            if slot_cid == *cid {
                self.slots[idx] = Slot::EMPTY;
                self.count -= 1;
                self.backward_shift(idx);
                return true;
            }

            dist += 1;
            idx = (idx + 1) & (self.capacity - 1);

            if dist >= self.capacity {
                return false;
            }
        }
    }

    fn backward_shift(&mut self, removed_idx: usize) {
        let mut empty = removed_idx;
        let mut probe = (empty + 1) & (self.capacity - 1);

        loop {
            let slot_cid = self.slots[probe].cid;

            if is_empty(&slot_cid) {
                break;
            }

            let slot_home = self.slot_index(&slot_cid);
            let slot_dist = self.probe_distance(probe, slot_home);
            if slot_dist == 0 {
                break;
            }
            self.slots[empty] = self.slots[probe];
            self.slots[probe] = Slot::EMPTY;
            empty = probe;

            probe = (probe + 1) & (self.capacity - 1);
        }
    }

    fn grow(&mut self) -> Result<(), CapacityExhausted> {
        let new_capacity = self.capacity.checked_mul(2).ok_or(CapacityExhausted)?;
        if new_capacity > MAX_SLOTS {
            return Err(CapacityExhausted);
        }
        self.rebuild(new_capacity);
        Ok(())
    }

    fn rebuild(&mut self, new_capacity: usize) {
        let new_shift = 64 - new_capacity.trailing_zeros();
        let old_slots = std::mem::replace(&mut self.slots, vec![Slot::EMPTY; new_capacity]);

        let old_count = self.count;
        self.capacity = new_capacity;
        self.shift = new_shift;
        self.count = 0;

        old_slots
            .into_iter()
            .filter(|s| is_occupied(&s.cid))
            .for_each(|s| {
                self.insert_probing(s);
            });

        debug_assert_eq!(self.count, old_count);
    }

    pub fn set_write_cursor(&mut self, cursor: WriteCursor) {
        self.write_cursor = Some(cursor);
    }

    pub fn write_cursor(&self) -> Option<WriteCursor> {
        self.write_cursor
    }

    pub fn iter(&self) -> impl Iterator<Item = &Slot> {
        self.slots.iter().filter(|s| is_occupied(&s.cid))
    }

    pub fn collect_dead_blocks(
        &self,
        current_epoch: CommitEpoch,
        now: WallClockMs,
        grace_period_ms: u64,
    ) -> CollectionResult {
        let mut candidates: HashMap<DataFileId, Vec<CidBytes>> = HashMap::new();
        let mut total_bytes: u64 = 0;

        self.iter()
            .filter(|s| s.refcount.is_zero() && s.gc_since_ms > WallClockMs::new(0))
            .filter(|s| {
                let epoch_advanced = current_epoch > s.gc_epoch;
                let grace_expired = now.raw().saturating_sub(s.gc_since_ms.raw()) > grace_period_ms;
                epoch_advanced && grace_expired
            })
            .for_each(|s| {
                let record_bytes =
                    s.length.as_u64() + super::data_file::BLOCK_RECORD_OVERHEAD as u64;
                total_bytes = total_bytes.saturating_add(record_bytes);
                candidates.entry(s.file_id).or_default().push(s.cid);
            });

        CollectionResult {
            candidates,
            total_bytes,
        }
    }

    pub fn is_gc_eligible(
        &self,
        cid: &[u8; CID_SIZE],
        current_epoch: CommitEpoch,
        now: WallClockMs,
        grace_period_ms: u64,
    ) -> bool {
        self.get(cid)
            .filter(|s| s.gc_since_ms > WallClockMs::new(0))
            .is_some_and(|s| {
                let epoch_advanced = current_epoch > s.gc_epoch;
                let grace_expired = now.raw().saturating_sub(s.gc_since_ms.raw()) > grace_period_ms;
                epoch_advanced && grace_expired
            })
    }

    pub fn apply_compaction(
        &mut self,
        relocations: &[(CidBytes, BlockLocation)],
        removals: &[CidBytes],
    ) {
        relocations.iter().for_each(|(cid, new_loc)| {
            if let Err(e) = self.relocate(cid, *new_loc, RefCount::one()) {
                tracing::error!(?e, "capacity exhausted during compaction relocation");
            }
        });

        removals.iter().for_each(|cid| {
            if let Some(slot) = self.get_mut(cid)
                && !slot.refcount.is_zero()
            {
                tracing::error!(
                    ?cid,
                    refcount = slot.refcount.raw(),
                    "BUG: compaction removing block with non-zero refcount"
                );
            }
            let _ = self.remove(cid);
        });
    }

    pub fn cleanup_stale_gc(&mut self) -> u64 {
        self.slots
            .iter_mut()
            .filter(|s| {
                is_occupied(&s.cid) && s.gc_since_ms > WallClockMs::new(0) && !s.refcount.is_zero()
            })
            .fold(0u64, |acc, s| {
                s.gc_since_ms = WallClockMs::new(0);
                s.gc_epoch = CommitEpoch::zero();
                acc.saturating_add(1)
            })
    }

    pub fn liveness_info(&self, file_id: DataFileId) -> LivenessInfo {
        self.iter().filter(|s| s.file_id == file_id).fold(
            LivenessInfo {
                live_bytes: 0,
                total_bytes: 0,
                live_blocks: 0,
                total_blocks: 0,
            },
            |mut info, s| {
                let record_bytes =
                    s.length.as_u64() + super::data_file::BLOCK_RECORD_OVERHEAD as u64;
                info.total_bytes = info.total_bytes.saturating_add(record_bytes);
                info.total_blocks = info.total_blocks.saturating_add(1);
                if !s.refcount.is_zero() {
                    info.live_bytes = info.live_bytes.saturating_add(record_bytes);
                    info.live_blocks = info.live_blocks.saturating_add(1);
                }
                info
            },
        )
    }

    pub fn liveness_by_file(
        &self,
        current_epoch: CommitEpoch,
        now: WallClockMs,
        grace_period_ms: u64,
    ) -> HashMap<DataFileId, LivenessInfo> {
        self.iter().fold(HashMap::new(), |mut stats, s| {
            let record_bytes = s.length.as_u64() + super::data_file::BLOCK_RECORD_OVERHEAD as u64;

            let info = stats.entry(s.file_id).or_insert(LivenessInfo {
                live_bytes: 0,
                total_bytes: 0,
                live_blocks: 0,
                total_blocks: 0,
            });

            info.total_bytes = info.total_bytes.saturating_add(record_bytes);
            info.total_blocks = info.total_blocks.saturating_add(1);

            let is_live = match s.refcount.is_zero() {
                false => true,
                true => {
                    let gc_eligible = s.gc_since_ms > WallClockMs::new(0)
                        && current_epoch > s.gc_epoch
                        && now.raw().saturating_sub(s.gc_since_ms.raw()) > grace_period_ms;
                    !gc_eligible
                }
            };

            if is_live {
                info.live_bytes = info.live_bytes.saturating_add(record_bytes);
                info.live_blocks = info.live_blocks.saturating_add(1);
            }

            stats
        })
    }

    pub fn find_leaked_refcounts(
        &self,
        is_reachable: impl Fn(&CidBytes) -> bool,
    ) -> (Vec<(CidBytes, RefCount)>, u64) {
        let mut leaked = Vec::new();
        let mut live_scanned: u64 = 0;

        self.iter().filter(|s| !s.refcount.is_zero()).for_each(|s| {
            live_scanned = live_scanned.saturating_add(1);
            if !is_reachable(&s.cid) {
                leaked.push((s.cid, s.refcount));
            }
        });

        (leaked, live_scanned)
    }

    pub fn approximate_count(&self) -> u64 {
        self.count as u64
    }
}

const CHECKPOINT_MAGIC: [u8; 8] = *b"TQCKPT01";
const CHECKPOINT_VERSION_V1: u32 = 1;
const CHECKPOINT_VERSION_V2: u32 = 2;
const CHECKPOINT_HEADER_SIZE: usize = 128;
const TRAILER_MAGIC: u64 = 0xDEAD_BEEF_CAFE_F00D;
const SLOT_SIZE: usize = std::mem::size_of::<Slot>();
const SHARD_POSITION_SIZE: usize = 12;

#[derive(Debug, Clone)]
pub struct CheckpointPositions(pub Vec<(DataFileId, HintOffset)>);

impl CheckpointPositions {
    pub fn single(file_id: DataFileId, offset: HintOffset) -> Self {
        Self(vec![(file_id, offset)])
    }

    pub fn as_slice(&self) -> &[(DataFileId, HintOffset)] {
        &self.0
    }
}

const H_MAGIC: usize = 0;
const H_VERSION: usize = 8;
const H_SHARD_COUNT: usize = 12;
const H_SLOT_COUNT: usize = 16;
const H_ENTRY_COUNT: usize = 24;
const H_CURSOR_FILE_ID: usize = 40;
const H_CURSOR_OFFSET: usize = 48;
const H_CHECKPOINT_EPOCH: usize = 56;
const H_HINT_FILE_ID: usize = 64;
const H_HINT_OFFSET: usize = 72;
const H_HEADER_CHECKSUM: usize = 80;

fn header_checksum(buf: &[u8; CHECKPOINT_HEADER_SIZE]) -> u64 {
    xxhash_rust::xxh3::xxh3_64(&buf[..H_HEADER_CHECKSUM])
}

fn serialize_header(
    slot_count: u64,
    entry_count: u64,
    cursor_file_id: u32,
    cursor_offset: u64,
    checkpoint_epoch: u64,
    shard_count: u16,
) -> [u8; CHECKPOINT_HEADER_SIZE] {
    let mut buf = [0u8; CHECKPOINT_HEADER_SIZE];
    buf[H_MAGIC..H_MAGIC + 8].copy_from_slice(&CHECKPOINT_MAGIC);
    buf[H_VERSION..H_VERSION + 4].copy_from_slice(&CHECKPOINT_VERSION_V2.to_le_bytes());
    buf[H_SHARD_COUNT..H_SHARD_COUNT + 2].copy_from_slice(&shard_count.to_le_bytes());
    buf[H_SLOT_COUNT..H_SLOT_COUNT + 8].copy_from_slice(&slot_count.to_le_bytes());
    buf[H_ENTRY_COUNT..H_ENTRY_COUNT + 8].copy_from_slice(&entry_count.to_le_bytes());
    buf[H_CURSOR_FILE_ID..H_CURSOR_FILE_ID + 4].copy_from_slice(&cursor_file_id.to_le_bytes());
    buf[H_CURSOR_OFFSET..H_CURSOR_OFFSET + 8].copy_from_slice(&cursor_offset.to_le_bytes());
    buf[H_CHECKPOINT_EPOCH..H_CHECKPOINT_EPOCH + 8]
        .copy_from_slice(&checkpoint_epoch.to_le_bytes());
    let checksum = header_checksum(&buf);
    buf[H_HEADER_CHECKSUM..H_HEADER_CHECKSUM + 8].copy_from_slice(&checksum.to_le_bytes());
    buf
}

fn slots_as_bytes(slots: &[Slot]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(slots.as_ptr().cast::<u8>(), slots.len() * SLOT_SIZE) }
}

fn copy_bytes_to_slots(bytes: &[u8], count: usize) -> io::Result<Vec<Slot>> {
    let expected = count * SLOT_SIZE;
    if bytes.len() < expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "checkpoint slot region too short",
        ));
    }
    let mut slots = vec![Slot::EMPTY; count];
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), slots.as_mut_ptr().cast::<u8>(), expected);
    }
    Ok(slots)
}

fn serialize_shard_positions(positions: &[(DataFileId, HintOffset)]) -> Vec<u8> {
    positions
        .iter()
        .flat_map(|(fid, off)| {
            let mut buf = [0u8; SHARD_POSITION_SIZE];
            buf[0..4].copy_from_slice(&fid.raw().to_le_bytes());
            buf[4..12].copy_from_slice(&off.raw().to_le_bytes());
            buf
        })
        .collect()
}

pub fn write_checkpoint(
    table: &HashTable,
    path: &Path,
    epoch: CommitEpoch,
    positions: &CheckpointPositions,
) -> io::Result<()> {
    use std::io::Write;

    let tmp_path = path.with_extension("tqc.tmp");

    let shard_count = u16::try_from(positions.0.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "shard count exceeds u16::MAX"))?;

    let (cursor_file_id, cursor_offset) = table
        .write_cursor()
        .map(|c| (c.file_id.raw(), c.offset.raw()))
        .unwrap_or((0, 0));

    let header_bytes = serialize_header(
        table.capacity() as u64,
        table.len() as u64,
        cursor_file_id,
        cursor_offset,
        epoch.raw(),
        shard_count,
    );

    let slot_bytes = slots_as_bytes(&table.slots);
    let shard_pos_bytes = serialize_shard_positions(&positions.0);

    let mut hasher = xxhash_rust::xxh3::Xxh3::new();
    hasher.update(slot_bytes);
    hasher.update(&shard_pos_bytes);
    let data_checksum = hasher.digest();

    let mut file = std::fs::File::create(&tmp_path)?;
    file.write_all(&header_bytes)?;
    file.write_all(slot_bytes)?;
    file.write_all(&shard_pos_bytes)?;
    file.write_all(&data_checksum.to_le_bytes())?;
    file.write_all(&TRAILER_MAGIC.to_le_bytes())?;
    file.sync_all()?;

    std::fs::rename(&tmp_path, path)?;

    path.parent()
        .map(|dir| std::fs::File::open(dir).and_then(|d| d.sync_all()))
        .transpose()?;

    Ok(())
}

fn parse_checkpoint_header(data: &[u8]) -> io::Result<(usize, usize, u32, u64, u64, u16)> {
    if data.len() < CHECKPOINT_HEADER_SIZE + 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "checkpoint file too small",
        ));
    }

    let hdr: &[u8; CHECKPOINT_HEADER_SIZE] = data[..CHECKPOINT_HEADER_SIZE].try_into().unwrap();

    let magic: [u8; 8] = hdr[H_MAGIC..H_MAGIC + 8].try_into().unwrap();
    if magic != CHECKPOINT_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "checkpoint magic mismatch",
        ));
    }

    let version = u32::from_le_bytes(hdr[H_VERSION..H_VERSION + 4].try_into().unwrap());
    if version != CHECKPOINT_VERSION_V1 && version != CHECKPOINT_VERSION_V2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("checkpoint version {version} unsupported"),
        ));
    }

    let stored_checksum = u64::from_le_bytes(
        hdr[H_HEADER_CHECKSUM..H_HEADER_CHECKSUM + 8]
            .try_into()
            .unwrap(),
    );
    if stored_checksum != header_checksum(hdr) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "checkpoint header checksum mismatch",
        ));
    }

    let slot_count =
        u64::from_le_bytes(hdr[H_SLOT_COUNT..H_SLOT_COUNT + 8].try_into().unwrap()) as usize;
    if slot_count == 0 || !slot_count.is_power_of_two() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("checkpoint slot_count {slot_count} is not a positive power of two"),
        ));
    }
    if slot_count > MAX_SLOTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("checkpoint slot_count {slot_count} exceeds MAX_SLOTS {MAX_SLOTS}"),
        ));
    }
    let entry_count =
        u64::from_le_bytes(hdr[H_ENTRY_COUNT..H_ENTRY_COUNT + 8].try_into().unwrap()) as usize;
    if entry_count > slot_count {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("checkpoint entry_count {entry_count} exceeds slot_count {slot_count}"),
        ));
    }
    let cursor_file_id = u32::from_le_bytes(
        hdr[H_CURSOR_FILE_ID..H_CURSOR_FILE_ID + 4]
            .try_into()
            .unwrap(),
    );
    let cursor_offset = u64::from_le_bytes(
        hdr[H_CURSOR_OFFSET..H_CURSOR_OFFSET + 8]
            .try_into()
            .unwrap(),
    );
    let checkpoint_epoch = u64::from_le_bytes(
        hdr[H_CHECKPOINT_EPOCH..H_CHECKPOINT_EPOCH + 8]
            .try_into()
            .unwrap(),
    );

    let shard_count = match version {
        CHECKPOINT_VERSION_V2 => {
            u16::from_le_bytes(hdr[H_SHARD_COUNT..H_SHARD_COUNT + 2].try_into().unwrap())
        }
        _ => 0,
    };

    Ok((
        slot_count,
        entry_count,
        cursor_file_id,
        cursor_offset,
        checkpoint_epoch,
        shard_count,
    ))
}

fn deserialize_shard_positions(data: &[u8], count: usize) -> Vec<(DataFileId, HintOffset)> {
    (0..count)
        .map(|i| {
            let base = i * SHARD_POSITION_SIZE;
            let fid = u32::from_le_bytes(data[base..base + 4].try_into().unwrap());
            let off = u64::from_le_bytes(data[base + 4..base + 12].try_into().unwrap());
            (DataFileId::new(fid), HintOffset::new(off))
        })
        .collect()
}

pub fn read_checkpoint(path: &Path) -> io::Result<(HashTable, CommitEpoch, CheckpointPositions)> {
    let data = std::fs::read(path)?;

    let (slot_count, entry_count, cursor_file_id, cursor_offset, checkpoint_epoch, shard_count) =
        parse_checkpoint_header(&data)?;

    let hdr: &[u8; CHECKPOINT_HEADER_SIZE] = data[..CHECKPOINT_HEADER_SIZE].try_into().unwrap();
    let version = u32::from_le_bytes(hdr[H_VERSION..H_VERSION + 4].try_into().unwrap());

    let slot_region_size = slot_count * SLOT_SIZE;
    let shard_pos_size = shard_count as usize * SHARD_POSITION_SIZE;
    let expected_total = CHECKPOINT_HEADER_SIZE + slot_region_size + shard_pos_size + 16;
    if data.len() < expected_total {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "checkpoint file truncated",
        ));
    }

    let slot_region = &data[CHECKPOINT_HEADER_SIZE..CHECKPOINT_HEADER_SIZE + slot_region_size];
    let shard_pos_start = CHECKPOINT_HEADER_SIZE + slot_region_size;
    let shard_pos_region = &data[shard_pos_start..shard_pos_start + shard_pos_size];

    let data_checksum = match version {
        CHECKPOINT_VERSION_V2 => {
            let mut hasher = xxhash_rust::xxh3::Xxh3::new();
            hasher.update(slot_region);
            hasher.update(shard_pos_region);
            hasher.digest()
        }
        _ => xxhash_rust::xxh3::xxh3_64(slot_region),
    };

    let trailer_start = shard_pos_start + shard_pos_size;
    let stored_data_checksum =
        u64::from_le_bytes(data[trailer_start..trailer_start + 8].try_into().unwrap());
    let stored_trailer_magic = u64::from_le_bytes(
        data[trailer_start + 8..trailer_start + 16]
            .try_into()
            .unwrap(),
    );

    if stored_data_checksum != data_checksum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "checkpoint data checksum mismatch",
        ));
    }
    if stored_trailer_magic != TRAILER_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "checkpoint trailer magic mismatch",
        ));
    }

    let slots = copy_bytes_to_slots(slot_region, slot_count)?;
    let shift = 64 - slot_count.trailing_zeros();

    let actual_count = slots.iter().filter(|s| is_occupied(&s.cid)).count();
    if actual_count != entry_count {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "checkpoint entry_count mismatch: header says {entry_count}, actual {actual_count}"
            ),
        ));
    }

    let cursor = match (cursor_file_id, cursor_offset) {
        (0, 0) => None,
        (fid, off) => Some(WriteCursor {
            file_id: DataFileId::new(fid),
            offset: BlockOffset::new(off),
        }),
    };

    let table = HashTable {
        slots,
        capacity: slot_count,
        count: entry_count,
        shift,
        write_cursor: cursor,
    };

    let epoch = CommitEpoch::new(checkpoint_epoch);

    let positions = match version {
        CHECKPOINT_VERSION_V2 if shard_count > 0 => CheckpointPositions(
            deserialize_shard_positions(shard_pos_region, shard_count as usize),
        ),
        _ => {
            let hint_file_id =
                u32::from_le_bytes(hdr[H_HINT_FILE_ID..H_HINT_FILE_ID + 4].try_into().unwrap());
            let hint_offset =
                u64::from_le_bytes(hdr[H_HINT_OFFSET..H_HINT_OFFSET + 8].try_into().unwrap());
            CheckpointPositions::single(DataFileId::new(hint_file_id), HintOffset::new(hint_offset))
        }
    };

    Ok((table, epoch, positions))
}

pub fn load_best_checkpoint(
    index_dir: &Path,
) -> Option<(HashTable, CommitEpoch, CheckpointPositions)> {
    let path_a = index_dir.join("checkpoint_a.tqc");
    let path_b = index_dir.join("checkpoint_b.tqc");

    let result_a = read_checkpoint(&path_a).ok();
    let result_b = read_checkpoint(&path_b).ok();

    match (result_a, result_b) {
        (Some(a), Some(b)) => match a.1.raw() >= b.1.raw() {
            true => Some(a),
            false => Some(b),
        },
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn read_checkpoint_epoch(path: &Path) -> Option<u64> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut buf = [0u8; CHECKPOINT_HEADER_SIZE];
    std::io::Read::read_exact(&mut file, &mut buf).ok()?;

    let magic: [u8; 8] = buf[H_MAGIC..H_MAGIC + 8].try_into().ok()?;
    if magic != CHECKPOINT_MAGIC {
        return None;
    }

    let version = u32::from_le_bytes(buf[H_VERSION..H_VERSION + 4].try_into().ok()?);
    if version != CHECKPOINT_VERSION_V1 && version != CHECKPOINT_VERSION_V2 {
        return None;
    }

    let stored = u64::from_le_bytes(
        buf[H_HEADER_CHECKSUM..H_HEADER_CHECKSUM + 8]
            .try_into()
            .ok()?,
    );
    if stored != header_checksum(&buf) {
        return None;
    }

    Some(u64::from_le_bytes(
        buf[H_CHECKPOINT_EPOCH..H_CHECKPOINT_EPOCH + 8]
            .try_into()
            .ok()?,
    ))
}

pub fn write_checkpoint_ab(
    table: &HashTable,
    index_dir: &Path,
    epoch: CommitEpoch,
    positions: &CheckpointPositions,
) -> io::Result<()> {
    let path_a = index_dir.join("checkpoint_a.tqc");
    let path_b = index_dir.join("checkpoint_b.tqc");

    let epoch_a = read_checkpoint_epoch(&path_a);
    let epoch_b = read_checkpoint_epoch(&path_b);

    let target_path = match (epoch_a, epoch_b) {
        (Some(a), Some(b)) if a >= b => path_b,
        (Some(_), Some(_)) => path_a,
        (Some(_), None) => path_b,
        (None, _) => path_a,
    };

    write_checkpoint(table, &target_path, epoch, positions)
}

#[derive(Debug)]
pub enum BlockIndexError {
    MissingEntry,
    CapacityExhausted,
}

impl std::fmt::Display for BlockIndexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingEntry => write!(f, "entry not found"),
            Self::CapacityExhausted => write!(f, "hash table capacity exhausted"),
        }
    }
}

impl std::error::Error for BlockIndexError {}

pub struct BlockIndex {
    table: RwLock<HashTable>,
    index_dir: PathBuf,
    checkpoint_lock: parking_lot::Mutex<()>,
    loaded_checkpoint_positions: Option<CheckpointPositions>,
    loaded_checkpoint_epoch: Option<CommitEpoch>,
}

impl BlockIndex {
    pub fn new(table: HashTable, index_dir: PathBuf) -> Self {
        Self {
            table: RwLock::new(table),
            index_dir,
            checkpoint_lock: parking_lot::Mutex::new(()),
            loaded_checkpoint_positions: None,
            loaded_checkpoint_epoch: None,
        }
    }

    pub fn open(index_dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(index_dir)?;
        let (table, checkpoint_positions, checkpoint_epoch) = match load_best_checkpoint(index_dir)
        {
            Some((table, epoch, positions)) => {
                tracing::info!(
                    blocks = table.len(),
                    epoch = epoch.raw(),
                    shard_positions = positions.0.len(),
                    "loaded block index from checkpoint"
                );
                (table, Some(positions), Some(epoch))
            }
            None => {
                tracing::info!("no valid checkpoint found, starting with empty index");
                (HashTable::with_capacity(64), None, None)
            }
        };
        Ok(Self {
            table: RwLock::new(table),
            index_dir: index_dir.to_path_buf(),
            checkpoint_lock: parking_lot::Mutex::new(()),
            loaded_checkpoint_positions: checkpoint_positions,
            loaded_checkpoint_epoch: checkpoint_epoch,
        })
    }

    pub fn loaded_checkpoint_positions(&self) -> Option<&CheckpointPositions> {
        self.loaded_checkpoint_positions.as_ref()
    }

    pub fn loaded_checkpoint_epoch(&self) -> Option<CommitEpoch> {
        self.loaded_checkpoint_epoch
    }

    pub fn get(&self, cid: &[u8; CID_SIZE]) -> Option<IndexEntry> {
        self.table.read().get(cid).map(|s| s.to_index_entry())
    }

    pub fn has(&self, cid: &[u8; CID_SIZE]) -> bool {
        self.table.read().contains_live(cid)
    }

    pub fn live_entries_snapshot(&self) -> Vec<([u8; CID_SIZE], RefCount)> {
        self.table
            .read()
            .iter()
            .filter(|s| !s.refcount.is_zero())
            .map(|s| (s.cid, s.refcount))
            .collect()
    }

    pub fn batch_put(
        &self,
        entries: &[([u8; CID_SIZE], BlockLocation)],
        decrements: &[[u8; CID_SIZE]],
        cursor: WriteCursor,
        epoch: CommitEpoch,
        now: WallClockMs,
    ) -> Result<(), BlockIndexError> {
        self.batch_put_inner(entries, decrements, cursor, epoch, now, None)
    }

    pub fn batch_put_and_advance_position(
        &self,
        entries: &[([u8; CID_SIZE], BlockLocation)],
        decrements: &[[u8; CID_SIZE]],
        cursor: WriteCursor,
        epoch: CommitEpoch,
        now: WallClockMs,
        position_update: PositionUpdate<'_>,
    ) -> Result<(), BlockIndexError> {
        self.batch_put_inner(
            entries,
            decrements,
            cursor,
            epoch,
            now,
            Some(position_update),
        )
    }

    fn batch_put_inner(
        &self,
        entries: &[([u8; CID_SIZE], BlockLocation)],
        decrements: &[[u8; CID_SIZE]],
        cursor: WriteCursor,
        epoch: CommitEpoch,
        now: WallClockMs,
        position_update: Option<PositionUpdate<'_>>,
    ) -> Result<(), BlockIndexError> {
        let mut table = self.table.write();

        entries.iter().try_for_each(|(cid, location)| {
            table
                .insert_or_increment(cid, *location)
                .map(|_| ())
                .map_err(|_| BlockIndexError::CapacityExhausted)
        })?;

        decrements.iter().for_each(|cid| {
            if table.decrement(cid, epoch, now).is_none() {
                tracing::warn!(
                    ?cid,
                    "decrement on missing entry during batch_put, skipping"
                );
            }
        });

        table.set_write_cursor(cursor);

        if let Some(pos) = position_update {
            pos.hint_positions
                .update(pos.shard_id, pos.file_id, pos.offset);
        }

        Ok(())
    }

    pub fn batch_put_buffered(
        &self,
        entries: &[([u8; CID_SIZE], BlockLocation)],
        cursor: WriteCursor,
    ) -> Result<(), BlockIndexError> {
        let mut table = self.table.write();
        entries.iter().try_for_each(|(cid, location)| {
            table
                .insert_or_increment(cid, *location)
                .map(|_| ())
                .map_err(|_| BlockIndexError::CapacityExhausted)
        })?;
        table.set_write_cursor(cursor);
        Ok(())
    }

    pub fn batch_insert_buffered(
        &self,
        entries: &[([u8; CID_SIZE], BlockLocation)],
    ) -> Result<(), BlockIndexError> {
        if entries.is_empty() {
            return Ok(());
        }
        let mut table = self.table.write();
        entries.iter().try_for_each(|(cid, location)| {
            table
                .insert_or_increment(cid, *location)
                .map(|_| ())
                .map_err(|_| BlockIndexError::CapacityExhausted)
        })?;
        Ok(())
    }

    pub fn batch_put_if_absent(
        &self,
        entries: &[([u8; CID_SIZE], BlockLocation)],
        cursor: WriteCursor,
    ) -> Result<u64, BlockIndexError> {
        let mut table = self.table.write();
        let inserted = entries.iter().try_fold(0u64, |acc, (cid, location)| {
            table
                .insert_if_absent(cid, *location)
                .map(|was_new| acc.saturating_add(was_new as u64))
                .map_err(|_| BlockIndexError::CapacityExhausted)
        })?;
        table.set_write_cursor(cursor);
        Ok(inserted)
    }

    pub fn batch_relocate(
        &self,
        relocations: &[(CidBytes, BlockLocation, u32)],
    ) -> Result<(), BlockIndexError> {
        if relocations.is_empty() {
            return Ok(());
        }
        let mut table = self.table.write();
        relocations
            .iter()
            .try_for_each(|(cid, location, refcount)| {
                table
                    .relocate(cid, *location, RefCount::new(*refcount))
                    .map(|_| ())
                    .map_err(|_| BlockIndexError::CapacityExhausted)
            })
    }

    pub fn batch_remove(&self, cids: &[CidBytes]) {
        if cids.is_empty() {
            return;
        }
        let mut table = self.table.write();
        cids.iter().for_each(|cid| {
            let _ = table.remove(cid);
        });
    }

    pub fn batch_decrement(
        &self,
        decrements: &[[u8; CID_SIZE]],
        epoch: CommitEpoch,
        now: WallClockMs,
    ) -> Result<(), BlockIndexError> {
        if decrements.is_empty() {
            return Ok(());
        }
        let mut table = self.table.write();
        decrements.iter().for_each(|cid| {
            if table.decrement(cid, epoch, now).is_none() {
                tracing::warn!(?cid, "deferred decrement on missing entry, skipping");
            }
        });
        Ok(())
    }

    pub fn decrement_refcount(
        &self,
        cid: &[u8; CID_SIZE],
        epoch: CommitEpoch,
        now: WallClockMs,
    ) -> Result<RefCount, BlockIndexError> {
        self.table
            .write()
            .decrement(cid, epoch, now)
            .ok_or(BlockIndexError::MissingEntry)
    }

    pub fn collect_dead_blocks(
        &self,
        current_epoch: CommitEpoch,
        now: WallClockMs,
        grace_period_ms: u64,
    ) -> CollectionResult {
        self.table
            .read()
            .collect_dead_blocks(current_epoch, now, grace_period_ms)
    }

    pub fn is_gc_eligible(
        &self,
        cid: &[u8; CID_SIZE],
        current_epoch: CommitEpoch,
        now: WallClockMs,
        grace_period_ms: u64,
    ) -> bool {
        self.table
            .read()
            .is_gc_eligible(cid, current_epoch, now, grace_period_ms)
    }

    pub fn apply_compaction(
        &self,
        relocations: &[(CidBytes, BlockLocation)],
        removals: &[CidBytes],
    ) {
        self.table.write().apply_compaction(relocations, removals);
    }

    pub fn cleanup_stale_gc_meta(&self) -> u64 {
        self.table.write().cleanup_stale_gc()
    }

    pub fn liveness_info(&self, file_id: DataFileId) -> LivenessInfo {
        self.table.read().liveness_info(file_id)
    }

    pub fn liveness_by_file(
        &self,
        current_epoch: CommitEpoch,
        now: WallClockMs,
        grace_period_ms: u64,
    ) -> HashMap<DataFileId, LivenessInfo> {
        self.table
            .read()
            .liveness_by_file(current_epoch, now, grace_period_ms)
    }

    pub fn find_leaked_refcounts(
        &self,
        is_reachable: impl Fn(&CidBytes) -> bool,
    ) -> (Vec<(CidBytes, RefCount)>, u64) {
        self.table.read().find_leaked_refcounts(is_reachable)
    }

    pub fn repair_leaked_refcounts(
        &self,
        leaked_cids: &[(CidBytes, RefCount)],
        epoch: CommitEpoch,
        now: WallClockMs,
    ) -> u64 {
        let mut table = self.table.write();
        leaked_cids
            .iter()
            .fold(0u64, |acc, (cid, expected_rc)| match table.get_mut(cid) {
                Some(slot) if slot.refcount == *expected_rc => {
                    slot.refcount = RefCount::new(0);
                    slot.gc_since_ms = now;
                    slot.gc_epoch = epoch;
                    acc.saturating_add(1)
                }
                _ => acc,
            })
    }

    pub fn read_write_cursor(&self) -> Option<WriteCursor> {
        self.table.read().write_cursor()
    }

    pub fn set_write_cursor(&self, cursor: WriteCursor) -> Result<(), BlockIndexError> {
        self.table.write().set_write_cursor(cursor);
        Ok(())
    }

    pub fn approximate_block_count(&self) -> u64 {
        self.table.read().approximate_count()
    }

    pub fn write_checkpoint(
        &self,
        epoch: CommitEpoch,
        hint_positions: &ShardHintPositions,
    ) -> io::Result<()> {
        let _guard = self.checkpoint_lock.lock();
        let table = self.table.read();
        let positions = hint_positions.snapshot();
        write_checkpoint_ab(&table, &self.index_dir, epoch, &positions)
    }

    pub fn write_checkpoint_with_positions(
        &self,
        epoch: CommitEpoch,
        positions: &CheckpointPositions,
    ) -> io::Result<()> {
        let _guard = self.checkpoint_lock.lock();
        let table = self.table.read();
        write_checkpoint_ab(&table, &self.index_dir, epoch, positions)
    }

    pub fn index_dir(&self) -> &Path {
        &self.index_dir
    }

    pub fn rebuild_from_hints<S: crate::io::StorageIO>(
        &self,
        io: &S,
        data_dir: &Path,
    ) -> Result<(), super::hint::RebuildError> {
        use super::data_file::BLOCK_RECORD_OVERHEAD;
        use super::hint::{
            HINT_FILE_EXTENSION, HintFileReader, ReadHintRecord, RebuildError, hint_file_path,
        };
        use super::list_files_by_extension;

        let hint_files = list_files_by_extension(io, data_dir, HINT_FILE_EXTENSION)?;
        if hint_files.is_empty() {
            return Err(RebuildError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                "no hint files found for rebuild",
            )));
        }

        let mut table = self.table.write();
        let mut max_cursor: Option<WriteCursor> = None;

        hint_files.iter().try_for_each(|&fid| {
            let path = hint_file_path(data_dir, fid);
            let fd = io.open(&path, crate::io::OpenOptions::read_only_existing())?;
            let mut reader = HintFileReader::open(io, fd)?;

            reader.try_for_each(|result| {
                match result? {
                    ReadHintRecord::Put {
                        cid_bytes,
                        file_id,
                        offset,
                        length,
                    } => {
                        let loc = BlockLocation {
                            file_id,
                            offset,
                            length,
                        };
                        table.insert_or_increment(&cid_bytes, loc).map_err(|_| {
                            io::Error::other("hash table capacity exhausted during rebuild")
                        })?;

                        let end = offset.advance(BLOCK_RECORD_OVERHEAD as u64 + length.as_u64());
                        let candidate = WriteCursor {
                            file_id,
                            offset: end,
                        };
                        match &max_cursor {
                            Some(c)
                                if (candidate.file_id, candidate.offset)
                                    > (c.file_id, c.offset) =>
                            {
                                max_cursor = Some(candidate);
                            }
                            None => max_cursor = Some(candidate),
                            _ => {}
                        }
                    }
                    ReadHintRecord::Decrement {
                        cid_bytes,
                        epoch,
                        timestamp,
                    } => {
                        if table.decrement(&cid_bytes, epoch, timestamp).is_none() {
                            tracing::warn!("decrement for missing entry during rebuild, skipping");
                        }
                    }
                    ReadHintRecord::Relocate {
                        cid_bytes,
                        file_id,
                        offset,
                        length,
                        refcount,
                    } => {
                        let loc = BlockLocation {
                            file_id,
                            offset,
                            length,
                        };
                        table
                            .relocate(&cid_bytes, loc, RefCount::new(refcount))
                            .map_err(|_| {
                                io::Error::other("hash table capacity exhausted during rebuild")
                            })?;
                    }
                    ReadHintRecord::Remove { cid_bytes } => {
                        let _ = table.remove(&cid_bytes);
                    }
                    ReadHintRecord::UnknownVersion { .. }
                    | ReadHintRecord::UnknownType { .. }
                    | ReadHintRecord::Corrupted
                    | ReadHintRecord::Truncated => {}
                }
                Ok::<_, io::Error>(())
            })?;

            let _ = io.close(fd);
            Ok::<_, RebuildError>(())
        })?;

        if let Some(cursor) = max_cursor {
            table.set_write_cursor(cursor);
        }

        Ok(())
    }

    pub fn rebuild_from_data_files<S: crate::io::StorageIO>(
        &self,
        io: &S,
        data_dir: &Path,
    ) -> Result<(), super::hint::RebuildError> {
        use super::hint::RebuildError;
        use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

        let data_files =
            super::list_files_by_extension(io, data_dir, super::manager::DATA_FILE_EXTENSION)?;

        let file_results: Vec<Result<Vec<_>, RebuildError>> = data_files
            .par_iter()
            .map(|&file_id| {
                let path =
                    data_dir.join(format!("{file_id}.{}", super::manager::DATA_FILE_EXTENSION,));
                let fd = io.open(&path, crate::io::OpenOptions::read_only_existing())?;
                let reader = super::data_file::DataFileReader::open(io, fd)?;

                let entries: Result<Vec<_>, RebuildError> = reader
                    .filter_map(|r| match r {
                        Ok(super::data_file::ReadBlockRecord::Valid {
                            offset,
                            cid_bytes,
                            data,
                        }) => {
                            let length = super::types::BlockLength::new(
                                u32::try_from(data.len()).expect("block size validated"),
                            );
                            Some(Ok((
                                cid_bytes,
                                super::types::BlockLocation {
                                    file_id,
                                    offset,
                                    length,
                                },
                            )))
                        }
                        Ok(_) => None,
                        Err(e) => Some(Err(RebuildError::Io(e))),
                    })
                    .collect();

                let _ = io.close(fd);
                entries
            })
            .collect();

        let mut table = self.table.write();
        let mut max_cursor: Option<WriteCursor> = None;
        file_results.into_iter().try_for_each(|result| {
            result?.into_iter().try_for_each(|(cid_bytes, location)| {
                table
                    .insert_or_increment(&cid_bytes, location)
                    .map_err(|_| {
                        RebuildError::Io(io::Error::other(
                            "hash table capacity exhausted during rebuild",
                        ))
                    })?;
                let end = location.offset.advance(
                    super::data_file::BLOCK_RECORD_OVERHEAD as u64 + location.length.as_u64(),
                );
                let new_cursor = WriteCursor {
                    file_id: location.file_id,
                    offset: end,
                };
                match &max_cursor {
                    Some(c) if (new_cursor.file_id, new_cursor.offset) > (c.file_id, c.offset) => {
                        max_cursor = Some(new_cursor);
                    }
                    None => {
                        max_cursor = Some(new_cursor);
                    }
                    _ => {}
                }
                Ok::<_, RebuildError>(())
            })
        })?;

        if let Some(cursor) = max_cursor {
            table.set_write_cursor(cursor);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cid(seed: u8) -> [u8; CID_SIZE] {
        let mut cid = [0u8; CID_SIZE];
        cid[0] = 0x01;
        cid[1] = 0x71;
        cid[2] = 0x12;
        cid[3] = 0x20;
        cid[4] = seed;
        cid
    }

    fn test_loc(file: u32, offset: u64, length: u32) -> BlockLocation {
        BlockLocation {
            file_id: DataFileId::new(file),
            offset: BlockOffset::new(offset),
            length: BlockLength::new(length),
        }
    }

    #[test]
    fn insert_and_get() {
        let mut table = HashTable::with_capacity(64);
        let cid = test_cid(1);
        let loc = test_loc(0, 100, 256);

        table.insert_or_increment(&cid, loc).unwrap();

        let slot = table.get(&cid).unwrap();
        assert_eq!(slot.refcount, RefCount::one());
        assert_eq!(slot.file_id, DataFileId::new(0));
        assert_eq!(slot.offset, BlockOffset::new(100));
        assert_eq!(slot.length, BlockLength::new(256));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn get_missing_returns_none() {
        let table = HashTable::with_capacity(64);
        assert!(table.get(&test_cid(42)).is_none());
    }

    #[test]
    fn duplicate_insert_increments_refcount() {
        let mut table = HashTable::with_capacity(64);
        let cid = test_cid(1);
        let loc = test_loc(0, 100, 256);

        table.insert_or_increment(&cid, loc).unwrap();
        table
            .insert_or_increment(&cid, test_loc(1, 200, 512))
            .unwrap();

        let slot = table.get(&cid).unwrap();
        assert_eq!(slot.refcount, RefCount::new(2));
        assert_eq!(slot.file_id, DataFileId::new(0));
        assert_eq!(slot.offset, BlockOffset::new(100));
    }

    #[test]
    fn decrement_to_zero_sets_gc() {
        let mut table = HashTable::with_capacity(64);
        let cid = test_cid(1);
        table.insert_or_increment(&cid, test_loc(0, 0, 10)).unwrap();

        let rc = table
            .decrement(&cid, CommitEpoch::new(5), WallClockMs::new(1_000_000))
            .unwrap();
        assert!(rc.is_zero());

        let slot = table.get(&cid).unwrap();
        assert_eq!(slot.gc_since_ms, WallClockMs::new(1_000_000));
        assert_eq!(slot.gc_epoch, CommitEpoch::new(5));
    }

    #[test]
    fn re_increment_clears_gc() {
        let mut table = HashTable::with_capacity(64);
        let cid = test_cid(1);
        let loc = test_loc(0, 0, 10);
        table.insert_or_increment(&cid, loc).unwrap();
        let _ = table.decrement(&cid, CommitEpoch::new(1), WallClockMs::new(1000));

        assert!(table.get(&cid).unwrap().gc_since_ms > WallClockMs::new(0));

        table.insert_or_increment(&cid, loc).unwrap();

        let slot = table.get(&cid).unwrap();
        assert_eq!(slot.refcount, RefCount::one());
        assert_eq!(slot.gc_since_ms, WallClockMs::new(0));
        assert_eq!(slot.gc_epoch, CommitEpoch::new(0));
    }

    #[test]
    fn decrement_missing_returns_none() {
        let mut table = HashTable::with_capacity(64);
        assert!(
            table
                .decrement(&test_cid(99), CommitEpoch::zero(), WallClockMs::new(0))
                .is_none()
        );
    }

    #[test]
    fn remove_entry() {
        let mut table = HashTable::with_capacity(64);
        let cid = test_cid(1);
        table.insert_or_increment(&cid, test_loc(0, 0, 10)).unwrap();

        assert!(table.remove(&cid));
        assert!(!table.contains(&cid));
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn remove_missing_returns_false() {
        let mut table = HashTable::with_capacity(64);
        assert!(!table.remove(&test_cid(99)));
    }

    #[test]
    fn many_inserts_trigger_grow() {
        let mut table = HashTable::with_capacity(64);
        let initial_cap = table.capacity();

        (0..50u8).for_each(|i| {
            table
                .insert_or_increment(&test_cid(i), test_loc(0, i as u64 * 100, 50))
                .unwrap();
        });

        assert!(table.capacity() > initial_cap);
        assert_eq!(table.len(), 50);

        (0..50u8).for_each(|i| {
            assert!(table.contains(&test_cid(i)), "missing {i} after grow");
        });
    }

    #[test]
    fn collect_dead_blocks_respects_grace() {
        let mut table = HashTable::with_capacity(64);
        let cid = test_cid(1);
        table
            .insert_or_increment(&cid, test_loc(0, 0, 100))
            .unwrap();
        let _ = table.decrement(&cid, CommitEpoch::new(1), WallClockMs::new(1_000));

        let result = table.collect_dead_blocks(CommitEpoch::new(2), WallClockMs::new(1_500), 1_000);
        assert!(result.candidates.is_empty());

        let result = table.collect_dead_blocks(CommitEpoch::new(2), WallClockMs::new(2_001), 1_000);
        assert_eq!(result.candidates.len(), 1);
    }

    #[test]
    fn collect_dead_blocks_respects_epoch() {
        let mut table = HashTable::with_capacity(64);
        let cid = test_cid(1);
        table
            .insert_or_increment(&cid, test_loc(0, 0, 100))
            .unwrap();
        let _ = table.decrement(&cid, CommitEpoch::new(3), WallClockMs::new(1_000));

        let result = table.collect_dead_blocks(CommitEpoch::new(3), WallClockMs::new(999_999), 0);
        assert!(result.candidates.is_empty());

        let result = table.collect_dead_blocks(CommitEpoch::new(4), WallClockMs::new(999_999), 0);
        assert_eq!(result.candidates.len(), 1);
    }

    #[test]
    fn apply_compaction_relocates_and_removes() {
        let mut table = HashTable::with_capacity(64);
        let cid_live = test_cid(1);
        let cid_dead = test_cid(2);
        table
            .insert_or_increment(&cid_live, test_loc(0, 0, 50))
            .unwrap();
        table
            .insert_or_increment(&cid_dead, test_loc(0, 100, 50))
            .unwrap();

        let new_loc = test_loc(1, 0, 50);
        table.apply_compaction(&[(cid_live, new_loc)], &[cid_dead]);

        let slot = table.get(&cid_live).unwrap();
        assert_eq!(slot.file_id, DataFileId::new(1));
        assert_eq!(slot.offset, BlockOffset::new(0));
        assert!(!table.contains(&cid_dead));
    }

    #[test]
    fn write_cursor_round_trip() {
        let mut table = HashTable::with_capacity(64);
        assert!(table.write_cursor().is_none());

        let cursor = WriteCursor {
            file_id: DataFileId::new(3),
            offset: BlockOffset::new(65536),
        };
        table.set_write_cursor(cursor);
        assert_eq!(table.write_cursor(), Some(cursor));
    }

    #[test]
    fn liveness_info_by_file() {
        let mut table = HashTable::with_capacity(64);
        table
            .insert_or_increment(&test_cid(1), test_loc(0, 0, 100))
            .unwrap();
        table
            .insert_or_increment(&test_cid(2), test_loc(0, 200, 50))
            .unwrap();
        table
            .insert_or_increment(&test_cid(3), test_loc(1, 0, 75))
            .unwrap();
        let _ = table.decrement(&test_cid(1), CommitEpoch::zero(), WallClockMs::new(1000));

        let info = table.liveness_info(DataFileId::new(0));
        assert_eq!(info.total_blocks, 2);
        assert_eq!(info.live_blocks, 1);
    }

    #[test]
    fn cleanup_stale_gc() {
        let mut table = HashTable::with_capacity(64);
        let cid = test_cid(1);
        table.insert_or_increment(&cid, test_loc(0, 0, 10)).unwrap();
        let _ = table.decrement(&cid, CommitEpoch::new(1), WallClockMs::new(1000));
        table.insert_or_increment(&cid, test_loc(0, 0, 10)).unwrap();

        let slot = table.get(&cid).unwrap();
        assert_eq!(slot.gc_since_ms, WallClockMs::new(0));

        table
            .slots
            .iter_mut()
            .filter(|s| s.cid == cid)
            .for_each(|s| {
                s.gc_since_ms = WallClockMs::new(999);
                s.gc_epoch = CommitEpoch::new(1);
            });

        let cleaned = table.cleanup_stale_gc();
        assert_eq!(cleaned, 1);
        assert_eq!(table.get(&cid).unwrap().gc_since_ms, WallClockMs::new(0));
    }

    #[test]
    fn iter_skips_empty_and_removed() {
        let mut table = HashTable::with_capacity(64);
        table
            .insert_or_increment(&test_cid(1), test_loc(0, 0, 10))
            .unwrap();
        table
            .insert_or_increment(&test_cid(2), test_loc(0, 100, 10))
            .unwrap();
        table
            .insert_or_increment(&test_cid(3), test_loc(0, 200, 10))
            .unwrap();
        let _ = table.remove(&test_cid(2));

        let count = table.iter().count();
        assert_eq!(count, 2);
    }

    #[test]
    fn reinsert_after_remove() {
        let mut table = HashTable::with_capacity(64);
        let cid = test_cid(1);
        table.insert_or_increment(&cid, test_loc(0, 0, 10)).unwrap();
        let _ = table.remove(&cid);

        table
            .insert_or_increment(&cid, test_loc(1, 100, 20))
            .unwrap();
        assert_eq!(table.len(), 1);

        let slot = table.get(&cid).unwrap();
        assert_eq!(slot.file_id, DataFileId::new(1));
        assert_eq!(slot.offset, BlockOffset::new(100));
    }

    #[test]
    fn stress_insert_remove_cycle() {
        let mut table = HashTable::with_capacity(64);

        (0..200u8).for_each(|i| {
            let mut cid = [0u8; CID_SIZE];
            cid[0] = 0x01;
            cid[1] = 0x71;
            cid[2] = 0x12;
            cid[3] = 0x20;
            cid[4] = i;
            cid[5] = (i as u16 * 7 % 256) as u8;
            table
                .insert_or_increment(&cid, test_loc(0, i as u64 * 100, 50))
                .unwrap();
        });

        assert_eq!(table.len(), 200);

        (0..100u8).for_each(|i| {
            let mut cid = [0u8; CID_SIZE];
            cid[0] = 0x01;
            cid[1] = 0x71;
            cid[2] = 0x12;
            cid[3] = 0x20;
            cid[4] = i;
            cid[5] = (i as u16 * 7 % 256) as u8;
            let _ = table.remove(&cid);
        });

        assert_eq!(table.len(), 100);

        (100..200u8).for_each(|i| {
            let mut cid = [0u8; CID_SIZE];
            cid[0] = 0x01;
            cid[1] = 0x71;
            cid[2] = 0x12;
            cid[3] = 0x20;
            cid[4] = i;
            cid[5] = (i as u16 * 7 % 256) as u8;
            assert!(table.contains(&cid), "entry {i} missing after remove cycle");
        });
    }

    #[test]
    fn checkpoint_round_trip() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut table = HashTable::with_capacity(64);

        (0..10u8).for_each(|i| {
            table
                .insert_or_increment(&test_cid(i), test_loc(0, i as u64 * 100, 50))
                .unwrap();
        });
        let _ = table.decrement(&test_cid(0), CommitEpoch::new(3), WallClockMs::new(5000));
        table.set_write_cursor(WriteCursor {
            file_id: DataFileId::new(2),
            offset: BlockOffset::new(9999),
        });

        let path = dir.path().join("test.tqc");
        let epoch = CommitEpoch::new(42);
        let positions = CheckpointPositions::single(DataFileId::new(5), HintOffset::new(12345));

        write_checkpoint(&table, &path, epoch, &positions).unwrap();
        let (restored, restored_epoch, restored_pos) = read_checkpoint(&path).unwrap();

        assert_eq!(restored.len(), 10);
        assert_eq!(restored_epoch.raw(), 42);
        assert_eq!(restored_pos.0.len(), 1);
        assert_eq!(restored_pos.0[0].0.raw(), 5);
        assert_eq!(restored_pos.0[0].1.raw(), 12345);

        (0..10u8).for_each(|i| {
            let slot = restored.get(&test_cid(i)).unwrap();
            assert_eq!(slot.offset, BlockOffset::new(i as u64 * 100));
        });

        let slot0 = restored.get(&test_cid(0)).unwrap();
        assert_eq!(slot0.refcount, RefCount::new(0));
        assert_eq!(slot0.gc_since_ms, WallClockMs::new(5000));
        assert_eq!(slot0.gc_epoch, CommitEpoch::new(3));

        let cursor = restored.write_cursor().unwrap();
        assert_eq!(cursor.file_id, DataFileId::new(2));
        assert_eq!(cursor.offset, BlockOffset::new(9999));
    }

    #[test]
    fn checkpoint_ab_alternates() {
        let dir = tempfile::TempDir::new().unwrap();
        let pos = CheckpointPositions::single(DataFileId::new(0), HintOffset::new(0));

        let mut table = HashTable::with_capacity(64);
        table
            .insert_or_increment(&test_cid(1), test_loc(0, 0, 10))
            .unwrap();
        write_checkpoint_ab(&table, dir.path(), CommitEpoch::new(1), &pos).unwrap();

        table
            .insert_or_increment(&test_cid(2), test_loc(0, 100, 10))
            .unwrap();
        write_checkpoint_ab(&table, dir.path(), CommitEpoch::new(2), &pos).unwrap();

        let (best, epoch, _) = load_best_checkpoint(dir.path()).unwrap();
        assert_eq!(epoch.raw(), 2);
        assert_eq!(best.len(), 2);
    }

    #[test]
    fn checkpoint_corrupt_falls_back() {
        let dir = tempfile::TempDir::new().unwrap();
        let pos = CheckpointPositions::single(DataFileId::new(0), HintOffset::new(0));

        let mut table = HashTable::with_capacity(64);
        table
            .insert_or_increment(&test_cid(1), test_loc(0, 0, 10))
            .unwrap();
        write_checkpoint_ab(&table, dir.path(), CommitEpoch::new(1), &pos).unwrap();

        table
            .insert_or_increment(&test_cid(2), test_loc(0, 100, 10))
            .unwrap();
        write_checkpoint_ab(&table, dir.path(), CommitEpoch::new(2), &pos).unwrap();

        std::fs::write(dir.path().join("checkpoint_b.tqc"), b"corrupt").unwrap();

        let (best, epoch, _) = load_best_checkpoint(dir.path()).unwrap();
        assert_eq!(epoch.raw(), 1);
        assert_eq!(best.len(), 1);
    }

    #[test]
    fn both_checkpoints_corrupt_returns_none() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("checkpoint_a.tqc"), b"corrupt").unwrap();
        std::fs::write(dir.path().join("checkpoint_b.tqc"), b"corrupt").unwrap();
        assert!(load_best_checkpoint(dir.path()).is_none());
    }

    #[test]
    fn no_checkpoints_returns_none() {
        let dir = tempfile::TempDir::new().unwrap();
        assert!(load_best_checkpoint(dir.path()).is_none());
    }
}
