use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

use crate::io::{FileId, OpenOptions, StorageIO};

use super::data_file::{BLOCK_RECORD_OVERHEAD, CID_SIZE};
use super::list_files_by_extension;
use super::types::{
    BlockLength, BlockLocation, BlockOffset, CidBytes, CommitEpoch, DataFileId, HintOffset,
    MAX_BLOCK_SIZE, WallClockMs, WriteCursor,
};

pub const HINT_RECORD_SIZE: usize = 1 + 3 + CID_SIZE + 8 + 8 + 8;
pub const HINT_FILE_EXTENSION: &str = "tqh";

const _: () = assert!(HINT_RECORD_SIZE == 64);

const HINT_PAYLOAD_SIZE: usize = HINT_RECORD_SIZE - 8;

const RECORD_TYPE_PUT: u8 = 0x01;
const RECORD_TYPE_DECREMENT: u8 = 0x02;
const RECORD_TYPE_RELOCATE: u8 = 0x03;
const RECORD_TYPE_REMOVE: u8 = 0x04;

const HINT_FORMAT_VERSION: u8 = 1;

fn hint_checksum(payload: &[u8]) -> u64 {
    xxhash_rust::xxh3::xxh3_64(payload)
}

pub fn hint_file_path(data_dir: &Path, file_id: DataFileId) -> PathBuf {
    data_dir.join(format!("{file_id}.{HINT_FILE_EXTENSION}"))
}

const TYPE_OFFSET: usize = 0;
const VERSION_OFFSET: usize = 1;
const CID_OFFSET: usize = 4;
const FIELD_A_OFFSET: usize = CID_OFFSET + CID_SIZE;
const FIELD_B_OFFSET: usize = FIELD_A_OFFSET + 8;
const CHECKSUM_OFFSET: usize = FIELD_B_OFFSET + 8;

fn write_hint_record<S: StorageIO>(
    io: &S,
    fd: FileId,
    write_offset: HintOffset,
    record: &[u8; HINT_RECORD_SIZE],
) -> io::Result<()> {
    assert!(
        write_offset.raw().is_multiple_of(HINT_RECORD_SIZE as u64),
        "hint write_offset {} not aligned to HINT_RECORD_SIZE {}",
        write_offset.raw(),
        HINT_RECORD_SIZE,
    );
    io.write_all_at(fd, write_offset.raw(), record)
}

pub(crate) fn encode_hint_record<S: StorageIO>(
    io: &S,
    fd: FileId,
    write_offset: HintOffset,
    cid_bytes: &[u8; CID_SIZE],
    file_id: DataFileId,
    block_offset: BlockOffset,
    length: BlockLength,
) -> io::Result<()> {
    let mut record = [0u8; HINT_RECORD_SIZE];
    record[TYPE_OFFSET] = RECORD_TYPE_PUT;
    record[VERSION_OFFSET] = HINT_FORMAT_VERSION;
    record[CID_OFFSET..CID_OFFSET + CID_SIZE].copy_from_slice(cid_bytes);
    record[FIELD_A_OFFSET..FIELD_A_OFFSET + 4].copy_from_slice(&file_id.raw().to_le_bytes());
    record[FIELD_A_OFFSET + 4..FIELD_A_OFFSET + 8].copy_from_slice(&length.raw().to_le_bytes());
    record[FIELD_B_OFFSET..FIELD_B_OFFSET + 8].copy_from_slice(&block_offset.raw().to_le_bytes());

    let checksum = hint_checksum(&record[..HINT_PAYLOAD_SIZE]);
    record[CHECKSUM_OFFSET..].copy_from_slice(&checksum.to_le_bytes());

    write_hint_record(io, fd, write_offset, &record)
}

const REFCOUNT_OFFSET: usize = 2;

pub(crate) fn encode_relocate_record<S: StorageIO>(
    io: &S,
    fd: FileId,
    write_offset: HintOffset,
    cid_bytes: &[u8; CID_SIZE],
    file_id: DataFileId,
    block_offset: BlockOffset,
    length: BlockLength,
    refcount: u32,
) -> io::Result<()> {
    let mut record = [0u8; HINT_RECORD_SIZE];
    record[TYPE_OFFSET] = RECORD_TYPE_RELOCATE;
    record[VERSION_OFFSET] = HINT_FORMAT_VERSION;
    let rc16 = u16::try_from(refcount).unwrap_or(u16::MAX);
    record[REFCOUNT_OFFSET..REFCOUNT_OFFSET + 2].copy_from_slice(&rc16.to_le_bytes());
    record[CID_OFFSET..CID_OFFSET + CID_SIZE].copy_from_slice(cid_bytes);
    record[FIELD_A_OFFSET..FIELD_A_OFFSET + 4].copy_from_slice(&file_id.raw().to_le_bytes());
    record[FIELD_A_OFFSET + 4..FIELD_A_OFFSET + 8].copy_from_slice(&length.raw().to_le_bytes());
    record[FIELD_B_OFFSET..FIELD_B_OFFSET + 8].copy_from_slice(&block_offset.raw().to_le_bytes());

    let checksum = hint_checksum(&record[..HINT_PAYLOAD_SIZE]);
    record[CHECKSUM_OFFSET..].copy_from_slice(&checksum.to_le_bytes());

    write_hint_record(io, fd, write_offset, &record)
}

pub(crate) fn encode_remove_record<S: StorageIO>(
    io: &S,
    fd: FileId,
    write_offset: HintOffset,
    cid_bytes: &[u8; CID_SIZE],
) -> io::Result<()> {
    let mut record = [0u8; HINT_RECORD_SIZE];
    record[TYPE_OFFSET] = RECORD_TYPE_REMOVE;
    record[VERSION_OFFSET] = HINT_FORMAT_VERSION;
    record[CID_OFFSET..CID_OFFSET + CID_SIZE].copy_from_slice(cid_bytes);

    let checksum = hint_checksum(&record[..HINT_PAYLOAD_SIZE]);
    record[CHECKSUM_OFFSET..].copy_from_slice(&checksum.to_le_bytes());

    write_hint_record(io, fd, write_offset, &record)
}

pub(crate) fn encode_decrement_record<S: StorageIO>(
    io: &S,
    fd: FileId,
    write_offset: HintOffset,
    cid_bytes: &[u8; CID_SIZE],
    epoch: CommitEpoch,
    timestamp: WallClockMs,
) -> io::Result<()> {
    let mut record = [0u8; HINT_RECORD_SIZE];
    record[TYPE_OFFSET] = RECORD_TYPE_DECREMENT;
    record[VERSION_OFFSET] = HINT_FORMAT_VERSION;
    record[CID_OFFSET..CID_OFFSET + CID_SIZE].copy_from_slice(cid_bytes);
    record[FIELD_A_OFFSET..FIELD_A_OFFSET + 8].copy_from_slice(&epoch.raw().to_le_bytes());
    record[FIELD_B_OFFSET..FIELD_B_OFFSET + 8].copy_from_slice(&timestamp.raw().to_le_bytes());

    let checksum = hint_checksum(&record[..HINT_PAYLOAD_SIZE]);
    record[CHECKSUM_OFFSET..].copy_from_slice(&checksum.to_le_bytes());

    write_hint_record(io, fd, write_offset, &record)
}

#[must_use]
#[derive(Debug)]
pub enum ReadHintRecord {
    Put {
        cid_bytes: [u8; CID_SIZE],
        file_id: DataFileId,
        offset: BlockOffset,
        length: BlockLength,
    },
    Decrement {
        cid_bytes: [u8; CID_SIZE],
        epoch: CommitEpoch,
        timestamp: WallClockMs,
    },
    Relocate {
        cid_bytes: [u8; CID_SIZE],
        file_id: DataFileId,
        offset: BlockOffset,
        length: BlockLength,
        refcount: u32,
    },
    Remove {
        cid_bytes: [u8; CID_SIZE],
    },
    UnknownVersion {
        version: u8,
    },
    UnknownType {
        record_type: u8,
    },
    Corrupted,
    Truncated,
}

pub fn decode_hint_record<S: StorageIO>(
    io: &S,
    fd: FileId,
    read_offset: HintOffset,
    file_size: u64,
) -> io::Result<Option<ReadHintRecord>> {
    let raw = read_offset.raw();
    let remaining = match file_size.checked_sub(raw) {
        Some(r) => r,
        None => return Ok(None),
    };
    if remaining == 0 {
        return Ok(None);
    }

    if remaining < HINT_RECORD_SIZE as u64 {
        return Ok(Some(ReadHintRecord::Truncated));
    }

    let mut record = [0u8; HINT_RECORD_SIZE];
    io.read_exact_at(fd, raw, &mut record)?;

    let stored = u64::from_le_bytes(record[CHECKSUM_OFFSET..].try_into().unwrap());
    let computed = hint_checksum(&record[..HINT_PAYLOAD_SIZE]);
    if stored != computed {
        return Ok(Some(ReadHintRecord::Corrupted));
    }

    let version = record[VERSION_OFFSET];
    if version != HINT_FORMAT_VERSION {
        return Ok(Some(ReadHintRecord::UnknownVersion { version }));
    }

    let record_type = record[TYPE_OFFSET];

    let mut cid_bytes = [0u8; CID_SIZE];
    cid_bytes.copy_from_slice(&record[CID_OFFSET..CID_OFFSET + CID_SIZE]);

    match record_type {
        RECORD_TYPE_PUT => {
            let file_id = DataFileId::new(u32::from_le_bytes(
                record[FIELD_A_OFFSET..FIELD_A_OFFSET + 4]
                    .try_into()
                    .unwrap(),
            ));
            let raw_length = u32::from_le_bytes(
                record[FIELD_A_OFFSET + 4..FIELD_A_OFFSET + 8]
                    .try_into()
                    .unwrap(),
            );
            let block_offset = BlockOffset::new(u64::from_le_bytes(
                record[FIELD_B_OFFSET..FIELD_B_OFFSET + 8]
                    .try_into()
                    .unwrap(),
            ));
            if raw_length > MAX_BLOCK_SIZE {
                return Ok(Some(ReadHintRecord::Corrupted));
            }
            Ok(Some(ReadHintRecord::Put {
                cid_bytes,
                file_id,
                offset: block_offset,
                length: BlockLength::new(raw_length),
            }))
        }
        RECORD_TYPE_DECREMENT => {
            let epoch = CommitEpoch::new(u64::from_le_bytes(
                record[FIELD_A_OFFSET..FIELD_A_OFFSET + 8]
                    .try_into()
                    .unwrap(),
            ));
            let timestamp = WallClockMs::new(u64::from_le_bytes(
                record[FIELD_B_OFFSET..FIELD_B_OFFSET + 8]
                    .try_into()
                    .unwrap(),
            ));
            Ok(Some(ReadHintRecord::Decrement {
                cid_bytes,
                epoch,
                timestamp,
            }))
        }
        RECORD_TYPE_RELOCATE => {
            let rc16 = u16::from_le_bytes(
                record[REFCOUNT_OFFSET..REFCOUNT_OFFSET + 2]
                    .try_into()
                    .unwrap(),
            );
            let refcount = match rc16 {
                0 => 1,
                n => u32::from(n),
            };
            let file_id = DataFileId::new(u32::from_le_bytes(
                record[FIELD_A_OFFSET..FIELD_A_OFFSET + 4]
                    .try_into()
                    .unwrap(),
            ));
            let raw_length = u32::from_le_bytes(
                record[FIELD_A_OFFSET + 4..FIELD_A_OFFSET + 8]
                    .try_into()
                    .unwrap(),
            );
            let block_offset = BlockOffset::new(u64::from_le_bytes(
                record[FIELD_B_OFFSET..FIELD_B_OFFSET + 8]
                    .try_into()
                    .unwrap(),
            ));
            if raw_length > MAX_BLOCK_SIZE {
                return Ok(Some(ReadHintRecord::Corrupted));
            }
            Ok(Some(ReadHintRecord::Relocate {
                cid_bytes,
                file_id,
                offset: block_offset,
                length: BlockLength::new(raw_length),
                refcount,
            }))
        }
        RECORD_TYPE_REMOVE => Ok(Some(ReadHintRecord::Remove { cid_bytes })),
        other => Ok(Some(ReadHintRecord::UnknownType { record_type: other })),
    }
}

pub struct HintFileWriter<'a, S: StorageIO> {
    io: &'a S,
    fd: FileId,
    position: HintOffset,
}

impl<'a, S: StorageIO> HintFileWriter<'a, S> {
    pub fn new(io: &'a S, fd: FileId) -> Self {
        Self {
            io,
            fd,
            position: HintOffset::new(0),
        }
    }

    pub fn resume(io: &'a S, fd: FileId, position: HintOffset) -> Self {
        Self { io, fd, position }
    }

    pub fn append_hint(
        &mut self,
        cid_bytes: &[u8; CID_SIZE],
        file_id: DataFileId,
        offset: BlockOffset,
        length: BlockLength,
    ) -> io::Result<()> {
        encode_hint_record(
            self.io,
            self.fd,
            self.position,
            cid_bytes,
            file_id,
            offset,
            length,
        )?;
        self.position = self.position.advance(HINT_RECORD_SIZE as u64);
        Ok(())
    }

    pub fn append_decrement(
        &mut self,
        cid_bytes: &[u8; CID_SIZE],
        epoch: CommitEpoch,
        timestamp: WallClockMs,
    ) -> io::Result<()> {
        encode_decrement_record(self.io, self.fd, self.position, cid_bytes, epoch, timestamp)?;
        self.position = self.position.advance(HINT_RECORD_SIZE as u64);
        Ok(())
    }

    pub fn append_relocate(
        &mut self,
        cid_bytes: &[u8; CID_SIZE],
        file_id: DataFileId,
        offset: BlockOffset,
        length: BlockLength,
        refcount: u32,
    ) -> io::Result<()> {
        encode_relocate_record(
            self.io,
            self.fd,
            self.position,
            cid_bytes,
            file_id,
            offset,
            length,
            refcount,
        )?;
        self.position = self.position.advance(HINT_RECORD_SIZE as u64);
        Ok(())
    }

    pub fn append_remove(&mut self, cid_bytes: &[u8; CID_SIZE]) -> io::Result<()> {
        encode_remove_record(self.io, self.fd, self.position, cid_bytes)?;
        self.position = self.position.advance(HINT_RECORD_SIZE as u64);
        Ok(())
    }

    pub fn sync(&self) -> io::Result<()> {
        self.io.sync(self.fd)
    }

    pub fn position(&self) -> HintOffset {
        self.position
    }
}

pub struct HintFileReader<'a, S: StorageIO> {
    io: &'a S,
    fd: FileId,
    position: HintOffset,
    file_size: u64,
}

impl<'a, S: StorageIO> HintFileReader<'a, S> {
    pub fn open(io: &'a S, fd: FileId) -> io::Result<Self> {
        let file_size = io.file_size(fd)?;
        Ok(Self {
            io,
            fd,
            position: HintOffset::new(0),
            file_size,
        })
    }

    pub fn resume(io: &'a S, fd: FileId, position: HintOffset) -> io::Result<Self> {
        assert!(
            position.raw().is_multiple_of(HINT_RECORD_SIZE as u64),
            "hint resume position {} not aligned to HINT_RECORD_SIZE {}",
            position.raw(),
            HINT_RECORD_SIZE,
        );
        let file_size = io.file_size(fd)?;
        Ok(Self {
            io,
            fd,
            position,
            file_size,
        })
    }
}

impl<S: StorageIO> Iterator for HintFileReader<'_, S> {
    type Item = io::Result<ReadHintRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        match decode_hint_record(self.io, self.fd, self.position, self.file_size) {
            Err(e) => {
                self.position = HintOffset::new(self.file_size);
                Some(Err(e))
            }
            Ok(None) => None,
            Ok(Some(record)) => {
                match &record {
                    ReadHintRecord::Put { .. }
                    | ReadHintRecord::Decrement { .. }
                    | ReadHintRecord::Relocate { .. }
                    | ReadHintRecord::Remove { .. }
                    | ReadHintRecord::UnknownType { .. } => {
                        self.position = self.position.advance(HINT_RECORD_SIZE as u64);
                    }
                    ReadHintRecord::UnknownVersion { .. }
                    | ReadHintRecord::Corrupted
                    | ReadHintRecord::Truncated => {
                        self.position = HintOffset::new(self.file_size);
                    }
                }
                Some(Ok(record))
            }
        }
    }
}

#[derive(Debug)]
pub enum RebuildError {
    Io(io::Error),
    BlockIndex(super::hash_index::BlockIndexError),
}

impl std::fmt::Display for RebuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::BlockIndex(e) => write!(f, "block index: {e}"),
        }
    }
}

impl std::error::Error for RebuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::BlockIndex(e) => Some(e),
        }
    }
}

impl From<io::Error> for RebuildError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<super::hash_index::BlockIndexError> for RebuildError {
    fn from(e: super::hash_index::BlockIndexError) -> Self {
        Self::BlockIndex(e)
    }
}

struct RebuildState {
    entries: Vec<([u8; CID_SIZE], BlockLocation)>,
    cursor_file: DataFileId,
    cursor_offset: BlockOffset,
}

impl RebuildState {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            cursor_file: DataFileId::new(0),
            cursor_offset: BlockOffset::new(0),
        }
    }

    fn push(&mut self, cid_bytes: [u8; CID_SIZE], location: BlockLocation) {
        let end = location
            .offset
            .advance(BLOCK_RECORD_OVERHEAD as u64 + location.length.as_u64());
        if (location.file_id, end) > (self.cursor_file, self.cursor_offset) {
            self.cursor_file = location.file_id;
            self.cursor_offset = end;
        }
        self.entries.push((cid_bytes, location));
    }

    fn cursor(&self) -> WriteCursor {
        WriteCursor {
            file_id: self.cursor_file,
            offset: self.cursor_offset,
        }
    }
}

fn scan_single_hint_file<S: StorageIO>(
    io: &S,
    data_dir: &Path,
    hf_id: DataFileId,
) -> Result<Vec<([u8; CID_SIZE], BlockLocation)>, RebuildError> {
    let path = hint_file_path(data_dir, hf_id);
    let fd = io.open(&path, OpenOptions::read_only_existing())?;
    let reader = HintFileReader::open(io, fd)?;

    let entries: Result<Vec<_>, RebuildError> = reader
        .filter_map(|r| match r {
            Ok(ReadHintRecord::Put {
                cid_bytes,
                file_id,
                offset,
                length,
            }) => Some(Ok((
                cid_bytes,
                BlockLocation {
                    file_id,
                    offset,
                    length,
                },
            ))),
            Ok(
                ReadHintRecord::Decrement { .. }
                | ReadHintRecord::Relocate { .. }
                | ReadHintRecord::Remove { .. }
                | ReadHintRecord::UnknownVersion { .. }
                | ReadHintRecord::UnknownType { .. }
                | ReadHintRecord::Corrupted
                | ReadHintRecord::Truncated,
            ) => None,
            Err(e) => Some(Err(RebuildError::Io(e))),
        })
        .collect();

    let _ = io.close(fd);
    entries
}

const REPLAY_BATCH_SIZE: usize = 10_000;

pub fn replay_hints_into_block_index<S: StorageIO>(
    io: &S,
    data_dir: &Path,
    index: &super::hash_index::BlockIndex,
    from: Option<&super::hash_index::CheckpointPositions>,
) -> Result<(u64, HashMap<DataFileId, BlockOffset>), RebuildError> {
    let hint_files = list_files_by_extension(io, data_dir, HINT_FILE_EXTENSION)?;
    if hint_files.is_empty() {
        return Ok((0, HashMap::new()));
    }

    let checkpointed_files: HashMap<DataFileId, HintOffset> = from
        .map(|cp| cp.0.iter().copied().collect())
        .unwrap_or_default();

    let max_checkpointed_fid = checkpointed_files
        .keys()
        .max()
        .copied()
        .unwrap_or(DataFileId::new(0));

    let mut max_cursor: Option<WriteCursor> = None;
    let mut file_cursors: HashMap<DataFileId, BlockOffset> = HashMap::new();
    let mut replayed: u64 = 0;
    let mut put_buffer: Vec<([u8; CID_SIZE], BlockLocation)> =
        Vec::with_capacity(REPLAY_BATCH_SIZE);
    let mut relocate_buffer: Vec<([u8; CID_SIZE], BlockLocation, u32)> =
        Vec::with_capacity(REPLAY_BATCH_SIZE);
    let mut remove_buffer: Vec<[u8; CID_SIZE]> = Vec::with_capacity(REPLAY_BATCH_SIZE);

    hint_files
        .iter()
        .filter_map(|&fid| match checkpointed_files.get(&fid) {
            Some(&offset) => Some((fid, offset)),
            None if fid > max_checkpointed_fid => Some((fid, HintOffset::new(0))),
            None => None,
        })
        .try_for_each(|(fid, start_pos)| {
            let path = hint_file_path(data_dir, fid);
            let fd = match io.open(&path, OpenOptions::read_only_existing()) {
                Ok(fd) => fd,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(RebuildError::Io(e)),
            };

            let mut reader = HintFileReader::resume(io, fd, start_pos)?;

            reader.try_for_each(|record_result| {
                match record_result? {
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
                        put_buffer.push((cid_bytes, loc));

                        let record_end =
                            offset.advance(BLOCK_RECORD_OVERHEAD as u64 + length.as_u64());
                        let candidate = WriteCursor {
                            file_id,
                            offset: record_end,
                        };
                        max_cursor = Some(match max_cursor {
                            Some(c) => {
                                std::cmp::max_by_key(c, candidate, |w| (w.file_id, w.offset))
                            }
                            None => candidate,
                        });
                        file_cursors
                            .entry(file_id)
                            .and_modify(|existing| {
                                if record_end > *existing {
                                    *existing = record_end;
                                }
                            })
                            .or_insert(record_end);

                        replayed = replayed.saturating_add(1);
                        if put_buffer.len() >= REPLAY_BATCH_SIZE {
                            index.batch_insert_buffered(&put_buffer)?;
                            put_buffer.clear();
                        }
                    }
                    ReadHintRecord::Decrement {
                        cid_bytes,
                        epoch,
                        timestamp,
                    } => {
                        if !put_buffer.is_empty() {
                            index.batch_insert_buffered(&put_buffer)?;
                            put_buffer.clear();
                        }
                        if !relocate_buffer.is_empty() {
                            index.batch_relocate(&relocate_buffer)?;
                            relocate_buffer.clear();
                        }
                        if !remove_buffer.is_empty() {
                            index.batch_remove(&remove_buffer);
                            remove_buffer.clear();
                        }
                        index.batch_decrement(&[cid_bytes], epoch, timestamp)?;
                        replayed = replayed.saturating_add(1);
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
                        relocate_buffer.push((cid_bytes, loc, refcount));

                        let record_end =
                            offset.advance(BLOCK_RECORD_OVERHEAD as u64 + length.as_u64());
                        file_cursors
                            .entry(file_id)
                            .and_modify(|existing| {
                                if record_end > *existing {
                                    *existing = record_end;
                                }
                            })
                            .or_insert(record_end);

                        replayed = replayed.saturating_add(1);
                        if relocate_buffer.len() >= REPLAY_BATCH_SIZE {
                            if !put_buffer.is_empty() {
                                index.batch_insert_buffered(&put_buffer)?;
                                put_buffer.clear();
                            }
                            index.batch_relocate(&relocate_buffer)?;
                            relocate_buffer.clear();
                        }
                    }
                    ReadHintRecord::Remove { cid_bytes } => {
                        remove_buffer.push(cid_bytes);
                        replayed = replayed.saturating_add(1);
                        if remove_buffer.len() >= REPLAY_BATCH_SIZE {
                            if !put_buffer.is_empty() {
                                index.batch_insert_buffered(&put_buffer)?;
                                put_buffer.clear();
                            }
                            if !relocate_buffer.is_empty() {
                                index.batch_relocate(&relocate_buffer)?;
                                relocate_buffer.clear();
                            }
                            index.batch_remove(&remove_buffer);
                            remove_buffer.clear();
                        }
                    }
                    ReadHintRecord::Corrupted => {
                        tracing::warn!(
                            file_id = %fid,
                            "corrupted hint record during replay, skipping"
                        );
                    }
                    ReadHintRecord::UnknownVersion { .. }
                    | ReadHintRecord::UnknownType { .. }
                    | ReadHintRecord::Truncated => {}
                }
                Ok::<_, RebuildError>(())
            })?;

            if !put_buffer.is_empty() {
                index.batch_insert_buffered(&put_buffer)?;
                put_buffer.clear();
            }
            if !relocate_buffer.is_empty() {
                index.batch_relocate(&relocate_buffer)?;
                relocate_buffer.clear();
            }
            if !remove_buffer.is_empty() {
                index.batch_remove(&remove_buffer);
                remove_buffer.clear();
            }

            let _ = io.close(fd);
            Ok(())
        })?;

    if let Some(cursor) = max_cursor {
        index.set_write_cursor(cursor)?;
    }

    Ok((replayed, file_cursors))
}

#[derive(Debug)]
pub struct HintIndex {
    entries: HashMap<CidBytes, BlockLocation>,
}

impl HintIndex {
    pub fn from_scanned(scanned: Vec<(CidBytes, BlockLocation)>) -> Self {
        let mut entries = HashMap::with_capacity(scanned.len());
        scanned.into_iter().for_each(|(cid, loc)| {
            entries.entry(cid).or_insert(loc);
        });
        Self { entries }
    }

    pub fn get(&self, cid: &[u8; CID_SIZE]) -> Option<BlockLocation> {
        self.entries.get(cid).copied()
    }

    pub fn contains(&self, cid: &[u8; CID_SIZE]) -> bool {
        self.entries.contains_key(cid)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

pub fn scan_hints_to_memory<S: StorageIO>(
    io: &S,
    data_dir: &Path,
) -> Result<(HintIndex, WriteCursor), RebuildError> {
    use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

    let hint_files = list_files_by_extension(io, data_dir, HINT_FILE_EXTENSION)?;
    if hint_files.is_empty() {
        return Err(RebuildError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "no hint files found for instant recovery",
        )));
    }

    let file_results: Vec<Result<Vec<_>, RebuildError>> = hint_files
        .par_iter()
        .map(|&hf_id| scan_single_hint_file(io, data_dir, hf_id))
        .collect();

    let mut state = RebuildState::new();
    file_results.into_iter().try_for_each(|result| {
        result?.into_iter().for_each(|(cid_bytes, location)| {
            state.push(cid_bytes, location);
        });
        Ok::<_, RebuildError>(())
    })?;

    if state.entries.is_empty() {
        return Err(RebuildError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "hint files contained no valid entries",
        )));
    }

    let cursor = state.cursor();
    let hint_index = HintIndex::from_scanned(state.entries);

    Ok((hint_index, cursor))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OpenOptions;
    use crate::blockstore::test_cid;
    use crate::sim::SimulatedIO;
    use std::path::Path;

    fn setup() -> (SimulatedIO, FileId) {
        let sim = SimulatedIO::pristine(42);
        let dir = Path::new("/test");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();
        let fd = sim
            .open(Path::new("/test/hints.tqh"), OpenOptions::read_write())
            .unwrap();
        (sim, fd)
    }

    #[test]
    fn hint_record_round_trip() {
        let (sim, fd) = setup();
        let cid = test_cid(1);
        let file_id = DataFileId::new(3);
        let offset = BlockOffset::new(1024);
        let length = BlockLength::new(256);

        encode_hint_record(&sim, fd, HintOffset::new(0), &cid, file_id, offset, length).unwrap();

        let file_size = sim.file_size(fd).unwrap();
        let record = decode_hint_record(&sim, fd, HintOffset::new(0), file_size)
            .unwrap()
            .unwrap();

        match record {
            ReadHintRecord::Put {
                cid_bytes,
                file_id: fid,
                offset: off,
                length: len,
            } => {
                assert_eq!(cid_bytes, cid);
                assert_eq!(fid, file_id);
                assert_eq!(off, offset);
                assert_eq!(len, length);
            }
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn decrement_record_round_trip() {
        let (sim, fd) = setup();
        let cid = test_cid(42);
        let epoch = CommitEpoch::new(7);
        let timestamp = WallClockMs::new(1_700_000_000_000);

        encode_decrement_record(&sim, fd, HintOffset::new(0), &cid, epoch, timestamp).unwrap();

        let file_size = sim.file_size(fd).unwrap();
        let record = decode_hint_record(&sim, fd, HintOffset::new(0), file_size)
            .unwrap()
            .unwrap();

        match record {
            ReadHintRecord::Decrement {
                cid_bytes,
                epoch: decoded_epoch,
                timestamp: decoded_ts,
            } => {
                assert_eq!(cid_bytes, cid);
                assert_eq!(decoded_epoch, epoch);
                assert_eq!(decoded_ts, timestamp);
            }
            other => panic!("expected Decrement, got {other:?}"),
        }
    }

    #[test]
    fn multiple_hint_records() {
        let (sim, fd) = setup();

        (0u8..5).for_each(|i| {
            let cid = test_cid(i);
            let write_offset = HintOffset::new(i as u64 * HINT_RECORD_SIZE as u64);
            encode_hint_record(
                &sim,
                fd,
                write_offset,
                &cid,
                DataFileId::new(i as u32),
                BlockOffset::new(i as u64 * 100),
                BlockLength::new(50 + i as u32),
            )
            .unwrap();
        });

        let file_size = sim.file_size(fd).unwrap();
        assert_eq!(file_size, 5 * HINT_RECORD_SIZE as u64);

        let records: Vec<_> = (0u8..5)
            .map(|i| {
                let read_offset = HintOffset::new(i as u64 * HINT_RECORD_SIZE as u64);
                decode_hint_record(&sim, fd, read_offset, file_size)
                    .unwrap()
                    .unwrap()
            })
            .collect();

        records.iter().enumerate().for_each(|(i, r)| match r {
            ReadHintRecord::Put {
                file_id, length, ..
            } => {
                assert_eq!(file_id.raw(), i as u32);
                assert_eq!(length.raw(), 50 + i as u32);
            }
            other => panic!("expected Valid at index {i}, got {other:?}"),
        });
    }

    #[test]
    fn detects_truncated_hint() {
        let (sim, fd) = setup();
        sim.write_all_at(fd, 0, &[0u8; HINT_RECORD_SIZE - 1])
            .unwrap();
        let file_size = sim.file_size(fd).unwrap();
        let record = decode_hint_record(&sim, fd, HintOffset::new(0), file_size)
            .unwrap()
            .unwrap();
        assert!(matches!(record, ReadHintRecord::Truncated));
    }

    #[test]
    fn detects_corrupted_hint() {
        let (sim, fd) = setup();
        let cid = test_cid(1);
        encode_hint_record(
            &sim,
            fd,
            HintOffset::new(0),
            &cid,
            DataFileId::new(0),
            BlockOffset::new(0),
            BlockLength::new(100),
        )
        .unwrap();

        sim.write_all_at(fd, 10, &[0xFF]).unwrap();

        let file_size = sim.file_size(fd).unwrap();
        let record = decode_hint_record(&sim, fd, HintOffset::new(0), file_size)
            .unwrap()
            .unwrap();
        assert!(matches!(record, ReadHintRecord::Corrupted));
    }

    #[test]
    fn returns_none_at_eof() {
        let (sim, fd) = setup();
        let file_size = sim.file_size(fd).unwrap();
        assert!(
            decode_hint_record(&sim, fd, HintOffset::new(0), file_size)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn oversized_length_treated_as_corrupted() {
        let (sim, fd) = setup();
        let cid = test_cid(1);
        encode_hint_record(
            &sim,
            fd,
            HintOffset::new(0),
            &cid,
            DataFileId::new(0),
            BlockOffset::new(0),
            BlockLength::new(100),
        )
        .unwrap();

        let length_offset = FIELD_A_OFFSET as u64 + 4;
        let oversized = (MAX_BLOCK_SIZE + 1).to_le_bytes();
        sim.write_all_at(fd, length_offset, &oversized).unwrap();

        let mut buf = [0u8; HINT_PAYLOAD_SIZE];
        sim.read_exact_at(fd, 0, &mut buf).unwrap();
        let fixed_checksum = hint_checksum(&buf);
        sim.write_all_at(fd, CHECKSUM_OFFSET as u64, &fixed_checksum.to_le_bytes())
            .unwrap();

        let file_size = sim.file_size(fd).unwrap();
        let record = decode_hint_record(&sim, fd, HintOffset::new(0), file_size)
            .unwrap()
            .unwrap();
        assert!(matches!(record, ReadHintRecord::Corrupted));
    }

    #[test]
    fn hint_writer_writes_readable_records() {
        let (sim, fd) = setup();
        let mut writer = HintFileWriter::new(&sim, fd);

        (0u8..5).for_each(|i| {
            writer
                .append_hint(
                    &test_cid(i),
                    DataFileId::new(0),
                    BlockOffset::new(i as u64 * 100),
                    BlockLength::new(50 + i as u32),
                )
                .unwrap();
        });

        assert_eq!(
            writer.position(),
            HintOffset::new(5 * HINT_RECORD_SIZE as u64)
        );

        let reader = HintFileReader::open(&sim, fd).unwrap();
        let records: Vec<_> = reader.map(|r| r.unwrap()).collect();
        assert_eq!(records.len(), 5);

        records.iter().enumerate().for_each(|(i, r)| match r {
            ReadHintRecord::Put {
                file_id, length, ..
            } => {
                assert_eq!(file_id.raw(), 0);
                assert_eq!(length.raw(), 50 + i as u32);
            }
            other => panic!("expected Valid at {i}, got {other:?}"),
        });
    }

    #[test]
    fn hint_writer_resume_continues_at_position() {
        let (sim, fd) = setup();
        let mut writer = HintFileWriter::new(&sim, fd);
        writer
            .append_hint(
                &test_cid(0),
                DataFileId::new(0),
                BlockOffset::new(0),
                BlockLength::new(100),
            )
            .unwrap();

        let pos = writer.position();
        let mut writer2 = HintFileWriter::resume(&sim, fd, pos);
        writer2
            .append_hint(
                &test_cid(1),
                DataFileId::new(0),
                BlockOffset::new(100),
                BlockLength::new(200),
            )
            .unwrap();

        let reader = HintFileReader::open(&sim, fd).unwrap();
        let valid_count = reader
            .filter_map(|r| match r.ok()? {
                ReadHintRecord::Put { .. } => Some(()),
                _ => None,
            })
            .count();
        assert_eq!(valid_count, 2);
    }

    #[test]
    fn hint_reader_empty_file() {
        let (sim, fd) = setup();
        let reader = HintFileReader::open(&sim, fd).unwrap();
        assert_eq!(reader.count(), 0);
    }

    #[test]
    fn hint_reader_stops_on_truncated() {
        let (sim, fd) = setup();
        let mut writer = HintFileWriter::new(&sim, fd);
        writer
            .append_hint(
                &test_cid(0),
                DataFileId::new(0),
                BlockOffset::new(0),
                BlockLength::new(100),
            )
            .unwrap();

        sim.write_all_at(fd, writer.position().raw(), &[0u8; HINT_RECORD_SIZE - 1])
            .unwrap();

        let reader = HintFileReader::open(&sim, fd).unwrap();
        let records: Vec<_> = reader.map(|r| r.unwrap()).collect();
        assert_eq!(records.len(), 2);
        assert!(matches!(records[0], ReadHintRecord::Put { .. }));
        assert!(matches!(records[1], ReadHintRecord::Truncated));
    }

    #[test]
    fn hint_reader_stops_on_corrupted() {
        let (sim, fd) = setup();
        let mut writer = HintFileWriter::new(&sim, fd);

        (0u8..3).for_each(|i| {
            writer
                .append_hint(
                    &test_cid(i),
                    DataFileId::new(0),
                    BlockOffset::new(i as u64 * 100),
                    BlockLength::new(50),
                )
                .unwrap();
        });

        sim.write_all_at(fd, HINT_RECORD_SIZE as u64 + 5, &[0xFF])
            .unwrap();

        let reader = HintFileReader::open(&sim, fd).unwrap();
        let records: Vec<_> = reader.map(|r| r.unwrap()).collect();
        assert_eq!(records.len(), 2);
        assert!(matches!(records[0], ReadHintRecord::Put { .. }));
        assert!(matches!(records[1], ReadHintRecord::Corrupted));
    }

    #[test]
    fn hint_file_path_format() {
        let path = hint_file_path(Path::new("/data"), DataFileId::new(0));
        assert_eq!(path, Path::new("/data/000000.tqh"));

        let path = hint_file_path(Path::new("/data"), DataFileId::new(42));
        assert_eq!(path, Path::new("/data/000042.tqh"));
    }
}
