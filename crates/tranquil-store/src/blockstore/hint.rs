use std::io;
use std::path::{Path, PathBuf};

use crate::io::{FileId, OpenOptions, StorageIO};

use super::data_file::{BLOCK_RECORD_OVERHEAD, CID_SIZE, DataFileReader};
use super::key_index::{KeyIndex, KeyIndexError};
use super::list_files_by_extension;
use super::manager::DATA_FILE_EXTENSION;
use super::types::{
    BlockLength, BlockLocation, BlockOffset, DataFileId, HintOffset, MAX_BLOCK_SIZE, WriteCursor,
};

pub const HINT_RECORD_SIZE: usize = CID_SIZE + 4 + 8 + 4 + 4;
pub const HINT_FILE_EXTENSION: &str = "tqh";

fn hint_checksum(buf: &[u8; CID_SIZE + 4 + 8 + 4]) -> u32 {
    xxhash_rust::xxh3::xxh3_64(buf) as u32
}

pub fn hint_file_path(data_dir: &Path, file_id: DataFileId) -> PathBuf {
    data_dir.join(format!("{file_id}.{HINT_FILE_EXTENSION}"))
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
    debug_assert!(
        write_offset.raw().is_multiple_of(HINT_RECORD_SIZE as u64),
        "hint write_offset {} not aligned to HINT_RECORD_SIZE {}",
        write_offset.raw(),
        HINT_RECORD_SIZE,
    );

    let mut record = [0u8; HINT_RECORD_SIZE];
    record[..CID_SIZE].copy_from_slice(cid_bytes);
    record[CID_SIZE..CID_SIZE + 4].copy_from_slice(&file_id.raw().to_le_bytes());
    record[CID_SIZE + 4..CID_SIZE + 12].copy_from_slice(&block_offset.raw().to_le_bytes());
    record[CID_SIZE + 12..CID_SIZE + 16].copy_from_slice(&length.raw().to_le_bytes());

    let checksum =
        hint_checksum(<&[u8; CID_SIZE + 4 + 8 + 4]>::try_from(&record[..CID_SIZE + 16]).unwrap());
    record[CID_SIZE + 16..].copy_from_slice(&checksum.to_le_bytes());

    io.write_all_at(fd, write_offset.raw(), &record)
}

#[must_use]
#[derive(Debug)]
pub enum ReadHintRecord {
    Valid {
        cid_bytes: [u8; CID_SIZE],
        file_id: DataFileId,
        offset: BlockOffset,
        length: BlockLength,
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

    let payload: &[u8; CID_SIZE + 4 + 8 + 4] = record[..CID_SIZE + 16].try_into().unwrap();
    let stored = u32::from_le_bytes(record[CID_SIZE + 16..].try_into().unwrap());
    let computed = hint_checksum(payload);
    if stored != computed {
        return Ok(Some(ReadHintRecord::Corrupted));
    }

    let mut cid_bytes = [0u8; CID_SIZE];
    cid_bytes.copy_from_slice(&record[..CID_SIZE]);

    let file_id = DataFileId::new(u32::from_le_bytes(
        record[CID_SIZE..CID_SIZE + 4].try_into().unwrap(),
    ));
    let block_offset = BlockOffset::new(u64::from_le_bytes(
        record[CID_SIZE + 4..CID_SIZE + 12].try_into().unwrap(),
    ));
    let raw_length = u32::from_le_bytes(record[CID_SIZE + 12..CID_SIZE + 16].try_into().unwrap());
    if raw_length > MAX_BLOCK_SIZE {
        return Ok(Some(ReadHintRecord::Corrupted));
    }
    let length = BlockLength::new(raw_length);

    Ok(Some(ReadHintRecord::Valid {
        cid_bytes,
        file_id,
        offset: block_offset,
        length,
    }))
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
                    ReadHintRecord::Valid { .. } => {
                        self.position = self.position.advance(HINT_RECORD_SIZE as u64);
                    }
                    ReadHintRecord::Corrupted | ReadHintRecord::Truncated => {
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
    Index(KeyIndexError),
}

impl std::fmt::Display for RebuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Index(e) => write!(f, "index: {e}"),
        }
    }
}

impl std::error::Error for RebuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Index(e) => Some(e),
        }
    }
}

impl From<io::Error> for RebuildError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<KeyIndexError> for RebuildError {
    fn from(e: KeyIndexError) -> Self {
        Self::Index(e)
    }
}

const REBUILD_BATCH_SIZE: usize = 10_000;

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

    fn flush_if_full(&mut self, index: &KeyIndex) -> Result<(), RebuildError> {
        if self.entries.len() >= REBUILD_BATCH_SIZE {
            self.flush(index)?;
        }
        Ok(())
    }

    fn flush(&mut self, index: &KeyIndex) -> Result<(), RebuildError> {
        if self.entries.is_empty() {
            return Ok(());
        }
        index.batch_put(
            &self.entries,
            &[],
            WriteCursor {
                file_id: self.cursor_file,
                offset: self.cursor_offset,
            },
        )?;
        self.entries.clear();
        Ok(())
    }
}

pub fn rebuild_index_from_hints<S: StorageIO>(
    io: &S,
    data_dir: &Path,
    index: &KeyIndex,
) -> Result<(), RebuildError> {
    let hint_files = list_files_by_extension(io, data_dir, HINT_FILE_EXTENSION)?;
    let mut state = RebuildState::new();

    hint_files.iter().try_for_each(|&hf_id| {
        let path = hint_file_path(data_dir, hf_id);
        let fd = io.open(&path, OpenOptions::read_only_existing())?;
        let reader = HintFileReader::open(io, fd)?;

        let result: Result<(), RebuildError> = reader
            .filter_map(|r| match r {
                Ok(ReadHintRecord::Valid {
                    cid_bytes,
                    file_id,
                    offset,
                    length,
                }) => Some(Ok((cid_bytes, file_id, offset, length))),
                Ok(_) => None,
                Err(e) => Some(Err(RebuildError::Io(e))),
            })
            .try_for_each(|r| {
                let (cid_bytes, file_id, offset, length) = r?;
                state.push(
                    cid_bytes,
                    BlockLocation {
                        file_id,
                        offset,
                        length,
                    },
                );
                state.flush_if_full(index)
            });

        let _ = io.close(fd);
        result
    })?;

    state.flush(index)
}

pub fn rebuild_index_from_data_files<S: StorageIO>(
    io: &S,
    data_dir: &Path,
    index: &KeyIndex,
) -> Result<(), RebuildError> {
    let data_files = list_files_by_extension(io, data_dir, DATA_FILE_EXTENSION)?;
    let mut state = RebuildState::new();

    data_files.iter().try_for_each(|&file_id| {
        let path = data_dir.join(format!("{file_id}.{DATA_FILE_EXTENSION}"));
        let fd = io.open(&path, OpenOptions::read_only_existing())?;
        let reader = DataFileReader::open(io, fd)?;

        let result: Result<(), RebuildError> = reader
            .filter_map(|r| match r {
                Ok(super::data_file::ReadBlockRecord::Valid {
                    offset,
                    cid_bytes,
                    data,
                }) => {
                    let length = BlockLength::new(
                        u32::try_from(data.len()).expect("block size validated by reader"),
                    );
                    Some(Ok((cid_bytes, offset, length)))
                }
                Ok(_) => None,
                Err(e) => Some(Err(RebuildError::Io(e))),
            })
            .try_for_each(|r| {
                let (cid_bytes, offset, length) = r?;
                state.push(
                    cid_bytes,
                    BlockLocation {
                        file_id,
                        offset,
                        length,
                    },
                );
                state.flush_if_full(index)
            });

        let _ = io.close(fd);
        result
    })?;

    state.flush(index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OpenOptions;
    use crate::blockstore::data_file::{DataFileWriter, ReadBlockRecord, decode_block_record};
    use crate::blockstore::test_cid;
    use crate::blockstore::types::RefCount;
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
            ReadHintRecord::Valid {
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
            ReadHintRecord::Valid {
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

        let length_offset = CID_SIZE as u64 + 4 + 8;
        let oversized = (MAX_BLOCK_SIZE + 1).to_le_bytes();
        sim.write_all_at(fd, length_offset, &oversized).unwrap();

        let checksum_offset = (CID_SIZE + 4 + 8 + 4) as u64;
        let mut buf = [0u8; CID_SIZE + 4 + 8 + 4];
        sim.read_exact_at(fd, 0, &mut buf).unwrap();
        let fixed_checksum = hint_checksum(&buf);
        sim.write_all_at(fd, checksum_offset, &fixed_checksum.to_le_bytes())
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
            ReadHintRecord::Valid {
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
                ReadHintRecord::Valid { .. } => Some(()),
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
        assert!(matches!(records[0], ReadHintRecord::Valid { .. }));
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
        assert!(matches!(records[0], ReadHintRecord::Valid { .. }));
        assert!(matches!(records[1], ReadHintRecord::Corrupted));
    }

    fn setup_data_dir(sim: &SimulatedIO) -> &'static Path {
        let dir = Path::new("/data");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();
        dir
    }

    fn write_test_blocks(
        sim: &SimulatedIO,
        dir: &Path,
        file_id: DataFileId,
        count: u8,
    ) -> (Vec<BlockLocation>, BlockOffset) {
        let data_path = dir.join(format!("{file_id}.tqb"));
        let data_fd = sim.open(&data_path, OpenOptions::read_write()).unwrap();
        let mut data_writer = DataFileWriter::new(sim, data_fd, file_id).unwrap();

        let hint_fd = sim
            .open(&hint_file_path(dir, file_id), OpenOptions::read_write())
            .unwrap();
        let mut hint_writer = HintFileWriter::new(sim, hint_fd);

        let locations: Vec<BlockLocation> = (0..count)
            .map(|i| {
                let cid = test_cid(i);
                let data = vec![i; (i as usize + 1) * 10];
                let loc = data_writer.append_block(&cid, &data).unwrap();
                hint_writer
                    .append_hint(&cid, loc.file_id, loc.offset, loc.length)
                    .unwrap();
                loc
            })
            .collect();

        data_writer.sync().unwrap();
        hint_writer.sync().unwrap();
        sim.sync_dir(dir).unwrap();

        let final_pos = data_writer.position();
        (locations, final_pos)
    }

    fn write_test_blocks_no_hints(
        sim: &SimulatedIO,
        dir: &Path,
        file_id: DataFileId,
        count: u8,
    ) -> (Vec<BlockLocation>, BlockOffset) {
        let data_path = dir.join(format!("{file_id}.tqb"));
        let data_fd = sim.open(&data_path, OpenOptions::read_write()).unwrap();
        let mut data_writer = DataFileWriter::new(sim, data_fd, file_id).unwrap();

        let locations: Vec<BlockLocation> = (0..count)
            .map(|i| {
                let cid = test_cid(i);
                let data = vec![i; (i as usize + 1) * 10];
                data_writer.append_block(&cid, &data).unwrap()
            })
            .collect();

        data_writer.sync().unwrap();
        sim.sync_dir(dir).unwrap();

        let final_pos = data_writer.position();
        (locations, final_pos)
    }

    #[test]
    fn rebuild_from_hints_restores_index() {
        let sim = SimulatedIO::pristine(42);
        let dir = setup_data_dir(&sim);
        let block_count = 10u8;
        let (locations, final_pos) = write_test_blocks(&sim, dir, DataFileId::new(0), block_count);

        let index_dir = tempfile::TempDir::new().unwrap();
        let index = KeyIndex::open(index_dir.path()).unwrap().into_inner();

        rebuild_index_from_hints(&sim, dir, &index).unwrap();

        (0..block_count).for_each(|i| {
            let entry = index.get(&test_cid(i)).unwrap().unwrap();
            assert_eq!(entry.location, locations[i as usize]);
            assert_eq!(entry.refcount, RefCount::one());
        });

        let cursor = index.read_write_cursor().unwrap().unwrap();
        assert_eq!(cursor.file_id, DataFileId::new(0));
        assert_eq!(cursor.offset, final_pos);
    }

    #[test]
    fn rebuild_from_data_files_restores_index() {
        let sim = SimulatedIO::pristine(42);
        let dir = setup_data_dir(&sim);
        let block_count = 10u8;
        let (locations, final_pos) =
            write_test_blocks_no_hints(&sim, dir, DataFileId::new(0), block_count);

        let index_dir = tempfile::TempDir::new().unwrap();
        let index = KeyIndex::open(index_dir.path()).unwrap().into_inner();

        rebuild_index_from_data_files(&sim, dir, &index).unwrap();

        (0..block_count).for_each(|i| {
            let entry = index.get(&test_cid(i)).unwrap().unwrap();
            assert_eq!(entry.location, locations[i as usize]);
            assert_eq!(entry.refcount, RefCount::one());
        });

        let cursor = index.read_write_cursor().unwrap().unwrap();
        assert_eq!(cursor.file_id, DataFileId::new(0));
        assert_eq!(cursor.offset, final_pos);
    }

    #[test]
    fn rebuild_from_hints_handles_empty_dir() {
        let sim = SimulatedIO::pristine(42);
        let dir = setup_data_dir(&sim);

        let index_dir = tempfile::TempDir::new().unwrap();
        let index = KeyIndex::open(index_dir.path()).unwrap().into_inner();

        rebuild_index_from_hints(&sim, dir, &index).unwrap();
        assert!(index.read_write_cursor().unwrap().is_none());
    }

    #[test]
    fn rebuild_from_data_files_handles_empty_dir() {
        let sim = SimulatedIO::pristine(42);
        let dir = setup_data_dir(&sim);

        let index_dir = tempfile::TempDir::new().unwrap();
        let index = KeyIndex::open(index_dir.path()).unwrap().into_inner();

        rebuild_index_from_data_files(&sim, dir, &index).unwrap();
        assert!(index.read_write_cursor().unwrap().is_none());
    }

    #[test]
    fn rebuild_from_hints_handles_duplicate_cids() {
        let sim = SimulatedIO::pristine(42);
        let dir = setup_data_dir(&sim);

        let data_fd = sim
            .open(Path::new("/data/000000.tqb"), OpenOptions::read_write())
            .unwrap();
        let mut data_writer = DataFileWriter::new(&sim, data_fd, DataFileId::new(0)).unwrap();

        let hint_fd = sim
            .open(
                &hint_file_path(dir, DataFileId::new(0)),
                OpenOptions::read_write(),
            )
            .unwrap();
        let mut hint_writer = HintFileWriter::new(&sim, hint_fd);

        let cid = test_cid(1);
        let data = vec![0xAA; 64];

        let loc1 = data_writer.append_block(&cid, &data).unwrap();
        hint_writer
            .append_hint(&cid, loc1.file_id, loc1.offset, loc1.length)
            .unwrap();

        let loc2 = data_writer.append_block(&cid, &data).unwrap();
        hint_writer
            .append_hint(&cid, loc2.file_id, loc2.offset, loc2.length)
            .unwrap();

        data_writer.sync().unwrap();
        hint_writer.sync().unwrap();
        sim.sync_dir(dir).unwrap();

        let index_dir = tempfile::TempDir::new().unwrap();
        let index = KeyIndex::open(index_dir.path()).unwrap().into_inner();

        rebuild_index_from_hints(&sim, dir, &index).unwrap();

        let entry = index.get(&cid).unwrap().unwrap();
        assert_eq!(entry.refcount, RefCount::new(2));
        assert_eq!(entry.location, loc1);
    }

    #[test]
    fn sim_hints_survive_crash_and_enable_rebuild() {
        let sim = SimulatedIO::pristine(42);
        let dir = setup_data_dir(&sim);
        let block_count = 15u8;
        let (locations, _) = write_test_blocks(&sim, dir, DataFileId::new(0), block_count);

        sim.crash();

        let hint_fd = sim
            .open(
                &hint_file_path(dir, DataFileId::new(0)),
                OpenOptions::read_only_existing(),
            )
            .unwrap();
        let hint_size = sim.file_size(hint_fd).unwrap();
        assert_eq!(hint_size, block_count as u64 * HINT_RECORD_SIZE as u64);
        let _ = sim.close(hint_fd);

        let index_dir = tempfile::TempDir::new().unwrap();
        let index = KeyIndex::open(index_dir.path()).unwrap().into_inner();

        rebuild_index_from_hints(&sim, dir, &index).unwrap();

        let data_fd = sim
            .open(
                Path::new("/data/000000.tqb"),
                OpenOptions::read_only_existing(),
            )
            .unwrap();
        let data_size = sim.file_size(data_fd).unwrap();

        (0..block_count).for_each(|i| {
            let entry = index.get(&test_cid(i)).unwrap().unwrap();
            assert_eq!(entry.location, locations[i as usize]);

            let record = decode_block_record(&sim, data_fd, entry.location.offset, data_size)
                .unwrap()
                .unwrap();
            match record {
                ReadBlockRecord::Valid {
                    cid_bytes, data, ..
                } => {
                    assert_eq!(cid_bytes, test_cid(i));
                    assert_eq!(data, vec![i; (i as usize + 1) * 10]);
                }
                other => panic!("expected Valid for block {i}, got {other:?}"),
            }
        });
    }

    #[test]
    fn sim_rebuild_from_data_files_without_hints() {
        let sim = SimulatedIO::pristine(42);
        let dir = setup_data_dir(&sim);
        let block_count = 15u8;
        let (locations, _) = write_test_blocks_no_hints(&sim, dir, DataFileId::new(0), block_count);

        sim.crash();

        let index_dir = tempfile::TempDir::new().unwrap();
        let index = KeyIndex::open(index_dir.path()).unwrap().into_inner();

        rebuild_index_from_data_files(&sim, dir, &index).unwrap();

        let data_fd = sim
            .open(
                Path::new("/data/000000.tqb"),
                OpenOptions::read_only_existing(),
            )
            .unwrap();
        let data_size = sim.file_size(data_fd).unwrap();

        (0..block_count).for_each(|i| {
            let entry = index.get(&test_cid(i)).unwrap().unwrap();
            assert_eq!(entry.location, locations[i as usize]);

            let record = decode_block_record(&sim, data_fd, entry.location.offset, data_size)
                .unwrap()
                .unwrap();
            match record {
                ReadBlockRecord::Valid {
                    cid_bytes, data, ..
                } => {
                    assert_eq!(cid_bytes, test_cid(i));
                    assert_eq!(data, vec![i; (i as usize + 1) * 10]);
                }
                other => panic!("expected Valid for block {i}, got {other:?}"),
            }
        });
    }

    #[test]
    fn rebuild_across_multiple_data_files() {
        let sim = SimulatedIO::pristine(42);
        let dir = setup_data_dir(&sim);

        let (locs0, _) = write_test_blocks(&sim, dir, DataFileId::new(0), 5);

        let data_fd1 = sim
            .open(Path::new("/data/000001.tqb"), OpenOptions::read_write())
            .unwrap();
        let mut data_writer1 = DataFileWriter::new(&sim, data_fd1, DataFileId::new(1)).unwrap();
        let hint_fd1 = sim
            .open(
                &hint_file_path(dir, DataFileId::new(1)),
                OpenOptions::read_write(),
            )
            .unwrap();
        let mut hint_writer1 = HintFileWriter::new(&sim, hint_fd1);

        let locs1: Vec<BlockLocation> = (5u8..10)
            .map(|i| {
                let cid = test_cid(i);
                let data = vec![i; (i as usize + 1) * 10];
                let loc = data_writer1.append_block(&cid, &data).unwrap();
                hint_writer1
                    .append_hint(&cid, loc.file_id, loc.offset, loc.length)
                    .unwrap();
                loc
            })
            .collect();

        data_writer1.sync().unwrap();
        hint_writer1.sync().unwrap();
        sim.sync_dir(dir).unwrap();

        let index_dir = tempfile::TempDir::new().unwrap();
        let index = KeyIndex::open(index_dir.path()).unwrap().into_inner();

        rebuild_index_from_hints(&sim, dir, &index).unwrap();

        (0u8..5).for_each(|i| {
            let entry = index.get(&test_cid(i)).unwrap().unwrap();
            assert_eq!(entry.location, locs0[i as usize]);
        });
        (5u8..10).for_each(|i| {
            let entry = index.get(&test_cid(i)).unwrap().unwrap();
            assert_eq!(entry.location, locs1[(i - 5) as usize]);
        });

        let cursor = index.read_write_cursor().unwrap().unwrap();
        assert_eq!(cursor.file_id, DataFileId::new(1));
    }

    #[test]
    fn hint_file_path_format() {
        let path = hint_file_path(Path::new("/data"), DataFileId::new(0));
        assert_eq!(path, Path::new("/data/000000.tqh"));

        let path = hint_file_path(Path::new("/data"), DataFileId::new(42));
        assert_eq!(path, Path::new("/data/000042.tqh"));
    }
}
