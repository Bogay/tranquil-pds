use std::io;

use crate::io::{FileId, StorageIO};

use super::types::{BlockLength, BlockLocation, BlockOffset, DataFileId, MAX_BLOCK_SIZE};

pub const BLOCK_MAGIC: [u8; 4] = *b"TQBL";
pub const BLOCK_FORMAT_VERSION: u8 = 1;
pub const BLOCK_HEADER_SIZE: usize = 5;

pub const CID_SIZE: usize = 36;
pub const BLOCK_RECORD_OVERHEAD: usize = CID_SIZE + 4 + 4;

pub type ValidBlock = (BlockOffset, [u8; CID_SIZE], Vec<u8>);

fn block_record_checksum(cid_bytes: &[u8; CID_SIZE], length_bytes: &[u8; 4], data: &[u8]) -> u32 {
    let mut hasher = xxhash_rust::xxh3::Xxh3::new();
    hasher.update(cid_bytes);
    hasher.update(length_bytes);
    hasher.update(data);
    hasher.digest() as u32
}

pub fn encode_block_record<S: StorageIO>(
    io: &S,
    fd: FileId,
    offset: BlockOffset,
    cid_bytes: &[u8; CID_SIZE],
    data: &[u8],
) -> io::Result<u64> {
    let length = u32::try_from(data.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "block data exceeds u32::MAX"))?;
    if length > MAX_BLOCK_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "block data exceeds MAX_BLOCK_SIZE",
        ));
    }

    let length_bytes = length.to_le_bytes();
    let checksum = block_record_checksum(cid_bytes, &length_bytes, data);

    let mut cursor = offset.raw();

    io.write_all_at(fd, cursor, cid_bytes)?;
    cursor += CID_SIZE as u64;

    io.write_all_at(fd, cursor, &length_bytes)?;
    cursor += 4;

    io.write_all_at(fd, cursor, data)?;
    cursor += data.len() as u64;

    io.write_all_at(fd, cursor, &checksum.to_le_bytes())?;
    cursor += 4;

    Ok(cursor - offset.raw())
}

pub fn decode_block_record<S: StorageIO>(
    io: &S,
    fd: FileId,
    offset: BlockOffset,
    file_size: u64,
) -> io::Result<Option<ReadBlockRecord>> {
    let raw = offset.raw();
    let remaining = match file_size.checked_sub(raw) {
        Some(r) => r,
        None => return Ok(None),
    };
    if remaining == 0 {
        return Ok(None);
    }

    if remaining < (CID_SIZE + 4) as u64 {
        return Ok(Some(ReadBlockRecord::Truncated { offset }));
    }

    let mut cid_bytes = [0u8; CID_SIZE];
    io.read_exact_at(fd, raw, &mut cid_bytes)?;

    let mut length_bytes = [0u8; 4];
    io.read_exact_at(fd, raw + CID_SIZE as u64, &mut length_bytes)?;

    let length = u32::from_le_bytes(length_bytes);
    if length > MAX_BLOCK_SIZE {
        return Ok(Some(ReadBlockRecord::Corrupted { offset }));
    }

    let record_size = BLOCK_RECORD_OVERHEAD as u64 + u64::from(length);
    if record_size > remaining {
        return Ok(Some(ReadBlockRecord::Truncated { offset }));
    }

    let data_offset = raw + CID_SIZE as u64 + 4;
    let mut data = vec![0u8; length as usize];
    io.read_exact_at(fd, data_offset, &mut data)?;

    let mut checksum_bytes = [0u8; 4];
    io.read_exact_at(fd, data_offset + u64::from(length), &mut checksum_bytes)?;

    let stored_checksum = u32::from_le_bytes(checksum_bytes);
    let computed_checksum = block_record_checksum(&cid_bytes, &length_bytes, &data);

    if stored_checksum != computed_checksum {
        return Ok(Some(ReadBlockRecord::Corrupted { offset }));
    }

    Ok(Some(ReadBlockRecord::Valid {
        offset,
        cid_bytes,
        data,
    }))
}

#[must_use]
#[derive(Debug)]
pub enum ReadBlockRecord {
    Valid {
        offset: BlockOffset,
        cid_bytes: [u8; CID_SIZE],
        data: Vec<u8>,
    },
    Corrupted {
        offset: BlockOffset,
    },
    Truncated {
        offset: BlockOffset,
    },
}

pub struct DataFileWriter<'a, S: StorageIO> {
    io: &'a S,
    fd: FileId,
    file_id: DataFileId,
    position: BlockOffset,
}

impl<'a, S: StorageIO> DataFileWriter<'a, S> {
    pub fn new(io: &'a S, fd: FileId, file_id: DataFileId) -> io::Result<Self> {
        let mut header = [0u8; BLOCK_HEADER_SIZE];
        header[..4].copy_from_slice(&BLOCK_MAGIC);
        header[4] = BLOCK_FORMAT_VERSION;
        io.write_all_at(fd, 0, &header)?;
        Ok(Self {
            io,
            fd,
            file_id,
            position: BlockOffset::new(BLOCK_HEADER_SIZE as u64),
        })
    }

    pub fn resume(io: &'a S, fd: FileId, file_id: DataFileId, position: BlockOffset) -> Self {
        assert!(
            position.raw() >= BLOCK_HEADER_SIZE as u64,
            "resume position {position:?} is before header end"
        );
        Self {
            io,
            fd,
            file_id,
            position,
        }
    }

    pub fn append_block(
        &mut self,
        cid_bytes: &[u8; CID_SIZE],
        data: &[u8],
    ) -> io::Result<BlockLocation> {
        let record_offset = self.position;
        let bytes_written = encode_block_record(self.io, self.fd, record_offset, cid_bytes, data)?;
        self.position = self.position.advance(bytes_written);

        Ok(BlockLocation {
            file_id: self.file_id,
            offset: record_offset,
            length: BlockLength::new(
                u32::try_from(data.len()).expect("encode_block_record validated length"),
            ),
        })
    }

    pub fn sync(&self) -> io::Result<()> {
        self.io.sync(self.fd)
    }

    pub fn position(&self) -> BlockOffset {
        self.position
    }

    pub fn fd(&self) -> FileId {
        self.fd
    }

    pub fn file_id(&self) -> DataFileId {
        self.file_id
    }
}

pub struct DataFileReader<'a, S: StorageIO> {
    io: &'a S,
    fd: FileId,
    position: BlockOffset,
    file_size: u64,
}

impl<'a, S: StorageIO> DataFileReader<'a, S> {
    pub fn open(io: &'a S, fd: FileId) -> io::Result<Self> {
        let file_size = io.file_size(fd)?;
        if file_size < BLOCK_HEADER_SIZE as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "file too small for header",
            ));
        }

        let mut header = [0u8; BLOCK_HEADER_SIZE];
        io.read_exact_at(fd, 0, &mut header)?;

        if header[..4] != BLOCK_MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad magic"));
        }
        if header[4] != BLOCK_FORMAT_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported block format version",
            ));
        }

        Ok(Self {
            io,
            fd,
            position: BlockOffset::new(BLOCK_HEADER_SIZE as u64),
            file_size,
        })
    }

    pub fn valid_blocks(self) -> io::Result<Vec<ValidBlock>> {
        self.map_while(|r| match r {
            Ok(ReadBlockRecord::Valid {
                offset,
                cid_bytes,
                data,
            }) => Some(Ok((offset, cid_bytes, data))),
            Err(e) => Some(Err(e)),
            _ => None,
        })
        .collect()
    }
}

impl<S: StorageIO> Iterator for DataFileReader<'_, S> {
    type Item = io::Result<ReadBlockRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        match decode_block_record(self.io, self.fd, self.position, self.file_size) {
            Err(e) => {
                self.position = BlockOffset::new(self.file_size);
                Some(Err(e))
            }
            Ok(None) => None,
            Ok(Some(record)) => {
                match &record {
                    ReadBlockRecord::Valid { data, .. } => {
                        self.position = self
                            .position
                            .advance(BLOCK_RECORD_OVERHEAD as u64 + data.len() as u64);
                    }
                    ReadBlockRecord::Corrupted { .. } | ReadBlockRecord::Truncated { .. } => {
                        self.position = BlockOffset::new(self.file_size);
                    }
                }
                Some(Ok(record))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OpenOptions;
    use crate::blockstore::test_cid;
    use crate::sim::{FaultConfig, SimulatedIO};
    use proptest::prelude::*;
    use std::path::Path;

    fn setup() -> (SimulatedIO, FileId) {
        let sim = SimulatedIO::pristine(42);
        let dir = Path::new("/test");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();
        let fd = sim
            .open(Path::new("/test/data.tqb"), OpenOptions::read_write())
            .unwrap();
        (sim, fd)
    }

    #[test]
    fn write_and_read_single_block() {
        let (sim, fd) = setup();
        let mut writer = DataFileWriter::new(&sim, fd, DataFileId::new(0)).unwrap();
        let cid = test_cid(1);
        let data = b"hello blockstore";

        let location = writer.append_block(&cid, data).unwrap();
        writer.sync().unwrap();

        assert_eq!(location.file_id, DataFileId::new(0));
        assert_eq!(location.offset, BlockOffset::new(BLOCK_HEADER_SIZE as u64));
        assert_eq!(location.length, BlockLength::new(data.len() as u32));

        let reader = DataFileReader::open(&sim, fd).unwrap();
        let blocks = reader.valid_blocks().unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].1, cid);
        assert_eq!(blocks[0].2, data);
    }

    #[test]
    fn write_and_read_multiple_blocks() {
        let (sim, fd) = setup();
        let mut writer = DataFileWriter::new(&sim, fd, DataFileId::new(0)).unwrap();

        let payloads: Vec<(&[u8], u8)> = vec![(b"first", 1), (b"second", 2), (b"third", 3)];
        let cids: Vec<[u8; CID_SIZE]> = payloads.iter().map(|(_, s)| test_cid(*s)).collect();

        payloads
            .iter()
            .zip(cids.iter())
            .for_each(|((data, _), cid)| {
                let _ = writer.append_block(cid, data).unwrap();
            });
        writer.sync().unwrap();

        let reader = DataFileReader::open(&sim, fd).unwrap();
        let blocks = reader.valid_blocks().unwrap();
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].2, b"first");
        assert_eq!(blocks[1].2, b"second");
        assert_eq!(blocks[2].2, b"third");
        assert_eq!(blocks[0].1, cids[0]);
        assert_eq!(blocks[1].1, cids[1]);
        assert_eq!(blocks[2].1, cids[2]);
    }

    #[test]
    fn empty_file_has_no_blocks() {
        let (sim, fd) = setup();
        DataFileWriter::new(&sim, fd, DataFileId::new(0)).unwrap();

        let reader = DataFileReader::open(&sim, fd).unwrap();
        let blocks = reader.valid_blocks().unwrap();
        assert!(blocks.is_empty());
    }

    #[test]
    fn detects_truncated_block() {
        let (sim, fd) = setup();
        let mut writer = DataFileWriter::new(&sim, fd, DataFileId::new(0)).unwrap();
        let cid = test_cid(1);
        let _ = writer.append_block(&cid, b"complete block").unwrap();
        writer.sync().unwrap();

        let partial_cid = test_cid(2);
        sim.write_all_at(fd, writer.position().raw(), &partial_cid[..10])
            .unwrap();

        let mut reader = DataFileReader::open(&sim, fd).unwrap();
        let first = reader.next().unwrap().unwrap();
        assert!(matches!(first, ReadBlockRecord::Valid { .. }));

        let second = reader.next().unwrap().unwrap();
        assert!(matches!(second, ReadBlockRecord::Truncated { .. }));
    }

    #[test]
    fn checksum_detects_corruption() {
        let (sim, fd) = setup();
        let mut writer = DataFileWriter::new(&sim, fd, DataFileId::new(0)).unwrap();
        let cid = test_cid(1);
        let data = vec![0xAA; 256];
        let _ = writer.append_block(&cid, &data).unwrap();
        writer.sync().unwrap();

        let corrupt_offset = BLOCK_HEADER_SIZE as u64 + CID_SIZE as u64 + 4 + 128;
        sim.write_all_at(fd, corrupt_offset, &[0x00]).unwrap();

        let mut reader = DataFileReader::open(&sim, fd).unwrap();
        let record = reader.next().unwrap().unwrap();
        assert!(matches!(record, ReadBlockRecord::Corrupted { .. }));
    }

    #[test]
    fn crash_before_sync_loses_blocks() {
        let (sim, fd) = setup();
        let mut writer = DataFileWriter::new(&sim, fd, DataFileId::new(0)).unwrap();
        let cid1 = test_cid(1);
        let _ = writer.append_block(&cid1, b"synced").unwrap();
        writer.sync().unwrap();
        sim.sync_dir(Path::new("/test")).unwrap();

        let cid2 = test_cid(2);
        let _ = writer.append_block(&cid2, b"not synced").unwrap();

        sim.crash();

        let fd = sim
            .open(Path::new("/test/data.tqb"), OpenOptions::read())
            .unwrap();
        let reader = DataFileReader::open(&sim, fd).unwrap();
        let blocks = reader.valid_blocks().unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].2, b"synced");
    }

    #[test]
    fn rejects_oversized_block() {
        let (sim, fd) = setup();
        let mut writer = DataFileWriter::new(&sim, fd, DataFileId::new(0)).unwrap();
        let cid = test_cid(1);
        let oversized = vec![0u8; MAX_BLOCK_SIZE as usize + 1];
        let result = writer.append_block(&cid, &oversized);
        assert!(result.is_err());
    }

    #[test]
    fn zero_length_block_round_trips() {
        let (sim, fd) = setup();
        let mut writer = DataFileWriter::new(&sim, fd, DataFileId::new(0)).unwrap();
        let cid = test_cid(1);

        let location = writer.append_block(&cid, &[]).unwrap();
        writer.sync().unwrap();

        assert_eq!(location.length, BlockLength::new(0));

        let reader = DataFileReader::open(&sim, fd).unwrap();
        let blocks = reader.valid_blocks().unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].1, cid);
        assert!(blocks[0].2.is_empty());
    }

    #[test]
    fn accepts_exact_max_block_size() {
        let (sim, fd) = setup();
        let mut writer = DataFileWriter::new(&sim, fd, DataFileId::new(0)).unwrap();
        let cid = test_cid(1);
        let max_data = vec![0xBB; MAX_BLOCK_SIZE as usize];

        let location = writer.append_block(&cid, &max_data).unwrap();
        assert_eq!(location.length, BlockLength::new(MAX_BLOCK_SIZE));
    }

    #[test]
    fn bad_magic_rejected() {
        let sim = SimulatedIO::pristine(42);
        let dir = Path::new("/test");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();
        let fd = sim
            .open(Path::new("/test/bad.tqb"), OpenOptions::read_write())
            .unwrap();
        sim.write_all_at(fd, 0, b"NOPE\x01").unwrap();

        let result = DataFileReader::open(&sim, fd);
        assert!(result.is_err());
    }

    #[test]
    fn encode_decode_round_trip_at_offset() {
        let (sim, fd) = setup();
        let cid = test_cid(42);
        let data = b"round trip test data";

        sim.write_all_at(fd, 0, &[0u8; 100]).unwrap();

        let offset = BlockOffset::new(100);
        let bytes_written = encode_block_record(&sim, fd, offset, &cid, data).unwrap();
        let expected_size = BLOCK_RECORD_OVERHEAD as u64 + data.len() as u64;
        assert_eq!(bytes_written, expected_size);

        let file_size = sim.file_size(fd).unwrap();
        let record = decode_block_record(&sim, fd, offset, file_size)
            .unwrap()
            .unwrap();
        match record {
            ReadBlockRecord::Valid {
                cid_bytes,
                data: decoded_data,
                ..
            } => {
                assert_eq!(cid_bytes, cid);
                assert_eq!(decoded_data, data);
            }
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn resume_writer_continues_at_position() {
        let (sim, fd) = setup();
        let mut writer = DataFileWriter::new(&sim, fd, DataFileId::new(0)).unwrap();
        let cid1 = test_cid(1);
        let _ = writer.append_block(&cid1, b"first").unwrap();
        writer.sync().unwrap();

        let resume_pos = writer.position();
        let mut writer2 = DataFileWriter::resume(&sim, fd, DataFileId::new(0), resume_pos);
        let cid2 = test_cid(2);
        let _ = writer2.append_block(&cid2, b"second").unwrap();
        writer2.sync().unwrap();

        let reader = DataFileReader::open(&sim, fd).unwrap();
        let blocks = reader.valid_blocks().unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].2, b"first");
        assert_eq!(blocks[1].2, b"second");
    }

    fn run_crash_recovery_seed(seed: u64) {
        let sim = SimulatedIO::new(seed, FaultConfig::aggressive());
        let dir = Path::new("/data");
        let _ = sim.mkdir(dir);
        let _ = sim.sync_dir(dir);

        let mut written_blocks: Vec<(u8, Vec<u8>)> = Vec::new();

        if let Ok(fd) = sim.open(Path::new("/data/000000.tqb"), OpenOptions::read_write())
            && let Ok(mut writer) = DataFileWriter::new(&sim, fd, DataFileId::new(0))
        {
            (0u8..20).for_each(|i| {
                let cid = test_cid(i);
                let data = vec![i; (i as usize + 1) * 10];
                if writer.append_block(&cid, &data).is_ok() {
                    written_blocks.push((i, data));
                }
            });
            let _ = writer.sync();
        }
        let _ = sim.sync_dir(dir);

        sim.crash();

        if let Ok(fd) = sim.open(Path::new("/data/000000.tqb"), OpenOptions::read())
            && let Ok(reader) = DataFileReader::open(&sim, fd)
        {
            let recovered: Vec<_> = reader
                .map_while(|r| match r {
                    Ok(ReadBlockRecord::Valid {
                        cid_bytes, data, ..
                    }) => Some((cid_bytes, data)),
                    _ => None,
                })
                .collect();

            assert!(
                recovered.len() <= written_blocks.len(),
                "recovered {} blocks but only wrote {}",
                recovered.len(),
                written_blocks.len()
            );

            recovered
                .iter()
                .enumerate()
                .for_each(|(i, (cid_bytes, data))| {
                    assert_eq!(cid_bytes[0], 0x01, "phantom block at index {i}");
                    assert_eq!(
                        *cid_bytes,
                        test_cid(written_blocks[i].0),
                        "block {i} cid does not match written order"
                    );
                    assert_eq!(
                        *data, written_blocks[i].1,
                        "block {i} data does not match what was written"
                    );
                });
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        #[test]
        fn sim_crash_recovery_aggressive_faults(seed in 0u64..u64::MAX) {
            run_crash_recovery_seed(seed);
        }
    }

    #[test]
    fn sim_partial_write_mid_block_reports_truncated() {
        let sim = SimulatedIO::pristine(42);
        let dir = Path::new("/data");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();

        let fd = sim
            .open(Path::new("/data/000000.tqb"), OpenOptions::read_write())
            .unwrap();
        let mut writer = DataFileWriter::new(&sim, fd, DataFileId::new(0)).unwrap();

        (0u8..5).for_each(|i| {
            let _ = writer.append_block(&test_cid(i), &[i; 50]).unwrap();
        });
        writer.sync().unwrap();

        let synced_pos = writer.position();

        sim.write_all_at(fd, synced_pos.raw(), &test_cid(5)[..20])
            .unwrap();
        sim.sync(fd).unwrap();
        sim.sync_dir(dir).unwrap();

        sim.crash();

        let fd = sim
            .open(Path::new("/data/000000.tqb"), OpenOptions::read())
            .unwrap();
        let records: Vec<_> = DataFileReader::open(&sim, fd)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(records.len(), 6);
        (0usize..5).for_each(|i| {
            assert!(matches!(&records[i], ReadBlockRecord::Valid { .. }));
        });
        assert!(matches!(&records[5], ReadBlockRecord::Truncated { .. }));

        match &records[5] {
            ReadBlockRecord::Truncated { offset } => {
                assert_eq!(offset.raw(), synced_pos.raw());
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    fn run_bit_flip_detection_seed(seed: u64) {
        let sim = SimulatedIO::pristine(seed);
        let dir = Path::new("/data");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();

        let fd = sim
            .open(Path::new("/data/000000.tqb"), OpenOptions::read_write())
            .unwrap();
        let mut writer = DataFileWriter::new(&sim, fd, DataFileId::new(0)).unwrap();

        let data_len = ((seed % 256) as usize).max(1);
        let cid = test_cid((seed % 256) as u8);
        let data = vec![0xAA; data_len];
        let _ = writer.append_block(&cid, &data).unwrap();
        writer.sync().unwrap();

        let data_start = BLOCK_HEADER_SIZE as u64 + CID_SIZE as u64 + 4;
        let flip_pos = data_start + (seed.wrapping_mul(7) % data_len as u64);
        let flip_bit = (seed.wrapping_mul(13) % 8) as u8;

        let mut byte_buf = [0u8; 1];
        sim.read_exact_at(fd, flip_pos, &mut byte_buf).unwrap();
        byte_buf[0] ^= 1 << flip_bit;
        sim.write_all_at(fd, flip_pos, &byte_buf).unwrap();

        let mut reader = DataFileReader::open(&sim, fd).unwrap();
        let record = reader.next().unwrap().unwrap();
        assert!(matches!(record, ReadBlockRecord::Corrupted { .. }));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        #[test]
        fn sim_bit_flip_detected_by_checksum(seed in 0u64..u64::MAX) {
            run_bit_flip_detection_seed(seed);
        }
    }

    #[test]
    fn sim_rotation_without_dir_sync_loses_new_file() {
        let sim = SimulatedIO::pristine(42);
        let dir = Path::new("/data");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();

        let fd0 = sim
            .open(Path::new("/data/000000.tqb"), OpenOptions::read_write())
            .unwrap();
        let mut writer0 = DataFileWriter::new(&sim, fd0, DataFileId::new(0)).unwrap();
        (0u8..3).for_each(|i| {
            let _ = writer0.append_block(&test_cid(i), &[i; 50]).unwrap();
        });
        writer0.sync().unwrap();
        sim.sync_dir(dir).unwrap();

        let fd1 = sim
            .open(Path::new("/data/000001.tqb"), OpenOptions::read_write())
            .unwrap();
        let mut writer1 = DataFileWriter::new(&sim, fd1, DataFileId::new(1)).unwrap();
        let _ = writer1
            .append_block(&test_cid(10), b"new file data")
            .unwrap();
        writer1.sync().unwrap();

        sim.crash();

        assert!(
            sim.open(Path::new("/data/000001.tqb"), OpenOptions::read())
                .is_err()
        );

        let fd0 = sim
            .open(Path::new("/data/000000.tqb"), OpenOptions::read())
            .unwrap();
        let blocks = DataFileReader::open(&sim, fd0)
            .unwrap()
            .valid_blocks()
            .unwrap();
        assert_eq!(blocks.len(), 3);
    }
}
