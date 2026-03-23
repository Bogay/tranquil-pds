use std::io;

use crate::io::{FileId, StorageIO};

pub const FILE_MAGIC: [u8; 4] = *b"TQST";
pub const FORMAT_VERSION: u8 = 2;
pub const HEADER_SIZE: usize = 5;
pub const RECORD_OVERHEAD: usize = 8;
pub const MAX_RECORD_PAYLOAD: usize = 16 * 1024 * 1024;

fn record_checksum(length_bytes: &[u8; 4], payload: &[u8]) -> u32 {
    let mut hasher = xxhash_rust::xxh3::Xxh3::new();
    hasher.update(length_bytes);
    hasher.update(payload);
    hasher.digest() as u32
}

pub struct RecordWriter<'a, S: StorageIO> {
    io: &'a S,
    fd: FileId,
    position: u64,
}

impl<'a, S: StorageIO> RecordWriter<'a, S> {
    pub fn new(io: &'a S, fd: FileId) -> io::Result<Self> {
        let header = [
            FILE_MAGIC[0],
            FILE_MAGIC[1],
            FILE_MAGIC[2],
            FILE_MAGIC[3],
            FORMAT_VERSION,
        ];
        io.write_all_at(fd, 0, &header)?;
        Ok(Self {
            io,
            fd,
            position: HEADER_SIZE as u64,
        })
    }

    pub fn resume(io: &'a S, fd: FileId, position: u64) -> Self {
        Self { io, fd, position }
    }

    pub fn append(&mut self, payload: &[u8]) -> io::Result<u64> {
        let length = u32::try_from(payload.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "payload exceeds u32::MAX"))?;
        if payload.len() > MAX_RECORD_PAYLOAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "payload exceeds MAX_RECORD_PAYLOAD",
            ));
        }

        let length_bytes = length.to_le_bytes();
        let checksum = record_checksum(&length_bytes, payload);
        let mut cursor = self.position;

        self.io.write_all_at(self.fd, cursor, &length_bytes)?;
        cursor += 4;

        self.io.write_all_at(self.fd, cursor, payload)?;
        cursor += payload.len() as u64;

        let checksum_bytes = checksum.to_le_bytes();
        self.io.write_all_at(self.fd, cursor, &checksum_bytes)?;
        cursor += 4;

        let record_start = self.position;
        self.position = cursor;
        Ok(record_start)
    }

    pub fn sync(&self) -> io::Result<()> {
        self.io.sync(self.fd)
    }

    pub fn position(&self) -> u64 {
        self.position
    }
}

#[derive(Debug)]
pub enum ReadRecord {
    Valid { offset: u64, payload: Vec<u8> },
    Corrupted { offset: u64 },
    Truncated { offset: u64 },
}

pub struct RecordReader<'a, S: StorageIO> {
    io: &'a S,
    fd: FileId,
    position: u64,
    file_size: u64,
}

impl<'a, S: StorageIO> RecordReader<'a, S> {
    pub fn open(io: &'a S, fd: FileId) -> io::Result<Self> {
        let file_size = io.file_size(fd)?;
        if file_size < HEADER_SIZE as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "file too small for header",
            ));
        }

        let mut header = [0u8; HEADER_SIZE];
        io.read_exact_at(fd, 0, &mut header)?;

        if header[..4] != FILE_MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad magic"));
        }
        if header[4] != FORMAT_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported format version",
            ));
        }

        Ok(Self {
            io,
            fd,
            position: HEADER_SIZE as u64,
            file_size,
        })
    }

    pub fn valid_records(self) -> Vec<Vec<u8>> {
        self.map_while(|r| match r {
            ReadRecord::Valid { payload, .. } => Some(payload),
            _ => None,
        })
        .collect()
    }

    fn advance_truncated(&mut self) -> ReadRecord {
        let offset = self.position;
        self.position = self.file_size;
        ReadRecord::Truncated { offset }
    }
}

impl<S: StorageIO> Iterator for RecordReader<'_, S> {
    type Item = ReadRecord;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position >= self.file_size {
            return None;
        }

        let remaining = self.file_size - self.position;
        if remaining < 4 {
            return Some(self.advance_truncated());
        }

        let mut length_bytes = [0u8; 4];
        if self
            .io
            .read_exact_at(self.fd, self.position, &mut length_bytes)
            .is_err()
        {
            return Some(self.advance_truncated());
        }

        let length = u32::from_le_bytes(length_bytes) as u64;

        if length as usize > MAX_RECORD_PAYLOAD {
            let offset = self.position;
            self.position = self.file_size;
            return Some(ReadRecord::Corrupted { offset });
        }

        let record_size = 4 + length + 4;

        if self.position + record_size > self.file_size {
            return Some(self.advance_truncated());
        }

        let mut payload = vec![0u8; length as usize];
        if self
            .io
            .read_exact_at(self.fd, self.position + 4, &mut payload)
            .is_err()
        {
            return Some(self.advance_truncated());
        }

        let mut checksum_bytes = [0u8; 4];
        if self
            .io
            .read_exact_at(self.fd, self.position + 4 + length, &mut checksum_bytes)
            .is_err()
        {
            return Some(self.advance_truncated());
        }

        let stored_checksum = u32::from_le_bytes(checksum_bytes);
        let computed_checksum = record_checksum(&length_bytes, &payload);

        let offset = self.position;

        if stored_checksum == computed_checksum {
            self.position += record_size;
            Some(ReadRecord::Valid { offset, payload })
        } else {
            self.position = self.file_size;
            Some(ReadRecord::Corrupted { offset })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OpenOptions;
    use crate::sim::SimulatedIO;
    use std::path::Path;

    fn setup() -> (SimulatedIO, FileId) {
        let sim = SimulatedIO::pristine(42);
        let dir = Path::new("/test");
        sim.mkdir(dir).unwrap();
        sim.sync_dir(dir).unwrap();
        let fd = sim
            .open(Path::new("/test/records.dat"), OpenOptions::read_write())
            .unwrap();
        (sim, fd)
    }

    #[test]
    fn write_and_read_single_record() {
        let (sim, fd) = setup();
        let mut writer = RecordWriter::new(&sim, fd).unwrap();
        writer.append(b"hello world").unwrap();
        writer.sync().unwrap();

        let reader = RecordReader::open(&sim, fd).unwrap();
        let records = reader.valid_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0], b"hello world");
    }

    #[test]
    fn write_and_read_multiple_records() {
        let (sim, fd) = setup();
        let mut writer = RecordWriter::new(&sim, fd).unwrap();
        writer.append(b"first").unwrap();
        writer.append(b"second").unwrap();
        writer.append(b"third").unwrap();
        writer.sync().unwrap();

        let reader = RecordReader::open(&sim, fd).unwrap();
        let records = reader.valid_records();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0], b"first");
        assert_eq!(records[1], b"second");
        assert_eq!(records[2], b"third");
    }

    #[test]
    fn empty_file_has_no_records() {
        let (sim, fd) = setup();
        RecordWriter::new(&sim, fd).unwrap();

        let reader = RecordReader::open(&sim, fd).unwrap();
        let records = reader.valid_records();
        assert!(records.is_empty());
    }

    #[test]
    fn detects_truncated_record() {
        let (sim, fd) = setup();
        let mut writer = RecordWriter::new(&sim, fd).unwrap();
        writer.append(b"complete record").unwrap();
        writer.sync().unwrap();

        let length_bytes = 100u32.to_le_bytes();
        sim.write_all_at(fd, writer.position(), &length_bytes)
            .unwrap();
        sim.write_all_at(fd, writer.position() + 4, b"short")
            .unwrap();

        let mut reader = RecordReader::open(&sim, fd).unwrap();
        let first = reader.next().unwrap();
        assert!(matches!(first, ReadRecord::Valid { .. }));

        let second = reader.next().unwrap();
        assert!(matches!(second, ReadRecord::Truncated { .. }));
    }

    #[test]
    fn crash_before_sync_loses_records() {
        let (sim, fd) = setup();
        let mut writer = RecordWriter::new(&sim, fd).unwrap();
        writer.append(b"synced").unwrap();
        writer.sync().unwrap();
        sim.sync_dir(Path::new("/test")).unwrap();

        writer.append(b"not synced").unwrap();

        sim.crash();

        let fd = sim
            .open(Path::new("/test/records.dat"), OpenOptions::read())
            .unwrap();
        let reader = RecordReader::open(&sim, fd).unwrap();
        let records = reader.valid_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0], b"synced");
    }

    #[test]
    fn real_io_record_round_trip() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("records.dat");
        let real = crate::RealIO::new();

        let fd = real.open(&path, OpenOptions::read_write()).unwrap();
        let mut writer = RecordWriter::new(&real, fd).unwrap();
        writer.append(b"real record 1").unwrap();
        writer.append(b"real record 2").unwrap();
        writer.sync().unwrap();

        let reader = RecordReader::open(&real, fd).unwrap();
        let records = reader.valid_records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0], b"real record 1");
        assert_eq!(records[1], b"real record 2");

        real.close(fd).unwrap();
    }

    #[test]
    fn checksum_detects_single_bit_flip() {
        let (sim, fd) = setup();
        let mut writer = RecordWriter::new(&sim, fd).unwrap();
        let payload = vec![0xAA; 256];
        writer.append(&payload).unwrap();
        writer.sync().unwrap();

        let mut contents = sim.buffered_contents(fd).unwrap();
        let payload_start = HEADER_SIZE + 4;
        contents[payload_start + 128] ^= 0x01;

        let sim2 = SimulatedIO::pristine(99);
        let dir2 = Path::new("/verify");
        sim2.mkdir(dir2).unwrap();
        sim2.sync_dir(dir2).unwrap();
        let fd2 = sim2
            .open(Path::new("/verify/check.dat"), OpenOptions::read_write())
            .unwrap();
        sim2.write_all_at(fd2, 0, &contents).unwrap();

        let mut reader = RecordReader::open(&sim2, fd2).unwrap();
        let record = reader.next().unwrap();
        assert!(matches!(record, ReadRecord::Corrupted { .. }));
    }
}
