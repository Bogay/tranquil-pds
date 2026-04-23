#![no_main]

use std::path::Path;

use libfuzzer_sys::fuzz_target;
use tranquil_store::eventlog::SegmentReader;

const FUZZ_MAX_PAYLOAD: u32 = 1 << 20;
use tranquil_store::{FaultConfig, OpenOptions, SimulatedIO, StorageIO};

fuzz_target!(|data: &[u8]| {
    let sim = SimulatedIO::new(0, FaultConfig::none());
    let opts = OpenOptions {
        read: true,
        write: true,
        create: true,
        truncate: false,
    };
    let fd = match sim.open(Path::new("/fuzz/segment.tqe"), opts) {
        Ok(fd) => fd,
        Err(_) => return,
    };
    if !data.is_empty() {
        let _ = sim.write_all_at(fd, 0, data);
        let _ = sim.sync(fd);
    }
    if let Ok(reader) = SegmentReader::open(&sim, fd, FUZZ_MAX_PAYLOAD) {
        reader.for_each(|_result| {});
    }
    let _ = sim.close(fd);
});
