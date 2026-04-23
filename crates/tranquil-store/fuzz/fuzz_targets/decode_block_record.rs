#![no_main]

use std::path::Path;

use libfuzzer_sys::fuzz_target;
use tranquil_store::blockstore::{BlockOffset, decode_block_record};
use tranquil_store::{FaultConfig, OpenOptions, SimulatedIO, StorageIO};

fuzz_target!(|data: &[u8]| {
    let sim = SimulatedIO::new(0, FaultConfig::none());
    let opts = OpenOptions {
        read: true,
        write: true,
        create: true,
        truncate: false,
    };
    let fd = match sim.open(Path::new("/fuzz/block.tqb"), opts) {
        Ok(fd) => fd,
        Err(_) => return,
    };
    if !data.is_empty() {
        let _ = sim.write_all_at(fd, 0, data);
        let _ = sim.sync(fd);
    }
    let file_size = data.len() as u64;
    let _ = decode_block_record(&sim, fd, BlockOffset::new(0), file_size);
    let _ = sim.close(fd);
});
