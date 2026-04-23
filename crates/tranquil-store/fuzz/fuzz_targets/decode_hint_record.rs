#![no_main]

use std::path::Path;

use libfuzzer_sys::fuzz_target;
use tranquil_store::blockstore::{HintOffset, decode_hint_record};
use tranquil_store::{FaultConfig, OpenOptions, SimulatedIO, StorageIO};

fuzz_target!(|data: &[u8]| {
    let sim = SimulatedIO::new(0, FaultConfig::none());
    let opts = OpenOptions {
        read: true,
        write: true,
        create: true,
        truncate: false,
    };
    let fd = match sim.open(Path::new("/fuzz/hint.tqh"), opts) {
        Ok(fd) => fd,
        Err(_) => return,
    };
    if !data.is_empty() {
        let _ = sim.write_all_at(fd, 0, data);
        let _ = sim.sync(fd);
    }
    let file_size = data.len() as u64;
    let cursor = std::cell::Cell::new(0u64);
    std::iter::from_fn(|| {
        if cursor.get() >= file_size {
            return None;
        }
        match decode_hint_record(&sim, fd, HintOffset::new(cursor.get()), file_size) {
            Ok(Some(_)) => {
                cursor.set(cursor.get() + 64);
                Some(())
            }
            _ => None,
        }
    })
    .for_each(|()| {});
    let _ = sim.close(fd);
});
