pub mod archival;
pub mod backup;
pub mod blockstore;
pub mod bloom;
pub mod consistency;
pub mod eventlog;
pub mod fsync_order;
#[cfg(any(test, feature = "test-harness"))]
pub mod gauntlet;
#[cfg(any(test, feature = "test-harness"))]
mod harness;
mod io;
pub mod metastore;
mod record;
#[cfg(any(test, feature = "test-harness"))]
mod sim;

pub use blockstore::BlocksSynced;
pub use fsync_order::PostBlockstoreHook;
#[cfg(any(test, feature = "test-harness"))]
pub use harness::{
    CrashTestResult, PristineComparisonResult, run_crash_test, run_pristine_comparison,
};
pub use io::{FileId, MappedFile, OpenOptions, RealIO, StorageIO};
pub use record::{
    FILE_MAGIC, FORMAT_VERSION, HEADER_SIZE, MAX_RECORD_PAYLOAD, RECORD_OVERHEAD, ReadRecord,
    RecordReader, RecordWriter,
};
#[cfg(any(test, feature = "test-harness"))]
pub use sim::{
    FaultConfig, OpRecord, SimulatedIO, sim_proptest_cases, sim_seed_count, sim_seed_range,
    sim_single_seed,
};

pub(crate) fn wall_clock_ms() -> blockstore::WallClockMs {
    blockstore::WallClockMs::now()
}
