pub mod blockstore;
pub mod eventlog;
pub mod fsync_order;
mod harness;
mod io;
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
pub use sim::{FaultConfig, OpRecord, SimulatedIO};
