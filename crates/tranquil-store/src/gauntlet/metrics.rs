use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::warn;

use super::runner::{EventLogState, Harness};
use crate::blockstore::TranquilBlockStore;
use crate::io::StorageIO;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct MetricsSample {
    pub elapsed_ms: u64,
    pub rss_bytes: Option<u64>,
    pub fd_count: Option<u64>,
    pub data_dir_bytes: u64,
    pub index_dir_bytes: u64,
    pub segments_dir_bytes: u64,
    pub data_file_count: Option<u64>,
    pub segment_count: Option<u64>,
    pub block_index_entries: u64,
    pub hint_file_bytes: u64,
}

impl MetricsSample {
    pub fn metric(&self, name: MetricName) -> Option<u64> {
        match name {
            MetricName::RssBytes => self.rss_bytes,
            MetricName::FdCount => self.fd_count,
            MetricName::DataDirBytes => Some(self.data_dir_bytes),
            MetricName::IndexDirBytes => Some(self.index_dir_bytes),
            MetricName::SegmentsDirBytes => Some(self.segments_dir_bytes),
            MetricName::DataFileCount => self.data_file_count,
            MetricName::SegmentCount => self.segment_count,
            MetricName::BlockIndexEntries => Some(self.block_index_entries),
            MetricName::HintFileBytes => Some(self.hint_file_bytes),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MetricName {
    RssBytes,
    FdCount,
    DataDirBytes,
    IndexDirBytes,
    SegmentsDirBytes,
    DataFileCount,
    SegmentCount,
    BlockIndexEntries,
    HintFileBytes,
}

impl MetricName {
    pub const ALL: &'static [MetricName] = &[
        Self::RssBytes,
        Self::FdCount,
        Self::DataDirBytes,
        Self::IndexDirBytes,
        Self::SegmentsDirBytes,
        Self::DataFileCount,
        Self::SegmentCount,
        Self::BlockIndexEntries,
        Self::HintFileBytes,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RssBytes => "rss_bytes",
            Self::FdCount => "fd_count",
            Self::DataDirBytes => "data_dir_bytes",
            Self::IndexDirBytes => "index_dir_bytes",
            Self::SegmentsDirBytes => "segments_dir_bytes",
            Self::DataFileCount => "data_file_count",
            Self::SegmentCount => "segment_count",
            Self::BlockIndexEntries => "block_index_entries",
            Self::HintFileBytes => "hint_file_bytes",
        }
    }

    pub const fn min_absolute_delta(self) -> u64 {
        match self {
            Self::RssBytes => 16 * 1024 * 1024,
            Self::FdCount => 16,
            Self::DataDirBytes => 16 * 1024 * 1024,
            Self::IndexDirBytes => 1024 * 1024,
            Self::SegmentsDirBytes => 16 * 1024 * 1024,
            Self::DataFileCount => 16,
            Self::SegmentCount => 4,
            Self::BlockIndexEntries => 1024,
            Self::HintFileBytes => 1024 * 1024,
        }
    }
}

pub fn sample_harness<S: StorageIO + Send + Sync + 'static>(
    harness: &Harness<S>,
    elapsed: Duration,
) -> MetricsSample {
    MetricsSample {
        elapsed_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        rss_bytes: read_rss(),
        fd_count: count_open_fds(),
        data_dir_bytes: dir_bytes(harness.store.data_dir()),
        index_dir_bytes: dir_bytes(harness.store.block_index().index_dir()),
        segments_dir_bytes: harness
            .eventlog
            .as_ref()
            .map(|el| dir_bytes(&el.segments_dir))
            .unwrap_or(0),
        data_file_count: data_file_count(&harness.store),
        segment_count: harness.eventlog.as_ref().and_then(segment_count),
        block_index_entries: harness.store.block_index().approximate_block_count(),
        hint_file_bytes: hint_bytes(harness.store.data_dir()),
    }
}

fn data_file_count<S: StorageIO + Send + Sync + 'static>(
    store: &Arc<TranquilBlockStore<S>>,
) -> Option<u64> {
    match store.list_data_files() {
        Ok(v) => Some(v.len() as u64),
        Err(e) => {
            warn!(error = %e, "gauntlet metrics: list_data_files failed");
            None
        }
    }
}

fn segment_count<S: StorageIO + Send + Sync + 'static>(el: &EventLogState<S>) -> Option<u64> {
    match el.manager.list_segments() {
        Ok(v) => Some(v.len() as u64),
        Err(e) => {
            warn!(error = %e, "gauntlet metrics: list_segments failed");
            None
        }
    }
}

fn dir_bytes(path: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    entries
        .filter_map(Result::ok)
        .map(|entry| match entry.file_type() {
            Ok(ft) if ft.is_dir() => dir_bytes(&entry.path()),
            Ok(_) => entry.metadata().map(|m| m.len()).unwrap_or(0),
            Err(_) => 0,
        })
        .sum()
}

fn hint_bytes(data_dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(data_dir) else {
        return 0;
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .path()
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e == "tqh")
                .unwrap_or(false)
        })
        .map(|entry| entry.metadata().map(|m| m.len()).unwrap_or(0))
        .sum()
}

#[cfg(target_os = "linux")]
fn read_rss() -> Option<u64> {
    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "gauntlet metrics: read /proc/self/status failed");
            return None;
        }
    };
    let parsed = status.lines().find_map(|line| {
        let rest = line.strip_prefix("VmRSS:")?;
        let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
        Some(kb * 1024)
    });
    if parsed.is_none() {
        warn!("gauntlet metrics: VmRSS line missing from /proc/self/status");
    }
    parsed
}

#[cfg(not(target_os = "linux"))]
fn read_rss() -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn count_open_fds() -> Option<u64> {
    match std::fs::read_dir("/proc/self/fd") {
        Ok(entries) => Some(entries.filter_map(Result::ok).count() as u64),
        Err(e) => {
            warn!(error = %e, "gauntlet metrics: read /proc/self/fd failed");
            None
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn count_open_fds() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_names_roundtrip_strings() {
        MetricName::ALL.iter().for_each(|m| {
            let s = m.as_str();
            assert!(!s.is_empty());
        });
    }

    #[test]
    #[cfg_attr(not(target_os = "linux"), ignore = "linux /proc only")]
    fn rss_reads_nonzero() {
        let rss = read_rss().expect("rss");
        assert!(rss > 0, "rss should be positive, got {rss}");
    }

    #[test]
    #[cfg_attr(not(target_os = "linux"), ignore = "linux /proc only")]
    fn fd_count_reads_nonzero() {
        let fd = count_open_fds().expect("fd");
        assert!(fd > 0);
    }

    #[test]
    fn dir_bytes_sums_entries() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("a"), b"1234").unwrap();
        std::fs::write(dir.path().join("b"), b"5678").unwrap();
        assert_eq!(dir_bytes(dir.path()), 8);
    }
}
