use std::io;
use std::path::Path;

use crate::io::{OpenOptions, StorageIO};
use crate::record::{RecordReader, RecordWriter};
use crate::sim::{FaultConfig, SimulatedIO};

fn setup_sim_file(sim: &SimulatedIO, name: &str) -> io::Result<(crate::io::FileId, String)> {
    let dir = Path::new("/harness");
    sim.mkdir(dir)?;
    sim.sync_dir(dir)?;
    let path_str = format!("/harness/{name}");
    let path = Path::new(&path_str);
    let fd = sim.open(path, OpenOptions::read_write())?;
    sim.sync_dir(dir)?;
    Ok((fd, path_str))
}

fn reopen_after_crash(sim: &SimulatedIO, path: &str) -> io::Result<crate::io::FileId> {
    sim.open(Path::new(path), OpenOptions::read())
}

pub struct CrashTestResult {
    pub seed: u64,
    pub records_written: usize,
    pub records_synced: usize,
    pub records_recovered: usize,
    pub corrupted_detected: usize,
    pub truncated_detected: usize,
}

pub fn run_crash_test(
    seed: u64,
    fault_config: FaultConfig,
    payloads: &[Vec<u8>],
    sync_after: usize,
) -> io::Result<CrashTestResult> {
    let sim = SimulatedIO::new(seed, fault_config);
    let (fd, path) = setup_sim_file(&sim, "crash_test.dat")?;

    let mut writer = RecordWriter::new(&sim, fd)?;

    let mut records_written = 0usize;
    let mut records_synced = 0usize;

    let _stop_reason = payloads
        .iter()
        .enumerate()
        .try_fold((), |(), (i, payload)| {
            writer.append(payload)?;
            records_written += 1;
            if sync_after > 0
                && (i + 1) % sync_after == 0
                && writer.sync().is_ok()
                && sim.last_sync_persisted()
            {
                records_synced = records_written;
            }
            Ok::<_, io::Error>(())
        });

    sim.crash();

    let recovery_fd = match reopen_after_crash(&sim, &path) {
        Ok(fd) => fd,
        Err(_) => {
            return Ok(CrashTestResult {
                seed,
                records_written,
                records_synced,
                records_recovered: 0,
                corrupted_detected: 0,
                truncated_detected: 0,
            });
        }
    };

    let reader = match RecordReader::open(&sim, recovery_fd) {
        Ok(r) => r,
        Err(_) => {
            return Ok(CrashTestResult {
                seed,
                records_written,
                records_synced,
                records_recovered: 0,
                corrupted_detected: 0,
                truncated_detected: 0,
            });
        }
    };

    use crate::record::ReadRecord;

    let collected: Vec<_> = reader
        .scan(false, |stopped, record| {
            if *stopped {
                return None;
            }
            match record {
                ReadRecord::Valid { .. } => Some(record),
                other => {
                    *stopped = true;
                    Some(other)
                }
            }
        })
        .collect();

    let records_recovered = collected
        .iter()
        .filter(|r| matches!(r, ReadRecord::Valid { .. }))
        .count();
    let corrupted_detected = collected.last().map_or(0, |r| {
        usize::from(matches!(r, ReadRecord::Corrupted { .. }))
    });
    let truncated_detected = collected.last().map_or(0, |r| {
        usize::from(matches!(r, ReadRecord::Truncated { .. }))
    });

    Ok(CrashTestResult {
        seed,
        records_written,
        records_synced,
        records_recovered,
        corrupted_detected,
        truncated_detected,
    })
}

pub fn run_pristine_comparison(
    seed: u64,
    fault_config: FaultConfig,
    payloads: &[Vec<u8>],
    sync_after: usize,
) -> io::Result<PristineComparisonResult> {
    let pristine = SimulatedIO::pristine(seed);
    let (pristine_fd, _) = setup_sim_file(&pristine, "pristine.dat")?;
    let mut pristine_writer = RecordWriter::new(&pristine, pristine_fd)?;

    let synced_payloads = payloads
        .iter()
        .enumerate()
        .fold(
            (Vec::<Vec<u8>>::new(), Vec::<Vec<u8>>::new()),
            |(mut synced, mut pending), (i, payload)| {
                pristine_writer.append(payload).unwrap();
                pending.push(payload.clone());

                if sync_after > 0 && (i + 1) % sync_after == 0 {
                    pristine_writer.sync().unwrap();
                    synced.append(&mut pending);
                }
                (synced, pending)
            },
        )
        .0;

    let faulty = SimulatedIO::new(seed, fault_config);
    let (faulty_fd, faulty_path) = setup_sim_file(&faulty, "faulty.dat")?;
    let mut faulty_writer = RecordWriter::new(&faulty, faulty_fd)?;

    payloads
        .iter()
        .enumerate()
        .try_fold((), |(), (i, payload)| {
            faulty_writer.append(payload)?;
            if sync_after > 0 && (i + 1) % sync_after == 0 {
                let _ = faulty_writer.sync();
            }
            Ok::<_, io::Error>(())
        })
        .ok();

    faulty.crash();

    let recovered = match reopen_after_crash(&faulty, &faulty_path)
        .and_then(|fd| RecordReader::open(&faulty, fd))
    {
        Ok(reader) => reader.valid_records(),
        Err(_) => Vec::new(),
    };

    let prefix_valid = recovered
        .iter()
        .zip(synced_payloads.iter())
        .all(|(r, p)| r == p);

    let recovery_within_bounds = recovered.len() <= payloads.len();

    Ok(PristineComparisonResult {
        seed,
        synced_count: synced_payloads.len(),
        recovered_count: recovered.len(),
        prefix_matches_pristine: prefix_valid,
        recovery_within_bounds,
    })
}

pub struct PristineComparisonResult {
    pub seed: u64,
    pub synced_count: usize,
    pub recovered_count: usize,
    pub prefix_matches_pristine: bool,
    pub recovery_within_bounds: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_fault_recovers_all_synced() {
        let payloads: Vec<Vec<u8>> = (0..10)
            .map(|i| format!("record {i}").into_bytes())
            .collect();
        let result = run_crash_test(42, FaultConfig::none(), &payloads, 5).unwrap();
        assert_eq!(result.records_synced, 10);
        assert_eq!(result.records_recovered, 10);
        assert_eq!(result.corrupted_detected, 0);
    }

    #[test]
    fn no_fault_unsynced_records_lost() {
        let payloads: Vec<Vec<u8>> = (0..10)
            .map(|i| format!("record {i}").into_bytes())
            .collect();
        let result = run_crash_test(42, FaultConfig::none(), &payloads, 0).unwrap();
        assert_eq!(result.records_recovered, 0);
    }

    #[test]
    fn pristine_comparison_no_faults() {
        let payloads: Vec<Vec<u8>> = (0..20)
            .map(|i| format!("payload {i}").into_bytes())
            .collect();
        let result = run_pristine_comparison(42, FaultConfig::none(), &payloads, 5).unwrap();
        assert!(result.prefix_matches_pristine);
        assert!(result.recovery_within_bounds);
        assert_eq!(result.synced_count, 20);
        assert_eq!(result.recovered_count, 20);
    }

    #[test]
    fn faulted_recovery_never_exceeds_written() {
        (0..1000).for_each(|seed| {
            let payloads: Vec<Vec<u8>> = (0..5).map(|i| format!("data-{i}").into_bytes()).collect();
            let Ok(result) = run_crash_test(seed, FaultConfig::moderate(), &payloads, 2) else {
                return;
            };
            assert!(
                result.records_recovered <= result.records_written,
                "seed {seed}: recovered {} > written {}",
                result.records_recovered,
                result.records_written,
            );
        });
    }

    #[test]
    fn pristine_comparison_with_faults() {
        (0..1000).for_each(|seed| {
            let payloads: Vec<Vec<u8>> = (0..8).map(|i| format!("item-{i}").into_bytes()).collect();
            let Ok(result) = run_pristine_comparison(seed, FaultConfig::moderate(), &payloads, 4)
            else {
                return;
            };
            assert!(
                result.recovery_within_bounds,
                "seed {seed}: recovered more than written"
            );
        });
    }
}
