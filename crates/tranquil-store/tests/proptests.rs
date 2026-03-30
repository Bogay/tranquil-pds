use proptest::prelude::*;
use std::path::Path;

use tranquil_store::{
    FaultConfig, HEADER_SIZE, OpenOptions, ReadRecord, RecordReader, RecordWriter, SimulatedIO,
    StorageIO, run_crash_test, run_pristine_comparison, sim_proptest_cases,
};

fn arb_payloads(max_count: usize, max_size: usize) -> BoxedStrategy<Vec<Vec<u8>>> {
    proptest::collection::vec(
        proptest::collection::vec(any::<u8>(), 0..max_size),
        1..max_count,
    )
    .boxed()
}

fn sim_with_dir(seed: u64, config: FaultConfig) -> SimulatedIO {
    let sim = SimulatedIO::new(seed, config);
    sim.mkdir(Path::new("/test")).unwrap();
    sim.sync_dir(Path::new("/test")).unwrap();
    sim
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(sim_proptest_cases()))]

    #[test]
    fn synced_records_survive_crash(
        seed in any::<u64>(),
        payloads in arb_payloads(20, 256),
    ) {
        let result = run_crash_test(
            seed,
            FaultConfig::none(),
            &payloads,
            5,
        ).unwrap();

        prop_assert_eq!(result.records_recovered, result.records_synced);
        prop_assert_eq!(result.corrupted_detected, 0);
    }

    #[test]
    fn recovered_never_exceeds_written(
        seed in any::<u64>(),
        payloads in arb_payloads(15, 128),
    ) {
        let Ok(result) = run_crash_test(
            seed,
            FaultConfig::moderate(),
            &payloads,
            3,
        ) else { return Ok(()); };

        prop_assert!(
            result.records_recovered <= result.records_written,
            "seed {}: recovered {} > written {}",
            seed, result.records_recovered, result.records_written,
        );
    }

    #[test]
    fn no_phantom_records_after_crash(
        seed in any::<u64>(),
        payloads in arb_payloads(10, 512),
    ) {
        let Ok(result) = run_crash_test(
            seed,
            FaultConfig::aggressive(),
            &payloads,
            0,
        ) else { return Ok(()); };

        prop_assert!(
            result.records_recovered <= result.records_synced,
            "seed {}: recovered {} records but only {} were synced",
            seed, result.records_recovered, result.records_synced,
        );
    }

    #[test]
    fn pristine_prefix_holds_under_faults(
        seed in any::<u64>(),
        payloads in arb_payloads(12, 200),
    ) {
        let Ok(result) = run_pristine_comparison(
            seed,
            FaultConfig::moderate(),
            &payloads,
            4,
        ) else { return Ok(()); };

        prop_assert!(result.recovery_within_bounds);
    }

    #[test]
    fn bit_flip_detected_by_u32_checksum(
        seed in any::<u64>(),
        payload in proptest::collection::vec(any::<u8>(), 8..1024),
        flip_offset in any::<usize>(),
        flip_bit in 0u8..8,
    ) {
        let sim = sim_with_dir(seed, FaultConfig::none());
        let fd = sim.open(Path::new("/test/bitflip.dat"), OpenOptions::read_write()).unwrap();

        let mut writer = RecordWriter::new(&sim, fd).unwrap();
        writer.append(&payload).unwrap();
        writer.sync().unwrap();

        let mut contents = sim.durable_contents(fd).unwrap();
        let record_region = &mut contents[HEADER_SIZE..];
        let idx = flip_offset % record_region.len();
        record_region[idx] ^= 1 << flip_bit;

        let sim2 = sim_with_dir(seed.wrapping_add(1), FaultConfig::none());
        let fd2 = sim2.open(Path::new("/test/check.dat"), OpenOptions::read_write()).unwrap();
        sim2.write_all_at(fd2, 0, &contents).unwrap();
        sim2.sync(fd2).unwrap();

        let mut reader = RecordReader::open(&sim2, fd2).unwrap();
        match reader.next() {
            Some(ReadRecord::Valid { payload: ref recovered, .. }) => {
                prop_assert_eq!(recovered, &payload, "bit flip produced valid record with wrong data");
            }
            Some(ReadRecord::Corrupted { .. }) => {}
            Some(ReadRecord::Truncated { .. }) => {}
            None => {}
        }
    }

    #[test]
    fn aggressive_faults_many_seeds(
        seed in 0u64..10_000,
    ) {
        let payloads: Vec<Vec<u8>> = (0..5)
            .map(|i| format!("aggressive-test-{i}-{seed}").into_bytes())
            .collect();
        let Ok(result) = run_crash_test(
            seed,
            FaultConfig::aggressive(),
            &payloads,
            2,
        ) else { return Ok(()); };

        prop_assert!(result.records_recovered <= payloads.len());
    }

    #[test]
    fn write_all_at_handles_partial_writes(
        seed in any::<u64>(),
        data in proptest::collection::vec(any::<u8>(), 64..4096),
    ) {
        let config = FaultConfig {
            partial_write_probability: 0.5,
            ..FaultConfig::none()
        };
        let dir = Path::new("/test");
        let path = Path::new("/test/partial.dat");
        let sim = sim_with_dir(seed, config);
        let fd = sim.open(path, OpenOptions::read_write()).unwrap();
        sim.sync_dir(dir).unwrap();

        sim.write_all_at(fd, 0, &data).unwrap();
        sim.sync(fd).unwrap();

        sim.crash();

        let fd = sim.open(path, OpenOptions::read()).unwrap();
        let mut buf = vec![0u8; data.len()];
        sim.read_exact_at(fd, 0, &mut buf).unwrap();
        prop_assert_eq!(&buf, &data, "write_all_at must produce complete writes");
    }

    #[test]
    fn dir_sync_required_for_file_survival(
        seed in any::<u64>(),
        data in proptest::collection::vec(any::<u8>(), 1..256),
    ) {
        let sim = SimulatedIO::pristine(seed);
        sim.mkdir(Path::new("/ephemeral")).unwrap();

        let fd = sim.open(
            Path::new("/ephemeral/file.dat"),
            OpenOptions::read_write(),
        ).unwrap();
        sim.write_all_at(fd, 0, &data).unwrap();
        sim.sync(fd).unwrap();

        sim.crash();

        let result = sim.open(Path::new("/ephemeral/file.dat"), OpenOptions::read());
        prop_assert!(result.is_err(), "file must vanish without dir sync");
    }
}
