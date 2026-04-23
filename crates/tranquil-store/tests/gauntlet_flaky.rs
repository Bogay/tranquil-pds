use std::num::NonZeroU32;

use tranquil_store::gauntlet::{
    BackingMegabytes, DownIntervalSecs, FlakyConfig, FlakyMount, Gauntlet, Scenario, Seed,
    UpIntervalSecs, config_for,
};

#[tokio::test]
#[ignore = "requires root + dm-flakey; run under a privileged container"]
async fn flaky_device_scenario_sanity() {
    let cfg = config_for(Scenario::FlakyDevice, Seed(1));
    let op_count = cfg.op_count.0;
    let report = Gauntlet::new(cfg).expect("build gauntlet").run().await;
    let env_skip = report
        .violations
        .iter()
        .any(|v| v.invariant == "FlakyEnvironment");
    if env_skip {
        eprintln!(
            "flaky environment unavailable: {}",
            report
                .violations
                .iter()
                .map(|v| format!("{}: {}", v.invariant, v.detail))
                .collect::<Vec<_>>()
                .join(", ")
        );
        return;
    }
    let failures: Vec<String> = report
        .violations
        .iter()
        .map(|v| format!("{}: {}", v.invariant, v.detail))
        .collect();
    assert!(failures.is_empty(), "violations: {failures:?}");
    let floor = op_count / 2;
    assert!(
        report.ops_executed.0 >= floor,
        "flaky ops_executed {} below floor {} of {op_count}: {} op_errors, {} restarts",
        report.ops_executed.0,
        floor,
        report.op_errors.0,
        report.restarts.0,
    );
}

#[test]
#[ignore = "requires root + dm-flakey; exercises mount/teardown without running Gauntlet"]
fn flaky_mount_setup_teardown() {
    let cfg = FlakyConfig {
        up_interval: UpIntervalSecs(NonZeroU32::new(5).unwrap()),
        down_interval: DownIntervalSecs(NonZeroU32::new(1).unwrap()),
        backing_mb: BackingMegabytes(64),
    };
    let mount = match FlakyMount::try_new(&cfg) {
        Ok(m) => m,
        Err(e) if e.is_env_absent() => {
            eprintln!("flaky environment unavailable: {e}");
            return;
        }
        Err(e) => panic!("flaky mount setup failed: {e}"),
    };
    assert!(mount.path().exists(), "mount path should exist");
    assert!(mount.mapper_path().exists(), "mapper device should exist");
    let marker = mount.path().join("marker");
    std::fs::write(&marker, b"ok").expect("write through flaky mount");
    let back = std::fs::read(&marker).expect("read back");
    assert_eq!(back, b"ok");
    drop(mount);
}
