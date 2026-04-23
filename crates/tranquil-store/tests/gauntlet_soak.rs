use std::io::{self, BufWriter, Write};
use std::time::Duration;

use tranquil_store::gauntlet::{
    LeakGateConfig, Scenario, Seed, SoakConfig, SoakReport, config_for, run_soak,
};

#[cfg(feature = "gauntlet-jemalloc-prof")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn soak_hours() -> Option<f64> {
    std::env::var("GAUNTLET_SOAK_HOURS")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .filter(|h| h.is_finite() && *h > 0.0)
}

fn soak_sample_interval() -> Duration {
    std::env::var("GAUNTLET_SOAK_SAMPLE_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|s| *s > 0)
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(60))
}

fn emitter_stream() -> Box<dyn Write + Send> {
    match std::env::var("GAUNTLET_SOAK_OUTPUT").ok().as_deref() {
        Some(path) if !path.is_empty() => {
            let f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .expect("open GAUNTLET_SOAK_OUTPUT target");
            Box::new(BufWriter::new(f))
        }
        _ => Box::new(BufWriter::new(io::stderr())),
    }
}

fn report_summary(report: &SoakReport) -> String {
    let leaks: Vec<String> = report
        .leak_violations
        .iter()
        .map(|v| {
            format!(
                "{}: {} -> {} ({}% over {}ms window, limit {}%)",
                v.metric,
                v.start_value,
                v.end_value,
                v.growth_pct.round() as i64,
                v.end_ms - v.start_ms,
                v.limit_pct
            )
        })
        .collect();
    let invariants: Vec<String> = report
        .invariant_violations
        .iter()
        .map(|v| format!("{}: {}", v.invariant, v.detail))
        .collect();
    format!(
        "seed={:016x} ops={} chunks={} errors={} wall_ms={} leaks=[{}] invariants=[{}]",
        report.seed.0,
        report.ops_executed,
        report.chunks,
        report.op_errors,
        report.total_wall_ms,
        leaks.join(" ; "),
        invariants.join(" ; "),
    )
}

#[tokio::test]
async fn soak_short_smoke() {
    let cfg = SoakConfig {
        gauntlet: config_for(Scenario::SmokePR, Seed(7)),
        total_duration: Duration::from_secs(10),
        sample_interval: Duration::from_secs(2),
        chunk_ops: 200,
        leak_gate: LeakGateConfig::try_new(0, 60_000, 1000.0).expect("valid leak gate"),
    };
    let mut buf: Vec<u8> = Vec::new();
    let report = run_soak(cfg, &mut buf).await.expect("soak run");
    assert!(
        report.samples.len() >= 3,
        "expected at least initial + periodic + final samples, got {}",
        report.samples.len()
    );
    assert!(
        report.ops_executed > 0,
        "expected ops executed, got {}",
        report.ops_executed
    );
    let text = String::from_utf8(buf).expect("utf8 ndjson");
    assert!(
        text.contains("\"type\":\"summary\""),
        "ndjson must include summary line; got {text}"
    );
}

#[tokio::test]
#[ignore = "configurable via GAUNTLET_SOAK_HOURS; default 24h leak gate (1h warmup, 4h window, 5% limit)"]
async fn soak_long_leak_gate() {
    let hours = soak_hours().unwrap_or(24.0);
    let total = Duration::from_secs_f64(hours * 3600.0);
    let cfg = SoakConfig {
        gauntlet: config_for(Scenario::MstChurn, Seed(0)),
        total_duration: total,
        sample_interval: soak_sample_interval(),
        chunk_ops: 10_000,
        leak_gate: LeakGateConfig::standard(),
    };
    let mut emitter = emitter_stream();
    let report = run_soak(cfg, &mut emitter).await.expect("soak run");
    let _ = emitter.flush();
    assert!(
        report.is_clean(),
        "soak failed: {}",
        report_summary(&report)
    );
}
