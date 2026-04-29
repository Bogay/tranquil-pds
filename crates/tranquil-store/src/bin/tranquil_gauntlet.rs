use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;
use tranquil_store::gauntlet::{
    ConfigOverrides, Gauntlet, GauntletReport, InvariantViolation, OpStream, RegressionRecord,
    Scenario, Seed, config_for, farm,
    shrink::{DEFAULT_MAX_SHRINK_ITERATIONS, shrink_failure},
};

const MAX_HOURS: f64 = 1.0e6;
const DEFAULT_SWEEP_RUN_CAP: u64 = 10_000;

/// Deterministic storage-engine gauntlet: scenario fuzzing, shrinking, regression replay.
///
/// Writes one NDjson record per seed to stdout; `farm` adds a final summary record.
/// Progress, batch stats, interrupt notices, and errors go to stderr.
/// Exits 0 on success, 1 on invariant violation, 2 on argument or runtime error.
/// First SIGINT stops after the current batch; a second press aborts.
///
/// Hopefully we'll catch super complicated tranquil-store bugs with this!!
#[derive(Debug, Parser)]
#[command(name = "tranquil-gauntlet", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Run a scenario across many seeds in parallel.
    ///
    /// With --hours, the command loops batches of --seeds until the deadline passes.
    /// Without --hours, a single batch runs and the command exits.
    /// The last stdout line is always a `"type":"summary"` record.
    Farm {
        /// Scenario to run.
        #[arg(long, value_enum, required_unless_present = "config")]
        scenario: Option<Scenario>,

        /// First seed in the batch range. Default 0.
        #[arg(long)]
        seed_start: Option<u64>,

        /// Number of seeds per batch. Default 256. Must be > 0.
        #[arg(long)]
        seeds: Option<u64>,

        /// Wall-clock budget in hours; batches repeat until the deadline elapses.
        #[arg(long)]
        hours: Option<f64>,

        /// Directory to dump regression Json on failure.
        #[arg(long)]
        dump_regressions: Option<PathBuf>,

        /// Toml config with any of the above fields plus an `[overrides]` table.
        #[arg(long)]
        config: Option<PathBuf>,

        /// Tempdir parent for `IoBackend::Real` seeds only - ignored for
        /// flaky-mount and simulated backends. Repeatable; each rayon worker
        /// thread is pinned to one root so concurrent seeds on different
        /// threads land on different mounts. Default `/tmp`. Also reads
        /// colon-separated paths from `GAUNTLET_SCRATCH_ROOTS`. Set
        /// `RAYON_NUM_THREADS=N` to cap workers; for full distribution pass
        /// one root per worker.
        #[arg(long)]
        scratch_root: Vec<PathBuf>,

        /// Skip shrinking when dumping regressions.
        #[arg(long)]
        no_shrink: bool,

        /// Max shrink attempts per failing seed.
        #[arg(long, default_value_t = DEFAULT_MAX_SHRINK_ITERATIONS, conflicts_with = "no_shrink")]
        shrink_budget: usize,
    },
    /// Fan out a scenario across the cartesian product of declared axes.
    ///
    /// Reads a Toml config with [axes] lists (writer_concurrency, key_space, value_bytes,
    /// fault_density_scale, fault_density_uniform, restart_every_n_ops, commit_batch_size,
    /// max_file_size). For each combination, runs --seeds seeds and emits one NDjson record
    /// per (combo, seed).
    Sweep {
        /// Toml config declaring scenario & axes.
        #[arg(long)]
        config: PathBuf,

        /// First seed in the batch range. Default 0.
        #[arg(long)]
        seed_start: Option<u64>,

        /// Seeds per axis combination. Default 8. Must be > 0.
        #[arg(long)]
        seeds: Option<u64>,

        /// Directory to dump regression Json on failure.
        #[arg(long)]
        dump_regressions: Option<PathBuf>,

        /// Same as `farm --scratch-root`: tempdir parent for
        /// `IoBackend::Real` seeds only, pinned per worker thread. Ignored
        /// for flaky-mount and simulated backends. Repeatable; reads
        /// colon-separated paths from `GAUNTLET_SCRATCH_ROOTS`.
        #[arg(long)]
        scratch_root: Vec<PathBuf>,

        /// Skip shrinking when dumping regressions.
        #[arg(long)]
        no_shrink: bool,

        /// Max shrink attempts per failing seed.
        #[arg(long, default_value_t = DEFAULT_MAX_SHRINK_ITERATIONS, conflicts_with = "no_shrink")]
        shrink_budget: usize,

        /// Hard cap on total (combinations x seeds). Default 10_000. Set 0 to disable.
        #[arg(long, default_value_t = DEFAULT_SWEEP_RUN_CAP)]
        max_runs: u64,
    },
    /// Replay a single seed or a saved regression file.
    ///
    /// With --from, replays a regression Json produced by `farm --dump-regressions`.
    /// Otherwise supply --scenario and --seed, or a --config that sets them.
    /// Writes one NDjson record to stdout.
    Repro {
        /// Scenario to replay. Ignored when --from is set.
        #[arg(long, value_enum, conflicts_with = "from", required_unless_present_any = ["config", "from"])]
        scenario: Option<Scenario>,

        /// Seed to replay. Ignored when --from is set.
        #[arg(long, conflicts_with = "from", required_unless_present_any = ["config", "from"])]
        seed: Option<u64>,

        /// Toml config with optional scenario, seed, and overrides.
        #[arg(long, conflicts_with = "from")]
        config: Option<PathBuf>,

        /// Replay a saved regression Json from `farm --dump-regressions`.
        #[arg(long)]
        from: Option<PathBuf>,

        /// Directory to dump regression Json if replay fails.
        #[arg(long)]
        dump_regressions: Option<PathBuf>,

        /// Skip shrinking when dumping regressions.
        #[arg(long)]
        no_shrink: bool,

        /// Max shrink attempts when dumping regressions.
        #[arg(long, default_value_t = DEFAULT_MAX_SHRINK_ITERATIONS, conflicts_with = "no_shrink")]
        shrink_budget: usize,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    #[serde(default)]
    scenario: Option<Scenario>,
    #[serde(default)]
    seed: Option<u64>,
    #[serde(default)]
    seed_start: Option<u64>,
    #[serde(default)]
    seeds: Option<u64>,
    #[serde(default)]
    hours: Option<f64>,
    #[serde(default)]
    dump_regressions: Option<PathBuf>,
    #[serde(default)]
    scratch_roots: Vec<PathBuf>,
    #[serde(default)]
    overrides: ConfigOverrides,
}

fn load_config_file(path: &Path) -> Result<ConfigFile, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    toml::from_str(&raw).map_err(|e| format!("parse {}: {e}", path.display()))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SweepConfigFile {
    scenario: Scenario,
    #[serde(default)]
    seed_start: Option<u64>,
    #[serde(default)]
    seeds: Option<u64>,
    #[serde(default)]
    dump_regressions: Option<PathBuf>,
    #[serde(default)]
    scratch_roots: Vec<PathBuf>,
    #[serde(default)]
    base_overrides: ConfigOverrides,
    #[serde(default)]
    axes: SweepAxes,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SweepAxes {
    #[serde(default)]
    writer_concurrency: Vec<usize>,
    #[serde(default)]
    key_space: Vec<u32>,
    #[serde(default)]
    value_bytes: Vec<u32>,
    #[serde(default)]
    fault_density_scale: Vec<f64>,
    #[serde(default)]
    fault_density_uniform: Vec<f64>,
    #[serde(default)]
    restart_every_n_ops: Vec<usize>,
    #[serde(default)]
    commit_batch_size: Vec<usize>,
    #[serde(default)]
    max_file_size: Vec<u64>,
}

#[derive(Debug, Clone, Copy, Default)]
struct SweepAxisValues {
    writer_concurrency: Option<usize>,
    key_space: Option<u32>,
    value_bytes: Option<u32>,
    fault_density_scale: Option<f64>,
    fault_density_uniform: Option<f64>,
    restart_every_n_ops: Option<usize>,
    commit_batch_size: Option<usize>,
    max_file_size: Option<u64>,
}

impl SweepAxisValues {
    fn apply_to(self, o: &mut ConfigOverrides) {
        if let Some(v) = self.writer_concurrency {
            o.writer_concurrency = Some(v);
        }
        if let Some(v) = self.key_space {
            o.key_space = Some(v);
        }
        if let Some(v) = self.value_bytes {
            o.value_bytes = Some(v);
        }
        if let Some(v) = self.fault_density_scale {
            o.fault_density_scale = Some(v);
        }
        if let Some(v) = self.fault_density_uniform {
            o.fault_density_uniform = Some(v);
        }
        if let Some(v) = self.restart_every_n_ops {
            o.restart_every_n_ops = Some(v);
        }
        if let Some(v) = self.commit_batch_size {
            o.store.group_commit.max_batch_size = Some(v);
        }
        if let Some(v) = self.max_file_size {
            o.store.max_file_size = Some(v);
        }
    }
}

impl SweepAxes {
    fn axis_values(&self) -> Vec<SweepAxisValues> {
        expand(&self.writer_concurrency)
            .into_iter()
            .flat_map(|wc| {
                expand(&self.key_space).into_iter().flat_map(move |ks| {
                    expand(&self.value_bytes).into_iter().flat_map(move |vb| {
                        expand(&self.fault_density_scale)
                            .into_iter()
                            .flat_map(move |fds| {
                                expand(&self.fault_density_uniform).into_iter().flat_map(
                                    move |fdu| {
                                        expand(&self.restart_every_n_ops).into_iter().flat_map(
                                            move |rc| {
                                                expand(&self.commit_batch_size)
                                                    .into_iter()
                                                    .flat_map(move |cb| {
                                                        expand(&self.max_file_size).into_iter().map(
                                                            move |mfs| SweepAxisValues {
                                                                writer_concurrency: wc,
                                                                key_space: ks,
                                                                value_bytes: vb,
                                                                fault_density_scale: fds,
                                                                fault_density_uniform: fdu,
                                                                restart_every_n_ops: rc,
                                                                commit_batch_size: cb,
                                                                max_file_size: mfs,
                                                            },
                                                        )
                                                    })
                                            },
                                        )
                                    },
                                )
                            })
                    })
                })
            })
            .collect()
    }
}

fn expand<T: Copy>(values: &[T]) -> Vec<Option<T>> {
    if values.is_empty() {
        vec![None]
    } else {
        values.iter().copied().map(Some).collect()
    }
}

#[derive(Debug, Serialize)]
struct NdjsonResult {
    scenario: &'static str,
    seed: u64,
    ops_executed: usize,
    op_errors: usize,
    restarts: usize,
    clean: bool,
    violations: Vec<NdjsonViolation>,
    wall_ms: u64,
    ops_in_stream: usize,
    #[serde(skip_serializing_if = "serde_json::Value::is_null")]
    overrides: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct NdjsonViolation {
    invariant: &'static str,
    detail: String,
}

#[derive(Debug, Serialize)]
struct NdjsonSummary {
    #[serde(rename = "type")]
    kind: &'static str,
    scenario: &'static str,
    seeds_run: u64,
    clean: u64,
    failed: u64,
    total_ops: u64,
    wall_ms: u64,
    interrupted: bool,
}

fn emit_summary(summary: &NdjsonSummary) {
    let line = match serde_json::to_string(summary) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("summary serialize failed: {e}");
            return;
        }
    };
    let stdout = io::stdout();
    let mut w = stdout.lock();
    if let Err(e) = writeln!(w, "{line}").and_then(|()| w.flush())
        && e.kind() != io::ErrorKind::BrokenPipe
    {
        eprintln!("summary emit failed: {e}");
    }
}

fn overrides_json(overrides: &ConfigOverrides) -> serde_json::Value {
    match serde_json::to_value(overrides) {
        Ok(v) if v.as_object().map(|m| m.is_empty()).unwrap_or(true) => serde_json::Value::Null,
        Ok(v) => v,
        Err(_) => serde_json::Value::Null,
    }
}

fn emit(
    scenario: Scenario,
    report: &GauntletReport,
    elapsed: Duration,
    overrides: &ConfigOverrides,
) -> io::Result<()> {
    let result = NdjsonResult {
        scenario: scenario.cli_name(),
        seed: report.seed.0,
        ops_executed: report.ops_executed.0,
        op_errors: report.op_errors.0,
        restarts: report.restarts.0,
        clean: report.is_clean(),
        violations: report
            .violations
            .iter()
            .map(|v: &InvariantViolation| NdjsonViolation {
                invariant: v.invariant,
                detail: v.detail.clone(),
            })
            .collect(),
        wall_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        ops_in_stream: report.ops.len(),
        overrides: overrides_json(overrides),
    };
    let line = serde_json::to_string(&result).map_err(io::Error::other)?;
    let stdout = io::stdout();
    let mut w = stdout.lock();
    writeln!(w, "{line}")?;
    w.flush()
}

fn emit_or_log(
    scenario: Scenario,
    report: &GauntletReport,
    elapsed: Duration,
    overrides: &ConfigOverrides,
) {
    if let Err(e) = emit(scenario, report, elapsed, overrides)
        && e.kind() != io::ErrorKind::BrokenPipe
    {
        eprintln!("ndjson emit failed: {e}");
    }
}

struct FarmPlan {
    scenario: Scenario,
    seed_start: u64,
    seeds: u64,
    hours: Option<f64>,
    dump_regressions: Option<PathBuf>,
    scratch_roots: Vec<PathBuf>,
    overrides: ConfigOverrides,
    shrink: bool,
    shrink_budget: usize,
}

#[allow(clippy::too_many_arguments)]
fn resolve_farm(
    scenario: Option<Scenario>,
    seed_start: Option<u64>,
    seeds: Option<u64>,
    hours: Option<f64>,
    dump_regressions: Option<PathBuf>,
    config: Option<PathBuf>,
    scratch_root: Vec<PathBuf>,
    shrink: bool,
    shrink_budget: usize,
) -> Result<FarmPlan, String> {
    let file: Option<ConfigFile> = config.as_ref().map(|p| load_config_file(p)).transpose()?;
    let scenario = scenario
        .or_else(|| file.as_ref().and_then(|f| f.scenario))
        .ok_or("must pass --scenario or set `scenario` in --config")?;
    let seed_start = seed_start
        .or_else(|| file.as_ref().and_then(|f| f.seed_start))
        .unwrap_or(0);
    let seeds = seeds
        .or_else(|| file.as_ref().and_then(|f| f.seeds))
        .unwrap_or(256);
    if seeds == 0 {
        return Err("--seeds must be greater than zero".to_string());
    }
    let hours = hours.or_else(|| file.as_ref().and_then(|f| f.hours));
    if let Some(h) = hours {
        validate_hours(h)?;
    }
    if shrink && shrink_budget == 0 {
        return Err("--shrink-budget must be greater than zero".to_string());
    }
    let dump_regressions =
        dump_regressions.or_else(|| file.as_ref().and_then(|f| f.dump_regressions.clone()));
    let file_scratch_roots = file
        .as_ref()
        .map(|f| f.scratch_roots.clone())
        .unwrap_or_default();
    let scratch_roots = resolve_scratch_roots(scratch_root, file_scratch_roots)?;
    let overrides = file.map(|f| f.overrides).unwrap_or_default();
    Ok(FarmPlan {
        scenario,
        seed_start,
        seeds,
        hours,
        dump_regressions,
        scratch_roots,
        overrides,
        shrink,
        shrink_budget,
    })
}

const SCRATCH_ROOTS_ENV: &str = "GAUNTLET_SCRATCH_ROOTS";

fn resolve_scratch_roots(
    cli: Vec<PathBuf>,
    config_file: Vec<PathBuf>,
) -> Result<Vec<PathBuf>, String> {
    let env_roots: Vec<PathBuf> = std::env::var(SCRATCH_ROOTS_ENV)
        .ok()
        .filter(|s| !s.is_empty())
        .map(|s| s.split(':').map(PathBuf::from).collect())
        .unwrap_or_default();
    let candidate: Vec<PathBuf> = if !cli.is_empty() {
        cli
    } else if !config_file.is_empty() {
        config_file
    } else {
        env_roots
    };
    candidate
        .into_iter()
        .map(|p| validate_scratch_root(&p).map(|_| p))
        .collect()
}

fn validate_scratch_root(path: &Path) -> Result<(), String> {
    match path.metadata() {
        Ok(m) if m.is_dir() => {}
        Ok(_) => return Err(format!("scratch root not a directory: {}", path.display())),
        Err(e) => return Err(format!("scratch root {}: {e}", path.display())),
    }
    tempfile::Builder::new()
        .prefix(".tranquil-gauntlet-probe-")
        .tempfile_in(path)
        .map(|_| ())
        .map_err(|e| format!("scratch root {} not writable: {e}", path.display()))
}

fn validate_hours(h: f64) -> Result<(), String> {
    if !h.is_finite() || h <= 0.0 {
        return Err(format!("invalid --hours={h}: must be positive and finite"));
    }
    if h > MAX_HOURS {
        return Err(format!("invalid --hours={h}: must not exceed {MAX_HOURS}"));
    }
    Ok(())
}

enum ReproPlan {
    FromFile {
        record: RegressionRecord,
        dump_regressions: Option<PathBuf>,
        shrink: bool,
        shrink_budget: usize,
    },
    FromSeed {
        scenario: Scenario,
        seed: Seed,
        overrides: ConfigOverrides,
        dump_regressions: Option<PathBuf>,
        shrink: bool,
        shrink_budget: usize,
    },
}

#[allow(clippy::too_many_arguments)]
fn resolve_repro(
    scenario: Option<Scenario>,
    seed: Option<u64>,
    config: Option<PathBuf>,
    from: Option<PathBuf>,
    dump_regressions: Option<PathBuf>,
    shrink: bool,
    shrink_budget: usize,
) -> Result<ReproPlan, String> {
    if shrink && shrink_budget == 0 {
        return Err("--shrink-budget must be greater than zero".to_string());
    }
    if let Some(path) = from {
        let record = RegressionRecord::load(&path).map_err(|e| e.to_string())?;
        return Ok(ReproPlan::FromFile {
            record,
            dump_regressions,
            shrink,
            shrink_budget,
        });
    }
    let file: Option<ConfigFile> = config.as_ref().map(|p| load_config_file(p)).transpose()?;
    let scenario = scenario
        .or_else(|| file.as_ref().and_then(|f| f.scenario))
        .ok_or("must pass --scenario, set `scenario` in --config, or use --from")?;
    let seed = seed
        .or_else(|| file.as_ref().and_then(|f| f.seed))
        .ok_or("must pass --seed, set `seed` in --config, or use --from")?;
    let overrides = file.map(|f| f.overrides).unwrap_or_default();
    Ok(ReproPlan::FromSeed {
        scenario,
        seed: Seed(seed),
        overrides,
        dump_regressions,
        shrink,
        shrink_budget,
    })
}

fn build_runtime() -> Result<Runtime, ExitCode> {
    Runtime::new().map_err(|e| {
        eprintln!("failed to build tokio runtime: {e}");
        ExitCode::from(2)
    })
}

fn install_interrupt(rt: &Runtime) -> Arc<AtomicBool> {
    let flag = Arc::new(AtomicBool::new(false));
    let f = flag.clone();
    rt.spawn(async move {
        if tokio::signal::ctrl_c().await.is_err() {
            return;
        }
        f.store(true, Ordering::Relaxed);
        eprintln!("interrupt received, stopping after current batch; press Ctrl-C again to abort");
        if tokio::signal::ctrl_c().await.is_ok() {
            eprintln!("second interrupt, aborting");
            std::process::exit(130);
        }
    });
    flag
}

fn main() -> ExitCode {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("off")),
        )
        .with_writer(io::stderr)
        .try_init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Farm {
            scenario,
            seed_start,
            seeds,
            hours,
            dump_regressions,
            config,
            scratch_root,
            no_shrink,
            shrink_budget,
        } => {
            let plan = match resolve_farm(
                scenario,
                seed_start,
                seeds,
                hours,
                dump_regressions,
                config,
                scratch_root,
                !no_shrink,
                shrink_budget,
            ) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            };
            let rt = match build_runtime() {
                Ok(rt) => rt,
                Err(code) => return code,
            };
            let interrupt = install_interrupt(&rt);
            run_farm(plan, &rt, interrupt)
        }
        Cmd::Repro {
            scenario,
            seed,
            config,
            from,
            dump_regressions,
            no_shrink,
            shrink_budget,
        } => {
            let plan = match resolve_repro(
                scenario,
                seed,
                config,
                from,
                dump_regressions,
                !no_shrink,
                shrink_budget,
            ) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            };
            let rt = match build_runtime() {
                Ok(rt) => rt,
                Err(code) => return code,
            };
            run_repro(plan, &rt)
        }
        Cmd::Sweep {
            config,
            seed_start,
            seeds,
            dump_regressions,
            scratch_root,
            no_shrink,
            shrink_budget,
            max_runs,
        } => {
            let plan = match resolve_sweep(
                config,
                seed_start,
                seeds,
                dump_regressions,
                scratch_root,
                !no_shrink,
                shrink_budget,
                max_runs,
            ) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            };
            let rt = match build_runtime() {
                Ok(rt) => rt,
                Err(code) => return code,
            };
            let interrupt = install_interrupt(&rt);
            run_sweep(plan, &rt, interrupt)
        }
    }
}

struct SweepPlan {
    scenario: Scenario,
    seed_start: u64,
    seeds: u64,
    dump_regressions: Option<PathBuf>,
    scratch_roots: Vec<PathBuf>,
    shrink: bool,
    shrink_budget: usize,
    base_overrides: ConfigOverrides,
    axes: Vec<SweepAxisValues>,
}

#[allow(clippy::too_many_arguments)]
fn resolve_sweep(
    config: PathBuf,
    seed_start: Option<u64>,
    seeds: Option<u64>,
    dump_regressions: Option<PathBuf>,
    scratch_root: Vec<PathBuf>,
    shrink: bool,
    shrink_budget: usize,
    max_runs: u64,
) -> Result<SweepPlan, String> {
    let raw =
        std::fs::read_to_string(&config).map_err(|e| format!("read {}: {e}", config.display()))?;
    let file: SweepConfigFile =
        toml::from_str(&raw).map_err(|e| format!("parse {}: {e}", config.display()))?;
    let seed_start = seed_start.or(file.seed_start).unwrap_or(0);
    let seeds = seeds.or(file.seeds).unwrap_or(8);
    if seeds == 0 {
        return Err("--seeds must be greater than zero".to_string());
    }
    if shrink && shrink_budget == 0 {
        return Err("--shrink-budget must be greater than zero".to_string());
    }
    let dump_regressions = dump_regressions.or(file.dump_regressions.clone());
    let scratch_roots = resolve_scratch_roots(scratch_root, file.scratch_roots.clone())?;
    let axes = file.axes.axis_values();
    if axes.is_empty() {
        return Err("sweep produced no combinations".to_string());
    }
    if max_runs > 0 {
        let combos = axes.len() as u64;
        let total = combos.saturating_mul(seeds);
        if total > max_runs {
            return Err(format!(
                "sweep would run {total} cases (combinations={combos} x seeds={seeds}), exceeds --max-runs {max_runs}; raise --max-runs or shrink axes"
            ));
        }
    }
    Ok(SweepPlan {
        scenario: file.scenario,
        seed_start,
        seeds,
        dump_regressions,
        scratch_roots,
        shrink,
        shrink_budget,
        base_overrides: file.base_overrides,
        axes,
    })
}

#[derive(Debug, Serialize)]
struct NdjsonSweepSummary {
    #[serde(rename = "type")]
    kind: &'static str,
    scenario: &'static str,
    combinations: u64,
    seeds_per_combination: u64,
    total_seeds: u64,
    clean: u64,
    failed: u64,
    wall_ms: u64,
    interrupted: bool,
}

fn emit_sweep_summary(summary: &NdjsonSweepSummary) {
    let line = match serde_json::to_string(summary) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sweep summary serialize failed: {e}");
            return;
        }
    };
    let stdout = io::stdout();
    let mut w = stdout.lock();
    if let Err(e) = writeln!(w, "{line}").and_then(|()| w.flush())
        && e.kind() != io::ErrorKind::BrokenPipe
    {
        eprintln!("sweep summary emit failed: {e}");
    }
}

fn run_sweep(plan: SweepPlan, rt: &Runtime, interrupt: Arc<AtomicBool>) -> ExitCode {
    let SweepPlan {
        scenario,
        seed_start,
        seeds,
        dump_regressions,
        scratch_roots,
        shrink,
        shrink_budget,
        base_overrides,
        axes,
    } = plan;
    let run_start = Instant::now();
    let mut any_failed = false;
    let mut total_seeds: u64 = 0;
    let mut total_clean: u64 = 0;
    let mut total_failed: u64 = 0;
    let combos = axes.len() as u64;
    eprintln!(
        "sweep {}: {} combinations x {} seeds = {} runs",
        scenario.cli_name(),
        combos,
        seeds,
        combos.saturating_mul(seeds),
    );
    let end = match seed_start.checked_add(seeds) {
        Some(e) => e,
        None => {
            eprintln!("seed range overflowed u64: seed_start={seed_start} seeds={seeds}");
            return ExitCode::from(2);
        }
    };
    for (combo_idx, axis_values) in axes.iter().enumerate() {
        if interrupt.load(Ordering::Relaxed) {
            break;
        }
        let mut overrides = base_overrides.clone();
        axis_values.apply_to(&mut overrides);
        let combo_start = Instant::now();
        let overrides_for_farm = overrides.clone();
        let reports = farm::run_many_timed_with_scratch_roots(
            move |s| {
                let mut cfg = config_for(scenario, s);
                overrides_for_farm.apply_to(&mut cfg);
                cfg
            },
            &scratch_roots,
            (seed_start..end).map(Seed),
        );
        let combo_wall = combo_start.elapsed();
        let combo_failed = reports.iter().filter(|(r, _)| !r.is_clean()).count();
        let combo_clean = reports.len().saturating_sub(combo_failed);
        reports.iter().for_each(|(r, elapsed)| {
            if !r.is_clean() {
                any_failed = true;
                if let Some(root) = &dump_regressions {
                    dump_regression(scenario, r, root, &overrides, shrink, shrink_budget, rt);
                }
            }
            emit_or_log(scenario, r, *elapsed, &overrides);
        });
        total_seeds += reports.len() as u64;
        total_clean += combo_clean as u64;
        total_failed += combo_failed as u64;
        eprintln!(
            "combo {}/{}: {} clean, {} failed, {:.1}s",
            combo_idx + 1,
            combos,
            combo_clean,
            combo_failed,
            combo_wall.as_secs_f64(),
        );
    }
    let wall_ms = u64::try_from(run_start.elapsed().as_millis()).unwrap_or(u64::MAX);
    emit_sweep_summary(&NdjsonSweepSummary {
        kind: "sweep_summary",
        scenario: scenario.cli_name(),
        combinations: combos,
        seeds_per_combination: seeds,
        total_seeds,
        clean: total_clean,
        failed: total_failed,
        wall_ms,
        interrupted: interrupt.load(Ordering::Relaxed),
    });
    if any_failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn run_farm(plan: FarmPlan, rt: &Runtime, interrupt: Arc<AtomicBool>) -> ExitCode {
    let FarmPlan {
        scenario,
        seed_start,
        seeds,
        hours,
        dump_regressions,
        scratch_roots,
        overrides,
        shrink,
        shrink_budget,
    } = plan;
    let deadline = hours.map(|h| Instant::now() + Duration::from_secs_f64(h * 3600.0));
    let run_start = Instant::now();
    let mut any_failed = false;
    let mut next_seed = seed_start;
    let mut total_seeds: u64 = 0;
    let mut total_clean: u64 = 0;
    let mut total_failed: u64 = 0;
    let mut total_ops: u64 = 0;

    loop {
        if interrupt.load(Ordering::Relaxed) {
            break;
        }
        if let Some(d) = deadline
            && Instant::now() >= d
        {
            break;
        }
        let end = match next_seed.checked_add(seeds) {
            Some(e) => e,
            None => {
                eprintln!("seed range overflowed u64: seed_start={next_seed} seeds={seeds}");
                break;
            }
        };
        let overrides_ref = &overrides;
        let batch_start = Instant::now();
        let reports = farm::run_many_timed_with_scratch_roots(
            |s| {
                let mut cfg = config_for(scenario, s);
                overrides_ref.apply_to(&mut cfg);
                cfg
            },
            &scratch_roots,
            (next_seed..end).map(Seed),
        );
        let batch_wall = batch_start.elapsed();
        let batch_failed = reports.iter().filter(|(r, _)| !r.is_clean()).count();
        let batch_clean = reports.len().saturating_sub(batch_failed);
        let batch_ops: u64 = reports.iter().map(|(r, _)| r.ops_executed.0 as u64).sum();
        reports.iter().for_each(|(r, elapsed)| {
            if !r.is_clean() {
                any_failed = true;
                if let Some(root) = &dump_regressions {
                    dump_regression(scenario, r, root, &overrides, shrink, shrink_budget, rt);
                }
            }
            emit_or_log(scenario, r, *elapsed, &overrides);
        });
        total_seeds += reports.len() as u64;
        total_clean += batch_clean as u64;
        total_failed += batch_failed as u64;
        total_ops += batch_ops;
        let wall_secs = batch_wall.as_secs_f64();
        let ops_per_sec_display: String = if wall_secs > 0.0 {
            format!("{:.0} ops/s", batch_ops as f64 / wall_secs)
        } else {
            "n/a ops/s".to_string()
        };
        eprintln!(
            "batch {next_seed}..{end}: {batch_clean} clean, {batch_failed} failed, {wall_secs:.1}s, {ops_per_sec_display}",
        );
        if deadline.is_none() {
            break;
        }
        next_seed = end;
    }

    let wall_ms = u64::try_from(run_start.elapsed().as_millis()).unwrap_or(u64::MAX);
    emit_summary(&NdjsonSummary {
        kind: "summary",
        scenario: scenario.cli_name(),
        seeds_run: total_seeds,
        clean: total_clean,
        failed: total_failed,
        total_ops,
        wall_ms,
        interrupted: interrupt.load(Ordering::Relaxed),
    });

    if any_failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn dump_regression(
    scenario: Scenario,
    report: &GauntletReport,
    root: &Path,
    overrides: &ConfigOverrides,
    shrink: bool,
    shrink_budget: usize,
    rt: &Runtime,
) {
    let original_len = report.ops.len();
    let (final_ops, final_report) = if shrink && original_len > 0 {
        let mut cfg = config_for(scenario, report.seed);
        overrides.apply_to(&mut cfg);
        let outcome = rt.block_on(shrink_failure(
            cfg,
            report.ops.clone(),
            report.clone(),
            shrink_budget,
        ));
        eprintln!(
            "shrank {} -> {} ops for seed {:016x} in {} runs",
            original_len,
            outcome.ops.len(),
            report.seed.0,
            outcome.iterations,
        );
        (outcome.ops, outcome.report)
    } else {
        (report.ops.clone(), report.clone())
    };
    let record = RegressionRecord::from_report(
        scenario,
        overrides.clone(),
        &final_report,
        original_len,
        final_ops,
    );
    match record.write_to(root) {
        Ok(path) => eprintln!("wrote regression to {}", path.display()),
        Err(e) => eprintln!("regression dump failed: {e}"),
    }
}

fn run_repro(plan: ReproPlan, rt: &Runtime) -> ExitCode {
    match plan {
        ReproPlan::FromFile {
            record,
            dump_regressions,
            shrink,
            shrink_budget,
        } => run_repro_from_record(record, dump_regressions, shrink, shrink_budget, rt),
        ReproPlan::FromSeed {
            scenario,
            seed,
            overrides,
            dump_regressions,
            shrink,
            shrink_budget,
        } => {
            let mut cfg = config_for(scenario, seed);
            overrides.apply_to(&mut cfg);
            let start = Instant::now();
            let gauntlet = match Gauntlet::new(cfg) {
                Ok(g) => g,
                Err(e) => {
                    eprintln!("gauntlet init failed: {e}");
                    return ExitCode::from(2);
                }
            };
            let report = rt.block_on(gauntlet.run());
            let elapsed = start.elapsed();
            if !report.is_clean()
                && let Some(root) = &dump_regressions
            {
                dump_regression(
                    scenario,
                    &report,
                    root,
                    &overrides,
                    shrink,
                    shrink_budget,
                    rt,
                );
            }
            emit_or_log(scenario, &report, elapsed, &overrides);
            if report.is_clean() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
    }
}

fn run_repro_from_record(
    record: RegressionRecord,
    dump_regressions: Option<PathBuf>,
    shrink: bool,
    shrink_budget: usize,
    rt: &Runtime,
) -> ExitCode {
    let scenario = match record.scenario_enum() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let cfg = match record.build_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let shrunk_from = if record.original_ops_len > record.ops.len() {
        format!(", shrunk from {}", record.original_ops_len)
    } else {
        String::new()
    };
    eprintln!(
        "replay {} seed {:016x}: {} ops{}, {} recorded violations",
        scenario.cli_name(),
        record.seed.0,
        record.ops.len(),
        shrunk_from,
        record.violations.len(),
    );
    record.violations.iter().for_each(|v| {
        eprintln!("violation {}: {}", v.invariant, v.detail);
    });
    let overrides = record.overrides.clone();
    let ops: OpStream = record.op_stream();
    let start = Instant::now();
    let gauntlet = match Gauntlet::new(cfg) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("build gauntlet: {e}");
            return ExitCode::from(2);
        }
    };
    let report = rt.block_on(gauntlet.run_with_ops(ops));
    let elapsed = start.elapsed();
    if !report.is_clean()
        && let Some(root) = &dump_regressions
    {
        dump_regression(
            scenario,
            &report,
            root,
            &overrides,
            shrink,
            shrink_budget,
            rt,
        );
    }
    emit_or_log(scenario, &report, elapsed, &overrides);
    if report.is_clean() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
