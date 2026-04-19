use std::cell::RefCell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Duration, Instant};

use rayon::prelude::*;
use tokio::runtime::Runtime;

use super::invariants::InvariantViolation;
use super::op::{OpStream, Seed};
use super::runner::{
    Gauntlet, GauntletConfig, GauntletReport, OpErrorCount, OpsExecuted, RestartCount,
};

thread_local! {
    static RUNTIME: RefCell<Option<Runtime>> = const { RefCell::new(None) };
}

fn with_runtime<R>(f: impl FnOnce(&Runtime) -> R) -> R {
    RUNTIME.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            *slot = Some(
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build rt"),
            );
        }
        f(slot.as_ref().expect("runtime present"))
    })
}

pub fn run_many<F>(make_config: F, seeds: impl IntoIterator<Item = Seed>) -> Vec<GauntletReport>
where
    F: Fn(Seed) -> GauntletConfig + Sync + Send,
{
    run_many_timed(make_config, seeds)
        .into_iter()
        .map(|(r, _)| r)
        .collect()
}

pub fn run_many_timed<F>(
    make_config: F,
    seeds: impl IntoIterator<Item = Seed>,
) -> Vec<(GauntletReport, Duration)>
where
    F: Fn(Seed) -> GauntletConfig + Sync + Send,
{
    let seeds: Vec<Seed> = seeds.into_iter().collect();
    seeds
        .into_par_iter()
        .map(|s| {
            let start = Instant::now();
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                let cfg = make_config(s);
                let gauntlet = Gauntlet::new(cfg).expect("build gauntlet");
                with_runtime(|rt| rt.block_on(gauntlet.run()))
            }));
            let report = outcome.unwrap_or_else(|payload| {
                RUNTIME.with(|cell| cell.borrow_mut().take());
                panic_report(s, payload)
            });
            (report, start.elapsed())
        })
        .collect()
}

fn panic_report(seed: Seed, payload: Box<dyn std::any::Any + Send>) -> GauntletReport {
    let msg = payload
        .downcast_ref::<&'static str>()
        .map(|s| (*s).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".to_string());
    GauntletReport {
        seed,
        ops_executed: OpsExecuted(0),
        op_errors: OpErrorCount(0),
        restarts: RestartCount(0),
        violations: vec![InvariantViolation {
            invariant: "FarmPanic",
            detail: msg,
        }],
        ops: OpStream::empty(),
    }
}
