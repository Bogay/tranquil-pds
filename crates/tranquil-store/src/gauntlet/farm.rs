use std::cell::RefCell;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
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
    run_many_timed_with_scratch_roots(make_config, &[], seeds)
}

pub fn run_many_timed_with_scratch_roots<F>(
    make_config: F,
    scratch_roots: &[PathBuf],
    seeds: impl IntoIterator<Item = Seed>,
) -> Vec<(GauntletReport, Duration)>
where
    F: Fn(Seed) -> GauntletConfig + Sync + Send,
{
    let seeds: Vec<Seed> = seeds.into_iter().collect();
    seeds
        .into_par_iter()
        .map(|s| {
            let scratch = scratch_for_thread(scratch_roots, rayon::current_thread_index());
            let start = Instant::now();
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                let cfg = make_config(s);
                let mut gauntlet = Gauntlet::new(cfg).expect("build gauntlet");
                if let Some(root) = scratch {
                    gauntlet = gauntlet.with_scratch_root(root);
                }
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

fn scratch_for_thread(roots: &[PathBuf], thread_idx: Option<usize>) -> Option<PathBuf> {
    if roots.is_empty() {
        None
    } else {
        Some(roots[thread_idx.unwrap_or(0) % roots.len()].clone())
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scratch_for_thread_returns_none_when_roots_empty() {
        assert!(scratch_for_thread(&[], Some(0)).is_none());
        assert!(scratch_for_thread(&[], Some(7)).is_none());
        assert!(scratch_for_thread(&[], None).is_none());
    }

    #[test]
    fn scratch_for_thread_round_robins_across_roots() {
        let roots = vec![
            PathBuf::from("/scratch/a"),
            PathBuf::from("/scratch/b"),
            PathBuf::from("/scratch/c"),
        ];
        let assigned: Vec<PathBuf> = (0..7)
            .map(|i| scratch_for_thread(&roots, Some(i)).expect("scratch path"))
            .collect();
        assert_eq!(
            assigned,
            vec![
                PathBuf::from("/scratch/a"),
                PathBuf::from("/scratch/b"),
                PathBuf::from("/scratch/c"),
                PathBuf::from("/scratch/a"),
                PathBuf::from("/scratch/b"),
                PathBuf::from("/scratch/c"),
                PathBuf::from("/scratch/a"),
            ]
        );
    }

    #[test]
    fn scratch_for_thread_with_single_root_returns_same_path() {
        let roots = vec![PathBuf::from("/scratch/only")];
        (0..5).for_each(|i| {
            assert_eq!(
                scratch_for_thread(&roots, Some(i)),
                Some(PathBuf::from("/scratch/only"))
            );
        });
    }

    #[test]
    fn scratch_for_thread_falls_back_to_root_zero_outside_pool() {
        let roots = vec![PathBuf::from("/scratch/a"), PathBuf::from("/scratch/b")];
        assert_eq!(
            scratch_for_thread(&roots, None),
            Some(PathBuf::from("/scratch/a"))
        );
    }
}
