use std::cell::RefCell;

use rayon::prelude::*;
use tokio::runtime::Runtime;

use super::op::Seed;
use super::runner::{Gauntlet, GauntletConfig, GauntletReport};

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
    let seeds: Vec<Seed> = seeds.into_iter().collect();
    seeds
        .into_par_iter()
        .map(|s| {
            let cfg = make_config(s);
            let gauntlet = Gauntlet::new(cfg).expect("build gauntlet");
            with_runtime(|rt| rt.block_on(gauntlet.run()))
        })
        .collect()
}
