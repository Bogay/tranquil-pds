use std::collections::{HashMap, HashSet};

use super::oracle::Oracle;
use crate::blockstore::{CidBytes, TranquilBlockStore};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvariantSet(u32);

impl InvariantSet {
    pub const EMPTY: Self = Self(0);
    pub const REFCOUNT_CONSERVATION: Self = Self(1 << 0);
    pub const REACHABILITY: Self = Self(1 << 1);

    const ALL_KNOWN: u32 = Self::REFCOUNT_CONSERVATION.0 | Self::REACHABILITY.0;

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn unknown_bits(self) -> u32 {
        self.0 & !Self::ALL_KNOWN
    }
}

impl std::ops::BitOr for InvariantSet {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

#[derive(Debug)]
pub struct InvariantViolation {
    pub invariant: &'static str,
    pub detail: String,
}

pub trait Invariant {
    fn name(&self) -> &'static str;
    fn check(&self, store: &TranquilBlockStore, oracle: &Oracle) -> Result<(), InvariantViolation>;
}

pub struct RefcountConservation;

impl Invariant for RefcountConservation {
    fn name(&self) -> &'static str {
        "RefcountConservation"
    }

    fn check(&self, store: &TranquilBlockStore, oracle: &Oracle) -> Result<(), InvariantViolation> {
        let live: Vec<(String, CidBytes)> = oracle.live_cids_labeled();
        let live_set: HashSet<CidBytes> = live.iter().map(|(_, c)| *c).collect();
        let index: HashMap<CidBytes, u32> = store
            .block_index()
            .live_entries_snapshot()
            .into_iter()
            .map(|(c, r)| (c, r.raw()))
            .collect();

        let forward: Vec<String> = live
            .iter()
            .filter_map(|(label, cid)| match index.get(cid) {
                Some(&r) if r >= 1 => None,
                Some(&r) => Some(format!("{label}: refcount {r}")),
                None => Some(format!("{label}: missing from index")),
            })
            .collect();

        let inverse: Vec<String> = index
            .iter()
            .filter(|(cid, _)| !live_set.contains(*cid))
            .map(|(cid, r)| format!("orphan cid {} refcount {}", hex_short(cid), r))
            .collect();

        let violations: Vec<String> = forward.into_iter().chain(inverse).collect();
        if violations.is_empty() {
            Ok(())
        } else {
            Err(InvariantViolation {
                invariant: "RefcountConservation",
                detail: violations.join("; "),
            })
        }
    }
}

pub struct Reachability;

impl Invariant for Reachability {
    fn name(&self) -> &'static str {
        "Reachability"
    }

    fn check(&self, store: &TranquilBlockStore, oracle: &Oracle) -> Result<(), InvariantViolation> {
        let violations: Vec<String> = oracle
            .live_cids_labeled()
            .into_iter()
            .filter_map(|(label, fixed)| match store.get_block_sync(&fixed) {
                Ok(Some(_)) => None,
                Ok(None) => Some(format!("{label}: missing")),
                Err(e) => Some(format!("{label}: read error {e}")),
            })
            .collect();

        if violations.is_empty() {
            Ok(())
        } else {
            Err(InvariantViolation {
                invariant: "Reachability",
                detail: violations.join("; "),
            })
        }
    }
}

fn hex_short(cid: &CidBytes) -> String {
    let tail = &cid[cid.len() - 6..];
    tail.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn invariants_for(set: InvariantSet) -> Vec<Box<dyn Invariant>> {
    let unknown = set.unknown_bits();
    assert!(
        unknown == 0,
        "invariants_for: unknown InvariantSet bits 0x{unknown:x}; all bits must map to an impl"
    );
    [
        (
            InvariantSet::REFCOUNT_CONSERVATION,
            Box::new(RefcountConservation) as Box<dyn Invariant>,
        ),
        (InvariantSet::REACHABILITY, Box::new(Reachability)),
    ]
    .into_iter()
    .filter_map(|(flag, inv)| set.contains(flag).then_some(inv))
    .collect()
}
