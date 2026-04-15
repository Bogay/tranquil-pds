use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use cid::Cid;
use jacquard_repo::mst::Mst;

use super::oracle::{Oracle, hex_short, try_cid_to_fixed};
use crate::blockstore::{CidBytes, TranquilBlockStore};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvariantSet(u32);

impl InvariantSet {
    pub const EMPTY: Self = Self(0);
    pub const REFCOUNT_CONSERVATION: Self = Self(1 << 0);
    pub const REACHABILITY: Self = Self(1 << 1);
    pub const ACKED_WRITE_PERSISTENCE: Self = Self(1 << 2);
    pub const READ_AFTER_WRITE: Self = Self(1 << 3);
    pub const RESTART_IDEMPOTENT: Self = Self(1 << 4);

    const ALL_KNOWN: u32 = Self::REFCOUNT_CONSERVATION.0
        | Self::REACHABILITY.0
        | Self::ACKED_WRITE_PERSISTENCE.0
        | Self::READ_AFTER_WRITE.0
        | Self::RESTART_IDEMPOTENT.0;

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
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

pub struct InvariantCtx<'a> {
    pub store: &'a Arc<TranquilBlockStore>,
    pub oracle: &'a Oracle,
    pub root: Option<Cid>,
}

#[async_trait]
pub trait Invariant: Send + Sync {
    fn name(&self) -> &'static str;
    async fn check(&self, ctx: &InvariantCtx<'_>) -> Result<(), InvariantViolation>;
}

pub struct RefcountConservation;

#[async_trait]
impl Invariant for RefcountConservation {
    fn name(&self) -> &'static str {
        "RefcountConservation"
    }

    async fn check(&self, ctx: &InvariantCtx<'_>) -> Result<(), InvariantViolation> {
        let live: Vec<(String, CidBytes)> = ctx.oracle.live_cids_labeled();
        let live_set: HashSet<CidBytes> = live.iter().map(|(_, c)| *c).collect();
        let index: HashMap<CidBytes, u32> = ctx
            .store
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

#[async_trait]
impl Invariant for Reachability {
    fn name(&self) -> &'static str {
        "Reachability"
    }

    async fn check(&self, ctx: &InvariantCtx<'_>) -> Result<(), InvariantViolation> {
        let violations: Vec<String> = ctx
            .oracle
            .live_cids_labeled()
            .into_iter()
            .filter_map(|(label, fixed)| match ctx.store.get_block_sync(&fixed) {
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

pub struct AckedWritePersistence;

#[async_trait]
impl Invariant for AckedWritePersistence {
    fn name(&self) -> &'static str {
        "AckedWritePersistence"
    }

    async fn check(&self, ctx: &InvariantCtx<'_>) -> Result<(), InvariantViolation> {
        let Some(root) = ctx.root else {
            if ctx.oracle.live_count() == 0 {
                return Ok(());
            }
            return Err(InvariantViolation {
                invariant: "AckedWritePersistence",
                detail: format!(
                    "oracle has {} live records but reopened store has no root",
                    ctx.oracle.live_count()
                ),
            });
        };
        let mst = Mst::load(ctx.store.clone(), root, None);
        let keys: Vec<String> = ctx
            .oracle
            .live_records()
            .map(|(c, r, _)| format!("{}/{}", c.0, r.0))
            .collect();

        let mut missing: Vec<String> = Vec::new();
        for key in &keys {
            match mst.get(key).await {
                Ok(Some(_)) => {}
                Ok(None) => missing.push(format!("{key}: missing after reopen")),
                Err(e) => missing.push(format!("{key}: mst.get error after reopen: {e}")),
            }
        }

        if missing.is_empty() {
            Ok(())
        } else {
            Err(InvariantViolation {
                invariant: "AckedWritePersistence",
                detail: missing.join("; "),
            })
        }
    }
}

pub struct ReadAfterWrite;

#[async_trait]
impl Invariant for ReadAfterWrite {
    fn name(&self) -> &'static str {
        "ReadAfterWrite"
    }

    async fn check(&self, ctx: &InvariantCtx<'_>) -> Result<(), InvariantViolation> {
        let Some(root) = ctx.root else {
            return Ok(());
        };
        let mst = Mst::load(ctx.store.clone(), root, None);

        let entries: Vec<(String, CidBytes)> = ctx
            .oracle
            .live_records()
            .map(|(c, r, v)| (format!("{}/{}", c.0, r.0), *v))
            .collect();

        let mut violations: Vec<String> = Vec::new();
        for (key, expected) in &entries {
            match mst.get(key).await {
                Ok(Some(cid)) => match try_cid_to_fixed(&cid) {
                    Ok(actual) if actual == *expected => match ctx.store.get_block_sync(&actual) {
                        Ok(Some(_)) => {}
                        Ok(None) => violations.push(format!("{key}: block missing for cid")),
                        Err(e) => violations.push(format!("{key}: block read error {e}")),
                    },
                    Ok(actual) => violations.push(format!(
                        "{key}: MST cid {} != oracle cid {}",
                        hex_short(&actual),
                        hex_short(expected),
                    )),
                    Err(e) => {
                        violations.push(format!("{key}: unexpected CID format from MST: {e}"))
                    }
                },
                Ok(None) => violations.push(format!("{key}: MST returned None")),
                Err(e) => violations.push(format!("{key}: mst.get error {e}")),
            }
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(InvariantViolation {
                invariant: "ReadAfterWrite",
                detail: violations.join("; "),
            })
        }
    }
}

pub fn invariants_for(set: InvariantSet) -> Vec<Box<dyn Invariant>> {
    let unknown = set.unknown_bits();
    assert!(
        unknown == 0,
        "invariants_for: unknown InvariantSet bits 0x{unknown:x}; all bits must map to an impl"
    );
    let candidates: Vec<(InvariantSet, Box<dyn Invariant>)> = vec![
        (
            InvariantSet::REFCOUNT_CONSERVATION,
            Box::new(RefcountConservation),
        ),
        (InvariantSet::REACHABILITY, Box::new(Reachability)),
        (
            InvariantSet::ACKED_WRITE_PERSISTENCE,
            Box::new(AckedWritePersistence),
        ),
        (InvariantSet::READ_AFTER_WRITE, Box::new(ReadAfterWrite)),
    ];
    candidates
        .into_iter()
        .filter_map(|(flag, inv)| set.contains(flag).then_some(inv))
        .collect()
}
