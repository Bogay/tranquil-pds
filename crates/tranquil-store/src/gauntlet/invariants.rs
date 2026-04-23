use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use cid::Cid;
use jacquard_repo::mst::Mst;

use super::oracle::{Oracle, hex_short, try_cid_to_fixed};
use crate::blockstore::{
    BLOCK_HEADER_SIZE, CidBytes, CompactionError, TranquilBlockStore, hash_to_cid_bytes,
};
use crate::eventlog::{EventSequence, SegmentId};
use crate::io::{RealIO, StorageIO};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvariantSet(u32);

impl InvariantSet {
    pub const EMPTY: Self = Self(0);
    pub const REFCOUNT_CONSERVATION: Self = Self(1 << 0);
    pub const REACHABILITY: Self = Self(1 << 1);
    pub const ACKED_WRITE_PERSISTENCE: Self = Self(1 << 2);
    pub const READ_AFTER_WRITE: Self = Self(1 << 3);
    pub const RESTART_IDEMPOTENT: Self = Self(1 << 4);
    pub const COMPACTION_IDEMPOTENT: Self = Self(1 << 5);
    pub const NO_ORPHAN_FILES: Self = Self(1 << 6);
    pub const BYTE_BUDGET: Self = Self(1 << 7);
    pub const MANIFEST_EQUALS_REALITY: Self = Self(1 << 8);
    pub const CHECKSUM_COVERAGE: Self = Self(1 << 9);
    pub const MONOTONIC_SEQ: Self = Self(1 << 10);
    pub const FSYNC_ORDERING: Self = Self(1 << 11);
    pub const TOMBSTONE_BOUND: Self = Self(1 << 12);

    const ALL_KNOWN: u32 = Self::REFCOUNT_CONSERVATION.0
        | Self::REACHABILITY.0
        | Self::ACKED_WRITE_PERSISTENCE.0
        | Self::READ_AFTER_WRITE.0
        | Self::RESTART_IDEMPOTENT.0
        | Self::COMPACTION_IDEMPOTENT.0
        | Self::NO_ORPHAN_FILES.0
        | Self::BYTE_BUDGET.0
        | Self::MANIFEST_EQUALS_REALITY.0
        | Self::CHECKSUM_COVERAGE.0
        | Self::MONOTONIC_SEQ.0
        | Self::FSYNC_ORDERING.0
        | Self::TOMBSTONE_BOUND.0;

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

#[derive(Debug, Clone)]
pub struct InvariantViolation {
    pub invariant: &'static str,
    pub detail: String,
}

#[derive(Debug, Clone, Copy)]
pub struct SnapshotEvent {
    pub seq: EventSequence,
    pub timestamp_us: u64,
    pub event_type_raw: u8,
    pub did_hash: u32,
}

#[derive(Debug, Clone)]
pub struct EventLogSnapshot {
    pub segments_dir: PathBuf,
    pub max_segment_size: u64,
    pub synced_seq: EventSequence,
    pub segments: Vec<SegmentId>,
    pub events: Vec<SnapshotEvent>,
    pub segment_last_ts: Vec<(SegmentId, u64)>,
}

pub struct InvariantCtx<'a, S: StorageIO + Send + Sync + 'static = RealIO> {
    pub store: &'a Arc<TranquilBlockStore<S>>,
    pub oracle: &'a Oracle,
    pub root: Option<Cid>,
    pub eventlog: Option<&'a EventLogSnapshot>,
}

#[async_trait]
pub trait Invariant<S: StorageIO + Send + Sync + 'static>: Send + Sync {
    fn name(&self) -> &'static str;
    async fn check(&self, ctx: &InvariantCtx<'_, S>) -> Result<(), InvariantViolation>;
}

pub struct RefcountConservation;

#[async_trait]
impl<S: StorageIO + Send + Sync + 'static> Invariant<S> for RefcountConservation {
    fn name(&self) -> &'static str {
        "RefcountConservation"
    }

    async fn check(&self, ctx: &InvariantCtx<'_, S>) -> Result<(), InvariantViolation> {
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
impl<S: StorageIO + Send + Sync + 'static> Invariant<S> for Reachability {
    fn name(&self) -> &'static str {
        "Reachability"
    }

    async fn check(&self, ctx: &InvariantCtx<'_, S>) -> Result<(), InvariantViolation> {
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
impl<S: StorageIO + Send + Sync + 'static> Invariant<S> for AckedWritePersistence {
    fn name(&self) -> &'static str {
        "AckedWritePersistence"
    }

    async fn check(&self, ctx: &InvariantCtx<'_, S>) -> Result<(), InvariantViolation> {
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
impl<S: StorageIO + Send + Sync + 'static> Invariant<S> for ReadAfterWrite {
    fn name(&self) -> &'static str {
        "ReadAfterWrite"
    }

    async fn check(&self, ctx: &InvariantCtx<'_, S>) -> Result<(), InvariantViolation> {
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

pub struct CompactionIdempotent;

#[async_trait]
impl<S: StorageIO + Send + Sync + 'static> Invariant<S> for CompactionIdempotent {
    fn name(&self) -> &'static str {
        "CompactionIdempotent"
    }

    async fn check(&self, ctx: &InvariantCtx<'_, S>) -> Result<(), InvariantViolation> {
        let store_a = ctx.store.clone();
        let first = tokio::task::spawn_blocking(move || compact_by_liveness(&store_a))
            .await
            .map_err(|e| InvariantViolation {
                invariant: "CompactionIdempotent",
                detail: format!("first compaction join: {e}"),
            })?;
        if let Err(e) = first {
            return Err(InvariantViolation {
                invariant: "CompactionIdempotent",
                detail: format!("first compaction: {e}"),
            });
        }

        let pre = snapshot(ctx.store);

        let store_b = ctx.store.clone();
        let second = tokio::task::spawn_blocking(move || compact_by_liveness(&store_b))
            .await
            .map_err(|e| InvariantViolation {
                invariant: "CompactionIdempotent",
                detail: format!("second compaction join: {e}"),
            })?;
        if let Err(e) = second {
            return Err(InvariantViolation {
                invariant: "CompactionIdempotent",
                detail: format!("second compaction: {e}"),
            });
        }

        let post = snapshot(ctx.store);

        if pre == post {
            Ok(())
        } else {
            Err(InvariantViolation {
                invariant: "CompactionIdempotent",
                detail: format!(
                    "second compaction changed observable state: pre={} entries, post={} entries",
                    pre.len(),
                    post.len(),
                ),
            })
        }
    }
}

fn snapshot<S: StorageIO + Send + Sync + 'static>(
    store: &Arc<TranquilBlockStore<S>>,
) -> Vec<(CidBytes, u32)> {
    let mut v: Vec<(CidBytes, u32)> = store
        .block_index()
        .live_entries_snapshot()
        .into_iter()
        .map(|(c, r)| (c, r.raw()))
        .collect();
    v.sort_unstable_by_key(|a| a.0);
    v
}

const COMPACT_LIVENESS_CEILING: f64 = 0.99;

fn compact_by_liveness<S: StorageIO + Send + Sync + 'static>(
    store: &TranquilBlockStore<S>,
) -> Result<(), String> {
    let liveness = store
        .compaction_liveness(0)
        .map_err(|e| format!("compaction_liveness: {e}"))?;
    let targets: Vec<_> = liveness
        .iter()
        .filter(|(_, info)| info.total_blocks > 0 && info.ratio() < COMPACT_LIVENESS_CEILING)
        .map(|(&fid, _)| fid)
        .collect();
    targets
        .into_iter()
        .try_for_each(|fid| match store.compact_file(fid, 0) {
            Ok(_) => Ok(()),
            Err(CompactionError::ActiveFileCannotBeCompacted) => Ok(()),
            Err(e) => Err(format!("{fid}: {e}")),
        })
}

pub struct NoOrphanFiles;

#[async_trait]
impl<S: StorageIO + Send + Sync + 'static> Invariant<S> for NoOrphanFiles {
    fn name(&self) -> &'static str {
        "NoOrphanFiles"
    }

    async fn check(&self, ctx: &InvariantCtx<'_, S>) -> Result<(), InvariantViolation> {
        let store_c = ctx.store.clone();
        let result = tokio::task::spawn_blocking(move || {
            let disk = store_c.list_data_files().map_err(|e| e.to_string())?;
            let liveness = store_c.compaction_liveness(0).map_err(|e| e.to_string())?;
            let header = BLOCK_HEADER_SIZE as u64;
            let orphans: Vec<String> = disk
                .iter()
                .filter(|fid| !liveness.contains_key(fid))
                .filter_map(|fid| {
                    let path = store_c.data_file_path(*fid);
                    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                    match size > header {
                        true => Some(format!("{fid} ({size} B)")),
                        false => None,
                    }
                })
                .collect();
            Ok::<_, String>(orphans)
        })
        .await
        .map_err(|e| InvariantViolation {
            invariant: "NoOrphanFiles",
            detail: format!("join: {e}"),
        })?;

        let orphans = result.map_err(|e| InvariantViolation {
            invariant: "NoOrphanFiles",
            detail: e,
        })?;

        if orphans.is_empty() {
            Ok(())
        } else {
            Err(InvariantViolation {
                invariant: "NoOrphanFiles",
                detail: format!("files on disk missing from index: {}", orphans.join(", ")),
            })
        }
    }
}

pub struct ByteBudget {
    pub overhead_factor: f64,
    pub floor_bytes: u64,
}

impl Default for ByteBudget {
    fn default() -> Self {
        Self {
            overhead_factor: 8.0,
            floor_bytes: 1 << 20,
        }
    }
}

#[async_trait]
impl<S: StorageIO + Send + Sync + 'static> Invariant<S> for ByteBudget {
    fn name(&self) -> &'static str {
        "ByteBudget"
    }

    async fn check(&self, ctx: &InvariantCtx<'_, S>) -> Result<(), InvariantViolation> {
        let store = ctx.store.clone();
        let factor = self.overhead_factor;
        let floor = self.floor_bytes;
        tokio::task::spawn_blocking(move || {
            let liveness = store.compaction_liveness(0).map_err(|e| e.to_string())?;
            let live: u64 = liveness.values().map(|i| i.live_bytes).sum();
            let total: u64 = liveness.values().map(|i| i.total_bytes).sum();
            let budget = (live as f64 * factor) as u64 + floor;
            if total <= budget {
                Ok(())
            } else {
                Err(format!(
                    "total_bytes {total} exceeds budget {budget}: live_bytes {live}, factor {factor}, floor {floor}"
                ))
            }
        })
        .await
        .map_err(|e| InvariantViolation {
            invariant: "ByteBudget",
            detail: format!("join: {e}"),
        })?
        .map_err(|e| InvariantViolation {
            invariant: "ByteBudget",
            detail: e,
        })
    }
}

pub struct ManifestEqualsReality;

#[async_trait]
impl<S: StorageIO + Send + Sync + 'static> Invariant<S> for ManifestEqualsReality {
    fn name(&self) -> &'static str {
        "ManifestEqualsReality"
    }

    async fn check(&self, ctx: &InvariantCtx<'_, S>) -> Result<(), InvariantViolation> {
        let store = ctx.store.clone();
        tokio::task::spawn_blocking(move || {
            let listed = store.list_data_files().map_err(|e| e.to_string())?;
            let liveness = store.compaction_liveness(0).map_err(|e| e.to_string())?;
            let header = BLOCK_HEADER_SIZE as u64;

            let mut violations: Vec<String> = Vec::new();
            listed.iter().for_each(|fid| {
                let path = store.data_file_path(*fid);
                match std::fs::metadata(&path) {
                    Err(e) => violations.push(format!("{fid}: metadata {e}")),
                    Ok(meta) => {
                        let on_disk = meta.len();
                        let content = on_disk.saturating_sub(header);
                        match liveness.get(fid) {
                            None if on_disk > header => violations.push(format!(
                                "{fid}: listed on disk at {on_disk} B but not in index liveness"
                            )),
                            None => {}
                            Some(info) if content < info.total_bytes => {
                                violations.push(format!(
                                    "{fid}: on-disk {on_disk} B (content {content}) < index total_bytes {}",
                                    info.total_bytes
                                ));
                            }
                            Some(info) if content > info.total_bytes => {
                                violations.push(format!(
                                    "{fid}: on-disk {on_disk} B (content {content}) > index total_bytes {}, {} B unaccounted",
                                    info.total_bytes,
                                    content - info.total_bytes
                                ));
                            }
                            Some(_) => {}
                        }
                    }
                }
            });

            let listed_set: std::collections::HashSet<_> = listed.into_iter().collect();
            liveness.keys().for_each(|fid| {
                if !listed_set.contains(fid) {
                    violations.push(format!("{fid}: in index liveness but missing on disk"));
                }
            });

            if violations.is_empty() {
                Ok(())
            } else {
                Err(violations.join("; "))
            }
        })
        .await
        .map_err(|e| InvariantViolation {
            invariant: "ManifestEqualsReality",
            detail: format!("join: {e}"),
        })?
        .map_err(|e| InvariantViolation {
            invariant: "ManifestEqualsReality",
            detail: e,
        })
    }
}

pub struct ChecksumCoverage;

#[async_trait]
impl<S: StorageIO + Send + Sync + 'static> Invariant<S> for ChecksumCoverage {
    fn name(&self) -> &'static str {
        "ChecksumCoverage"
    }

    async fn check(&self, ctx: &InvariantCtx<'_, S>) -> Result<(), InvariantViolation> {
        let violations: Vec<String> = ctx
            .oracle
            .live_cids_labeled()
            .into_iter()
            .filter_map(|(label, expected)| match ctx.store.get_block_sync(&expected) {
                Ok(Some(bytes)) => {
                    let actual = hash_to_cid_bytes(&bytes);
                    (actual != expected).then(|| {
                        format!(
                            "{label}: silent corruption, bytes hash to {} but store returned them under {}",
                            hex_short(&actual),
                            hex_short(&expected),
                        )
                    })
                }
                Ok(None) => Some(format!(
                    "{label}: live CID {} missing from store",
                    hex_short(&expected)
                )),
                Err(e) => Some(format!(
                    "{label}: read error for live CID {}: {e}",
                    hex_short(&expected)
                )),
            })
            .collect();

        if violations.is_empty() {
            Ok(())
        } else {
            Err(InvariantViolation {
                invariant: "ChecksumCoverage",
                detail: violations.join("; "),
            })
        }
    }
}

pub struct MonotonicSeq;

#[async_trait]
impl<S: StorageIO + Send + Sync + 'static> Invariant<S> for MonotonicSeq {
    fn name(&self) -> &'static str {
        "MonotonicSeq"
    }

    async fn check(&self, ctx: &InvariantCtx<'_, S>) -> Result<(), InvariantViolation> {
        let Some(el) = ctx.eventlog else {
            return Ok(());
        };
        let mut violations: Vec<String> = Vec::new();
        el.events
            .iter()
            .zip(el.events.iter().skip(1))
            .for_each(|(prev, next)| match next.seq.raw() {
                n if n == prev.seq.raw() + 1 => {}
                n if n == prev.seq.raw() => violations.push(format!("duplicate seq {n}")),
                n => violations.push(format!(
                    "gap: seq {} followed by {n}, expected {}",
                    prev.seq.raw(),
                    prev.seq.raw() + 1
                )),
            });
        if ctx.oracle.last_retention_cutoff_us().is_none()
            && let Some(first) = el.events.first()
            && first.seq.raw() != 1
        {
            violations.push(format!(
                "first persisted seq is {}, expected 1",
                first.seq.raw()
            ));
        }
        let acked_max = ctx
            .oracle
            .synced_events()
            .iter()
            .map(|e| e.seq.raw())
            .max()
            .unwrap_or(0);
        let disk_max = el.events.last().map(|e| e.seq.raw()).unwrap_or(0);
        if disk_max < acked_max {
            violations.push(format!(
                "acked seq {acked_max} missing on disk, disk max {disk_max}"
            ));
        }
        if violations.is_empty() {
            Ok(())
        } else {
            Err(InvariantViolation {
                invariant: "MonotonicSeq",
                detail: violations.join("; "),
            })
        }
    }
}

pub struct FsyncOrdering;

#[async_trait]
impl<S: StorageIO + Send + Sync + 'static> Invariant<S> for FsyncOrdering {
    fn name(&self) -> &'static str {
        "FsyncOrdering"
    }

    async fn check(&self, ctx: &InvariantCtx<'_, S>) -> Result<(), InvariantViolation> {
        let Some(el) = ctx.eventlog else {
            return Ok(());
        };
        let mut violations: Vec<String> = Vec::new();

        let acked_seqs: HashSet<u64> = ctx
            .oracle
            .synced_events()
            .iter()
            .map(|e| e.seq.raw())
            .collect();
        let disk_seqs: HashSet<u64> = el.events.iter().map(|e| e.seq.raw()).collect();
        let missing: Vec<u64> = acked_seqs.difference(&disk_seqs).copied().collect();
        if !missing.is_empty() {
            let mut sorted = missing;
            sorted.sort_unstable();
            violations.push(format!(
                "{} acked events lost on disk, lowest missing seq {}",
                sorted.len(),
                sorted[0]
            ));
        }

        if let Some(last_synced) = ctx.oracle.last_synced_seq()
            && el.synced_seq.raw() != 0
            && el.synced_seq.raw() < last_synced.raw()
        {
            violations.push(format!(
                "writer synced_seq {} below oracle last_synced_seq {}",
                el.synced_seq.raw(),
                last_synced.raw()
            ));
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(InvariantViolation {
                invariant: "FsyncOrdering",
                detail: violations.join("; "),
            })
        }
    }
}

pub struct TombstoneBound;

#[async_trait]
impl<S: StorageIO + Send + Sync + 'static> Invariant<S> for TombstoneBound {
    fn name(&self) -> &'static str {
        "TombstoneBound"
    }

    async fn check(&self, ctx: &InvariantCtx<'_, S>) -> Result<(), InvariantViolation> {
        let Some(el) = ctx.eventlog else {
            return Ok(());
        };
        let Some(cutoff_us) = ctx.oracle.last_retention_cutoff_us() else {
            return Ok(());
        };

        let active = el.segments.last().copied();

        let stale: Vec<String> = el
            .segment_last_ts
            .iter()
            .filter(|(id, last_ts)| Some(*id) != active && *last_ts < cutoff_us)
            .map(|(id, last_ts)| format!("segment {id} last_ts {last_ts} < cutoff {cutoff_us}"))
            .collect();

        if stale.is_empty() {
            Ok(())
        } else {
            Err(InvariantViolation {
                invariant: "TombstoneBound",
                detail: stale.join("; "),
            })
        }
    }
}

pub fn invariants_for<S: StorageIO + Send + Sync + 'static>(
    set: InvariantSet,
) -> Vec<Box<dyn Invariant<S>>> {
    let unknown = set.unknown_bits();
    assert!(
        unknown == 0,
        "invariants_for: unknown InvariantSet bits 0x{unknown:x}; all bits must map to an impl"
    );
    let candidates: Vec<(InvariantSet, Box<dyn Invariant<S>>)> = vec![
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
        (
            InvariantSet::COMPACTION_IDEMPOTENT,
            Box::new(CompactionIdempotent),
        ),
        (InvariantSet::NO_ORPHAN_FILES, Box::new(NoOrphanFiles)),
        (InvariantSet::BYTE_BUDGET, Box::new(ByteBudget::default())),
        (
            InvariantSet::MANIFEST_EQUALS_REALITY,
            Box::new(ManifestEqualsReality),
        ),
        (InvariantSet::CHECKSUM_COVERAGE, Box::new(ChecksumCoverage)),
        (InvariantSet::MONOTONIC_SEQ, Box::new(MonotonicSeq)),
        (InvariantSet::FSYNC_ORDERING, Box::new(FsyncOrdering)),
        (InvariantSet::TOMBSTONE_BOUND, Box::new(TombstoneBound)),
    ];
    candidates
        .into_iter()
        .filter_map(|(flag, inv)| set.contains(flag).then_some(inv))
        .collect()
}
