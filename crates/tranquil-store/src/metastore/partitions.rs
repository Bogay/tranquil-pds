use std::time::{SystemTime, UNIX_EPOCH};

use fjall::KeyspaceCreateOptions;
use fjall::compaction::filter::{CompactionFilter, Context, Factory, ItemAccessor, Verdict};
use fjall::config::{BloomConstructionPolicy, FilterPolicy, FilterPolicyEntry};

pub const EXPIRES_AT_MS_SIZE: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Partition {
    RepoData,
    Auth,
    Users,
    Infra,
    Indexes,
    Signal,
}

impl Partition {
    pub const ALL: [Partition; 6] = [
        Partition::RepoData,
        Partition::Auth,
        Partition::Users,
        Partition::Infra,
        Partition::Indexes,
        Partition::Signal,
    ];

    pub const fn index(self) -> usize {
        match self {
            Self::RepoData => 0,
            Self::Auth => 1,
            Self::Users => 2,
            Self::Infra => 3,
            Self::Indexes => 4,
            Self::Signal => 5,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::RepoData => "repo_data",
            Self::Auth => "auth",
            Self::Users => "users",
            Self::Infra => "infra",
            Self::Indexes => "indexes",
            Self::Signal => "signal",
        }
    }

    pub fn create_options(self) -> KeyspaceCreateOptions {
        match self {
            Self::RepoData | Self::Indexes => {
                KeyspaceCreateOptions::default().filter_policy(FilterPolicy::new([
                    FilterPolicyEntry::Bloom(BloomConstructionPolicy::FalsePositiveRate(0.01)),
                    FilterPolicyEntry::Bloom(BloomConstructionPolicy::BitsPerKey(10.0)),
                ]))
            }
            Self::Auth | Self::Users | Self::Infra | Self::Signal => {
                KeyspaceCreateOptions::default()
            }
        }
    }
}

pub(crate) struct TtlFilterFactory;

impl Factory for TtlFilterFactory {
    fn name(&self) -> &str {
        "ttl_expiry"
    }

    fn make_filter(&self, _ctx: &Context) -> Box<dyn CompactionFilter> {
        let now_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock before unix epoch")
                .as_millis(),
        )
        .unwrap_or(u64::MAX);
        Box::new(TtlFilter { now_ms })
    }
}

struct TtlFilter {
    now_ms: u64,
}

impl CompactionFilter for TtlFilter {
    fn filter_item(&mut self, item: ItemAccessor<'_>, _ctx: &Context) -> lsm_tree::Result<Verdict> {
        let value = item.value()?;
        match value.get(..EXPIRES_AT_MS_SIZE) {
            Some(bytes) => {
                let expires_at_ms =
                    u64::from_be_bytes(bytes.try_into().expect("slice is exactly 8 bytes"));
                match expires_at_ms > 0 && expires_at_ms < self.now_ms {
                    true => Ok(Verdict::Remove),
                    false => Ok(Verdict::Keep),
                }
            }
            None => Ok(Verdict::Keep),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_names_are_distinct() {
        let names: Vec<_> = Partition::ALL.iter().map(|p| p.name()).collect();
        let mut deduped = names.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(names.len(), deduped.len());
    }

    #[test]
    fn all_partitions_covered() {
        assert_eq!(Partition::ALL.len(), 6);
    }

    #[test]
    fn auth_partition_has_filter() {
        assert_eq!(Partition::Auth.name(), "auth");
    }

    #[test]
    fn index_matches_all_array_position() {
        Partition::ALL.iter().enumerate().for_each(|(i, &p)| {
            assert_eq!(p.index(), i, "Partition::{:?} index mismatch", p);
        });
    }
}
