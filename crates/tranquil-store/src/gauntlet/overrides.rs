use serde::{Deserialize, Serialize};

use super::runner::{GauntletConfig, MaxFileSize, RunLimits, ShardCount, WallMs};
use super::workload::OpCount;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConfigOverrides {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_wall_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "StoreOverrides::is_empty")]
    pub store: StoreOverrides,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StoreOverrides {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_file_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shard_count: Option<u8>,
    #[serde(default, skip_serializing_if = "GroupCommitOverrides::is_empty")]
    pub group_commit: GroupCommitOverrides,
}

impl StoreOverrides {
    pub fn is_empty(&self) -> bool {
        self.max_file_size.is_none() && self.shard_count.is_none() && self.group_commit.is_empty()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GroupCommitOverrides {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_batch_size: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_capacity: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_interval_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_write_threshold: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify_persisted_blocks: Option<bool>,
}

impl GroupCommitOverrides {
    pub fn is_empty(&self) -> bool {
        self.max_batch_size.is_none()
            && self.channel_capacity.is_none()
            && self.checkpoint_interval_ms.is_none()
            && self.checkpoint_write_threshold.is_none()
            && self.verify_persisted_blocks.is_none()
    }
}

impl ConfigOverrides {
    pub fn apply_to(&self, cfg: &mut GauntletConfig) {
        if let Some(n) = self.op_count {
            cfg.op_count = OpCount(n);
        }
        if let Some(ms) = self.max_wall_ms {
            cfg.limits = RunLimits {
                max_wall_ms: Some(WallMs(ms)),
            };
        }
        if let Some(n) = self.store.max_file_size {
            cfg.store.max_file_size = MaxFileSize(n);
        }
        if let Some(n) = self.store.shard_count {
            cfg.store.shard_count = ShardCount(n);
        }
        let gc = &self.store.group_commit;
        if let Some(n) = gc.max_batch_size {
            cfg.store.group_commit.max_batch_size = n;
        }
        if let Some(n) = gc.channel_capacity {
            cfg.store.group_commit.channel_capacity = n;
        }
        if let Some(n) = gc.checkpoint_interval_ms {
            cfg.store.group_commit.checkpoint_interval_ms = n;
        }
        if let Some(n) = gc.checkpoint_write_threshold {
            cfg.store.group_commit.checkpoint_write_threshold = n;
        }
        if let Some(b) = gc.verify_persisted_blocks {
            cfg.store.group_commit.verify_persisted_blocks = b;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_overrides_serialize_empty() {
        let o = ConfigOverrides::default();
        let json = serde_json::to_string(&o).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn round_trip_preserves_set_fields() {
        let o = ConfigOverrides {
            op_count: Some(42),
            store: StoreOverrides {
                max_file_size: Some(4096),
                group_commit: GroupCommitOverrides {
                    max_batch_size: Some(16),
                    ..GroupCommitOverrides::default()
                },
                ..StoreOverrides::default()
            },
            ..ConfigOverrides::default()
        };
        let json = serde_json::to_string(&o).unwrap();
        let back: ConfigOverrides = serde_json::from_str(&json).unwrap();
        assert_eq!(o, back);
    }
}
