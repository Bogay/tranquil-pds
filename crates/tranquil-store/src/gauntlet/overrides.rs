use serde::{Deserialize, Serialize};

use super::runner::{
    GauntletConfig, IoBackend, MaxFileSize, OpInterval, RestartPolicy, RunLimits, ShardCount,
    WallMs, WriterConcurrency,
};
use super::workload::{KeySpaceSize, OpCount, SizeDistribution, ValueBytes};
use crate::sim::FaultConfig;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConfigOverrides {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_wall_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writer_concurrency: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_space: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_bytes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fault_density_scale: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fault_density_uniform: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_every_n_ops: Option<usize>,
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
        if let Some(n) = self.writer_concurrency {
            cfg.writer_concurrency = WriterConcurrency(n.max(1));
        }
        if let Some(n) = self.key_space {
            cfg.workload.key_space = KeySpaceSize(n.max(1));
        }
        if let Some(n) = self.value_bytes {
            cfg.workload.size_distribution = SizeDistribution::Fixed(ValueBytes(n));
        }
        if let Some(m) = self.fault_density_scale
            && let IoBackend::Simulated { fault } = cfg.io
        {
            cfg.io = IoBackend::Simulated {
                fault: fault.scale_probabilities(m),
            };
        }
        if let Some(d) = self.fault_density_uniform {
            cfg.io = IoBackend::Simulated {
                fault: FaultConfig::uniform_density(d.clamp(0.0, 1.0)),
            };
        }
        if let Some(n) = self.restart_every_n_ops {
            cfg.restart_policy = if n == 0 {
                RestartPolicy::Never
            } else {
                RestartPolicy::EveryNOps(OpInterval(n))
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
            writer_concurrency: Some(16),
            key_space: Some(1_000_000),
            value_bytes: Some(4096),
            fault_density_scale: Some(1e-3),
            fault_density_uniform: Some(5e-4),
            restart_every_n_ops: Some(10_000),
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

    #[test]
    fn fault_density_scale_scales_moderate() {
        use crate::gauntlet::op::Seed;
        use crate::gauntlet::scenarios::{Scenario, config_for};
        let mut cfg = config_for(Scenario::ModerateFaults, Seed(1));
        let o = ConfigOverrides {
            fault_density_scale: Some(0.1),
            ..ConfigOverrides::default()
        };
        o.apply_to(&mut cfg);
        match cfg.io {
            IoBackend::Simulated { fault } => {
                assert!(fault.torn_page_probability.raw() < 0.02);
                assert!(fault.torn_page_probability.raw() > 0.0);
            }
            _ => panic!("expected simulated io"),
        }
    }

    #[test]
    fn fault_density_scale_zero_kills_probabilities() {
        use crate::gauntlet::op::Seed;
        use crate::gauntlet::scenarios::{Scenario, config_for};
        let mut cfg = config_for(Scenario::ModerateFaults, Seed(1));
        let o = ConfigOverrides {
            fault_density_scale: Some(0.0),
            ..ConfigOverrides::default()
        };
        o.apply_to(&mut cfg);
        match cfg.io {
            IoBackend::Simulated { fault } => {
                assert_eq!(fault.partial_write_probability.raw(), 0.0);
                assert_eq!(fault.torn_page_probability.raw(), 0.0);
                assert_eq!(fault.io_error_probability.raw(), 0.0);
                assert_eq!(fault.sync_failure_probability.raw(), 0.0);
            }
            _ => panic!("expected simulated io"),
        }
    }

    #[test]
    fn fault_density_scale_is_noop_on_real_backend() {
        use crate::gauntlet::op::Seed;
        use crate::gauntlet::scenarios::{Scenario, config_for};
        let mut cfg = config_for(Scenario::SmokePR, Seed(1));
        assert!(matches!(cfg.io, IoBackend::Real));
        let o = ConfigOverrides {
            fault_density_scale: Some(0.5),
            ..ConfigOverrides::default()
        };
        o.apply_to(&mut cfg);
        assert!(matches!(cfg.io, IoBackend::Real));
    }

    #[test]
    fn fault_density_uniform_forces_simulated_backend() {
        use crate::gauntlet::op::Seed;
        use crate::gauntlet::scenarios::{Scenario, config_for};
        let mut cfg = config_for(Scenario::SmokePR, Seed(1));
        assert!(matches!(cfg.io, IoBackend::Real));
        let o = ConfigOverrides {
            fault_density_uniform: Some(0.25),
            ..ConfigOverrides::default()
        };
        o.apply_to(&mut cfg);
        match cfg.io {
            IoBackend::Simulated { fault } => {
                assert_eq!(fault.torn_page_probability.raw(), 0.25);
                assert_eq!(fault.io_error_probability.raw(), 0.25);
            }
            _ => panic!("expected simulated io"),
        }
    }
}
