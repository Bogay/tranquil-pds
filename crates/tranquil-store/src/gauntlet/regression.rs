use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::invariants::InvariantViolation;
use super::op::{Op, OpStream, Seed};
use super::overrides::ConfigOverrides;
use super::runner::{GauntletConfig, GauntletReport};
use super::scenarios::{Scenario, UnknownScenario, config_for};

pub const SCHEMA_VERSION: u32 = 1;
pub const MIN_SUPPORTED_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegressionViolation {
    pub invariant: String,
    pub detail: String,
}

impl From<&InvariantViolation> for RegressionViolation {
    fn from(v: &InvariantViolation) -> Self {
        Self {
            invariant: v.invariant.to_string(),
            detail: v.detail.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionRecord {
    pub schema_version: u32,
    pub scenario: String,
    pub seed: Seed,
    #[serde(default)]
    pub overrides: ConfigOverrides,
    pub violations: Vec<RegressionViolation>,
    pub ops: Vec<Op>,
    #[serde(default)]
    pub original_ops_len: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum RegressionLoadError {
    #[error("read {path}: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error("parse {path}: {source}")]
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("schema version {found} outside supported range {min}..={max}")]
    UnsupportedVersion { found: u32, min: u32, max: u32 },
    #[error(transparent)]
    UnknownScenario(#[from] UnknownScenario),
}

impl RegressionRecord {
    pub fn from_report(
        scenario: Scenario,
        overrides: ConfigOverrides,
        report: &GauntletReport,
        original_ops_len: usize,
        shrunk_ops: OpStream,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            scenario: scenario.name().to_string(),
            seed: report.seed,
            overrides,
            violations: report
                .violations
                .iter()
                .map(RegressionViolation::from)
                .collect(),
            ops: shrunk_ops.into_vec(),
            original_ops_len,
        }
    }

    pub fn file_path(&self, root: &Path) -> PathBuf {
        root.join("gauntlet")
            .join(sanitize(&self.scenario))
            .join(format!("{:016x}.json", self.seed.0))
    }

    pub fn write_to(&self, root: &Path) -> io::Result<PathBuf> {
        let path = self.file_path(root);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        let tmp = path.with_extension("json.tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            io::Write::write_all(&mut f, &json)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &path)?;
        if let Some(parent) = path.parent()
            && let Ok(dir) = std::fs::File::open(parent)
        {
            let _ = dir.sync_all();
        }
        Ok(path)
    }

    pub fn load(path: &Path) -> Result<Self, RegressionLoadError> {
        let raw = std::fs::read(path).map_err(|source| RegressionLoadError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let record: RegressionRecord =
            serde_json::from_slice(&raw).map_err(|source| RegressionLoadError::Parse {
                path: path.to_path_buf(),
                source,
            })?;
        if record.schema_version < MIN_SUPPORTED_SCHEMA_VERSION
            || record.schema_version > SCHEMA_VERSION
        {
            return Err(RegressionLoadError::UnsupportedVersion {
                found: record.schema_version,
                min: MIN_SUPPORTED_SCHEMA_VERSION,
                max: SCHEMA_VERSION,
            });
        }
        Ok(record)
    }

    pub fn scenario_enum(&self) -> Result<Scenario, UnknownScenario> {
        self.scenario.parse::<Scenario>()
    }

    pub fn build_config(&self) -> Result<GauntletConfig, UnknownScenario> {
        let scenario = self.scenario_enum()?;
        let mut cfg = config_for(scenario, self.seed);
        self.overrides.apply_to(&mut cfg);
        Ok(cfg)
    }

    pub fn op_stream(&self) -> OpStream {
        OpStream::from_vec(self.ops.clone())
    }
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' => c,
            _ => '_',
        })
        .collect()
}

pub fn default_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("proptest-regressions")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gauntlet::op::{CollectionName, RecordKey, ValueSeed};
    use crate::gauntlet::overrides::ConfigOverrides;

    fn sample_record() -> RegressionRecord {
        use crate::gauntlet::overrides::StoreOverrides;

        let ops = vec![
            Op::AddRecord {
                collection: CollectionName("c".into()),
                rkey: RecordKey("r".into()),
                value_seed: ValueSeed(1),
            },
            Op::Compact,
        ];
        let overrides = ConfigOverrides {
            op_count: Some(128),
            store: StoreOverrides {
                max_file_size: Some(4096),
                ..StoreOverrides::default()
            },
            ..ConfigOverrides::default()
        };
        RegressionRecord {
            schema_version: SCHEMA_VERSION,
            scenario: "HugeValues".to_string(),
            seed: Seed(0xdeadbeef),
            overrides,
            violations: vec![RegressionViolation {
                invariant: "ByteBudget".to_string(),
                detail: "exceeded".to_string(),
            }],
            ops,
            original_ops_len: 500,
        }
    }

    #[test]
    fn round_trip_preserves_all_fields() {
        let dir = tempfile::TempDir::new().unwrap();
        let original = sample_record();
        let path = original.write_to(dir.path()).unwrap();
        assert!(path.exists());
        let loaded = RegressionRecord::load(&path).unwrap();
        assert_eq!(loaded.schema_version, original.schema_version);
        assert_eq!(loaded.scenario, original.scenario);
        assert_eq!(loaded.seed.0, original.seed.0);
        assert_eq!(loaded.overrides, original.overrides);
        assert_eq!(loaded.violations, original.violations);
        assert_eq!(loaded.ops.len(), original.ops.len());
        assert_eq!(loaded.original_ops_len, original.original_ops_len);
    }

    #[test]
    fn build_config_applies_overrides() {
        let record = sample_record();
        let cfg = record.build_config().unwrap();
        assert_eq!(cfg.op_count.0, 128);
        assert_eq!(cfg.store.max_file_size.0, 4096);
    }

    #[test]
    fn rejects_future_schema_version() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut r = sample_record();
        r.schema_version = SCHEMA_VERSION + 1;
        let path = r.write_to(dir.path()).unwrap();
        match RegressionRecord::load(&path) {
            Err(RegressionLoadError::UnsupportedVersion { found, min, max }) => {
                assert_eq!(found, SCHEMA_VERSION + 1);
                assert_eq!(min, MIN_SUPPORTED_SCHEMA_VERSION);
                assert_eq!(max, SCHEMA_VERSION);
            }
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn rejects_past_schema_version_below_min() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut r = sample_record();
        r.schema_version = MIN_SUPPORTED_SCHEMA_VERSION.saturating_sub(1);
        let path = r.write_to(dir.path()).unwrap();
        match RegressionRecord::load(&path) {
            Err(RegressionLoadError::UnsupportedVersion { found, min, max }) => {
                assert_eq!(found, MIN_SUPPORTED_SCHEMA_VERSION.saturating_sub(1));
                assert_eq!(min, MIN_SUPPORTED_SCHEMA_VERSION);
                assert_eq!(max, SCHEMA_VERSION);
            }
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn atomic_write_leaves_no_tmp_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let r = sample_record();
        let path = r.write_to(dir.path()).unwrap();
        assert!(path.exists());
        let tmp = path.with_extension("json.tmp");
        assert!(
            !tmp.exists(),
            "tmp sibling {tmp:?} should have been renamed"
        );
    }

    #[test]
    fn rejects_malformed_json() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, b"{not json").unwrap();
        assert!(matches!(
            RegressionRecord::load(&path),
            Err(RegressionLoadError::Parse { .. })
        ));
    }

    #[test]
    fn sanitize_strips_slashes_and_traversal() {
        assert_eq!(sanitize("foo/bar baz"), "foo_bar_baz");
        assert_eq!(sanitize("../etc"), "___etc");
    }

    #[test]
    fn unknown_scenario_name_errors() {
        let mut r = sample_record();
        r.scenario = "BogusScenario".to_string();
        assert!(r.build_config().is_err());
    }
}
