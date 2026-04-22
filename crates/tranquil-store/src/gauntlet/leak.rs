use std::num::NonZeroU64;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::metrics::{MetricName, MetricsSample};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct LeakGateConfig {
    pub warmup_ms: u64,
    pub window_ms: NonZeroU64,
    pub growth_limit_pct: f64,
}

#[derive(Debug, Clone, Copy)]
pub struct LeakGateBuildError(pub &'static str);

impl std::fmt::Display for LeakGateBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for LeakGateBuildError {}

impl LeakGateConfig {
    pub fn try_new(
        warmup_ms: u64,
        window_ms: u64,
        growth_limit_pct: f64,
    ) -> Result<Self, LeakGateBuildError> {
        let window_ms = NonZeroU64::new(window_ms)
            .ok_or(LeakGateBuildError("leak gate window_ms must be > 0"))?;
        if !growth_limit_pct.is_finite() || growth_limit_pct < 0.0 {
            return Err(LeakGateBuildError(
                "leak gate growth_limit_pct must be finite and non-negative",
            ));
        }
        Ok(Self {
            warmup_ms,
            window_ms,
            growth_limit_pct,
        })
    }

    pub fn standard() -> Self {
        Self::try_new(60 * 60 * 1_000, 4 * 60 * 60 * 1_000, 5.0)
            .expect("standard leak gate config is valid")
    }

    pub fn short_for_tests() -> Self {
        Self::try_new(60_000, 4 * 60_000, 5.0).expect("short_for_tests leak gate config is valid")
    }

    pub fn warmup(&self) -> Duration {
        Duration::from_millis(self.warmup_ms)
    }

    pub fn window(&self) -> Duration {
        Duration::from_millis(self.window_ms.get())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeakViolation {
    pub metric: String,
    pub start_ms: u64,
    pub end_ms: u64,
    pub start_value: u64,
    pub end_value: u64,
    pub growth_pct: f64,
    pub limit_pct: f64,
}

pub fn evaluate(samples: &[MetricsSample], cfg: LeakGateConfig) -> Vec<LeakViolation> {
    if samples.len() < 2 {
        return Vec::new();
    }
    MetricName::ALL
        .iter()
        .flat_map(|&m| evaluate_metric(samples, m, cfg))
        .collect()
}

fn evaluate_metric(
    samples: &[MetricsSample],
    metric: MetricName,
    cfg: LeakGateConfig,
) -> Option<LeakViolation> {
    let post_warmup: Vec<&MetricsSample> = samples
        .iter()
        .filter(|s| s.elapsed_ms >= cfg.warmup_ms)
        .collect();
    if post_warmup.len() < 2 {
        return None;
    }

    let min_delta = metric.min_absolute_delta();
    let window = cfg.window_ms.get();
    let mut worst: Option<LeakViolation> = None;
    for (i, start) in post_warmup.iter().enumerate() {
        let Some(start_v) = start.metric(metric) else {
            continue;
        };
        if start_v == 0 {
            continue;
        }
        let deadline = start.elapsed_ms.saturating_add(window);
        for end in post_warmup.iter().skip(i + 1) {
            if end.elapsed_ms > deadline {
                break;
            }
            let Some(end_v) = end.metric(metric) else {
                continue;
            };
            if end_v <= start_v {
                continue;
            }
            let delta = end_v - start_v;
            if delta < min_delta {
                continue;
            }
            let growth = (delta as f64 / start_v as f64) * 100.0;
            if growth <= cfg.growth_limit_pct {
                continue;
            }
            let candidate = LeakViolation {
                metric: metric.as_str().to_string(),
                start_ms: start.elapsed_ms,
                end_ms: end.elapsed_ms,
                start_value: start_v,
                end_value: end_v,
                growth_pct: growth,
                limit_pct: cfg.growth_limit_pct,
            };
            match &worst {
                Some(w) if w.growth_pct >= candidate.growth_pct => {}
                _ => worst = Some(candidate),
            }
        }
    }
    worst
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;

    fn sample(elapsed_ms: u64, rss: u64) -> MetricsSample {
        MetricsSample {
            elapsed_ms,
            rss_bytes: Some(rss),
            fd_count: Some(10),
            data_dir_bytes: 0,
            index_dir_bytes: 0,
            segments_dir_bytes: 0,
            data_file_count: Some(0),
            segment_count: Some(0),
            block_index_entries: 0,
            hint_file_bytes: 0,
        }
    }

    #[test]
    fn flat_metrics_no_violation() {
        let cfg = LeakGateConfig::short_for_tests();
        let series: Vec<MetricsSample> = (0..20)
            .map(|i| sample(60_000 + i * 60_000, GIB))
            .collect();
        assert!(evaluate(&series, cfg).is_empty());
    }

    #[test]
    fn growing_rss_flagged() {
        let cfg = LeakGateConfig::short_for_tests();
        let series: Vec<MetricsSample> = (0..20)
            .map(|i| sample(60_000 + i * 60_000, GIB + i * 64 * 1024 * 1024))
            .collect();
        let v = evaluate(&series, cfg);
        assert!(!v.is_empty());
        assert_eq!(v[0].metric, "rss_bytes");
        assert!(v[0].growth_pct > 5.0);
    }

    #[test]
    fn warmup_samples_ignored() {
        let cfg = LeakGateConfig::short_for_tests();
        let mut series: Vec<MetricsSample> = Vec::new();
        series.push(sample(10_000, 1));
        series.push(sample(30_000, GIB));
        (0..10).for_each(|i| {
            series.push(sample(60_000 + i * 60_000, GIB));
        });
        assert!(evaluate(&series, cfg).is_empty());
    }

    #[test]
    fn window_bound_honored() {
        let cfg = LeakGateConfig::try_new(0, 2 * 60_000, 5.0).unwrap();
        let series = vec![sample(0, GIB), sample(200_000, 2 * GIB)];
        assert!(
            evaluate(&series, cfg).is_empty(),
            "200s gap exceeds 120s window, growth must not be flagged"
        );
    }

    #[test]
    fn small_absolute_delta_not_flagged() {
        let cfg = LeakGateConfig::short_for_tests();
        let series: Vec<MetricsSample> = (0..10)
            .map(|i| sample(60_000 + i * 60_000, GIB + i * 1024))
            .collect();
        assert!(
            evaluate(&series, cfg).is_empty(),
            "kilobyte growth is below the RSS absolute-delta floor"
        );
    }

    #[test]
    fn missing_metric_samples_skipped() {
        let cfg = LeakGateConfig::short_for_tests();
        let mut series: Vec<MetricsSample> = (0..10)
            .map(|i| sample(60_000 + i * 60_000, GIB))
            .collect();
        series[3].rss_bytes = None;
        series[7].rss_bytes = None;
        assert!(evaluate(&series, cfg).is_empty());
    }

    #[test]
    fn zero_window_rejected_at_construction() {
        assert!(LeakGateConfig::try_new(0, 0, 5.0).is_err());
    }
}
