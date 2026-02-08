use std::net::SocketAddr;

pub(crate) fn fnv1a(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf29ce484222325u64, |hash, &byte| {
        (hash ^ byte as u64).wrapping_mul(0x100000001b3)
    })
}

#[derive(Debug, Clone)]
pub struct RippleConfig {
    pub bind_addr: SocketAddr,
    pub seed_peers: Vec<SocketAddr>,
    pub machine_id: u64,
    pub gossip_interval_ms: u64,
    pub cache_max_bytes: usize,
}

fn parse_env_with_warning<T: std::str::FromStr>(var_name: &str, raw: &str) -> Option<T> {
    match raw.parse::<T>() {
        Ok(v) => Some(v),
        Err(_) => {
            tracing::warn!(var = var_name, value = raw, "invalid env var value, using default");
            None
        }
    }
}

impl RippleConfig {
    pub fn from_env() -> Result<Self, RippleConfigError> {
        let bind_addr: SocketAddr = std::env::var("RIPPLE_BIND")
            .unwrap_or_else(|_| "0.0.0.0:0".into())
            .parse()
            .map_err(|e| RippleConfigError::InvalidAddr(format!("{e}")))?;

        let seed_peers: Vec<SocketAddr> = std::env::var("RIPPLE_PEERS")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .map(|s| {
                s.trim()
                    .parse()
                    .map_err(|e| RippleConfigError::InvalidAddr(format!("{s}: {e}")))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let machine_id: u64 = std::env::var("RIPPLE_MACHINE_ID")
            .ok()
            .and_then(|v| parse_env_with_warning::<u64>("RIPPLE_MACHINE_ID", &v))
            .unwrap_or_else(|| {
                let host_str = std::fs::read_to_string("/etc/hostname")
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|_| format!("pid-{}", std::process::id()));
                let input = format!("{host_str}:{bind_addr}:{}", std::process::id());
                fnv1a(input.as_bytes())
            });

        let gossip_interval_ms: u64 = std::env::var("RIPPLE_GOSSIP_INTERVAL_MS")
            .ok()
            .and_then(|v| parse_env_with_warning::<u64>("RIPPLE_GOSSIP_INTERVAL_MS", &v))
            .unwrap_or(200)
            .max(50);

        let cache_max_mb: usize = std::env::var("RIPPLE_CACHE_MAX_MB")
            .ok()
            .and_then(|v| parse_env_with_warning::<usize>("RIPPLE_CACHE_MAX_MB", &v))
            .unwrap_or(256)
            .clamp(1, 16_384);

        let cache_max_bytes = cache_max_mb.saturating_mul(1024).saturating_mul(1024);

        Ok(Self {
            bind_addr,
            seed_peers,
            machine_id,
            gossip_interval_ms,
            cache_max_bytes,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RippleConfigError {
    #[error("invalid address: {0}")]
    InvalidAddr(String),
}
