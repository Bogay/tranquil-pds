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

impl RippleConfig {
    pub fn from_config() -> Result<Self, RippleConfigError> {
        let ripple = &tranquil_config::get().cache.ripple;

        let bind_addr: SocketAddr = ripple
            .bind_addr
            .parse()
            .map_err(|e| RippleConfigError::InvalidAddr(format!("{e}")))?;

        let seed_peers: Vec<SocketAddr> = ripple
            .peers
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .filter(|s| !s.trim().is_empty())
            .map(|s| {
                s.trim()
                    .parse()
                    .map_err(|e| RippleConfigError::InvalidAddr(format!("{s}: {e}")))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let machine_id = ripple.machine_id.unwrap_or_else(|| {
            let host_str = std::fs::read_to_string("/etc/hostname")
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| format!("pid-{}", std::process::id()));
            let input = format!("{host_str}:{bind_addr}:{}", std::process::id());
            fnv1a(input.as_bytes())
        });

        let gossip_interval_ms = ripple.gossip_interval_ms.max(50);

        let cache_max_bytes = ripple
            .cache_max_mb
            .clamp(1, 16_384)
            .saturating_mul(1024)
            .saturating_mul(1024);

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
