use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

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
    pub cluster_key: Option<String>,
    pub allow_insecure: bool,
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

        let cluster_key = ripple
            .cluster_key
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let bind_addr = effective_bind_addr(
            bind_addr,
            cluster_key.is_some(),
            ripple.allow_insecure,
            !seed_peers.is_empty(),
        );

        Ok(Self {
            bind_addr,
            seed_peers,
            machine_id,
            gossip_interval_ms,
            cache_max_bytes,
            cluster_key,
            allow_insecure: ripple.allow_insecure,
        })
    }
}

fn effective_bind_addr(
    bind_addr: SocketAddr,
    has_cluster_key: bool,
    allow_insecure: bool,
    has_peers: bool,
) -> SocketAddr {
    let standalone_default = !has_cluster_key
        && !allow_insecure
        && !has_peers
        && bind_addr.ip().is_unspecified()
        && bind_addr.port() == 0;
    match standalone_default {
        false => bind_addr,
        true => {
            let loopback: IpAddr = match bind_addr.ip() {
                IpAddr::V4(_) => Ipv4Addr::LOCALHOST.into(),
                IpAddr::V6(_) => Ipv6Addr::LOCALHOST.into(),
            };
            tracing::info!(
                "ripple has no cluster key and no peers, binding loopback as a single node"
            );
            SocketAddr::new(loopback, 0)
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RippleConfigError {
    #[error("invalid address: {0}")]
    InvalidAddr(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn standalone_default_bind_rewrites_to_loopback() {
        assert_eq!(
            effective_bind_addr(addr("0.0.0.0:0"), false, false, false),
            addr("127.0.0.1:0")
        );
        assert_eq!(
            effective_bind_addr(addr("[::]:0"), false, false, false),
            addr("[::1]:0")
        );
    }

    #[test]
    fn explicit_or_clustered_binds_are_untouched() {
        assert_eq!(
            effective_bind_addr(addr("0.0.0.0:7000"), false, false, false),
            addr("0.0.0.0:7000")
        );
        assert_eq!(
            effective_bind_addr(addr("0.0.0.0:0"), true, false, false),
            addr("0.0.0.0:0")
        );
        assert_eq!(
            effective_bind_addr(addr("0.0.0.0:0"), false, true, false),
            addr("0.0.0.0:0")
        );
        assert_eq!(
            effective_bind_addr(addr("0.0.0.0:0"), false, false, true),
            addr("0.0.0.0:0")
        );
        assert_eq!(
            effective_bind_addr(addr("192.0.2.7:0"), false, false, false),
            addr("192.0.2.7:0")
        );
    }
}
