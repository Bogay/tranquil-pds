use reqwest::{Client, ClientBuilder, Url};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::OnceLock;
use std::time::Duration;
use tracing::warn;

pub const DEFAULT_HEADERS_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_BODY_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_RESPONSE_SIZE: u64 = 10 * 1024 * 1024;

static PROXY_CLIENT: OnceLock<Client> = OnceLock::new();
static DID_RESOLUTION_CLIENT: OnceLock<Client> = OnceLock::new();
static HANDLE_RESOLUTION_CLIENT: OnceLock<Client> = OnceLock::new();

pub fn proxy_client() -> &'static Client {
    PROXY_CLIENT.get_or_init(|| {
        ClientBuilder::new()
            .timeout(DEFAULT_BODY_TIMEOUT)
            .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(90))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect(
                "Failed to build HTTP client - this indicates a TLS or system configuration issue",
            )
    })
}

pub fn did_resolution_client() -> &'static Client {
    DID_RESOLUTION_CLIENT.get_or_init(|| {
        ClientBuilder::new()
            .timeout(Duration::from_secs(5))
            .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(90))
            .build()
            .expect(
                "Failed to build DID resolution client - this indicates a TLS or system configuration issue",
            )
    })
}

pub fn handle_resolution_client() -> &'static Client {
    HANDLE_RESOLUTION_CLIENT.get_or_init(|| {
        ClientBuilder::new()
            .timeout(Duration::from_secs(10))
            .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(90))
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .expect(
                "Failed to build handle resolution client - this indicates a TLS or system configuration issue",
            )
    })
}

pub fn is_ssrf_safe(url: &str) -> Result<(), SsrfError> {
    let parsed = Url::parse(url).map_err(|_| SsrfError::InvalidUrl)?;
    let scheme = parsed.scheme();
    if scheme != "https" {
        let allow_http = std::env::var("ALLOW_HTTP_PROXY").is_ok()
            || url.starts_with("http://127.0.0.1")
            || url.starts_with("http://localhost");
        if !allow_http {
            return Err(SsrfError::InsecureProtocol(scheme.to_string()));
        }
    }
    let host = parsed.host_str().ok_or(SsrfError::NoHost)?;
    if host == "localhost" {
        return Ok(());
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if ip.is_loopback() {
            return Ok(());
        }
        if !is_unicast_ip(&ip) {
            return Err(SsrfError::NonUnicastIp(ip.to_string()));
        }
        return Ok(());
    }
    let port = parsed
        .port()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });
    let socket_addrs: Vec<SocketAddr> = match (host, port).to_socket_addrs() {
        Ok(addrs) => addrs.collect(),
        Err(_) => return Err(SsrfError::DnsResolutionFailed(host.to_string())),
    };
    if let Some(addr) = socket_addrs.iter().find(|addr| !is_unicast_ip(&addr.ip())) {
        warn!(
            "DNS resolution for {} returned non-unicast IP: {}",
            host,
            addr.ip()
        );
        return Err(SsrfError::NonUnicastIp(addr.ip().to_string()));
    }
    Ok(())
}

fn is_unicast_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_loopback()
                && !v4.is_broadcast()
                && !v4.is_multicast()
                && !v4.is_unspecified()
                && !v4.is_link_local()
                && !is_private_v4(v4)
        }
        IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_multicast() && !v6.is_unspecified(),
    }
}

fn is_private_v4(ip: &std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 10
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
        || (octets[0] == 169 && octets[1] == 254)
}

#[derive(Debug, Clone)]
pub enum SsrfError {
    InvalidUrl,
    InsecureProtocol(String),
    NoHost,
    NonUnicastIp(String),
    DnsResolutionFailed(String),
}

impl std::fmt::Display for SsrfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SsrfError::InvalidUrl => write!(f, "Invalid URL"),
            SsrfError::InsecureProtocol(p) => write!(f, "Insecure protocol: {}", p),
            SsrfError::NoHost => write!(f, "No host in URL"),
            SsrfError::NonUnicastIp(ip) => write!(f, "Non-unicast IP address: {}", ip),
            SsrfError::DnsResolutionFailed(host) => {
                write!(f, "DNS resolution failed for: {}", host)
            }
        }
    }
}

impl std::error::Error for SsrfError {}

pub const HEADERS_TO_FORWARD: &[&str] = &[
    "accept-language",
    "atproto-accept-labelers",
    "x-bsky-topics",
    "content-type",
];
pub const RESPONSE_HEADERS_TO_FORWARD: &[&str] = &[
    "atproto-repo-rev",
    "atproto-content-labelers",
    "retry-after",
    "content-type",
    "cache-control",
    "etag",
];

pub fn validate_at_uri(uri: &str) -> Result<AtUriParts, &'static str> {
    if !uri.starts_with("at://") {
        return Err("URI must start with at://");
    }
    let path = uri.trim_start_matches("at://");
    let parts: Vec<&str> = path.split('/').collect();
    if parts.is_empty() {
        return Err("URI missing DID");
    }
    let did = parts[0];
    if !did.starts_with("did:") {
        return Err("Invalid DID in URI");
    }
    if parts.len() > 1 {
        let collection = parts[1];
        if collection.is_empty() || !collection.contains('.') {
            return Err("Invalid collection NSID");
        }
    }
    Ok(AtUriParts {
        did: did.to_string(),
        collection: parts.get(1).map(|s| s.to_string()),
        rkey: parts.get(2).map(|s| s.to_string()),
    })
}

#[derive(Debug, Clone)]
pub struct AtUriParts {
    pub did: String,
    pub collection: Option<String>,
    pub rkey: Option<String>,
}

pub fn validate_limit(limit: Option<u32>, default: u32, max: u32) -> u32 {
    match limit {
        Some(0) => default,
        Some(l) if l > max => max,
        Some(l) => l,
        None => default,
    }
}

pub fn validate_did(did: &str) -> Result<(), &'static str> {
    if !did.starts_with("did:") {
        return Err("Invalid DID format");
    }
    let parts: Vec<&str> = did.split(':').collect();
    if parts.len() < 3 {
        return Err("DID must have at least method and identifier");
    }
    let method = parts[1];
    if method != "plc" && method != "web" {
        return Err("Unsupported DID method");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ssrf_safe_https() {
        assert!(is_ssrf_safe("https://api.bsky.app/xrpc/test").is_ok());
    }
    #[test]
    fn test_ssrf_blocks_http_by_default() {
        let result = is_ssrf_safe("http://external.example.com/xrpc/test");
        assert!(matches!(
            result,
            Err(SsrfError::InsecureProtocol(_)) | Err(SsrfError::DnsResolutionFailed(_))
        ));
    }
    #[test]
    fn test_ssrf_allows_localhost_http() {
        assert!(is_ssrf_safe("http://127.0.0.1:8080/test").is_ok());
        assert!(is_ssrf_safe("http://localhost:8080/test").is_ok());
    }
    #[test]
    fn test_validate_at_uri() {
        let result = validate_at_uri("at://did:plc:test/app.bsky.feed.post/abc123");
        assert!(result.is_ok());
        let parts = result.unwrap();
        assert_eq!(parts.did, "did:plc:test");
        assert_eq!(parts.collection, Some("app.bsky.feed.post".to_string()));
        assert_eq!(parts.rkey, Some("abc123".to_string()));
    }
    #[test]
    fn test_validate_at_uri_invalid() {
        assert!(validate_at_uri("https://example.com").is_err());
        assert!(validate_at_uri("at://notadid/collection/rkey").is_err());
    }
    #[test]
    fn test_validate_limit() {
        assert_eq!(validate_limit(None, 50, 100), 50);
        assert_eq!(validate_limit(Some(0), 50, 100), 50);
        assert_eq!(validate_limit(Some(200), 50, 100), 100);
        assert_eq!(validate_limit(Some(75), 50, 100), 75);
    }
    #[test]
    fn test_validate_did() {
        assert!(validate_did("did:plc:abc123").is_ok());
        assert!(validate_did("did:web:example.com").is_ok());
        assert!(validate_did("notadid").is_err());
        assert!(validate_did("did:unknown:test").is_err());
    }
}
