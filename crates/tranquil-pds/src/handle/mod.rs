pub mod reserved;

use crate::types::{Did, Handle};
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use std::sync::LazyLock;
use thiserror::Error;

pub use tranquil_types::Domain;

static HOSTNAME_DOMAIN: LazyLock<Domain> = LazyLock::new(|| {
    Domain::new(tranquil_config::get().server.hostname_without_port())
        .expect("server.hostname is validated at config load")
});

#[derive(Error, Debug)]
pub enum HandleResolutionError {
    #[error("DNS lookup failed: {0}")]
    DnsError(String),
    #[error("HTTP request failed: {0}")]
    HttpError(String),
    #[error("No DID found for handle")]
    NotFound,
    #[error("Invalid DID format in record")]
    InvalidDid,
    #[error("DID mismatch: expected {expected}, got {actual}")]
    DidMismatch { expected: Did, actual: Did },
}

pub async fn resolve_handle_dns(handle: &Handle) -> Result<Did, HandleResolutionError> {
    let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap_or_else(|e| {
        tracing::warn!("falling back to default DNS resolvers: {}", e);
        TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
    });
    let query_name = format!("_atproto.{}", handle);
    let txt_lookup = resolver
        .txt_lookup(&query_name)
        .await
        .map_err(|e| HandleResolutionError::DnsError(e.to_string()))?;
    txt_lookup
        .iter()
        .flat_map(|record| record.txt_data())
        .find_map(|txt| {
            let txt_str = String::from_utf8_lossy(txt);
            txt_str
                .strip_prefix("did=")
                .and_then(|did| Did::new(did.trim()).ok())
        })
        .ok_or(HandleResolutionError::NotFound)
}

pub async fn resolve_handle_http(handle: &Handle) -> Result<Did, HandleResolutionError> {
    let url = format!("https://{}/.well-known/atproto-did", handle);
    let client = crate::api::proxy_client::handle_resolution_client();
    let response = client
        .get(&url)
        .header("Accept", "text/plain")
        .send()
        .await
        .map_err(|e| HandleResolutionError::HttpError(e.to_string()))?;
    if !response.status().is_success() {
        return Err(HandleResolutionError::NotFound);
    }
    let body = response
        .text()
        .await
        .map_err(|e| HandleResolutionError::HttpError(e.to_string()))?;
    Did::new(body.trim()).map_err(|_| HandleResolutionError::InvalidDid)
}

pub async fn resolve_handle(handle: &Handle) -> Result<Did, HandleResolutionError> {
    match resolve_handle_dns(handle).await {
        Ok(did) => return Ok(did),
        Err(e) => {
            tracing::debug!("DNS resolution failed for {}: {}, trying HTTP", handle, e);
        }
    }
    resolve_handle_http(handle).await
}

pub async fn verify_handle_ownership(
    handle: &Handle,
    expected_did: &Did,
) -> Result<(), HandleResolutionError> {
    let resolved_did = resolve_handle(handle).await?;
    if resolved_did == *expected_did {
        Ok(())
    } else {
        Err(HandleResolutionError::DidMismatch {
            expected: expected_did.clone(),
            actual: resolved_did,
        })
    }
}

#[derive(Clone, Copy)]
pub struct ServiceDomains<'a> {
    user_domains: &'a [Domain],
    hostname: &'a Domain,
    serve_hostname: bool,
}

impl ServiceDomains<'static> {
    pub fn for_user_handles() -> Self {
        Self::from_config(false)
    }

    pub fn served() -> Self {
        Self::from_config(true)
    }

    fn from_config(serve_hostname: bool) -> Self {
        let server = &tranquil_config::get().server;
        Self {
            user_domains: server.user_handle_domains.as_deref().unwrap_or_default(),
            hostname: &HOSTNAME_DOMAIN,
            serve_hostname,
        }
    }
}

impl<'a> ServiceDomains<'a> {
    pub fn iter(&self) -> impl Iterator<Item = &'a Domain> {
        let hostname = (self.serve_hostname || self.user_domains.is_empty())
            .then_some(self.hostname)
            .filter(|h| !self.user_domains.contains(h));
        self.user_domains.iter().chain(hostname)
    }

    pub fn primary(&self) -> &'a Domain {
        self.user_domains.first().unwrap_or(self.hostname)
    }

    pub fn contains(&self, name: &str) -> bool {
        self.iter().any(|d| d.eq_name(name))
    }

    pub fn split_handle<'h>(&self, handle: &'h str) -> Option<(&'a Domain, &'h str)> {
        self.iter()
            .filter_map(|d| d.strip_from(handle).map(|short| (d, short)))
            .max_by_key(|(d, _)| d.as_str().len())
    }
}

#[cfg(test)]
mod tests {
    use super::{Domain, ServiceDomains};
    use std::sync::LazyLock;

    static HOST: LazyLock<Domain> = LazyLock::new(|| "pds.oyster.cafe".parse().unwrap());

    fn domains(user_domains: &[Domain], serve_hostname: bool) -> ServiceDomains<'_> {
        ServiceDomains {
            user_domains,
            hostname: &HOST,
            serve_hostname,
        }
    }

    fn owned(list: &[&str]) -> Vec<Domain> {
        list.iter().map(|d| d.parse().unwrap()).collect()
    }

    #[test]
    fn thostname_until_domains_are_configured() {
        assert!(domains(&[], false).contains("pds.oyster.cafe"));
        assert_eq!(domains(&[], false).primary(), "pds.oyster.cafe");
        let configured = owned(&["oyster.cafe"]);
        assert!(!domains(&configured, false).contains("pds.oyster.cafe"));
        assert!(domains(&configured, false).contains("oyster.cafe"));
    }

    #[test]
    fn served_set_covers_hostname_and_handle_domains() {
        let configured = owned(&["oyster.cafe"]);
        assert!(domains(&configured, true).contains("pds.oyster.cafe"));
        assert!(domains(&configured, true).contains("oyster.cafe"));
    }

    #[test]
    fn hostname_in_list_is_yielded_once() {
        let configured = owned(&["pds.oyster.cafe", "oyster.cafe"]);
        let served: Vec<&str> = domains(&configured, true)
            .iter()
            .map(Domain::as_str)
            .collect();
        assert_eq!(served, ["pds.oyster.cafe", "oyster.cafe"]);
        let configured = owned(&["PDS.Oyster.Cafe"]);
        let served: Vec<&str> = domains(&configured, true)
            .iter()
            .map(Domain::as_str)
            .collect();
        assert_eq!(served, ["pds.oyster.cafe"]);
    }

    #[test]
    fn matching_case_insensitive() {
        let configured = owned(&["oyster.cafe"]);
        assert!(domains(&configured, false).contains("Oyster.Cafe"));
        let (domain, short) = domains(&configured, false)
            .split_handle("NEL.OYSTER.CAFE")
            .unwrap();
        assert_eq!(domain, "oyster.cafe");
        assert_eq!(short, "NEL");
    }

    #[test]
    fn longest_matching_domain_wins() {
        let configured = owned(&["oyster.cafe", "pets.oyster.cafe"]);
        let (domain, short) = domains(&configured, false)
            .split_handle("nel.pets.oyster.cafe")
            .unwrap();
        assert_eq!(domain, "pets.oyster.cafe");
        assert_eq!(short, "nel");
    }

    #[test]
    fn split_handle_requires_a_dot() {
        let configured = owned(&["oyster.cafe"]);
        assert_eq!(
            domains(&configured, false).split_handle("oyster.cafe"),
            None
        );
        assert_eq!(
            domains(&configured, false).split_handle("notoyster.cafe"),
            None
        );
    }
}
