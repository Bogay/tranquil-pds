pub mod reserved;

use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use thiserror::Error;

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
    DidMismatch { expected: String, actual: String },
}

pub async fn resolve_handle_dns(handle: &str) -> Result<String, HandleResolutionError> {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
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
            txt_str.strip_prefix("did=").and_then(|did| {
                let did = did.trim();
                did.starts_with("did:").then(|| did.to_string())
            })
        })
        .ok_or(HandleResolutionError::NotFound)
}

pub async fn resolve_handle_http(handle: &str) -> Result<String, HandleResolutionError> {
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
    let did = body.trim();
    if did.starts_with("did:") {
        Ok(did.to_string())
    } else {
        Err(HandleResolutionError::InvalidDid)
    }
}

pub async fn resolve_handle(handle: &str) -> Result<String, HandleResolutionError> {
    match resolve_handle_dns(handle).await {
        Ok(did) => return Ok(did),
        Err(e) => {
            tracing::debug!("DNS resolution failed for {}: {}, trying HTTP", handle, e);
        }
    }
    resolve_handle_http(handle).await
}

pub async fn verify_handle_ownership(
    handle: &str,
    expected_did: &str,
) -> Result<(), HandleResolutionError> {
    let resolved_did = resolve_handle(handle).await?;
    if resolved_did == expected_did {
        Ok(())
    } else {
        Err(HandleResolutionError::DidMismatch {
            expected: expected_did.to_string(),
            actual: resolved_did,
        })
    }
}

pub fn is_service_domain_handle(handle: &str, hostname: &str) -> bool {
    if !handle.contains('.') {
        return true;
    }
    let service_domains = tranquil_config::try_get()
        .map(|c| c.server.user_handle_domain_list())
        .unwrap_or_else(|| vec![hostname.to_string()]);
    service_domains
        .iter()
        .any(|domain| handle.ends_with(&format!(".{}", domain)) || handle == domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_service_domain_handle() {
        assert!(is_service_domain_handle("user.example.com", "example.com"));
        assert!(is_service_domain_handle("example.com", "example.com"));
        assert!(is_service_domain_handle("myhandle", "example.com"));
        assert!(!is_service_domain_handle("user.other.com", "example.com"));
        assert!(!is_service_domain_handle("myhandle.xyz", "example.com"));
    }
}
