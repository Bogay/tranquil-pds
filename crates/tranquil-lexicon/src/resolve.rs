use crate::schema::LexiconDoc;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use reqwest::Client;
use std::sync::OnceLock;
use std::time::Duration;

static RESOLVER_CLIENT: OnceLock<Client> = OnceLock::new();

const MAX_RESPONSE_BYTES: usize = 512 * 1024;

fn client() -> &'static Client {
    RESOLVER_CLIENT.get_or_init(|| {
        Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .pool_max_idle_per_host(4)
            .pool_idle_timeout(Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .expect("failed to build lexicon resolver HTTP client")
    })
}

const DEFAULT_PLC_DIRECTORY: &str = "https://plc.directory";

async fn read_body_limited(resp: reqwest::Response, max_bytes: usize) -> Result<Vec<u8>, String> {
    if let Some(len) = resp.content_length()
        && len > max_bytes as u64
    {
        return Err(format!(
            "response too large: {} bytes (max {})",
            len, max_bytes
        ));
    }

    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("failed to read response body: {}", e))?;

    if bytes.len() > max_bytes {
        return Err(format!(
            "response too large: {} bytes (max {})",
            bytes.len(),
            max_bytes
        ));
    }

    Ok(bytes.to_vec())
}

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("failed to derive authority from NSID: {0}")]
    InvalidNsid(String),
    #[error("DNS lookup failed for {domain}: {reason}")]
    DnsLookup { domain: String, reason: String },
    #[error("no DID found in DNS TXT records for {domain}")]
    NoDid { domain: String },
    #[error("DID document fetch failed for {did}: {reason}")]
    DidResolution { did: String, reason: String },
    #[error("no PDS endpoint found in DID document for {did}")]
    NoPdsEndpoint { did: String },
    #[error("schema fetch failed from {url}: {reason}")]
    SchemaFetch { url: String, reason: String },
    #[error("schema deserialization failed: {0}")]
    InvalidSchema(String),
    #[error("schema resolution recently failed for {nsid}, cached for {ttl_secs}s")]
    NegativelyCached { nsid: String, ttl_secs: u64 },
    #[error("network resolution disabled")]
    NetworkDisabled,
    #[error("leader task for {nsid} aborted before completion")]
    LeaderAborted { nsid: String },
}

pub fn nsid_to_authority(nsid: &str) -> Result<String, ResolveError> {
    let mut segments: Vec<&str> = nsid.split('.').collect();
    if segments.len() < 3 {
        return Err(ResolveError::InvalidNsid(nsid.to_string()));
    }
    segments.pop();
    segments.reverse();
    Ok(segments.join("."))
}

pub async fn resolve_did_from_dns(authority: &str) -> Result<String, ResolveError> {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    let extract_did = |lookup: hickory_resolver::lookup::TxtLookup| -> Option<String> {
        lookup
            .iter()
            .flat_map(|record| record.txt_data())
            .find_map(|txt| {
                let txt_str = String::from_utf8_lossy(txt);
                txt_str.strip_prefix("did=").and_then(|did| {
                    let did = did.trim();
                    did.starts_with("did:").then(|| did.to_string())
                })
            })
    };

    let lexicon_query = format!("_lexicon.{}", authority);
    if let Ok(lookup) = resolver.txt_lookup(&lexicon_query).await
        && let Some(did) = extract_did(lookup)
    {
        return Ok(did);
    }

    let atproto_query = format!("_atproto.{}", authority);
    let lookup =
        resolver
            .txt_lookup(&atproto_query)
            .await
            .map_err(|e| ResolveError::DnsLookup {
                domain: authority.to_string(),
                reason: e.to_string(),
            })?;

    extract_did(lookup).ok_or(ResolveError::NoDid {
        domain: authority.to_string(),
    })
}

pub async fn resolve_pds_endpoint(
    did: &str,
    plc_directory_url: Option<&str>,
) -> Result<String, ResolveError> {
    let plc_base = plc_directory_url.unwrap_or(DEFAULT_PLC_DIRECTORY);

    let url = match did
        .split_once(':')
        .and_then(|(_, rest)| rest.split_once(':'))
    {
        Some(("plc", _)) => format!("{}/{}", plc_base.trim_end_matches('/'), did),
        Some(("web", domain)) => format!("https://{}/.well-known/did.json", domain),
        _ => {
            return Err(ResolveError::DidResolution {
                did: did.to_string(),
                reason: "unsupported DID method".to_string(),
            });
        }
    };

    let resp = client()
        .get(&url)
        .send()
        .await
        .map_err(|e| ResolveError::DidResolution {
            did: did.to_string(),
            reason: e.to_string(),
        })?;

    let body = read_body_limited(resp, MAX_RESPONSE_BYTES)
        .await
        .map_err(|reason| ResolveError::DidResolution {
            did: did.to_string(),
            reason,
        })?;

    let doc: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| ResolveError::DidResolution {
            did: did.to_string(),
            reason: e.to_string(),
        })?;

    extract_pds_endpoint(&doc).ok_or(ResolveError::NoPdsEndpoint {
        did: did.to_string(),
    })
}

fn extract_pds_endpoint(doc: &serde_json::Value) -> Option<String> {
    doc.get("service")
        .and_then(|s| s.as_array())
        .and_then(|services| {
            services.iter().find_map(|svc| {
                let is_pds = svc
                    .get("type")
                    .and_then(|t| t.as_str())
                    .is_some_and(|t| t == "AtprotoPersonalDataServer");
                is_pds
                    .then(|| svc.get("serviceEndpoint").and_then(|ep| ep.as_str()))?
                    .map(|s| s.to_string())
            })
        })
}

pub async fn fetch_schema_from_pds(
    pds_endpoint: &str,
    did: &str,
    nsid: &str,
) -> Result<LexiconDoc, ResolveError> {
    let url = format!(
        "{}/xrpc/com.atproto.repo.getRecord?repo={}&collection=com.atproto.lexicon.schema&rkey={}",
        pds_endpoint.trim_end_matches('/'),
        urlencoding::encode(did),
        urlencoding::encode(nsid)
    );

    let resp = client()
        .get(&url)
        .send()
        .await
        .map_err(|e| ResolveError::SchemaFetch {
            url: url.clone(),
            reason: e.to_string(),
        })?;

    let status = resp.status();
    if !status.is_success() {
        return Err(ResolveError::SchemaFetch {
            url,
            reason: format!("HTTP {}", status),
        });
    }

    let body = read_body_limited(resp, MAX_RESPONSE_BYTES)
        .await
        .map_err(|reason| ResolveError::SchemaFetch {
            url: url.clone(),
            reason,
        })?;

    let resp_value: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| ResolveError::SchemaFetch {
            url: url.clone(),
            reason: e.to_string(),
        })?;

    let value = resp_value
        .get("value")
        .ok_or_else(|| ResolveError::SchemaFetch {
            url: url.clone(),
            reason: "response missing 'value' field".to_string(),
        })?;

    serde_json::from_value::<LexiconDoc>(value.clone())
        .map_err(|e| ResolveError::InvalidSchema(e.to_string()))
}

fn validate_fetched_schema(doc: &LexiconDoc, nsid: &str) -> Result<(), ResolveError> {
    if doc.id != nsid {
        return Err(ResolveError::InvalidSchema(format!(
            "schema id '{}' does not match requested NSID '{}'",
            doc.id, nsid
        )));
    }
    if doc.lexicon != 1 {
        return Err(ResolveError::InvalidSchema(format!(
            "unsupported lexicon version: {}",
            doc.lexicon
        )));
    }
    Ok(())
}

pub async fn resolve_lexicon(nsid: &str) -> Result<LexiconDoc, ResolveError> {
    resolve_lexicon_with_config(nsid, None).await
}

pub async fn resolve_lexicon_with_config(
    nsid: &str,
    plc_directory_url: Option<&str>,
) -> Result<LexiconDoc, ResolveError> {
    let authority = nsid_to_authority(nsid)?;
    tracing::debug!(nsid = nsid, authority = %authority, "resolving lexicon schema");

    let did = resolve_did_from_dns(&authority).await?;
    tracing::debug!(nsid = nsid, did = %did, "resolved authority DID");

    let pds_endpoint = resolve_pds_endpoint(&did, plc_directory_url).await?;
    tracing::debug!(nsid = nsid, pds = %pds_endpoint, "resolved PDS endpoint");

    let doc = fetch_schema_from_pds(&pds_endpoint, &did, nsid).await?;
    validate_fetched_schema(&doc, nsid)?;

    Ok(doc)
}

pub async fn resolve_lexicon_from_did(
    nsid: &str,
    did: &str,
    plc_directory_url: Option<&str>,
) -> Result<LexiconDoc, ResolveError> {
    let pds_endpoint = resolve_pds_endpoint(did, plc_directory_url).await?;
    let doc = fetch_schema_from_pds(&pds_endpoint, did, nsid).await?;
    validate_fetched_schema(&doc, nsid)?;
    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nsid_to_authority() {
        assert_eq!(
            nsid_to_authority("app.bsky.feed.post").unwrap(),
            "feed.bsky.app"
        );
        assert_eq!(
            nsid_to_authority("com.atproto.repo.strongRef").unwrap(),
            "repo.atproto.com"
        );
        assert_eq!(
            nsid_to_authority("com.germnetwork.social.post").unwrap(),
            "social.germnetwork.com"
        );
        assert!(nsid_to_authority("tooShort").is_err());
    }

    #[test]
    fn test_nsid_to_authority_three_segments() {
        assert_eq!(
            nsid_to_authority("org.example.record").unwrap(),
            "example.org"
        );
    }

    #[test]
    fn test_extract_pds_endpoint_valid() {
        let doc = serde_json::json!({
            "service": [{
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": "https://pds.example.com"
            }]
        });
        assert_eq!(
            extract_pds_endpoint(&doc),
            Some("https://pds.example.com".to_string())
        );
    }

    #[test]
    fn test_extract_pds_endpoint_multiple_services() {
        let doc = serde_json::json!({
            "service": [
                {
                    "type": "AtprotoLabeler",
                    "serviceEndpoint": "https://labeler.example.com"
                },
                {
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": "https://pds.example.com"
                }
            ]
        });
        assert_eq!(
            extract_pds_endpoint(&doc),
            Some("https://pds.example.com".to_string())
        );
    }

    #[test]
    fn test_extract_pds_endpoint_missing() {
        let doc = serde_json::json!({
            "service": [{
                "type": "AtprotoLabeler",
                "serviceEndpoint": "https://labeler.example.com"
            }]
        });
        assert_eq!(extract_pds_endpoint(&doc), None);
    }

    #[test]
    fn test_extract_pds_endpoint_no_services() {
        let doc = serde_json::json!({});
        assert_eq!(extract_pds_endpoint(&doc), None);
    }

    #[test]
    fn test_validate_fetched_schema_ok() {
        let doc = LexiconDoc {
            lexicon: 1,
            id: "com.example.thing".to_string(),
            defs: Default::default(),
        };
        assert!(validate_fetched_schema(&doc, "com.example.thing").is_ok());
    }

    #[test]
    fn test_validate_fetched_schema_id_mismatch() {
        let doc = LexiconDoc {
            lexicon: 1,
            id: "com.example.other".to_string(),
            defs: Default::default(),
        };
        let err = validate_fetched_schema(&doc, "com.example.thing").unwrap_err();
        assert!(matches!(err, ResolveError::InvalidSchema(_)));
    }

    #[test]
    fn test_validate_fetched_schema_bad_version() {
        let doc = LexiconDoc {
            lexicon: 99,
            id: "com.example.thing".to_string(),
            defs: Default::default(),
        };
        let err = validate_fetched_schema(&doc, "com.example.thing").unwrap_err();
        assert!(matches!(err, ResolveError::InvalidSchema(_)));
    }
}
