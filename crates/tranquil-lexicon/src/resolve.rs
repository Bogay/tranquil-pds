use crate::schema::LexiconDoc;
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use reqwest::Client;
use std::sync::OnceLock;
use std::time::Duration;
use tranquil_types::did_doc::extract_pds_endpoint;
use tranquil_types::{
    Did, Nsid, SchemaHostUrl, UrlKind, dns_guard, redirect_policy, url_kind, url_reach_permits,
};

static RESOLVER_CLIENT: OnceLock<Client> = OnceLock::new();

const MAX_RESPONSE_BYTES: usize = 512 * 1024;

fn client() -> &'static Client {
    RESOLVER_CLIENT.get_or_init(|| {
        Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .pool_max_idle_per_host(4)
            .pool_idle_timeout(Duration::from_secs(60))
            .redirect(redirect_policy(url_kind::SchemaHost::REACH_POLICY))
            .dns_resolver(dns_guard(url_kind::SchemaHost::REACH_POLICY))
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
    #[error("DNS lookup failed for {domain}: {reason}")]
    DnsLookup { domain: String, reason: String },
    #[error("no DID found in DNS TXT records for {domain}")]
    NoDid { domain: String },
    #[error("DID document fetch failed for {did}: {reason}")]
    DidResolution { did: Did, reason: String },
    #[error("no PDS endpoint found in DID document for {did}")]
    NoPdsEndpoint { did: Did },
    #[error("schema fetch failed from {url}: {reason}")]
    SchemaFetch { url: String, reason: String },
    #[error("no schema record for {nsid} at {url}")]
    SchemaNotFound { nsid: Nsid, url: String },
    #[error("schema deserialization failed: {0}")]
    InvalidSchema(String),
    #[error("schema resolution recently failed for {nsid}, cached for {ttl_secs}s")]
    NegativelyCached { nsid: Nsid, ttl_secs: u64 },
    #[error("network resolution disabled")]
    NetworkDisabled,
    #[error("leader task for {nsid} aborted before completion")]
    LeaderAborted { nsid: Nsid },
}

impl ResolveError {
    pub fn is_definitive(&self) -> bool {
        match self {
            Self::NoDid { .. }
            | Self::NoPdsEndpoint { .. }
            | Self::InvalidSchema(_)
            | Self::SchemaNotFound { .. } => true,
            Self::DnsLookup { .. }
            | Self::DidResolution { .. }
            | Self::SchemaFetch { .. }
            | Self::NegativelyCached { .. }
            | Self::NetworkDisabled
            | Self::LeaderAborted { .. } => false,
        }
    }
}

pub fn nsid_to_authority(nsid: &Nsid) -> String {
    let mut segments: Vec<&str> = nsid.split('.').collect();
    segments.pop();
    segments.reverse();
    segments.join(".")
}

pub async fn resolve_did_from_dns(authority: &str) -> Result<Did, ResolveError> {
    let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap_or_else(|e| {
        tracing::warn!("falling back to default DNS resolvers: {}", e);
        TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
    });

    let extract_did = |lookup: hickory_resolver::lookup::TxtLookup| -> Option<Did> {
        lookup
            .iter()
            .flat_map(|record| record.txt_data())
            .find_map(|txt| {
                let txt_str = String::from_utf8_lossy(txt);
                txt_str
                    .strip_prefix("did=")
                    .and_then(|did| Did::new(did.trim()).ok())
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
    did: &Did,
    plc_directory_url: Option<&str>,
) -> Result<SchemaHostUrl, ResolveError> {
    let plc_base = plc_directory_url.unwrap_or(DEFAULT_PLC_DIRECTORY);

    let url = match did
        .split_once(':')
        .and_then(|(_, rest)| rest.split_once(':'))
    {
        Some(("plc", _)) => format!("{}/{}", plc_base.trim_end_matches('/'), did),
        Some(("web", domain)) => {
            let url = format!("https://{}/.well-known/did.json", domain);
            let permitted = reqwest::Url::parse(&url)
                .is_ok_and(|u| url_reach_permits(&u, url_kind::SchemaHost::REACH_POLICY));
            match permitted {
                true => url,
                false => {
                    return Err(ResolveError::DidResolution {
                        did: did.clone(),
                        reason: "did:web host is outside the allowed host reach".to_string(),
                    });
                }
            }
        }
        _ => {
            return Err(ResolveError::DidResolution {
                did: did.clone(),
                reason: "unsupported DID method".to_string(),
            });
        }
    };

    let resp = client()
        .get(&url)
        .send()
        .await
        .map_err(|e| ResolveError::DidResolution {
            did: did.clone(),
            reason: e.to_string(),
        })?;

    let body = read_body_limited(resp, MAX_RESPONSE_BYTES)
        .await
        .map_err(|reason| ResolveError::DidResolution {
            did: did.clone(),
            reason,
        })?;

    let doc: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| ResolveError::DidResolution {
            did: did.clone(),
            reason: e.to_string(),
        })?;

    extract_pds_endpoint(&doc).map_err(|_| ResolveError::NoPdsEndpoint { did: did.clone() })
}

fn is_record_absent(xrpc_error: &str, xrpc_message: &str) -> bool {
    xrpc_error == "RecordNotFound"
        || xrpc_error == "InvalidRequest" && xrpc_message.starts_with("Could not locate record")
}

pub async fn fetch_schema_from_pds(
    pds_endpoint: &SchemaHostUrl,
    did: &Did,
    nsid: &Nsid,
) -> Result<LexiconDoc, ResolveError> {
    let mut request_url = pds_endpoint.endpoint("xrpc/com.atproto.repo.getRecord");
    request_url
        .query_pairs_mut()
        .append_pair("repo", did.as_str())
        .append_pair("collection", "com.atproto.lexicon.schema")
        .append_pair("rkey", nsid.as_str());
    let url = request_url.to_string();

    let resp = client()
        .get(request_url)
        .send()
        .await
        .map_err(|e| ResolveError::SchemaFetch {
            url: url.clone(),
            reason: e.to_string(),
        })?;

    let status = resp.status();
    if !status.is_success() {
        let body = read_body_limited(resp, MAX_RESPONSE_BYTES)
            .await
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .unwrap_or(serde_json::Value::Null);
        let field = |name: &str| {
            body.get(name)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string()
        };
        return match is_record_absent(&field("error"), &field("message")) {
            true => Err(ResolveError::SchemaNotFound {
                nsid: nsid.clone(),
                url,
            }),
            false => Err(ResolveError::SchemaFetch {
                url,
                reason: format!("HTTP {}", status),
            }),
        };
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

fn validate_fetched_schema(doc: &LexiconDoc, nsid: &Nsid) -> Result<(), ResolveError> {
    if doc.id != *nsid {
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

pub async fn resolve_lexicon(nsid: &Nsid) -> Result<LexiconDoc, ResolveError> {
    resolve_lexicon_with_config(nsid, None).await
}

pub async fn resolve_lexicon_with_config(
    nsid: &Nsid,
    plc_directory_url: Option<&str>,
) -> Result<LexiconDoc, ResolveError> {
    let authority = nsid_to_authority(nsid);
    tracing::debug!(nsid = %nsid, authority = %authority, "resolving lexicon schema");

    let did = resolve_did_from_dns(&authority).await?;
    tracing::debug!(nsid = %nsid, did = %did, "resolved authority DID");

    let pds_endpoint = resolve_pds_endpoint(&did, plc_directory_url).await?;
    tracing::debug!(nsid = %nsid, pds = %pds_endpoint, "resolved PDS endpoint");

    let doc = fetch_schema_from_pds(&pds_endpoint, &did, nsid).await?;
    validate_fetched_schema(&doc, nsid)?;

    Ok(doc)
}

pub async fn resolve_lexicon_from_did(
    nsid: &Nsid,
    did: &Did,
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

    fn nsid(s: &str) -> Nsid {
        s.parse().unwrap()
    }

    #[test]
    fn is_record_absent_recognizes_only_the_reference_pds_absence_shapes() {
        assert!(is_record_absent(
            "RecordNotFound",
            "Could not locate record: at://did:plc:nel/com.atproto.lexicon.schema/x"
        ));
        assert!(is_record_absent("RecordNotFound", ""));
        assert!(is_record_absent(
            "InvalidRequest",
            "Could not locate record"
        ));
        assert!(!is_record_absent(
            "InvalidRequest",
            "Error: rkey must be a valid record key"
        ));
        assert!(!is_record_absent("InvalidRequest", ""));
        assert!(!is_record_absent("InternalServerError", ""));
        assert!(!is_record_absent("RateLimitExceeded", ""));
        assert!(!is_record_absent("", ""));
    }

    #[test]
    fn test_nsid_to_authority() {
        assert_eq!(
            nsid_to_authority(&nsid("app.bsky.feed.post")),
            "feed.bsky.app"
        );
        assert_eq!(
            nsid_to_authority(&nsid("com.atproto.repo.strongRef")),
            "repo.atproto.com"
        );
        assert_eq!(
            nsid_to_authority(&nsid("com.germnetwork.social.post")),
            "social.germnetwork.com"
        );
    }

    #[test]
    fn test_nsid_to_authority_three_segments() {
        assert_eq!(
            nsid_to_authority(&nsid("org.example.record")),
            "example.org"
        );
    }

    #[test]
    fn test_validate_fetched_schema_ok() {
        let doc = LexiconDoc {
            lexicon: 1,
            id: nsid("com.example.thing"),
            defs: Default::default(),
        };
        assert!(validate_fetched_schema(&doc, &nsid("com.example.thing")).is_ok());
    }

    #[test]
    fn test_validate_fetched_schema_id_mismatch() {
        let doc = LexiconDoc {
            lexicon: 1,
            id: nsid("com.example.other"),
            defs: Default::default(),
        };
        let err = validate_fetched_schema(&doc, &nsid("com.example.thing")).unwrap_err();
        assert!(matches!(err, ResolveError::InvalidSchema(_)));
    }

    #[test]
    fn test_validate_fetched_schema_bad_version() {
        let doc = LexiconDoc {
            lexicon: 99,
            id: nsid("com.example.thing"),
            defs: Default::default(),
        };
        let err = validate_fetched_schema(&doc, &nsid("com.example.thing")).unwrap_err();
        assert!(matches!(err, ResolveError::InvalidSchema(_)));
    }
}
