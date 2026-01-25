use axum::http::HeaderMap;
use cid::Cid;
use ipld_core::ipld::Ipld;
use rand::Rng;
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::OnceLock;

const BASE32_ALPHABET: &str = "abcdefghijklmnopqrstuvwxyz234567";
const DEFAULT_MAX_BLOB_SIZE: usize = 10 * 1024 * 1024 * 1024;

static MAX_BLOB_SIZE: OnceLock<usize> = OnceLock::new();
static PDS_HOSTNAME: OnceLock<String> = OnceLock::new();
static PDS_HOSTNAME_WITHOUT_PORT: OnceLock<String> = OnceLock::new();

pub fn get_max_blob_size() -> usize {
    *MAX_BLOB_SIZE.get_or_init(|| {
        std::env::var("MAX_BLOB_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_MAX_BLOB_SIZE)
    })
}

pub fn generate_token_code() -> String {
    generate_token_code_parts(2, 5)
}

pub fn generate_token_code_parts(parts: usize, part_len: usize) -> String {
    let mut rng = rand::thread_rng();
    let chars: Vec<char> = BASE32_ALPHABET.chars().collect();

    (0..parts)
        .map(|_| {
            (0..part_len)
                .map(|_| chars[rng.gen_range(0..chars.len())])
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("-")
}

pub fn parse_repeated_query_param(query: Option<&str>, key: &str) -> Vec<String> {
    query
        .map(|q| {
            q.split('&')
                .filter_map(|pair| {
                    pair.split_once('=')
                        .filter(|(k, _)| *k == key)
                        .and_then(|(_, v)| urlencoding::decode(v).ok())
                        .map(|decoded| decoded.into_owned())
                })
                .flat_map(|decoded| {
                    if decoded.contains(',') {
                        decoded
                            .split(',')
                            .filter_map(|part| {
                                let trimmed = part.trim();
                                (!trimmed.is_empty()).then(|| trimmed.to_string())
                            })
                            .collect::<Vec<_>>()
                    } else if decoded.is_empty() {
                        vec![]
                    } else {
                        vec![decoded]
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn get_header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|h| h.to_str().ok())
}

pub fn extract_client_ip(headers: &HeaderMap, addr: Option<SocketAddr>) -> String {
    if let Some(forwarded) = headers.get("x-forwarded-for")
        && let Ok(value) = forwarded.to_str()
        && let Some(first_ip) = value.split(',').next()
    {
        return first_ip.trim().to_string();
    }
    if let Some(real_ip) = headers.get("x-real-ip")
        && let Ok(value) = real_ip.to_str()
    {
        return value.trim().to_string();
    }
    addr.map(|a| a.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn pds_hostname() -> &'static str {
    PDS_HOSTNAME
        .get_or_init(|| std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string()))
}

pub fn pds_hostname_without_port() -> &'static str {
    PDS_HOSTNAME_WITHOUT_PORT.get_or_init(|| {
        let hostname = pds_hostname();
        hostname.split(':').next().unwrap_or(hostname).to_string()
    })
}

pub fn pds_public_url() -> String {
    format!("https://{}", pds_hostname())
}

pub fn build_full_url(path: &str) -> String {
    let normalized_path = if !path.starts_with("/xrpc/")
        && (path.starts_with("/com.atproto.")
            || path.starts_with("/app.bsky.")
            || path.starts_with("/_"))
    {
        format!("/xrpc{}", path)
    } else {
        path.to_string()
    };
    format!("{}{}", pds_public_url(), normalized_path)
}

pub fn json_to_ipld(value: &JsonValue) -> Ipld {
    match value {
        JsonValue::Null => Ipld::Null,
        JsonValue::Bool(b) => Ipld::Bool(*b),
        JsonValue::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ipld::Integer(i as i128)
            } else if let Some(f) = n.as_f64() {
                Ipld::Float(f)
            } else {
                Ipld::Null
            }
        }
        JsonValue::String(s) => Ipld::String(s.clone()),
        JsonValue::Array(arr) => Ipld::List(arr.iter().map(json_to_ipld).collect()),
        JsonValue::Object(obj) => {
            if let Some(JsonValue::String(link)) = obj.get("$link")
                && obj.len() == 1
                && let Ok(cid) = Cid::from_str(link)
            {
                return Ipld::Link(cid);
            }
            let map: BTreeMap<String, Ipld> = obj
                .iter()
                .map(|(k, v)| (k.clone(), json_to_ipld(v)))
                .collect();
            Ipld::Map(map)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_repeated_query_param_repeated() {
        let query = "did=test&cids=a&cids=b&cids=c";
        let result = parse_repeated_query_param(Some(query), "cids");
        assert_eq!(result, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_parse_repeated_query_param_comma_separated() {
        let query = "did=test&cids=a,b,c";
        let result = parse_repeated_query_param(Some(query), "cids");
        assert_eq!(result, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_parse_repeated_query_param_mixed() {
        let query = "did=test&cids=a,b&cids=c";
        let result = parse_repeated_query_param(Some(query), "cids");
        assert_eq!(result, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_parse_repeated_query_param_single() {
        let query = "did=test&cids=a";
        let result = parse_repeated_query_param(Some(query), "cids");
        assert_eq!(result, vec!["a"]);
    }

    #[test]
    fn test_parse_repeated_query_param_empty() {
        let query = "did=test";
        let result = parse_repeated_query_param(Some(query), "cids");
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_repeated_query_param_url_encoded() {
        let query = "did=test&cids=bafyreib%2Btest";
        let result = parse_repeated_query_param(Some(query), "cids");
        assert_eq!(result, vec!["bafyreib+test"]);
    }

    #[test]
    fn test_generate_token_code() {
        let code = generate_token_code();
        assert_eq!(code.len(), 11);
        assert!(code.contains('-'));

        let parts: Vec<&str> = code.split('-').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].len(), 5);
        assert_eq!(parts[1].len(), 5);

        assert!(
            code.chars()
                .filter(|&c| c != '-')
                .all(|c| BASE32_ALPHABET.contains(c))
        );
    }

    #[test]
    fn test_generate_token_code_parts() {
        let code = generate_token_code_parts(3, 4);
        let parts: Vec<&str> = code.split('-').collect();
        assert_eq!(parts.len(), 3);

        assert!(parts.iter().all(|part| part.len() == 4));
    }

    #[test]
    fn test_json_to_ipld_cid_link() {
        let json = serde_json::json!({
            "$link": "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
        });
        let ipld = json_to_ipld(&json);
        match ipld {
            Ipld::Link(cid) => {
                assert_eq!(
                    cid.to_string(),
                    "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
                );
            }
            _ => panic!("Expected Ipld::Link, got {:?}", ipld),
        }
    }

    #[test]
    fn test_json_to_ipld_blob_ref() {
        let json = serde_json::json!({
            "$type": "blob",
            "ref": {
                "$link": "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
            },
            "mimeType": "image/jpeg",
            "size": 12345
        });
        let ipld = json_to_ipld(&json);
        match ipld {
            Ipld::Map(map) => {
                assert_eq!(map.get("$type"), Some(&Ipld::String("blob".to_string())));
                assert_eq!(
                    map.get("mimeType"),
                    Some(&Ipld::String("image/jpeg".to_string()))
                );
                assert_eq!(map.get("size"), Some(&Ipld::Integer(12345)));
                match map.get("ref") {
                    Some(Ipld::Link(cid)) => {
                        assert_eq!(
                            cid.to_string(),
                            "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
                        );
                    }
                    _ => panic!("Expected Ipld::Link in ref field, got {:?}", map.get("ref")),
                }
            }
            _ => panic!("Expected Ipld::Map, got {:?}", ipld),
        }
    }

    #[test]
    fn test_json_to_ipld_nested_blob_refs_serializes_correctly() {
        let record = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "Hello world",
            "embed": {
                "$type": "app.bsky.embed.images",
                "images": [
                    {
                        "alt": "Test image",
                        "image": {
                            "$type": "blob",
                            "ref": {
                                "$link": "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
                            },
                            "mimeType": "image/jpeg",
                            "size": 12345
                        }
                    }
                ]
            }
        });
        let ipld = json_to_ipld(&record);
        let cbor_bytes = serde_ipld_dagcbor::to_vec(&ipld).expect("CBOR serialization failed");
        assert!(!cbor_bytes.is_empty());
        let parsed: Ipld =
            serde_ipld_dagcbor::from_slice(&cbor_bytes).expect("CBOR deserialization failed");
        if let Ipld::Map(map) = &parsed
            && let Some(Ipld::Map(embed)) = map.get("embed")
            && let Some(Ipld::List(images)) = embed.get("images")
            && let Some(Ipld::Map(img)) = images.first()
            && let Some(Ipld::Map(blob)) = img.get("image")
            && let Some(Ipld::Link(cid)) = blob.get("ref")
        {
            assert_eq!(
                cid.to_string(),
                "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
            );
            return;
        }
        panic!("Failed to find CID link in parsed CBOR");
    }

    #[test]
    fn test_build_full_url_adds_xrpc_prefix_for_atproto_paths() {
        unsafe { std::env::set_var("PDS_HOSTNAME", "example.com") };
        assert_eq!(
            build_full_url("/com.atproto.server.getSession"),
            "https://example.com/xrpc/com.atproto.server.getSession"
        );
        assert_eq!(
            build_full_url("/app.bsky.feed.getTimeline"),
            "https://example.com/xrpc/app.bsky.feed.getTimeline"
        );
        assert_eq!(
            build_full_url("/_health"),
            "https://example.com/xrpc/_health"
        );
        assert_eq!(
            build_full_url("/xrpc/com.atproto.server.getSession"),
            "https://example.com/xrpc/com.atproto.server.getSession"
        );
        assert_eq!(
            build_full_url("/oauth/token"),
            "https://example.com/oauth/token"
        );
    }
}
