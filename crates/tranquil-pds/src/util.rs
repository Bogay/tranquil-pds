use axum::http::{HeaderMap, HeaderName};
use base64::Engine as _;

use cid::Cid;
use ipld_core::ipld::Ipld;
use rand::Rng;
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::OnceLock;

const BASE64_STANDARD_INDIFFERENT: base64::engine::GeneralPurpose =
    base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    );

const BASE32_ALPHABET: &str = "abcdefghijklmnopqrstuvwxyz234567";

static DISCORD_BOT_USERNAME: OnceLock<String> = OnceLock::new();
static DISCORD_PUBLIC_KEY: OnceLock<ed25519_dalek::VerifyingKey> = OnceLock::new();
static DISCORD_APP_ID: OnceLock<String> = OnceLock::new();
static TELEGRAM_BOT_USERNAME: OnceLock<String> = OnceLock::new();

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

pub const HEADER_DPOP: HeaderName = HeaderName::from_static("dpop");
pub const HEADER_DPOP_NONCE: HeaderName = HeaderName::from_static("dpop-nonce");
pub const HEADER_ATPROTO_PROXY: HeaderName = HeaderName::from_static("atproto-proxy");
pub const HEADER_ATPROTO_ACCEPT_LABELERS: HeaderName =
    HeaderName::from_static("atproto-accept-labelers");
pub const HEADER_ATPROTO_REPO_REV: HeaderName = HeaderName::from_static("atproto-repo-rev");
pub const HEADER_ATPROTO_CONTENT_LABELERS: HeaderName =
    HeaderName::from_static("atproto-content-labelers");
pub const HEADER_X_BSKY_TOPICS: HeaderName = HeaderName::from_static("x-bsky-topics");

pub fn get_header_str(
    headers: &HeaderMap,
    name: impl axum::http::header::AsHeaderName,
) -> Option<&str> {
    headers.get(name).and_then(|h| h.to_str().ok())
}

pub fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

pub fn generate_random_token() -> String {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let bytes: [u8; 32] = rand::thread_rng().r#gen();
    URL_SAFE_NO_PAD.encode(bytes)
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

pub fn set_discord_bot_username(username: String) {
    DISCORD_BOT_USERNAME.set(username).ok();
}

pub fn discord_bot_username() -> Option<&'static str> {
    DISCORD_BOT_USERNAME.get().map(|s| s.as_str())
}

pub fn set_discord_public_key(key: ed25519_dalek::VerifyingKey) {
    DISCORD_PUBLIC_KEY.set(key).ok();
}

pub fn discord_public_key() -> Option<&'static ed25519_dalek::VerifyingKey> {
    DISCORD_PUBLIC_KEY.get()
}

pub fn set_discord_app_id(app_id: String) {
    DISCORD_APP_ID.set(app_id).ok();
}

pub fn discord_app_id() -> Option<&'static str> {
    DISCORD_APP_ID.get().map(|s| s.as_str())
}

pub fn set_telegram_bot_username(username: String) {
    TELEGRAM_BOT_USERNAME.set(username).ok();
}

pub fn telegram_bot_username() -> Option<&'static str> {
    TELEGRAM_BOT_USERNAME.get().map(|s| s.as_str())
}

pub fn parse_env_bool(key: &str) -> bool {
    // Check the config system first, then fall back to env var for dynamic
    // SSO keys that are not in the static config struct.
    std::env::var(key)
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}

pub fn build_full_url(path: &str) -> String {
    let cfg = tranquil_config::get();
    let normalized_path = if !path.starts_with("/xrpc/")
        && (path.starts_with("/com.atproto.")
            || path.starts_with("/app.bsky.")
            || path.starts_with("/_"))
    {
        format!("/xrpc{path}")
    } else {
        path.to_string()
    };
    format!("{}{normalized_path}", cfg.server.public_url())
}

pub fn json_to_ipld(value: &JsonValue) -> Ipld {
    match value {
        JsonValue::Null => Ipld::Null,
        JsonValue::Bool(b) => Ipld::Bool(*b),
        JsonValue::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ipld::Integer(i128::from(i))
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
            if let Some(JsonValue::String(b64)) = obj.get("$bytes")
                && obj.len() == 1
                && let Ok(bytes) = BASE64_STANDARD_INDIFFERENT.decode(b64)
            {
                return Ipld::Bytes(bytes);
            }
            let map: BTreeMap<String, Ipld> = obj
                .iter()
                .map(|(k, v)| (k.clone(), json_to_ipld(v)))
                .collect();
            Ipld::Map(map)
        }
    }
}

pub(crate) fn gen_invite_random_token() -> String {
    let mut rng = rand::thread_rng();
    let chars: Vec<char> = BASE32_ALPHABET.chars().collect();
    let gen_segment = |rng: &mut rand::rngs::ThreadRng, len: usize| -> String {
        (0..len)
            .map(|_| chars[rng.gen_range(0..chars.len())])
            .collect()
    };
    format!("{}-{}", gen_segment(&mut rng, 5), gen_segment(&mut rng, 5))
}

pub fn gen_invite_code() -> String {
    let hostname = &tranquil_config::get().server.hostname;
    let hostname_prefix = hostname.replace('.', "-");
    format!("{}-{}", hostname_prefix, gen_invite_random_token())
}

pub fn is_self_hosted_did_web_enabled() -> bool {
    tranquil_config::get().server.enable_pds_hosted_did_web
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
    fn test_json_to_ipld_bytes_simple() {
        let json = serde_json::json!({
            "$bytes": "aGVsbG8gd29ybGQ="
        });
        let ipld = json_to_ipld(&json);
        match ipld {
            Ipld::Bytes(bytes) => {
                assert_eq!(bytes, b"hello world");
            }
            _ => panic!("Expected Ipld::Bytes, got {:?}", ipld),
        }
    }

    #[test]
    fn test_json_to_ipld_bytes_empty() {
        let json = serde_json::json!({
            "$bytes": ""
        });
        let ipld = json_to_ipld(&json);
        match ipld {
            Ipld::Bytes(bytes) => {
                assert!(bytes.is_empty());
            }
            _ => panic!("Expected Ipld::Bytes, got {:?}", ipld),
        }
    }

    #[test]
    fn test_json_to_ipld_bytes_with_special_base64_chars() {
        let json = serde_json::json!({
            "$bytes": "ygoGIpnVb/HQTIZythM9t1iLHkoWY5OeeqlhD0JEEgqHedDSCxG8F1YfipZPMA3JzKG6ssWNzOmZ9iSSW0nDvmjJ5ldwwbgt"
        });
        let ipld = json_to_ipld(&json);
        match ipld {
            Ipld::Bytes(bytes) => {
                assert!(!bytes.is_empty());
            }
            _ => panic!("Expected Ipld::Bytes, got {:?}", ipld),
        }
    }

    #[test]
    fn test_json_to_ipld_bytes_unpadded() {
        let padded = json_to_ipld(&serde_json::json!({ "$bytes": "aGVsbG8=" }));
        let unpadded = json_to_ipld(&serde_json::json!({ "$bytes": "aGVsbG8" }));
        match (&padded, &unpadded) {
            (Ipld::Bytes(a), Ipld::Bytes(b)) => {
                assert_eq!(a, b"hello");
                assert_eq!(b, b"hello");
            }
            _ => panic!(
                "Expected Ipld::Bytes for both, got {:?} / {:?}",
                padded, unpadded
            ),
        }
    }

    #[test]
    fn test_json_to_ipld_bytes_produces_cbor_byte_string_not_map() {
        let json = serde_json::json!({"$bytes": "SGVsbG8="});
        let ipld = json_to_ipld(&json);
        let cbor = serde_ipld_dagcbor::to_vec(&ipld).expect("CBOR serialization failed");
        assert_eq!(
            cbor[0] & 0xE0,
            0x40,
            "expected CBOR byte string (major type 2), got major type {}",
            cbor[0] >> 5
        );
    }

    #[test]
    fn test_json_to_ipld_bytes_not_confused_with_extra_keys() {
        let json = serde_json::json!({
            "$bytes": "aGVsbG8=",
            "extra": "field"
        });
        let ipld = json_to_ipld(&json);
        match ipld {
            Ipld::Map(_) => {}
            _ => panic!(
                "Expected Ipld::Map for $bytes with extra keys, got {:?}",
                ipld
            ),
        }
    }

    #[test]
    fn test_json_to_ipld_bytes_nested_in_record() {
        let record = serde_json::json!({
            "$type": "app.opake.grant",
            "recipient": "did:plc:example",
            "wrappedKey": {
                "algo": "x25519-hkdf-a256kw",
                "ciphertext": {
                    "$bytes": "ygoGIpnVb/HQTIZythM9t1iLHkoWY5OeeqlhD0JEEgqHedDSCxG8F1YfipZPMA3JzKG6ssWNzOmZ9iSSW0nDvmjJ5ldwwbgt"
                }
            },
            "encryptedMetadata": {
                "ciphertext": { "$bytes": "aGVsbG8=" },
                "nonce": { "$bytes": "d29ybGQ=" }
            }
        });
        let ipld = json_to_ipld(&record);
        let cbor_bytes = serde_ipld_dagcbor::to_vec(&ipld).expect("CBOR serialization failed");
        let parsed: Ipld =
            serde_ipld_dagcbor::from_slice(&cbor_bytes).expect("CBOR deserialization failed");
        if let Ipld::Map(map) = &parsed
            && let Some(Ipld::Map(wrapped)) = map.get("wrappedKey")
            && let Some(Ipld::Bytes(ct)) = wrapped.get("ciphertext")
            && let Some(Ipld::Map(meta)) = map.get("encryptedMetadata")
            && let Some(Ipld::Bytes(meta_ct)) = meta.get("ciphertext")
            && let Some(Ipld::Bytes(nonce)) = meta.get("nonce")
        {
            assert!(!ct.is_empty());
            assert_eq!(meta_ct, b"hello");
            assert_eq!(nonce, b"world");
            return;
        }
        panic!("Failed to find Bytes in parsed CBOR: {:?}", parsed);
    }

    #[test]
    fn test_parse_env_bool_true_values() {
        unsafe { std::env::set_var("TEST_PARSE_ENV_BOOL_1", "true") };
        assert!(parse_env_bool("TEST_PARSE_ENV_BOOL_1"));
        unsafe { std::env::set_var("TEST_PARSE_ENV_BOOL_1", "1") };
        assert!(parse_env_bool("TEST_PARSE_ENV_BOOL_1"));
    }

    #[test]
    fn test_parse_env_bool_false_values() {
        unsafe { std::env::set_var("TEST_PARSE_ENV_BOOL_2", "false") };
        assert!(!parse_env_bool("TEST_PARSE_ENV_BOOL_2"));
        unsafe { std::env::set_var("TEST_PARSE_ENV_BOOL_2", "0") };
        assert!(!parse_env_bool("TEST_PARSE_ENV_BOOL_2"));
        unsafe { std::env::set_var("TEST_PARSE_ENV_BOOL_2", "yes") };
        assert!(!parse_env_bool("TEST_PARSE_ENV_BOOL_2"));
    }

    #[test]
    fn test_parse_env_bool_unset() {
        unsafe { std::env::remove_var("TEST_PARSE_ENV_BOOL_UNSET_KEY") };
        assert!(!parse_env_bool("TEST_PARSE_ENV_BOOL_UNSET_KEY"));
    }

    #[test]
    fn test_build_full_url_adds_xrpc_prefix_for_atproto_paths() {
        unsafe { std::env::set_var("PDS_HOSTNAME", "example.com") };
        tranquil_config::ensure_test_defaults();
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
