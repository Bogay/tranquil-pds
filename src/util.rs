use axum::http::HeaderMap;
use cid::Cid;
use ipld_core::ipld::Ipld;
use rand::Rng;
use serde_json::Value as JsonValue;
use sqlx::PgPool;
use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::OnceLock;
use uuid::Uuid;

const BASE32_ALPHABET: &str = "abcdefghijklmnopqrstuvwxyz234567";
const DEFAULT_MAX_BLOB_SIZE: usize = 10 * 1024 * 1024 * 1024;

static MAX_BLOB_SIZE: OnceLock<usize> = OnceLock::new();

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

#[derive(Debug)]
pub enum DbLookupError {
    NotFound,
    DatabaseError(sqlx::Error),
}

impl From<sqlx::Error> for DbLookupError {
    fn from(e: sqlx::Error) -> Self {
        DbLookupError::DatabaseError(e)
    }
}

pub async fn get_user_id_by_did(db: &PgPool, did: &str) -> Result<Uuid, DbLookupError> {
    sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", did)
        .fetch_optional(db)
        .await?
        .ok_or(DbLookupError::NotFound)
}

pub struct UserInfo {
    pub id: Uuid,
    pub did: String,
    pub handle: String,
}

pub async fn get_user_by_did(db: &PgPool, did: &str) -> Result<UserInfo, DbLookupError> {
    sqlx::query_as!(
        UserInfo,
        "SELECT id, did, handle FROM users WHERE did = $1",
        did
    )
    .fetch_optional(db)
    .await?
    .ok_or(DbLookupError::NotFound)
}

pub async fn get_user_by_identifier(
    db: &PgPool,
    identifier: &str,
) -> Result<UserInfo, DbLookupError> {
    sqlx::query_as!(
        UserInfo,
        "SELECT id, did, handle FROM users WHERE did = $1 OR handle = $1",
        identifier
    )
    .fetch_optional(db)
    .await?
    .ok_or(DbLookupError::NotFound)
}

pub async fn is_account_migrated(db: &PgPool, did: &str) -> Result<bool, sqlx::Error> {
    let row = sqlx::query!(
        r#"SELECT (migrated_to_pds IS NOT NULL AND deactivated_at IS NOT NULL) as "migrated!: bool" FROM users WHERE did = $1"#,
        did
    )
    .fetch_optional(db)
    .await?;
    Ok(row.map(|r| r.migrated).unwrap_or(false))
}

pub fn parse_repeated_query_param(query: Option<&str>, key: &str) -> Vec<String> {
    query
        .map(|q| {
            let mut values = Vec::new();
            for pair in q.split('&') {
                if let Some((k, v)) = pair.split_once('=')
                    && k == key
                    && let Ok(decoded) = urlencoding::decode(v)
                {
                    let decoded = decoded.into_owned();
                    if decoded.contains(',') {
                        for part in decoded.split(',') {
                            let trimmed = part.trim();
                            if !trimmed.is_empty() {
                                values.push(trimmed.to_string());
                            }
                        }
                    } else if !decoded.is_empty() {
                        values.push(decoded);
                    }
                }
            }
            values
        })
        .unwrap_or_default()
}

pub fn extract_client_ip(headers: &HeaderMap) -> String {
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
    "unknown".to_string()
}

pub fn pds_hostname() -> String {
    std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string())
}

pub fn pds_public_url() -> String {
    format!("https://{}", pds_hostname())
}

pub fn build_full_url(path: &str) -> String {
    format!("{}{}", pds_public_url(), path)
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

        for c in code.chars() {
            if c != '-' {
                assert!(BASE32_ALPHABET.contains(c));
            }
        }
    }

    #[test]
    fn test_generate_token_code_parts() {
        let code = generate_token_code_parts(3, 4);
        let parts: Vec<&str> = code.split('-').collect();
        assert_eq!(parts.len(), 3);

        for part in parts {
            assert_eq!(part.len(), 4);
        }
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
}
