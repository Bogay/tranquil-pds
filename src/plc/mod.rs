use crate::cache::Cache;
use base32::Alphabet;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use k256::ecdsa::{Signature, SigningKey, signature::Signer};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PlcError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    #[error("DID not found")]
    NotFound,
    #[error("DID is tombstoned")]
    Tombstoned,
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Signing error: {0}")]
    Signing(String),
    #[error("Request timeout")]
    Timeout,
    #[error("Service unavailable (circuit breaker open)")]
    CircuitBreakerOpen,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlcOperation {
    #[serde(rename = "type")]
    pub op_type: String,
    #[serde(rename = "rotationKeys")]
    pub rotation_keys: Vec<String>,
    #[serde(rename = "verificationMethods")]
    pub verification_methods: HashMap<String, String>,
    #[serde(rename = "alsoKnownAs")]
    pub also_known_as: Vec<String>,
    pub services: HashMap<String, PlcService>,
    pub prev: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlcService {
    #[serde(rename = "type")]
    pub service_type: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlcTombstone {
    #[serde(rename = "type")]
    pub op_type: String,
    pub prev: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PlcOpOrTombstone {
    Operation(PlcOperation),
    Tombstone(PlcTombstone),
}

impl PlcOpOrTombstone {
    pub fn is_tombstone(&self) -> bool {
        match self {
            PlcOpOrTombstone::Tombstone(_) => true,
            PlcOpOrTombstone::Operation(op) => op.op_type == "plc_tombstone",
        }
    }
}

const PLC_CACHE_TTL_SECS: u64 = 300;

pub struct PlcClient {
    base_url: String,
    client: Client,
    cache: Option<Arc<dyn Cache>>,
}

impl PlcClient {
    pub fn new(base_url: Option<String>) -> Self {
        Self::with_cache(base_url, None)
    }

    pub fn with_cache(base_url: Option<String>, cache: Option<Arc<dyn Cache>>) -> Self {
        let base_url = base_url.unwrap_or_else(|| {
            std::env::var("PLC_DIRECTORY_URL")
                .unwrap_or_else(|_| "https://plc.directory".to_string())
        });
        let timeout_secs: u64 = std::env::var("PLC_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10);
        let connect_timeout_secs: u64 = std::env::var("PLC_CONNECT_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5);
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .connect_timeout(Duration::from_secs(connect_timeout_secs))
            .pool_max_idle_per_host(5)
            .pool_idle_timeout(Duration::from_secs(90))
            .build()
            .unwrap_or_else(|_| Client::new());
        Self {
            base_url,
            client,
            cache,
        }
    }

    fn encode_did(did: &str) -> String {
        urlencoding::encode(did).to_string()
    }

    pub async fn get_document(&self, did: &str) -> Result<Value, PlcError> {
        let cache_key = format!("plc:doc:{}", did);
        if let Some(ref cache) = self.cache
            && let Some(cached) = cache.get(&cache_key).await
            && let Ok(value) = serde_json::from_str(&cached)
        {
            return Ok(value);
        }
        let url = format!("{}/{}", self.base_url, Self::encode_did(did));
        let response = self.client.get(&url).send().await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(PlcError::NotFound);
        }
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(PlcError::InvalidResponse(format!(
                "HTTP {}: {}",
                status, body
            )));
        }
        let value: Value = response
            .json()
            .await
            .map_err(|e| PlcError::InvalidResponse(e.to_string()))?;
        if let Some(ref cache) = self.cache
            && let Ok(json_str) = serde_json::to_string(&value)
        {
            let _ = cache
                .set(
                    &cache_key,
                    &json_str,
                    Duration::from_secs(PLC_CACHE_TTL_SECS),
                )
                .await;
        }
        Ok(value)
    }

    pub async fn get_document_data(&self, did: &str) -> Result<Value, PlcError> {
        let cache_key = format!("plc:data:{}", did);
        if let Some(ref cache) = self.cache
            && let Some(cached) = cache.get(&cache_key).await
            && let Ok(value) = serde_json::from_str(&cached)
        {
            return Ok(value);
        }
        let url = format!("{}/{}/data", self.base_url, Self::encode_did(did));
        let response = self.client.get(&url).send().await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(PlcError::NotFound);
        }
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(PlcError::InvalidResponse(format!(
                "HTTP {}: {}",
                status, body
            )));
        }
        let value: Value = response
            .json()
            .await
            .map_err(|e| PlcError::InvalidResponse(e.to_string()))?;
        if let Some(ref cache) = self.cache
            && let Ok(json_str) = serde_json::to_string(&value)
        {
            let _ = cache
                .set(
                    &cache_key,
                    &json_str,
                    Duration::from_secs(PLC_CACHE_TTL_SECS),
                )
                .await;
        }
        Ok(value)
    }

    pub async fn get_last_op(&self, did: &str) -> Result<PlcOpOrTombstone, PlcError> {
        let url = format!("{}/{}/log/last", self.base_url, Self::encode_did(did));
        let response = self.client.get(&url).send().await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(PlcError::NotFound);
        }
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(PlcError::InvalidResponse(format!(
                "HTTP {}: {}",
                status, body
            )));
        }
        response
            .json()
            .await
            .map_err(|e| PlcError::InvalidResponse(e.to_string()))
    }

    pub async fn get_audit_log(&self, did: &str) -> Result<Vec<Value>, PlcError> {
        let url = format!("{}/{}/log/audit", self.base_url, Self::encode_did(did));
        let response = self.client.get(&url).send().await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(PlcError::NotFound);
        }
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(PlcError::InvalidResponse(format!(
                "HTTP {}: {}",
                status, body
            )));
        }
        response
            .json()
            .await
            .map_err(|e| PlcError::InvalidResponse(e.to_string()))
    }

    pub async fn send_operation(&self, did: &str, operation: &Value) -> Result<(), PlcError> {
        let url = format!("{}/{}", self.base_url, Self::encode_did(did));
        let response = self.client.post(&url).json(operation).send().await?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(PlcError::InvalidResponse(format!(
                "HTTP {}: {}",
                status, body
            )));
        }
        Ok(())
    }
}

pub fn cid_for_cbor(value: &Value) -> Result<String, PlcError> {
    let cbor_bytes =
        serde_ipld_dagcbor::to_vec(value).map_err(|e| PlcError::Serialization(e.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(&cbor_bytes);
    let hash = hasher.finalize();
    let multihash = multihash::Multihash::wrap(0x12, &hash)
        .map_err(|e| PlcError::Serialization(e.to_string()))?;
    let cid = cid::Cid::new_v1(0x71, multihash);
    Ok(cid.to_string())
}

pub fn sign_operation(operation: &Value, signing_key: &SigningKey) -> Result<Value, PlcError> {
    let mut op = operation.clone();
    if let Some(obj) = op.as_object_mut() {
        obj.remove("sig");
    }
    let cbor_bytes =
        serde_ipld_dagcbor::to_vec(&op).map_err(|e| PlcError::Serialization(e.to_string()))?;
    let signature: Signature = signing_key.sign(&cbor_bytes);
    let sig_bytes = signature.to_bytes();
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig_bytes);
    if let Some(obj) = op.as_object_mut() {
        obj.insert("sig".to_string(), json!(sig_b64));
    }
    Ok(op)
}

pub fn create_update_op(
    last_op: &PlcOpOrTombstone,
    rotation_keys: Option<Vec<String>>,
    verification_methods: Option<HashMap<String, String>>,
    also_known_as: Option<Vec<String>>,
    services: Option<HashMap<String, PlcService>>,
) -> Result<Value, PlcError> {
    let prev_value = match last_op {
        PlcOpOrTombstone::Operation(op) => {
            serde_json::to_value(op).map_err(|e| PlcError::Serialization(e.to_string()))?
        }
        PlcOpOrTombstone::Tombstone(t) => {
            serde_json::to_value(t).map_err(|e| PlcError::Serialization(e.to_string()))?
        }
    };
    let prev_cid = cid_for_cbor(&prev_value)?;
    let (base_rotation_keys, base_verification_methods, base_also_known_as, base_services) =
        match last_op {
            PlcOpOrTombstone::Operation(op) => (
                op.rotation_keys.clone(),
                op.verification_methods.clone(),
                op.also_known_as.clone(),
                op.services.clone(),
            ),
            PlcOpOrTombstone::Tombstone(_) => {
                return Err(PlcError::Tombstoned);
            }
        };
    let new_op = PlcOperation {
        op_type: "plc_operation".to_string(),
        rotation_keys: rotation_keys.unwrap_or(base_rotation_keys),
        verification_methods: verification_methods.unwrap_or(base_verification_methods),
        also_known_as: also_known_as.unwrap_or(base_also_known_as),
        services: services.unwrap_or(base_services),
        prev: Some(prev_cid),
        sig: None,
    };
    serde_json::to_value(new_op).map_err(|e| PlcError::Serialization(e.to_string()))
}

pub fn signing_key_to_did_key(signing_key: &SigningKey) -> String {
    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(true);
    let compressed_bytes = point.as_bytes();
    let mut prefixed = vec![0xe7, 0x01];
    prefixed.extend_from_slice(compressed_bytes);
    let encoded = multibase::encode(multibase::Base::Base58Btc, &prefixed);
    format!("did:key:{}", encoded)
}

pub struct GenesisResult {
    pub did: String,
    pub signed_operation: Value,
}

pub fn create_genesis_operation(
    signing_key: &SigningKey,
    rotation_key: &str,
    handle: &str,
    pds_endpoint: &str,
) -> Result<GenesisResult, PlcError> {
    let signing_did_key = signing_key_to_did_key(signing_key);
    let mut verification_methods = HashMap::new();
    verification_methods.insert("atproto".to_string(), signing_did_key.clone());
    let mut services = HashMap::new();
    services.insert(
        "atproto_pds".to_string(),
        PlcService {
            service_type: "AtprotoPersonalDataServer".to_string(),
            endpoint: pds_endpoint.to_string(),
        },
    );
    let genesis_op = PlcOperation {
        op_type: "plc_operation".to_string(),
        rotation_keys: vec![rotation_key.to_string()],
        verification_methods,
        also_known_as: vec![format!("at://{}", handle)],
        services,
        prev: None,
        sig: None,
    };
    let genesis_value =
        serde_json::to_value(&genesis_op).map_err(|e| PlcError::Serialization(e.to_string()))?;
    let signed_op = sign_operation(&genesis_value, signing_key)?;
    let did = did_for_genesis_op(&signed_op)?;
    Ok(GenesisResult {
        did,
        signed_operation: signed_op,
    })
}

pub fn did_for_genesis_op(signed_op: &Value) -> Result<String, PlcError> {
    let cbor_bytes = serde_ipld_dagcbor::to_vec(signed_op)
        .map_err(|e| PlcError::Serialization(e.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(&cbor_bytes);
    let hash = hasher.finalize();
    let encoded = base32::encode(Alphabet::Rfc4648Lower { padding: false }, &hash);
    let truncated = &encoded[..24];
    Ok(format!("did:plc:{}", truncated))
}

pub fn validate_plc_operation(op: &Value) -> Result<(), PlcError> {
    let obj = op
        .as_object()
        .ok_or_else(|| PlcError::InvalidResponse("Operation must be an object".to_string()))?;
    let op_type = obj
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PlcError::InvalidResponse("Missing type field".to_string()))?;
    if op_type != "plc_operation" && op_type != "plc_tombstone" {
        return Err(PlcError::InvalidResponse(format!(
            "Invalid type: {}",
            op_type
        )));
    }
    if op_type == "plc_operation" {
        if obj.get("rotationKeys").is_none() {
            return Err(PlcError::InvalidResponse(
                "Missing rotationKeys".to_string(),
            ));
        }
        if obj.get("verificationMethods").is_none() {
            return Err(PlcError::InvalidResponse(
                "Missing verificationMethods".to_string(),
            ));
        }
        if obj.get("alsoKnownAs").is_none() {
            return Err(PlcError::InvalidResponse("Missing alsoKnownAs".to_string()));
        }
        if obj.get("services").is_none() {
            return Err(PlcError::InvalidResponse("Missing services".to_string()));
        }
    }
    if obj.get("sig").is_none() {
        return Err(PlcError::InvalidResponse("Missing sig".to_string()));
    }
    Ok(())
}

pub struct PlcValidationContext {
    pub server_rotation_key: String,
    pub expected_signing_key: String,
    pub expected_handle: String,
    pub expected_pds_endpoint: String,
}

pub fn validate_plc_operation_for_submission(
    op: &Value,
    ctx: &PlcValidationContext,
) -> Result<(), PlcError> {
    validate_plc_operation(op)?;
    let obj = op
        .as_object()
        .ok_or_else(|| PlcError::InvalidResponse("Operation must be an object".to_string()))?;
    let op_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
    if op_type != "plc_operation" {
        return Ok(());
    }
    let rotation_keys = obj
        .get("rotationKeys")
        .and_then(|v| v.as_array())
        .ok_or_else(|| PlcError::InvalidResponse("rotationKeys must be an array".to_string()))?;
    let rotation_key_strings: Vec<&str> = rotation_keys.iter().filter_map(|v| v.as_str()).collect();
    if !rotation_key_strings.contains(&ctx.server_rotation_key.as_str()) {
        return Err(PlcError::InvalidResponse(
            "Rotation keys do not include server's rotation key".to_string(),
        ));
    }
    let verification_methods = obj
        .get("verificationMethods")
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            PlcError::InvalidResponse("verificationMethods must be an object".to_string())
        })?;
    if let Some(atproto_key) = verification_methods.get("atproto").and_then(|v| v.as_str())
        && atproto_key != ctx.expected_signing_key
    {
        return Err(PlcError::InvalidResponse(
            "Incorrect signing key".to_string(),
        ));
    }
    let also_known_as = obj
        .get("alsoKnownAs")
        .and_then(|v| v.as_array())
        .ok_or_else(|| PlcError::InvalidResponse("alsoKnownAs must be an array".to_string()))?;
    let expected_handle_uri = format!("at://{}", ctx.expected_handle);
    let has_correct_handle = also_known_as
        .iter()
        .filter_map(|v| v.as_str())
        .any(|s| s == expected_handle_uri);
    if !has_correct_handle && !also_known_as.is_empty() {
        return Err(PlcError::InvalidResponse(
            "Incorrect handle in alsoKnownAs".to_string(),
        ));
    }
    let services = obj
        .get("services")
        .and_then(|v| v.as_object())
        .ok_or_else(|| PlcError::InvalidResponse("services must be an object".to_string()))?;
    if let Some(pds_service) = services.get("atproto_pds").and_then(|v| v.as_object()) {
        let service_type = pds_service
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if service_type != "AtprotoPersonalDataServer" {
            return Err(PlcError::InvalidResponse(
                "Incorrect type on atproto_pds service".to_string(),
            ));
        }
        let endpoint = pds_service
            .get("endpoint")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if endpoint != ctx.expected_pds_endpoint {
            return Err(PlcError::InvalidResponse(
                "Incorrect endpoint on atproto_pds service".to_string(),
            ));
        }
    }
    Ok(())
}

pub fn verify_operation_signature(op: &Value, rotation_keys: &[String]) -> Result<bool, PlcError> {
    let obj = op
        .as_object()
        .ok_or_else(|| PlcError::InvalidResponse("Operation must be an object".to_string()))?;
    let sig_b64 = obj
        .get("sig")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PlcError::InvalidResponse("Missing sig".to_string()))?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| PlcError::InvalidResponse(format!("Invalid signature encoding: {}", e)))?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| PlcError::InvalidResponse(format!("Invalid signature format: {}", e)))?;
    let mut unsigned_op = op.clone();
    if let Some(unsigned_obj) = unsigned_op.as_object_mut() {
        unsigned_obj.remove("sig");
    }
    let cbor_bytes = serde_ipld_dagcbor::to_vec(&unsigned_op)
        .map_err(|e| PlcError::Serialization(e.to_string()))?;
    for key_did in rotation_keys {
        if let Ok(true) = verify_signature_with_did_key(key_did, &cbor_bytes, &signature) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn verify_signature_with_did_key(
    did_key: &str,
    message: &[u8],
    signature: &Signature,
) -> Result<bool, PlcError> {
    use k256::ecdsa::{VerifyingKey, signature::Verifier};
    if !did_key.starts_with("did:key:z") {
        return Err(PlcError::InvalidResponse(
            "Invalid did:key format".to_string(),
        ));
    }
    let multibase_part = &did_key[8..];
    let (_, decoded) = multibase::decode(multibase_part)
        .map_err(|e| PlcError::InvalidResponse(format!("Failed to decode did:key: {}", e)))?;
    if decoded.len() < 2 {
        return Err(PlcError::InvalidResponse(
            "Invalid did:key data".to_string(),
        ));
    }
    let (codec, key_bytes) = if decoded[0] == 0xe7 && decoded[1] == 0x01 {
        (0xe701u16, &decoded[2..])
    } else {
        return Err(PlcError::InvalidResponse(
            "Unsupported key type in did:key".to_string(),
        ));
    };
    if codec != 0xe701 {
        return Err(PlcError::InvalidResponse(
            "Only secp256k1 keys are supported".to_string(),
        ));
    }
    let verifying_key = VerifyingKey::from_sec1_bytes(key_bytes)
        .map_err(|e| PlcError::InvalidResponse(format!("Invalid public key: {}", e)))?;
    Ok(verifying_key.verify(message, signature).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signing_key_to_did_key() {
        let key = SigningKey::random(&mut rand::thread_rng());
        let did_key = signing_key_to_did_key(&key);
        assert!(did_key.starts_with("did:key:z"));
    }

    #[test]
    fn test_cid_for_cbor() {
        let value = json!({
            "test": "data",
            "number": 42
        });
        let cid = cid_for_cbor(&value).unwrap();
        assert!(cid.starts_with("bafyrei"));
    }

    #[test]
    fn test_sign_operation() {
        let key = SigningKey::random(&mut rand::thread_rng());
        let op = json!({
            "type": "plc_operation",
            "rotationKeys": [],
            "verificationMethods": {},
            "alsoKnownAs": [],
            "services": {},
            "prev": null
        });
        let signed = sign_operation(&op, &key).unwrap();
        assert!(signed.get("sig").is_some());
    }
}
