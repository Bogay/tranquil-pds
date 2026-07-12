use crate::cache::Cache;
use crate::types::{Did, Handle};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlcOpType {
    #[serde(rename = "plc_operation")]
    Operation,
    #[serde(rename = "plc_tombstone")]
    Tombstone,
}

#[derive(Debug, Error)]
#[error("service type must not be empty")]
pub struct EmptyServiceType;

mod custom_service_type {
    use super::EmptyServiceType;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct CustomServiceType(String);

    impl CustomServiceType {
        pub(super) fn new(name: String) -> Result<Self, EmptyServiceType> {
            match name.as_str() {
                "" => Err(EmptyServiceType),
                _ => Ok(Self(name)),
            }
        }

        pub fn as_str(&self) -> &str {
            &self.0
        }
    }
}

pub use custom_service_type::CustomServiceType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceType {
    Pds,
    Labeler,
    Other(CustomServiceType),
}

impl ServiceType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Pds => "AtprotoPersonalDataServer",
            Self::Labeler => "AtprotoLabeler",
            Self::Other(name) => name.as_str(),
        }
    }
}

impl TryFrom<String> for ServiceType {
    type Error = EmptyServiceType;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        match name.as_str() {
            "AtprotoPersonalDataServer" => Ok(Self::Pds),
            "AtprotoLabeler" => Ok(Self::Labeler),
            _ => CustomServiceType::new(name).map(Self::Other),
        }
    }
}

impl Serialize for ServiceType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ServiceType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let name = String::deserialize(deserializer)?;
        Self::try_from(name).map_err(serde::de::Error::custom)
    }
}

pub const SECP256K1_MULTICODEC_PREFIX: [u8; 2] = [0xe7, 0x01];
pub const P256_MULTICODEC_PREFIX: [u8; 2] = [0x80, 0x24];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlcOperation {
    #[serde(rename = "type")]
    pub op_type: PlcOpType,
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
    pub service_type: ServiceType,
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlcTombstone {
    #[serde(rename = "type")]
    pub op_type: PlcOpType,
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
            PlcOpOrTombstone::Operation(op) => op.op_type == PlcOpType::Tombstone,
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
        let cfg = tranquil_config::try_get();
        let base_url = base_url
            .or_else(|| std::env::var("PLC_DIRECTORY_URL").ok())
            .unwrap_or_else(|| {
                cfg.map(|c| c.plc.directory_url.clone())
                    .unwrap_or_else(|| "https://plc.directory".to_string())
            });
        let timeout_secs = cfg.map_or(10, |c| c.plc.timeout_secs);
        let connect_timeout_secs = cfg.map_or(5, |c| c.plc.connect_timeout_secs);
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
        let cache_key = crate::cache_keys::plc_doc_key(did);
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
        let cache_key = crate::cache_keys::plc_data_key(did);
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
        op_type: PlcOpType::Operation,
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
    let mut prefixed = Vec::from(SECP256K1_MULTICODEC_PREFIX);
    prefixed.extend_from_slice(compressed_bytes);
    let encoded = multibase::encode(multibase::Base::Base58Btc, &prefixed);
    format!("did:key:{}", encoded)
}

pub fn rotation_keys_for(
    configured_rotation_key: Option<&str>,
    signing_key: &SigningKey,
) -> Vec<String> {
    let signing_did_key = signing_key_to_did_key(signing_key);
    match configured_rotation_key {
        Some(key) if key != signing_did_key.as_str() => vec![key.to_string(), signing_did_key],
        _ => vec![signing_did_key],
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredRotationKey {
    Signing,
    Operator,
}

impl RequiredRotationKey {
    pub fn message(self) -> &'static str {
        match self {
            Self::Signing => {
                "Rotation keys must include the PDS-managed signing key so the server can sign future operations"
            }
            Self::Operator => {
                "Rotation keys must include the operator-held PLC recovery key configured for this server"
            }
        }
    }
}

pub fn missing_required_rotation_key(
    rotation_keys: &[&str],
    signing_did_key: &str,
    configured_rotation_key: Option<&str>,
) -> Option<RequiredRotationKey> {
    if !rotation_keys.contains(&signing_did_key) {
        return Some(RequiredRotationKey::Signing);
    }
    match configured_rotation_key {
        Some(operator_key) if !rotation_keys.contains(&operator_key) => {
            Some(RequiredRotationKey::Operator)
        }
        _ => None,
    }
}

fn validate_compressed_did_key<V, E>(
    key_bytes: &[u8],
    label: &str,
    did_key: &str,
    parse: impl Fn(&[u8]) -> Result<V, E>,
) -> Result<(), String>
where
    E: std::fmt::Display,
{
    if key_bytes.len() != 33 {
        return Err(format!(
            "`{did_key}` must be a compressed {label} public key"
        ));
    }
    parse(key_bytes)
        .map(|_| ())
        .map_err(|e| format!("`{did_key}` is not a valid {label} public key: {e}"))
}

pub fn validate_rotation_did_key(did_key: &str) -> Result<(), String> {
    let multibase_part = did_key
        .strip_prefix("did:key:")
        .ok_or_else(|| format!("must be a did:key, got `{did_key}`"))?;
    let (base, decoded) = multibase::decode(multibase_part)
        .map_err(|e| format!("`{did_key}` is not valid multibase: {e}"))?;
    if base != multibase::Base::Base58Btc {
        return Err(format!("`{did_key}` must use base58btc multibase encoding"));
    }
    let (prefix, key_bytes) = decoded.split_at(decoded.len().min(2));
    if prefix == SECP256K1_MULTICODEC_PREFIX {
        validate_compressed_did_key(
            key_bytes,
            "secp256k1",
            did_key,
            k256::ecdsa::VerifyingKey::from_sec1_bytes,
        )
    } else if prefix == P256_MULTICODEC_PREFIX {
        validate_compressed_did_key(
            key_bytes,
            "p256",
            did_key,
            p256::ecdsa::VerifyingKey::from_sec1_bytes,
        )
    } else {
        Err(format!("`{did_key}` is not a secp256k1 or p256 did:key"))
    }
}

pub struct GenesisResult {
    pub did: String,
    pub signed_operation: Value,
}

pub fn create_genesis_operation(
    signing_key: &SigningKey,
    configured_rotation_key: Option<&str>,
    handle: &Handle,
    pds_endpoint: &str,
) -> Result<GenesisResult, PlcError> {
    let signing_did_key = signing_key_to_did_key(signing_key);
    let rotation_keys = rotation_keys_for(configured_rotation_key, signing_key);
    let mut verification_methods = HashMap::new();
    verification_methods.insert("atproto".to_string(), signing_did_key);
    let mut services = HashMap::new();
    services.insert(
        "atproto_pds".to_string(),
        PlcService {
            service_type: ServiceType::Pds,
            endpoint: pds_endpoint.to_string(),
        },
    );
    let genesis_op = PlcOperation {
        op_type: PlcOpType::Operation,
        rotation_keys,
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

pub fn validate_plc_operation(op: &Value) -> Result<PlcOpType, PlcError> {
    let obj = op
        .as_object()
        .ok_or_else(|| PlcError::InvalidResponse("Operation must be an object".to_string()))?;
    let op_type_str = obj
        .get("type")
        .ok_or_else(|| PlcError::InvalidResponse("Missing type field".to_string()))?;
    let op_type: PlcOpType = serde_json::from_value(op_type_str.clone()).map_err(|_| {
        PlcError::InvalidResponse(format!(
            "Invalid type: {}",
            op_type_str.as_str().unwrap_or("<non-string>")
        ))
    })?;
    match op_type {
        PlcOpType::Operation => {
            let required_fields = [
                "rotationKeys",
                "verificationMethods",
                "alsoKnownAs",
                "services",
            ];
            required_fields.iter().try_for_each(|field| {
                obj.get(*field)
                    .map(|_| ())
                    .ok_or_else(|| PlcError::InvalidResponse(format!("Missing {}", field)))
            })?;
        }
        PlcOpType::Tombstone => {}
    }
    if obj.get("sig").is_none() {
        return Err(PlcError::InvalidResponse("Missing sig".to_string()));
    }
    Ok(op_type)
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
    let op_type = validate_plc_operation(op)?;
    if op_type != PlcOpType::Operation {
        return Ok(());
    }
    let obj = op
        .as_object()
        .ok_or_else(|| PlcError::InvalidResponse("Operation must be an object".to_string()))?;
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
        if service_type != ServiceType::Pds.as_str() {
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
    let verified = rotation_keys.iter().any(|key_did| {
        verify_signature_with_did_key(key_did, &cbor_bytes, &signature).unwrap_or(false)
    });
    Ok(verified)
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
    let key_bytes = if decoded.starts_with(&SECP256K1_MULTICODEC_PREFIX) {
        &decoded[SECP256K1_MULTICODEC_PREFIX.len()..]
    } else {
        return Err(PlcError::InvalidResponse(
            "Unsupported key type in did:key (expected secp256k1)".to_string(),
        ));
    };
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
    fn test_rotation_keys_default_is_signing_key() {
        let key = SigningKey::random(&mut rand::thread_rng());
        let signing_did_key = signing_key_to_did_key(&key);
        assert_eq!(rotation_keys_for(None, &key), vec![signing_did_key]);
    }

    #[test]
    fn test_rotation_keys_prepends_operator_key() {
        let key = SigningKey::random(&mut rand::thread_rng());
        let signing_did_key = signing_key_to_did_key(&key);
        let operator_key = "did:key:zQ3shScallopRecoveryKey";
        assert_eq!(
            rotation_keys_for(Some(operator_key), &key),
            vec![operator_key.to_string(), signing_did_key.clone()]
        );
    }

    #[test]
    fn test_rotation_keys_dedupes_when_operator_equals_signing() {
        let key = SigningKey::random(&mut rand::thread_rng());
        let signing_did_key = signing_key_to_did_key(&key);
        assert_eq!(
            rotation_keys_for(Some(&signing_did_key), &key),
            vec![signing_did_key]
        );
    }

    #[test]
    fn test_genesis_includes_signing_key_with_operator_rotation_key() {
        let key = SigningKey::random(&mut rand::thread_rng());
        let signing_did_key = signing_key_to_did_key(&key);
        let operator_key = "did:key:zQ3shWhelkOperatorKey";
        let result = create_genesis_operation(
            &key,
            Some(operator_key),
            &crate::types::Handle::from("whelk.nel.pet".to_string()),
            "https://nel.pet",
        )
        .unwrap();
        let rotation_keys = result.signed_operation["rotationKeys"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>();
        assert_eq!(rotation_keys, vec![operator_key, signing_did_key.as_str()]);
        assert!(
            verify_operation_signature(
                &result.signed_operation,
                &[operator_key.to_string(), signing_did_key]
            )
            .unwrap()
        );
    }

    fn p256_did_key(key: &p256::ecdsa::SigningKey) -> String {
        let point = key.verifying_key().to_encoded_point(true);
        let mut prefixed = Vec::from(P256_MULTICODEC_PREFIX);
        prefixed.extend_from_slice(point.as_bytes());
        format!(
            "did:key:{}",
            multibase::encode(multibase::Base::Base58Btc, &prefixed)
        )
    }

    #[test]
    fn test_validate_rotation_did_key_accepts_secp256k1() {
        let key = SigningKey::random(&mut rand::thread_rng());
        assert!(validate_rotation_did_key(&signing_key_to_did_key(&key)).is_ok());
    }

    #[test]
    fn test_validate_rotation_did_key_accepts_p256() {
        let key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        assert!(validate_rotation_did_key(&p256_did_key(&key)).is_ok());
    }

    #[test]
    fn test_validate_rotation_did_key_rejects_non_did_key() {
        assert!(validate_rotation_did_key("did:plc:squid").is_err());
        assert!(validate_rotation_did_key("zSomeMultibaseButNoPrefix").is_err());
    }

    #[test]
    fn test_validate_rotation_did_key_rejects_unknown_multicodec() {
        let mut ed25519 = vec![0xed, 0x01];
        ed25519.extend_from_slice(&[0u8; 32]);
        let did_key = format!(
            "did:key:{}",
            multibase::encode(multibase::Base::Base58Btc, &ed25519)
        );
        assert!(validate_rotation_did_key(&did_key).is_err());
    }

    #[test]
    fn test_validate_rotation_did_key_rejects_non_base58btc() {
        let key = SigningKey::random(&mut rand::thread_rng());
        let point = key.verifying_key().to_encoded_point(true);
        let mut prefixed = Vec::from(SECP256K1_MULTICODEC_PREFIX);
        prefixed.extend_from_slice(point.as_bytes());
        let hex_did_key = format!(
            "did:key:{}",
            multibase::encode(multibase::Base::Base16Lower, &prefixed)
        );
        assert!(validate_rotation_did_key(&hex_did_key).is_err());
    }

    #[test]
    fn test_missing_required_rotation_key() {
        let signing = "did:key:zSigning";
        let operator = "did:key:zOperator";
        assert_eq!(
            missing_required_rotation_key(&[operator], signing, None),
            Some(RequiredRotationKey::Signing)
        );
        assert_eq!(
            missing_required_rotation_key(&[signing], signing, Some(operator)),
            Some(RequiredRotationKey::Operator)
        );
        assert_eq!(
            missing_required_rotation_key(&[operator, signing], signing, Some(operator)),
            None
        );
        assert_eq!(
            missing_required_rotation_key(&[signing], signing, None),
            None
        );
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

    #[test]
    fn test_service_type_known_round_trip() {
        let cases = [
            (ServiceType::Pds, "\"AtprotoPersonalDataServer\""),
            (ServiceType::Labeler, "\"AtprotoLabeler\""),
        ];
        cases.iter().for_each(|(variant, encoded)| {
            assert_eq!(serde_json::to_string(variant).unwrap(), *encoded);
            assert_eq!(
                serde_json::from_str::<ServiceType>(encoded).unwrap(),
                *variant
            );
        });
    }

    #[test]
    fn test_service_type_custom_round_trips() {
        let parsed: ServiceType = serde_json::from_str("\"ConchFeedGenerator\"").unwrap();
        assert_eq!(
            parsed,
            ServiceType::try_from("ConchFeedGenerator".to_string()).unwrap()
        );
        assert_eq!(
            serde_json::to_string(&parsed).unwrap(),
            "\"ConchFeedGenerator\""
        );
    }

    #[test]
    fn test_service_type_custom_normalizes_known_names() {
        assert_eq!(
            ServiceType::try_from("AtprotoPersonalDataServer".to_string()).unwrap(),
            ServiceType::Pds
        );
        assert_eq!(
            ServiceType::try_from("AtprotoLabeler".to_string()).unwrap(),
            ServiceType::Labeler
        );
    }

    #[test]
    fn test_appview_is_not_a_named_type() {
        assert_eq!(
            ServiceType::try_from("AtprotoAppView".to_string()).unwrap(),
            ServiceType::Other(CustomServiceType::new("AtprotoAppView".to_string()).unwrap())
        );
    }

    #[test]
    fn test_service_type_rejects_empty() {
        assert!(ServiceType::try_from(String::new()).is_err());
        assert!(serde_json::from_str::<ServiceType>("\"\"").is_err());
    }

    #[test]
    fn test_plc_operation_with_custom_service_round_trips() {
        let op_json = json!({
            "type": "plc_operation",
            "rotationKeys": ["did:key:zScallop"],
            "verificationMethods": { "atproto": "did:key:zUni" },
            "alsoKnownAs": ["at://whelk.nel.pet"],
            "services": {
                "atproto_pds": { "type": "AtprotoPersonalDataServer", "endpoint": "https://nel.pet" },
                "custom_feedgen": { "type": "ConchFeedGenerator", "endpoint": "https://feed.nel.pet" }
            },
            "prev": null
        });
        let op: PlcOperation = serde_json::from_value(op_json.clone()).unwrap();
        assert_eq!(
            op.services["custom_feedgen"].service_type,
            ServiceType::try_from("ConchFeedGenerator".to_string()).unwrap()
        );
        assert_eq!(op.services["atproto_pds"].service_type, ServiceType::Pds);
        assert_eq!(serde_json::to_value(&op).unwrap(), op_json);
    }
}
