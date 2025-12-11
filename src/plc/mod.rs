use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use k256::ecdsa::{SigningKey, Signature, signature::Signer};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
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

pub struct PlcClient {
    base_url: String,
    client: Client,
}

impl PlcClient {
    pub fn new(base_url: Option<String>) -> Self {
        let base_url = base_url.unwrap_or_else(|| {
            std::env::var("PLC_DIRECTORY_URL")
                .unwrap_or_else(|_| "https://plc.directory".to_string())
        });
        Self {
            base_url,
            client: Client::new(),
        }
    }

    fn encode_did(did: &str) -> String {
        urlencoding::encode(did).to_string()
    }

    pub async fn get_document(&self, did: &str) -> Result<Value, PlcError> {
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

        response.json().await.map_err(|e| PlcError::InvalidResponse(e.to_string()))
    }

    pub async fn get_document_data(&self, did: &str) -> Result<Value, PlcError> {
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

        response.json().await.map_err(|e| PlcError::InvalidResponse(e.to_string()))
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

        response.json().await.map_err(|e| PlcError::InvalidResponse(e.to_string()))
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

        response.json().await.map_err(|e| PlcError::InvalidResponse(e.to_string()))
    }

    pub async fn send_operation(&self, did: &str, operation: &Value) -> Result<(), PlcError> {
        let url = format!("{}/{}", self.base_url, Self::encode_did(did));
        let response = self.client
            .post(&url)
            .json(operation)
            .send()
            .await?;

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
    let cbor_bytes = serde_ipld_dagcbor::to_vec(value)
        .map_err(|e| PlcError::Serialization(e.to_string()))?;

    let mut hasher = Sha256::new();
    hasher.update(&cbor_bytes);
    let hash = hasher.finalize();

    let multihash = multihash::Multihash::wrap(0x12, &hash)
        .map_err(|e| PlcError::Serialization(e.to_string()))?;
    let cid = cid::Cid::new_v1(0x71, multihash);

    Ok(cid.to_string())
}

pub fn sign_operation(
    operation: &Value,
    signing_key: &SigningKey,
) -> Result<Value, PlcError> {
    let mut op = operation.clone();
    if let Some(obj) = op.as_object_mut() {
        obj.remove("sig");
    }

    let cbor_bytes = serde_ipld_dagcbor::to_vec(&op)
        .map_err(|e| PlcError::Serialization(e.to_string()))?;

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
        PlcOpOrTombstone::Operation(op) => serde_json::to_value(op)
            .map_err(|e| PlcError::Serialization(e.to_string()))?,
        PlcOpOrTombstone::Tombstone(t) => serde_json::to_value(t)
            .map_err(|e| PlcError::Serialization(e.to_string()))?,
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

pub fn validate_plc_operation(op: &Value) -> Result<(), PlcError> {
    let obj = op.as_object()
        .ok_or_else(|| PlcError::InvalidResponse("Operation must be an object".to_string()))?;

    let op_type = obj.get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PlcError::InvalidResponse("Missing type field".to_string()))?;

    if op_type != "plc_operation" && op_type != "plc_tombstone" {
        return Err(PlcError::InvalidResponse(format!("Invalid type: {}", op_type)));
    }

    if op_type == "plc_operation" {
        if obj.get("rotationKeys").is_none() {
            return Err(PlcError::InvalidResponse("Missing rotationKeys".to_string()));
        }
        if obj.get("verificationMethods").is_none() {
            return Err(PlcError::InvalidResponse("Missing verificationMethods".to_string()));
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
