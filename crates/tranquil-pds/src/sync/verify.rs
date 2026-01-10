use bytes::Bytes;
use cid::Cid;
use jacquard::common::IntoStatic;
use jacquard::common::types::crypto::PublicKey;
use jacquard::common::types::did_doc::DidDocument;
use jacquard_repo::commit::Commit;
use reqwest::Client;
use std::collections::HashMap;
use thiserror::Error;
use tracing::{debug, warn};

#[derive(Error, Debug)]
pub enum VerifyError {
    #[error("Invalid commit: {0}")]
    InvalidCommit(String),
    #[error("DID mismatch: commit has {commit_did}, expected {expected_did}")]
    DidMismatch {
        commit_did: String,
        expected_did: String,
    },
    #[error("Failed to resolve DID: {0}")]
    DidResolutionFailed(String),
    #[error("No signing key found in DID document")]
    NoSigningKey,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("MST validation failed: {0}")]
    MstValidationFailed(String),
    #[error("Block not found: {0}")]
    BlockNotFound(String),
    #[error("Invalid CBOR: {0}")]
    InvalidCbor(String),
}

pub struct CarVerifier {
    http_client: Client,
}

impl Default for CarVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl CarVerifier {
    pub fn new() -> Self {
        Self {
            http_client: Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .connect_timeout(std::time::Duration::from_secs(5))
                .pool_max_idle_per_host(10)
                .pool_idle_timeout(std::time::Duration::from_secs(90))
                .build()
                .unwrap_or_default(),
        }
    }

    pub async fn verify_car(
        &self,
        expected_did: &str,
        root_cid: &Cid,
        blocks: &HashMap<Cid, Bytes>,
    ) -> Result<VerifiedCar, VerifyError> {
        let root_block = blocks
            .get(root_cid)
            .ok_or_else(|| VerifyError::BlockNotFound(root_cid.to_string()))?;
        let commit =
            Commit::from_cbor(root_block).map_err(|e| VerifyError::InvalidCommit(e.to_string()))?;
        let commit_did = commit.did().as_str();
        if commit_did != expected_did {
            return Err(VerifyError::DidMismatch {
                commit_did: commit_did.to_string(),
                expected_did: expected_did.to_string(),
            });
        }
        let pubkey = self.resolve_did_signing_key(commit_did).await?;
        commit
            .verify(&pubkey)
            .map_err(|_| VerifyError::InvalidSignature)?;
        debug!("Commit signature verified for DID {}", commit_did);
        let data_cid = commit.data();
        self.verify_mst_structure(data_cid, blocks)?;
        debug!("MST structure verified for DID {}", commit_did);
        Ok(VerifiedCar {
            did: commit_did.to_string(),
            rev: commit.rev().to_string(),
            data_cid: *data_cid,
            prev: commit.prev().cloned(),
        })
    }

    pub fn verify_car_structure_only(
        &self,
        expected_did: &str,
        root_cid: &Cid,
        blocks: &HashMap<Cid, Bytes>,
    ) -> Result<VerifiedCar, VerifyError> {
        let root_block = blocks
            .get(root_cid)
            .ok_or_else(|| VerifyError::BlockNotFound(root_cid.to_string()))?;
        let commit =
            Commit::from_cbor(root_block).map_err(|e| VerifyError::InvalidCommit(e.to_string()))?;
        let commit_did = commit.did().as_str();
        if commit_did != expected_did {
            return Err(VerifyError::DidMismatch {
                commit_did: commit_did.to_string(),
                expected_did: expected_did.to_string(),
            });
        }
        let data_cid = commit.data();
        self.verify_mst_structure(data_cid, blocks)?;
        debug!(
            "MST structure verified for DID {} (signature verification skipped for migration)",
            commit_did
        );
        Ok(VerifiedCar {
            did: commit_did.to_string(),
            rev: commit.rev().to_string(),
            data_cid: *data_cid,
            prev: commit.prev().cloned(),
        })
    }

    async fn resolve_did_signing_key(&self, did: &str) -> Result<PublicKey<'static>, VerifyError> {
        let did_doc = self.resolve_did_document(did).await?;
        did_doc
            .atproto_public_key()
            .map_err(|e| VerifyError::DidResolutionFailed(e.to_string()))?
            .ok_or(VerifyError::NoSigningKey)
    }

    async fn resolve_did_document(&self, did: &str) -> Result<DidDocument<'static>, VerifyError> {
        if did.starts_with("did:plc:") {
            self.resolve_plc_did(did).await
        } else if did.starts_with("did:web:") {
            self.resolve_web_did(did).await
        } else {
            Err(VerifyError::DidResolutionFailed(format!(
                "Unsupported DID method: {}",
                did
            )))
        }
    }

    async fn resolve_plc_did(&self, did: &str) -> Result<DidDocument<'static>, VerifyError> {
        let plc_url = std::env::var("PLC_DIRECTORY_URL")
            .unwrap_or_else(|_| "https://plc.directory".to_string());
        let url = format!("{}/{}", plc_url, urlencoding::encode(did));
        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| VerifyError::DidResolutionFailed(e.to_string()))?;
        if !response.status().is_success() {
            return Err(VerifyError::DidResolutionFailed(format!(
                "PLC directory returned {}",
                response.status()
            )));
        }
        let body = response
            .text()
            .await
            .map_err(|e| VerifyError::DidResolutionFailed(e.to_string()))?;
        let doc: DidDocument<'_> = serde_json::from_str(&body)
            .map_err(|e| VerifyError::DidResolutionFailed(e.to_string()))?;
        Ok(doc.into_static())
    }

    async fn resolve_web_did(&self, did: &str) -> Result<DidDocument<'static>, VerifyError> {
        let domain = did.strip_prefix("did:web:").ok_or_else(|| {
            VerifyError::DidResolutionFailed("Invalid did:web format".to_string())
        })?;
        let domain_decoded = urlencoding::decode(domain)
            .map_err(|e| VerifyError::DidResolutionFailed(e.to_string()))?;
        let url = format!("https://{}/.well-known/did.json", domain_decoded);
        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| VerifyError::DidResolutionFailed(e.to_string()))?;
        if !response.status().is_success() {
            return Err(VerifyError::DidResolutionFailed(format!(
                "did:web resolution returned {}",
                response.status()
            )));
        }
        let body = response
            .text()
            .await
            .map_err(|e| VerifyError::DidResolutionFailed(e.to_string()))?;
        let doc: DidDocument<'_> = serde_json::from_str(&body)
            .map_err(|e| VerifyError::DidResolutionFailed(e.to_string()))?;
        Ok(doc.into_static())
    }

    fn verify_mst_structure(
        &self,
        data_cid: &Cid,
        blocks: &HashMap<Cid, Bytes>,
    ) -> Result<(), VerifyError> {
        use ipld_core::ipld::Ipld;

        let mut stack = vec![*data_cid];
        let mut visited = std::collections::HashSet::new();
        let mut node_count = 0;
        const MAX_NODES: usize = 100_000;
        while let Some(cid) = stack.pop() {
            if visited.contains(&cid) {
                continue;
            }
            visited.insert(cid);
            node_count += 1;
            if node_count > MAX_NODES {
                return Err(VerifyError::MstValidationFailed(
                    "MST exceeds maximum node count".to_string(),
                ));
            }
            let block = blocks
                .get(&cid)
                .ok_or_else(|| VerifyError::BlockNotFound(cid.to_string()))?;
            let node: Ipld = serde_ipld_dagcbor::from_slice(block)
                .map_err(|e| VerifyError::InvalidCbor(e.to_string()))?;
            if let Ipld::Map(ref obj) = node {
                if let Some(Ipld::Link(left_cid)) = obj.get("l") {
                    if !blocks.contains_key(left_cid) {
                        return Err(VerifyError::BlockNotFound(format!(
                            "MST left pointer {} not in CAR",
                            left_cid
                        )));
                    }
                    stack.push(*left_cid);
                }
                if let Some(Ipld::List(entries)) = obj.get("e") {
                    let mut last_full_key: Vec<u8> = Vec::new();
                    for entry in entries {
                        if let Ipld::Map(entry_obj) = entry {
                            let prefix_len = entry_obj
                                .get("p")
                                .and_then(|p| match p {
                                    Ipld::Integer(i) => Some(*i as usize),
                                    _ => None,
                                })
                                .unwrap_or(0);
                            let key_suffix = entry_obj.get("k").and_then(|k| match k {
                                Ipld::Bytes(b) => Some(b.clone()),
                                Ipld::String(s) => Some(s.as_bytes().to_vec()),
                                _ => None,
                            });
                            if let Some(suffix) = key_suffix {
                                let mut full_key = Vec::new();
                                if prefix_len > 0 && prefix_len <= last_full_key.len() {
                                    full_key.extend_from_slice(&last_full_key[..prefix_len]);
                                }
                                full_key.extend_from_slice(&suffix);
                                if !last_full_key.is_empty() && full_key <= last_full_key {
                                    return Err(VerifyError::MstValidationFailed(
                                        "MST keys not in sorted order".to_string(),
                                    ));
                                }
                                last_full_key = full_key;
                            }
                            if let Some(Ipld::Link(tree_cid)) = entry_obj.get("t") {
                                if !blocks.contains_key(tree_cid) {
                                    return Err(VerifyError::BlockNotFound(format!(
                                        "MST subtree {} not in CAR",
                                        tree_cid
                                    )));
                                }
                                stack.push(*tree_cid);
                            }
                            if let Some(Ipld::Link(value_cid)) = entry_obj.get("v")
                                && !blocks.contains_key(value_cid)
                            {
                                warn!(
                                    "Record block {} referenced in MST not in CAR (may be expected for partial export)",
                                    value_cid
                                );
                            }
                        }
                    }
                }
            }
        }
        debug!(
            "MST validation complete: {} nodes, {} blocks visited",
            node_count,
            visited.len()
        );
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedCar {
    pub did: String,
    pub rev: String,
    pub data_cid: Cid,
    pub prev: Option<Cid>,
}

#[cfg(test)]
#[path = "verify_tests.rs"]
mod tests;
