use jacquard_common::types::{integer::LimitedU32, string::Tid};
use jacquard_repo::{mst::Mst, storage::BlockStore};
use k256::ecdsa::SigningKey;
use std::sync::Arc;
use tranquil_pds::api::error::ApiError;
use tranquil_pds::repo_ops::create_signed_commit;
use tranquil_pds::state::AppState;
use tranquil_pds::types::Did;

pub struct PlcDidResult {
    pub did: Did,
    pub signing_key_bytes: Vec<u8>,
    pub signing_key: SigningKey,
}

pub async fn create_plc_did(state: &AppState, handle: &str) -> Result<PlcDidResult, ApiError> {
    use k256::SecretKey;
    use rand::rngs::OsRng;

    let secret_key = SecretKey::random(&mut OsRng);
    let secret_key_bytes = secret_key.to_bytes().to_vec();
    let signing_key = SigningKey::from_slice(&secret_key_bytes).map_err(|e| {
        tracing::error!("Error creating signing key: {:?}", e);
        ApiError::InternalError(None)
    })?;

    let did_str = submit_plc_genesis(state, &signing_key, handle).await?;
    let did: Did = did_str
        .parse()
        .map_err(|_| ApiError::InternalError(Some("PLC genesis returned invalid DID".into())))?;

    Ok(PlcDidResult {
        did,
        signing_key_bytes: secret_key_bytes,
        signing_key,
    })
}

pub async fn submit_plc_genesis(
    state: &AppState,
    signing_key: &SigningKey,
    handle: &str,
) -> Result<String, ApiError> {
    let hostname = &tranquil_config::get().server.hostname;
    let pds_endpoint = format!("https://{}", hostname);

    let rotation_key = tranquil_config::get()
        .secrets
        .plc_rotation_key
        .clone()
        .unwrap_or_else(|| tranquil_pds::plc::signing_key_to_did_key(signing_key));

    let genesis_result = tranquil_pds::plc::create_genesis_operation(
        signing_key,
        &rotation_key,
        handle,
        &pds_endpoint,
    )
    .map_err(|e| {
        tracing::error!("Error creating PLC genesis operation: {:?}", e);
        ApiError::InternalError(Some("Failed to create PLC operation".into()))
    })?;

    state
        .plc_client()
        .send_operation(&genesis_result.did, &genesis_result.signed_operation)
        .await
        .map_err(|e| {
            tracing::error!("Failed to submit PLC genesis operation: {:?}", e);
            ApiError::UpstreamErrorMsg(format!("Failed to register DID with PLC directory: {}", e))
        })?;

    tracing::info!(did = %genesis_result.did, "Registered DID with PLC directory");
    Ok(genesis_result.did)
}

pub struct GenesisRepo {
    pub encrypted_key_bytes: Vec<u8>,
    pub commit_cid: cid::Cid,
    pub mst_root_cid: cid::Cid,
    pub repo_rev: String,
    pub genesis_block_cids: Vec<Vec<u8>>,
}

pub async fn init_genesis_repo(
    state: &AppState,
    did: &Did,
    signing_key: &SigningKey,
    signing_key_bytes: &[u8],
) -> Result<GenesisRepo, ApiError> {
    let encrypted_key_bytes =
        tranquil_pds::config::encrypt_key(signing_key_bytes).map_err(|e| {
            tracing::error!("Error encrypting signing key: {:?}", e);
            ApiError::InternalError(None)
        })?;

    let mst = Mst::new(Arc::new(state.block_store.clone()));
    let mst_root = mst.persist().await.map_err(|e| {
        tracing::error!("Error persisting MST: {:?}", e);
        ApiError::InternalError(None)
    })?;

    let rev = Tid::now(LimitedU32::MIN);
    let (commit_bytes, _sig) = create_signed_commit(did, mst_root, rev.as_ref(), None, signing_key)
        .map_err(|e| {
            tracing::error!("Error creating genesis commit: {:?}", e);
            ApiError::InternalError(None)
        })?;

    let commit_cid: cid::Cid = state.block_store.put(&commit_bytes).await.map_err(|e| {
        tracing::error!("Error saving genesis commit: {:?}", e);
        ApiError::InternalError(None)
    })?;

    Ok(GenesisRepo {
        encrypted_key_bytes,
        commit_cid,
        mst_root_cid: mst_root,
        repo_rev: rev.as_ref().to_string(),
        genesis_block_cids: vec![mst_root.to_bytes(), commit_cid.to_bytes()],
    })
}
