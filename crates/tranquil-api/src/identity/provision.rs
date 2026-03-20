use jacquard_common::types::{integer::LimitedU32, string::Tid};
use jacquard_repo::{mst::Mst, storage::BlockStore};
use k256::ecdsa::SigningKey;
use std::sync::Arc;
use tranquil_db_traits::CommsChannel;
use tranquil_pds::api::error::ApiError;
use tranquil_pds::repo_ops::create_signed_commit;
use tranquil_pds::state::AppState;
use tranquil_pds::types::{Did, Handle};

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

#[derive(Clone)]
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

pub struct SigningKeyResult {
    pub secret_key_bytes: Vec<u8>,
    pub signing_key: SigningKey,
    pub reserved_key_id: Option<uuid::Uuid>,
}

pub async fn resolve_signing_key(
    state: &AppState,
    signing_key_did: Option<&str>,
) -> Result<SigningKeyResult, ApiError> {
    match signing_key_did {
        Some(key_did) => {
            let key = state
                .repos.infra
                .get_reserved_signing_key(key_did)
                .await
                .map_err(|e| {
                    tracing::error!("Error looking up reserved signing key: {:?}", e);
                    ApiError::InternalError(None)
                })?
                .ok_or(ApiError::InvalidSigningKey)?;
            let signing_key = SigningKey::from_slice(&key.private_key_bytes).map_err(|e| {
                tracing::error!("Error creating signing key: {:?}", e);
                ApiError::InternalError(None)
            })?;
            Ok(SigningKeyResult {
                secret_key_bytes: key.private_key_bytes,
                signing_key,
                reserved_key_id: Some(key.id),
            })
        }
        None => {
            use k256::SecretKey;
            use rand::rngs::OsRng;
            let secret_key = SecretKey::random(&mut OsRng);
            let secret_key_bytes = secret_key.to_bytes().to_vec();
            let signing_key = SigningKey::from_slice(&secret_key_bytes).map_err(|e| {
                tracing::error!("Error creating signing key: {:?}", e);
                ApiError::InternalError(None)
            })?;
            Ok(SigningKeyResult {
                secret_key_bytes,
                signing_key,
                reserved_key_id: None,
            })
        }
    }
}

pub async fn sequence_new_account(
    state: &AppState,
    did: &Did,
    handle: &Handle,
    repo: &GenesisRepo,
    display_name: &str,
) {
    if let Err(e) = tranquil_pds::repo_ops::sequence_identity_event(state, did, Some(handle)).await
    {
        tracing::warn!("Failed to sequence identity event for {}: {}", did, e);
    }
    if let Err(e) = tranquil_pds::repo_ops::sequence_account_event(
        state,
        did,
        tranquil_db_traits::AccountStatus::Active,
    )
    .await
    {
        tracing::warn!("Failed to sequence account event for {}: {}", did, e);
    }
    if let Err(e) = tranquil_pds::repo_ops::sequence_genesis_commit(
        state,
        did,
        &repo.commit_cid,
        &repo.mst_root_cid,
        &repo.repo_rev,
    )
    .await
    {
        tracing::warn!("Failed to sequence commit event for {}: {}", did, e);
    }
    if let Err(e) = tranquil_pds::repo_ops::sequence_sync_event(
        state,
        did,
        &repo.commit_cid.to_string(),
        Some(&repo.repo_rev),
    )
    .await
    {
        tracing::warn!("Failed to sequence sync event for {}: {}", did, e);
    }
    let profile_record = serde_json::json!({
        "$type": "app.bsky.actor.profile",
        "displayName": display_name
    });
    if let Err(e) = tranquil_pds::repo_ops::create_record_internal(
        state,
        did,
        &tranquil_pds::types::PROFILE_COLLECTION,
        &tranquil_pds::types::PROFILE_RKEY,
        &profile_record,
    )
    .await
    {
        tracing::warn!("Failed to create default profile for {}: {}", did, e);
    }
}

pub struct CommsUsernames {
    pub discord: Option<String>,
    pub telegram: Option<String>,
    pub signal: Option<String>,
}

pub fn normalize_comms_usernames(
    discord: Option<&str>,
    telegram: Option<&str>,
    signal: Option<&str>,
) -> CommsUsernames {
    CommsUsernames {
        discord: discord
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty()),
        telegram: telegram
            .map(|s| s.trim().trim_start_matches('@'))
            .filter(|s| !s.is_empty())
            .map(String::from),
        signal: signal
            .map(|s| s.trim().trim_start_matches('@'))
            .filter(|s| !s.is_empty())
            .map(|s| s.to_lowercase()),
    }
}

pub struct SessionResult {
    pub access_jwt: String,
    pub refresh_jwt: String,
}

pub async fn create_and_store_session(
    state: &AppState,
    did_str: &str,
    did: &Did,
    signing_key_bytes: &[u8],
    scope: &str,
    controller_did: Option<&Did>,
) -> Result<SessionResult, ApiError> {
    let access_meta =
        tranquil_pds::auth::create_access_token_with_metadata(did_str, signing_key_bytes).map_err(
            |e| {
                tracing::error!("Error creating access token: {:?}", e);
                ApiError::InternalError(None)
            },
        )?;
    let refresh_meta =
        tranquil_pds::auth::create_refresh_token_with_metadata(did_str, signing_key_bytes)
            .map_err(|e| {
                tracing::error!("Error creating refresh token: {:?}", e);
                ApiError::InternalError(None)
            })?;
    let session_data = tranquil_db_traits::SessionTokenCreate {
        did: did.clone(),
        access_jti: access_meta.jti.clone(),
        refresh_jti: refresh_meta.jti.clone(),
        access_expires_at: access_meta.expires_at,
        refresh_expires_at: refresh_meta.expires_at,
        login_type: tranquil_db_traits::LoginType::Modern,
        mfa_verified: false,
        scope: Some(scope.to_string()),
        controller_did: controller_did.cloned(),
        app_password_name: None,
    };
    state
        .repos.session
        .create_session(&session_data)
        .await
        .map_err(|e| {
            tracing::error!("Error creating session: {:?}", e);
            ApiError::InternalError(None)
        })?;
    Ok(SessionResult {
        access_jwt: access_meta.token,
        refresh_jwt: refresh_meta.token,
    })
}

pub async fn enqueue_signup_verification(
    state: &AppState,
    user_id: uuid::Uuid,
    did: &Did,
    channel: CommsChannel,
    recipient: &str,
) {
    let token =
        tranquil_pds::auth::verification_token::generate_signup_token(did, channel, recipient);
    let formatted = tranquil_pds::auth::verification_token::format_token_for_display(&token);
    let hostname = &tranquil_config::get().server.hostname;
    if let Err(e) = tranquil_pds::comms::comms_repo::enqueue_signup_verification(
        state.repos.user.as_ref(),
        state.repos.infra.as_ref(),
        user_id,
        channel,
        recipient,
        &formatted,
        hostname,
    )
    .await
    {
        tracing::warn!("Failed to enqueue signup verification: {:?}", e);
    }
}

pub async fn enqueue_migration_verification(
    state: &AppState,
    user_id: uuid::Uuid,
    did: &Did,
    channel: CommsChannel,
    recipient: &str,
) {
    let token =
        tranquil_pds::auth::verification_token::generate_migration_token(did, channel, recipient);
    let formatted = tranquil_pds::auth::verification_token::format_token_for_display(&token);
    let hostname = &tranquil_config::get().server.hostname;
    if let Err(e) = tranquil_pds::comms::comms_repo::enqueue_migration_verification(
        state.repos.user.as_ref(),
        state.repos.infra.as_ref(),
        user_id,
        channel,
        recipient,
        &formatted,
        hostname,
    )
    .await
    {
        tracing::warn!("Failed to enqueue migration verification: {:?}", e);
    }
}
