use crate::api::error::ApiError;
use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{Duration, Utc};
use k256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

const SECP256K1_MULTICODEC_PREFIX: [u8; 2] = [0xe7, 0x01];

fn public_key_to_did_key(signing_key: &SigningKey) -> String {
    let verifying_key = signing_key.verifying_key();
    let compressed_pubkey = verifying_key.to_sec1_bytes();
    let mut multicodec_key = Vec::with_capacity(2 + compressed_pubkey.len());
    multicodec_key.extend_from_slice(&SECP256K1_MULTICODEC_PREFIX);
    multicodec_key.extend_from_slice(&compressed_pubkey);
    let encoded = multibase::encode(multibase::Base::Base58Btc, &multicodec_key);
    format!("did:key:{}", encoded)
}

#[derive(Deserialize)]
pub struct ReserveSigningKeyInput {
    pub did: Option<crate::types::Did>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReserveSigningKeyOutput {
    pub signing_key: String,
}

pub async fn reserve_signing_key(
    State(state): State<AppState>,
    Json(input): Json<ReserveSigningKeyInput>,
) -> Response {
    let signing_key = SigningKey::random(&mut rand::thread_rng());
    let private_key_bytes = signing_key.to_bytes();
    let public_key_did_key = public_key_to_did_key(&signing_key);
    let expires_at = Utc::now() + Duration::hours(24);
    let private_bytes: &[u8] = &private_key_bytes;
    match state
        .infra_repo
        .reserve_signing_key(
            input.did.as_ref(),
            &public_key_did_key,
            private_bytes,
            expires_at,
        )
        .await
    {
        Ok(key_id) => {
            info!("Reserved signing key {} for did {:?}", key_id, input.did);
            (
                StatusCode::OK,
                Json(ReserveSigningKeyOutput {
                    signing_key: public_key_did_key,
                }),
            )
                .into_response()
        }
        Err(e) => {
            error!("DB error in reserve_signing_key: {:?}", e);
            ApiError::InternalError(None).into_response()
        }
    }
}
