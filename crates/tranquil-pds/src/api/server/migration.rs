use crate::api::ApiError;
use crate::api::error::DbResultExt;
use crate::auth::{Active, Auth};
use crate::state::AppState;
use crate::util::pds_hostname;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub method_type: String,
    pub public_key_multibase: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateDidDocumentInput {
    pub verification_methods: Option<Vec<VerificationMethod>>,
    pub also_known_as: Option<Vec<String>>,
    pub service_endpoint: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateDidDocumentOutput {
    pub success: bool,
    pub did_document: serde_json::Value,
}

pub async fn update_did_document(
    State(state): State<AppState>,
    auth: Auth<Active>,
    Json(input): Json<UpdateDidDocumentInput>,
) -> Result<Response, ApiError> {
    if !auth.did.starts_with("did:web:") {
        return Err(ApiError::InvalidRequest(
            "DID document updates are only available for did:web accounts".into(),
        ));
    }

    let user = state
        .user_repo
        .get_user_for_did_doc(&auth.did)
        .await
        .log_db_err("getting user")?
        .ok_or(ApiError::AccountNotFound)?;

    if let Some(ref methods) = input.verification_methods {
        if methods.is_empty() {
            return Err(ApiError::InvalidRequest(
                "verification_methods cannot be empty".into(),
            ));
        }
        let validation_error = methods.iter().find_map(|method| {
            if method.id.is_empty() {
                Some("verification method id is required")
            } else if method.method_type != "Multikey" {
                Some("verification method type must be 'Multikey'")
            } else if !method.public_key_multibase.starts_with('z') {
                Some("publicKeyMultibase must start with 'z' (base58btc)")
            } else if method.public_key_multibase.len() < 40 {
                Some("publicKeyMultibase appears too short for a valid key")
            } else {
                None
            }
        });
        if let Some(err) = validation_error {
            return Err(ApiError::InvalidRequest(err.into()));
        }
    }

    if let Some(ref handles) = input.also_known_as
        && handles.iter().any(|h| !h.starts_with("at://"))
    {
        return Err(ApiError::InvalidRequest(
            "alsoKnownAs entries must be at:// URIs".into(),
        ));
    }

    if let Some(ref endpoint) = input.service_endpoint {
        let endpoint = endpoint.trim();
        if !endpoint.starts_with("https://") {
            return Err(ApiError::InvalidRequest(
                "serviceEndpoint must start with https://".into(),
            ));
        }
    }

    let verification_methods_json = input
        .verification_methods
        .as_ref()
        .map(|v| serde_json::to_value(v).unwrap_or_default());

    let also_known_as: Option<Vec<String>> = input.also_known_as.clone();

    state
        .user_repo
        .upsert_did_web_overrides(user.id, verification_methods_json, also_known_as)
        .await
        .log_db_err("upserting did_web_overrides")?;

    if let Some(ref endpoint) = input.service_endpoint {
        let endpoint_clean = endpoint.trim().trim_end_matches('/');
        state
            .user_repo
            .update_migrated_to_pds(&auth.did, endpoint_clean)
            .await
            .log_db_err("updating service endpoint")?;
    }

    let did_doc = build_did_document(&state, &auth.did).await;

    tracing::info!("Updated DID document for {}", &auth.did);

    Ok((
        StatusCode::OK,
        Json(UpdateDidDocumentOutput {
            success: true,
            did_document: did_doc,
        }),
    )
        .into_response())
}

pub async fn get_did_document(
    State(state): State<AppState>,
    auth: Auth<Active>,
) -> Result<Response, ApiError> {
    if !auth.did.starts_with("did:web:") {
        return Err(ApiError::InvalidRequest(
            "This endpoint is only available for did:web accounts".into(),
        ));
    }

    let did_doc = build_did_document(&state, &auth.did).await;

    Ok((StatusCode::OK, Json(json!({ "didDocument": did_doc }))).into_response())
}

async fn build_did_document(state: &AppState, did: &crate::types::Did) -> serde_json::Value {
    let hostname = pds_hostname();

    let user = match state.user_repo.get_user_for_did_doc_build(did).await {
        Ok(Some(row)) => row,
        _ => {
            return json!({
                "error": "User not found"
            });
        }
    };

    let overrides = state
        .user_repo
        .get_did_web_overrides(user.id)
        .await
        .ok()
        .flatten();

    let service_endpoint = user
        .migrated_to_pds
        .unwrap_or_else(|| format!("https://{}", hostname));

    if let Some((ovr, parsed)) = overrides.as_ref().and_then(|ovr| {
        serde_json::from_value::<Vec<VerificationMethod>>(ovr.verification_methods.clone())
            .ok()
            .filter(|p| !p.is_empty())
            .map(|p| (ovr, p))
    }) {
        let also_known_as = if !ovr.also_known_as.is_empty() {
            ovr.also_known_as.clone()
        } else {
            vec![format!("at://{}", user.handle)]
        };
        return json!({
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/multikey/v1",
                "https://w3id.org/security/suites/secp256k1-2019/v1"
            ],
            "id": did,
            "alsoKnownAs": also_known_as,
            "verificationMethod": parsed.iter().map(|m| json!({
                "id": format!("{}{}", did, if m.id.starts_with('#') { m.id.clone() } else { format!("#{}", m.id) }),
                "type": m.method_type,
                "controller": did,
                "publicKeyMultibase": m.public_key_multibase
            })).collect::<Vec<_>>(),
            "service": [{
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": service_endpoint
            }]
        });
    }

    let key_info = state
        .user_repo
        .get_user_key_by_id(user.id)
        .await
        .ok()
        .flatten();

    let public_key_multibase = match key_info {
        Some(info) => match crate::config::decrypt_key(&info.key_bytes, info.encryption_version) {
            Ok(key_bytes) => crate::api::identity::did::get_public_key_multibase(&key_bytes)
                .unwrap_or_else(|_| "error".to_string()),
            Err(_) => "error".to_string(),
        },
        None => "error".to_string(),
    };

    let also_known_as = if let Some(ref ovr) = overrides {
        if !ovr.also_known_as.is_empty() {
            ovr.also_known_as.clone()
        } else {
            vec![format!("at://{}", user.handle)]
        }
    } else {
        vec![format!("at://{}", user.handle)]
    };

    json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
            "https://w3id.org/security/suites/secp256k1-2019/v1"
        ],
        "id": did,
        "alsoKnownAs": also_known_as,
        "verificationMethod": [{
            "id": format!("{}#atproto", did),
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": public_key_multibase
        }],
        "service": [{
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": service_endpoint
        }]
    })
}
