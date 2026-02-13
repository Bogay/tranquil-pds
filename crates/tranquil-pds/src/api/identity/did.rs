use crate::api::{ApiError, DidResponse, EmptyResponse};
use crate::auth::{Auth, NotTakendown};
use crate::plc::signing_key_to_did_key;
use crate::rate_limit::{
    HandleUpdateDailyLimit, HandleUpdateLimit, check_user_rate_limit_with_message,
};
use crate::state::AppState;
use crate::types::Handle;
use crate::util::get_header_str;
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use base64::Engine;
use k256::SecretKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{error, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidWebVerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub method_type: String,
    pub public_key_multibase: String,
}

#[derive(Deserialize)]
pub struct ResolveHandleParams {
    pub handle: String,
}

pub async fn resolve_handle(
    State(state): State<AppState>,
    Query(params): Query<ResolveHandleParams>,
) -> Response {
    let handle_str = params.handle.trim();
    if handle_str.is_empty() {
        return ApiError::InvalidRequest("handle is required".into()).into_response();
    }
    let cache_key = crate::cache_keys::handle_key(handle_str);
    if let Some(did) = state.cache.get(&cache_key).await {
        return DidResponse::response(did).into_response();
    }
    let handle: Handle = match handle_str.parse() {
        Ok(h) => h,
        Err(_) => {
            return ApiError::InvalidHandle(Some("Invalid handle format".into())).into_response();
        }
    };
    let user = state.user_repo.get_by_handle(&handle).await;
    match user {
        Ok(Some(row)) => {
            let _ = state
                .cache
                .set(&cache_key, &row.did, std::time::Duration::from_secs(300))
                .await;
            DidResponse::response(row.did).into_response()
        }
        Ok(None) => match crate::handle::resolve_handle(handle.as_str()).await {
            Ok(did) => {
                let _ = state
                    .cache
                    .set(&cache_key, &did, std::time::Duration::from_secs(300))
                    .await;
                DidResponse::response(did).into_response()
            }
            Err(_) => ApiError::HandleNotFound.into_response(),
        },
        Err(e) => {
            error!("DB error resolving handle: {:?}", e);
            ApiError::InternalError(None).into_response()
        }
    }
}

#[derive(Debug)]
pub enum KeyError {
    InvalidKeyLength,
    MissingCoordinate,
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKeyLength => write!(f, "invalid key length"),
            Self::MissingCoordinate => write!(f, "missing elliptic curve coordinate"),
        }
    }
}

impl std::error::Error for KeyError {}

pub fn get_jwk(key_bytes: &[u8]) -> Result<serde_json::Value, KeyError> {
    let secret_key = SecretKey::from_slice(key_bytes).map_err(|_| KeyError::InvalidKeyLength)?;
    let public_key = secret_key.public_key();
    let encoded = public_key.to_encoded_point(false);
    let x = encoded.x().ok_or(KeyError::MissingCoordinate)?;
    let y = encoded.y().ok_or(KeyError::MissingCoordinate)?;
    let x_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x);
    let y_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y);
    Ok(json!({
        "kty": "EC",
        "crv": "secp256k1",
        "x": x_b64,
        "y": y_b64
    }))
}

pub fn get_public_key_multibase(key_bytes: &[u8]) -> Result<String, KeyError> {
    let secret_key = SecretKey::from_slice(key_bytes).map_err(|_| KeyError::InvalidKeyLength)?;
    let public_key = secret_key.public_key();
    let compressed = public_key.to_encoded_point(true);
    let compressed_bytes = compressed.as_bytes();
    let mut multicodec_key = vec![0xe7, 0x01];
    multicodec_key.extend_from_slice(compressed_bytes);
    Ok(format!("z{}", bs58::encode(&multicodec_key).into_string()))
}

pub async fn well_known_did(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let hostname = &tranquil_config::get().server.hostname;
    let hostname_without_port = tranquil_config::get().server.hostname_without_port();
    let host_header = get_header_str(&headers, http::header::HOST).unwrap_or(hostname);
    let host_without_port = host_header.split(':').next().unwrap_or(host_header);
    if host_without_port != hostname_without_port
        && host_without_port.ends_with(&format!(".{}", hostname_without_port))
    {
        let handle = host_without_port
            .strip_suffix(&format!(".{}", hostname_without_port))
            .unwrap_or(host_without_port);
        return serve_subdomain_did_doc(&state, handle, hostname).await;
    }
    let did = if hostname.contains(':') {
        format!("did:web:{}", hostname.replace(':', "%3A"))
    } else {
        format!("did:web:{}", hostname)
    };
    Json(json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "service": [{
            "id": "#atproto_pds",
            "type": crate::plc::ServiceType::Pds.as_str(),
            "serviceEndpoint": format!("https://{}", hostname)
        }]
    }))
    .into_response()
}

async fn serve_subdomain_did_doc(state: &AppState, subdomain: &str, hostname: &str) -> Response {
    let hostname_for_handles = hostname.split(':').next().unwrap_or(hostname);
    let subdomain_host = format!("{}.{}", subdomain, hostname_for_handles);
    let encoded_subdomain = subdomain_host.replace(':', "%3A");
    let expected_did = format!("did:web:{}", encoded_subdomain);
    let expected_did_typed: crate::types::Did = match expected_did.parse() {
        Ok(d) => d,
        Err(_) => return ApiError::InvalidRequest("Invalid DID format".into()).into_response(),
    };
    let user = match state
        .user_repo
        .get_user_for_did_doc_build(&expected_did_typed)
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => {
            return ApiError::NotFoundMsg("User not found".into()).into_response();
        }
        Err(e) => {
            error!("DB Error: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let (user_id, current_handle, migrated_to_pds) = (user.id, user.handle, user.migrated_to_pds);
    let did = expected_did;

    let overrides = state
        .user_repo
        .get_did_web_overrides(user_id)
        .await
        .ok()
        .flatten();

    let service_endpoint = migrated_to_pds.unwrap_or_else(|| format!("https://{}", hostname));

    if let Some((ovr, parsed)) = overrides.as_ref().and_then(|ovr| {
        serde_json::from_value::<Vec<DidWebVerificationMethod>>(ovr.verification_methods.clone())
            .ok()
            .filter(|p| !p.is_empty())
            .map(|p| (ovr, p))
    }) {
        let also_known_as = if !ovr.also_known_as.is_empty() {
            ovr.also_known_as.clone()
        } else {
            vec![format!("at://{}", current_handle)]
        };

        return Json(json!({
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
                "type": crate::plc::ServiceType::Pds.as_str(),
                "serviceEndpoint": service_endpoint
            }]
        }))
        .into_response();
    }

    let key_info = match state.user_repo.get_user_key_by_id(user_id).await {
        Ok(Some(k)) => k,
        Ok(None) => return ApiError::InternalError(None).into_response(),
        Err(_) => return ApiError::InternalError(None).into_response(),
    };
    let key_bytes: Vec<u8> =
        match crate::config::decrypt_key(&key_info.key_bytes, key_info.encryption_version) {
            Ok(k) => k,
            Err(_) => {
                return ApiError::InternalError(None).into_response();
            }
        };
    let public_key_multibase = match get_public_key_multibase(&key_bytes) {
        Ok(pk) => pk,
        Err(e) => {
            tracing::error!("Failed to generate public key multibase: {}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let also_known_as = if let Some(ref ovr) = overrides {
        if !ovr.also_known_as.is_empty() {
            ovr.also_known_as.clone()
        } else {
            vec![format!("at://{}", current_handle)]
        }
    } else {
        vec![format!("at://{}", current_handle)]
    };

    Json(json!({
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
            "type": crate::plc::ServiceType::Pds.as_str(),
            "serviceEndpoint": service_endpoint
        }]
    }))
    .into_response()
}

pub async fn user_did_doc(State(state): State<AppState>, Path(handle): Path<String>) -> Response {
    let hostname = &tranquil_config::get().server.hostname;
    let hostname_for_handles = tranquil_config::get().server.hostname_without_port();
    let current_handle = format!("{}.{}", handle, hostname_for_handles);
    let current_handle_typed: Handle = match current_handle.parse() {
        Ok(h) => h,
        Err(_) => {
            return ApiError::InvalidHandle(Some("Invalid handle format".into())).into_response();
        }
    };
    let user = match state
        .user_repo
        .get_did_web_info_by_handle(&current_handle_typed)
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => {
            return ApiError::NotFoundMsg("User not found".into()).into_response();
        }
        Err(e) => {
            error!("DB Error: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let (user_id, did, migrated_to_pds) = (user.id, user.did, user.migrated_to_pds);
    if !did.starts_with("did:web:") {
        return ApiError::NotFoundMsg("User is not did:web".into()).into_response();
    }
    let encoded_hostname = hostname.replace(':', "%3A");
    let old_path_format = format!("did:web:{}:u:{}", encoded_hostname, handle);
    let subdomain_host = format!("{}.{}", handle, hostname_for_handles);
    let encoded_subdomain = subdomain_host.replace(':', "%3A");
    let new_subdomain_format = format!("did:web:{}", encoded_subdomain);
    if did != old_path_format && did != new_subdomain_format {
        return ApiError::NotFoundMsg("External did:web - DID document hosted by user".into())
            .into_response();
    }

    let overrides = state
        .user_repo
        .get_did_web_overrides(user_id)
        .await
        .ok()
        .flatten();

    let service_endpoint = migrated_to_pds.unwrap_or_else(|| format!("https://{}", hostname));

    if let Some((ovr, parsed)) = overrides.as_ref().and_then(|ovr| {
        serde_json::from_value::<Vec<DidWebVerificationMethod>>(ovr.verification_methods.clone())
            .ok()
            .filter(|p| !p.is_empty())
            .map(|p| (ovr, p))
    }) {
        let also_known_as = if !ovr.also_known_as.is_empty() {
            ovr.also_known_as.clone()
        } else {
            vec![format!("at://{}", current_handle)]
        };

        return Json(json!({
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
                "type": crate::plc::ServiceType::Pds.as_str(),
                "serviceEndpoint": service_endpoint
            }]
        }))
        .into_response();
    }

    let key_info = match state.user_repo.get_user_key_by_id(user_id).await {
        Ok(Some(k)) => k,
        Ok(None) => return ApiError::InternalError(None).into_response(),
        Err(_) => return ApiError::InternalError(None).into_response(),
    };
    let key_bytes: Vec<u8> =
        match crate::config::decrypt_key(&key_info.key_bytes, key_info.encryption_version) {
            Ok(k) => k,
            Err(_) => {
                return ApiError::InternalError(None).into_response();
            }
        };
    let public_key_multibase = match get_public_key_multibase(&key_bytes) {
        Ok(pk) => pk,
        Err(e) => {
            tracing::error!("Failed to generate public key multibase: {}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    let also_known_as = if let Some(ref ovr) = overrides {
        if !ovr.also_known_as.is_empty() {
            ovr.also_known_as.clone()
        } else {
            vec![format!("at://{}", current_handle)]
        }
    } else {
        vec![format!("at://{}", current_handle)]
    };

    Json(json!({
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
            "type": crate::plc::ServiceType::Pds.as_str(),
            "serviceEndpoint": service_endpoint
        }]
    }))
    .into_response()
}

#[derive(Debug, thiserror::Error)]
pub enum DidWebVerifyError {
    #[error("Invalid did:web format")]
    InvalidFormat,
    #[error("Invalid DID path for this PDS. Expected {0}")]
    InvalidPath(String),
    #[error(
        "External did:web requires a pre-reserved signing key. Call com.atproto.server.reserveSigningKey first, configure your DID document with the returned key, then provide the signingKey in createAccount."
    )]
    MissingSigningKey,
    #[error("Failed to fetch DID doc: {0}")]
    FetchFailed(String),
    #[error("Invalid DID document: {0}")]
    InvalidDocument(String),
    #[error("DID document does not list this PDS ({0}) as AtprotoPersonalDataServer")]
    PdsNotListed(String),
    #[error(
        "DID document verification key does not match reserved signing key. Expected publicKeyMultibase: {0}"
    )]
    KeyMismatch(String),
    #[error("Invalid signing key format")]
    InvalidSigningKey,
}

pub async fn verify_did_web(
    did: &str,
    hostname: &str,
    handle: &str,
    expected_signing_key: Option<&str>,
) -> Result<(), DidWebVerifyError> {
    let hostname_for_handles = hostname.split(':').next().unwrap_or(hostname);
    let subdomain_host = format!("{}.{}", handle, hostname_for_handles);
    let encoded_subdomain = subdomain_host.replace(':', "%3A");
    let expected_subdomain_did = format!("did:web:{}", encoded_subdomain);
    if did == expected_subdomain_did {
        return Ok(());
    }
    let expected_prefix = if hostname.contains(':') {
        format!("did:web:{}", hostname.replace(':', "%3A"))
    } else {
        format!("did:web:{}", hostname)
    };
    if did.starts_with(&expected_prefix) {
        let suffix = &did[expected_prefix.len()..];
        let expected_suffix = format!(":u:{}", handle);
        return if suffix == expected_suffix {
            Ok(())
        } else {
            Err(DidWebVerifyError::InvalidPath(expected_suffix))
        };
    }
    let expected_signing_key = expected_signing_key.ok_or(DidWebVerifyError::MissingSigningKey)?;
    let parts: Vec<&str> = did.split(':').collect();
    if parts.len() < 3 || parts[0] != "did" || parts[1] != "web" {
        return Err(DidWebVerifyError::InvalidFormat);
    }
    let domain_segment = parts[2];
    let domain = domain_segment.replace("%3A", ":");
    let scheme = if domain.starts_with("localhost") || domain.starts_with("127.0.0.1") {
        "http"
    } else {
        "https"
    };
    let url = if parts.len() == 3 {
        format!("{}://{}/.well-known/did.json", scheme, domain)
    } else {
        let path = parts[3..].join("/");
        format!("{}://{}/{}/did.json", scheme, domain, path)
    };
    let client = crate::api::proxy_client::did_resolution_client();
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| DidWebVerifyError::FetchFailed(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(DidWebVerifyError::FetchFailed(format!(
            "HTTP {}",
            resp.status()
        )));
    }
    let doc: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| DidWebVerifyError::InvalidDocument(e.to_string()))?;
    let services = doc["service"]
        .as_array()
        .ok_or(DidWebVerifyError::InvalidDocument(
            "No services found".to_string(),
        ))?;
    let pds_endpoint = format!("https://{}", hostname);
    let has_valid_service = services.iter().any(|s| {
        s["type"] == crate::plc::ServiceType::Pds.as_str() && s["serviceEndpoint"] == pds_endpoint
    });
    if !has_valid_service {
        return Err(DidWebVerifyError::PdsNotListed(pds_endpoint));
    }
    let verification_methods =
        doc["verificationMethod"]
            .as_array()
            .ok_or(DidWebVerifyError::InvalidDocument(
                "No verificationMethod found".to_string(),
            ))?;
    let expected_multibase = expected_signing_key
        .strip_prefix("did:key:")
        .ok_or(DidWebVerifyError::InvalidSigningKey)?;
    let has_matching_key = verification_methods.iter().any(|vm| {
        vm["publicKeyMultibase"]
            .as_str()
            .is_some_and(|pk| pk == expected_multibase)
    });
    if !has_matching_key {
        return Err(DidWebVerifyError::KeyMismatch(
            expected_multibase.to_string(),
        ));
    }
    Ok(())
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRecommendedDidCredentialsOutput {
    pub rotation_keys: Vec<String>,
    pub also_known_as: Vec<String>,
    pub verification_methods: VerificationMethods,
    pub services: Services,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethods {
    pub atproto: String,
}

#[derive(serde::Serialize)]
pub struct Services {
    pub atproto_pds: AtprotoPds,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AtprotoPds {
    #[serde(rename = "type")]
    pub service_type: String,
    pub endpoint: String,
}

pub async fn get_recommended_did_credentials(
    State(state): State<AppState>,
    auth: Auth<NotTakendown>,
) -> Result<Response, ApiError> {
    let handle = state
        .user_repo
        .get_handle_by_did(&auth.did)
        .await
        .map_err(|_| ApiError::InternalError(None))?
        .ok_or(ApiError::InternalError(None))?;

    let key_bytes = auth.key_bytes.clone().ok_or_else(|| {
        ApiError::AuthenticationFailed(Some("OAuth tokens cannot get DID credentials".into()))
    })?;

    let hostname = &tranquil_config::get().server.hostname;
    let pds_endpoint = format!("https://{}", hostname);
    let signing_key = k256::ecdsa::SigningKey::from_slice(&key_bytes)
        .map_err(|_| ApiError::InternalError(None))?;
    let did_key = signing_key_to_did_key(&signing_key);
    let rotation_keys = if auth.did.starts_with("did:web:") {
        vec![]
    } else {
        let server_rotation_key = match &tranquil_config::get().secrets.plc_rotation_key {
            Some(key) => key.clone(),
            None => {
                warn!(
                    "PLC_ROTATION_KEY not set, falling back to user's signing key for rotation key recommendation"
                );
                did_key.clone()
            }
        };
        vec![server_rotation_key]
    };
    Ok((
        StatusCode::OK,
        Json(GetRecommendedDidCredentialsOutput {
            rotation_keys,
            also_known_as: vec![format!("at://{}", handle)],
            verification_methods: VerificationMethods { atproto: did_key },
            services: Services {
                atproto_pds: AtprotoPds {
                    service_type: crate::plc::ServiceType::Pds.as_str().to_string(),
                    endpoint: pds_endpoint,
                },
            },
        }),
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct UpdateHandleInput {
    pub handle: String,
}

pub async fn update_handle(
    State(state): State<AppState>,
    auth: Auth<NotTakendown>,
    Json(input): Json<UpdateHandleInput>,
) -> Result<Response, ApiError> {
    if let Err(e) = crate::auth::scope_check::check_identity_scope(
        &auth.auth_source,
        auth.scope.as_deref(),
        crate::oauth::scopes::IdentityAttr::Handle,
    ) {
        return Ok(e);
    }
    let did = auth.did.clone();
    let _rate_limit = check_user_rate_limit_with_message::<HandleUpdateLimit>(
        &state,
        &did,
        "Too many handle updates. Try again later.",
    )
    .await?;
    let _daily_rate_limit = check_user_rate_limit_with_message::<HandleUpdateDailyLimit>(
        &state,
        &did,
        "Daily handle update limit exceeded.",
    )
    .await?;
    let user_row = state
        .user_repo
        .get_id_and_handle_by_did(&did)
        .await
        .map_err(|_| ApiError::InternalError(None))?
        .ok_or(ApiError::InternalError(None))?;
    let user_id = user_row.id;
    let current_handle = user_row.handle;
    let new_handle = input.handle.trim().to_ascii_lowercase();
    if new_handle.is_empty() {
        return Err(ApiError::InvalidRequest("handle is required".into()));
    }
    if !new_handle
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(ApiError::InvalidHandle(Some(
            "Handle contains invalid characters".into(),
        )));
    }
    if new_handle.split('.').any(|segment| segment.is_empty()) {
        return Err(ApiError::InvalidHandle(Some(
            "Handle contains empty segment".into(),
        )));
    }
    if new_handle
        .split('.')
        .any(|segment| segment.starts_with('-') || segment.ends_with('-'))
    {
        return Err(ApiError::InvalidHandle(Some(
            "Handle segment cannot start or end with hyphen".into(),
        )));
    }
    if crate::moderation::has_explicit_slur(&new_handle) {
        return Err(ApiError::InvalidHandle(Some(
            "Inappropriate language in handle".into(),
        )));
    }
    let hostname_for_handles = tranquil_config::get().server.hostname_without_port();
    let suffix = format!(".{}", hostname_for_handles);
    let is_service_domain =
        crate::handle::is_service_domain_handle(&new_handle, hostname_for_handles);
    let handle = if is_service_domain && new_handle != hostname_for_handles {
        let short_part = if new_handle.ends_with(&suffix) {
            new_handle.strip_suffix(&suffix).unwrap_or(&new_handle)
        } else {
            &new_handle
        };
        let full_handle = if new_handle.ends_with(&suffix) {
            new_handle.clone()
        } else {
            format!("{}.{}", new_handle, hostname_for_handles)
        };
        if full_handle == current_handle {
            let handle_typed: Handle = match full_handle.parse() {
                Ok(h) => h,
                Err(_) => return Err(ApiError::InvalidHandle(None)),
            };
            if let Err(e) =
                crate::api::repo::record::sequence_identity_event(&state, &did, Some(&handle_typed))
                    .await
            {
                warn!("Failed to sequence identity event for handle update: {}", e);
            }
            return Ok(EmptyResponse::ok().into_response());
        }
        if short_part.contains('.') {
            return Err(ApiError::InvalidHandle(Some(
                "Nested subdomains are not allowed. Use a simple handle without dots.".into(),
            )));
        }
        if short_part.len() < 3 {
            return Err(ApiError::InvalidHandle(Some("Handle too short".into())));
        }
        if short_part.len() > 18 {
            return Err(ApiError::InvalidHandle(Some("Handle too long".into())));
        }
        full_handle
    } else {
        if new_handle == current_handle {
            let handle_typed: Handle = match new_handle.parse() {
                Ok(h) => h,
                Err(_) => return Err(ApiError::InvalidHandle(None)),
            };
            if let Err(e) =
                crate::api::repo::record::sequence_identity_event(&state, &did, Some(&handle_typed))
                    .await
            {
                warn!("Failed to sequence identity event for handle update: {}", e);
            }
            return Ok(EmptyResponse::ok().into_response());
        }
        match crate::handle::verify_handle_ownership(&new_handle, &did).await {
            Ok(()) => {}
            Err(crate::handle::HandleResolutionError::NotFound) => {
                return Err(ApiError::HandleNotAvailable(None));
            }
            Err(crate::handle::HandleResolutionError::DidMismatch { expected, actual }) => {
                return Err(ApiError::HandleNotAvailable(Some(format!(
                    "Handle points to different DID. Expected {}, got {}",
                    expected, actual
                ))));
            }
            Err(e) => {
                warn!("Handle verification failed: {}", e);
                return Err(ApiError::HandleNotAvailable(Some(format!(
                    "Handle verification failed: {}",
                    e
                ))));
            }
        }
        new_handle.clone()
    };
    let handle_typed: Handle = handle
        .parse()
        .map_err(|_| ApiError::InvalidHandle(Some("Invalid handle format".into())))?;
    let handle_exists = state
        .user_repo
        .check_handle_exists(&handle_typed, user_id)
        .await
        .map_err(|_| ApiError::InternalError(None))?;
    if handle_exists {
        return Err(ApiError::HandleTaken);
    }
    state
        .user_repo
        .update_handle(user_id, &handle_typed)
        .await
        .map_err(|e| {
            error!("DB error updating handle: {:?}", e);
            ApiError::InternalError(None)
        })?;

    if !current_handle.is_empty() {
        let _ = state
            .cache
            .delete(&crate::cache_keys::handle_key(&current_handle))
            .await;
    }
    let _ = state
        .cache
        .delete(&crate::cache_keys::handle_key(&handle))
        .await;
    if let Err(e) =
        crate::api::repo::record::sequence_identity_event(&state, &did, Some(&handle_typed)).await
    {
        warn!("Failed to sequence identity event for handle update: {}", e);
    }
    if let Err(e) = update_plc_handle(&state, &did, &handle_typed).await {
        warn!("Failed to update PLC handle: {}", e);
    }
    Ok(EmptyResponse::ok().into_response())
}

pub async fn update_plc_handle(
    state: &AppState,
    did: &crate::types::Did,
    new_handle: &Handle,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !did.as_str().starts_with("did:plc:") {
        return Ok(());
    }
    let user_row = match state.user_repo.get_user_with_key_by_did(did).await? {
        Some(r) => r,
        None => return Ok(()),
    };
    let key_bytes = crate::config::decrypt_key(&user_row.key_bytes, user_row.encryption_version)?;
    let signing_key = k256::ecdsa::SigningKey::from_slice(&key_bytes)?;
    let plc_client = crate::plc::PlcClient::with_cache(None, Some(state.cache.clone()));
    let last_op = plc_client.get_last_op(did).await?;
    let new_also_known_as = vec![format!("at://{}", new_handle)];
    let update_op =
        crate::plc::create_update_op(&last_op, None, None, Some(new_also_known_as), None)?;
    let signed_op = crate::plc::sign_operation(&update_op, &signing_key)?;
    plc_client.send_operation(did, &signed_op).await?;
    Ok(())
}

pub async fn well_known_atproto_did(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let host = match crate::util::get_header_str(&headers, http::header::HOST) {
        Some(h) => h,
        None => return (StatusCode::BAD_REQUEST, "Missing host header").into_response(),
    };
    let handle_str = host.split(':').next().unwrap_or(host);
    let handle: Handle = match handle_str.parse() {
        Ok(h) => h,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid handle format").into_response(),
    };
    let user = state.user_repo.get_by_handle(&handle).await;
    match user {
        Ok(Some(row)) => row.did.to_string().into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "Handle not found").into_response(),
        Err(e) => {
            error!("DB error in well-known atproto-did: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response()
        }
    }
}
