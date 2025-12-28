use crate::api::ApiError;
use crate::plc::signing_key_to_did_key;
use crate::state::AppState;
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use base64::Engine;
use k256::SecretKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use reqwest;
use serde::Deserialize;
use serde_json::json;
use tracing::{error, warn};

#[derive(Deserialize)]
pub struct ResolveHandleParams {
    pub handle: String,
}

pub async fn resolve_handle(
    State(state): State<AppState>,
    Query(params): Query<ResolveHandleParams>,
) -> Response {
    let handle = params.handle.trim();
    if handle.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "handle is required"})),
        )
            .into_response();
    }
    let cache_key = format!("handle:{}", handle);
    if let Some(did) = state.cache.get(&cache_key).await {
        return (StatusCode::OK, Json(json!({ "did": did }))).into_response();
    }
    let user = sqlx::query!("SELECT did FROM users WHERE handle = $1", handle)
        .fetch_optional(&state.db)
        .await;
    match user {
        Ok(Some(row)) => {
            let _ = state
                .cache
                .set(&cache_key, &row.did, std::time::Duration::from_secs(300))
                .await;
            (StatusCode::OK, Json(json!({ "did": row.did }))).into_response()
        }
        Ok(None) => match crate::handle::resolve_handle(handle).await {
            Ok(did) => {
                let _ = state
                    .cache
                    .set(&cache_key, &did, std::time::Duration::from_secs(300))
                    .await;
                (StatusCode::OK, Json(json!({ "did": did }))).into_response()
            }
            Err(_) => (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "HandleNotFound", "message": "Unable to resolve handle"})),
            )
                .into_response(),
        },
        Err(e) => {
            error!("DB error resolving handle: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

pub fn get_jwk(key_bytes: &[u8]) -> Result<serde_json::Value, &'static str> {
    let secret_key = SecretKey::from_slice(key_bytes).map_err(|_| "Invalid key length")?;
    let public_key = secret_key.public_key();
    let encoded = public_key.to_encoded_point(false);
    let x = encoded.x().ok_or("Missing x coordinate")?;
    let y = encoded.y().ok_or("Missing y coordinate")?;
    let x_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x);
    let y_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y);
    Ok(json!({
        "kty": "EC",
        "crv": "secp256k1",
        "x": x_b64,
        "y": y_b64
    }))
}

pub fn get_public_key_multibase(key_bytes: &[u8]) -> Result<String, &'static str> {
    let secret_key = SecretKey::from_slice(key_bytes).map_err(|_| "Invalid key length")?;
    let public_key = secret_key.public_key();
    let compressed = public_key.to_encoded_point(true);
    let compressed_bytes = compressed.as_bytes();
    let mut multicodec_key = vec![0xe7, 0x01];
    multicodec_key.extend_from_slice(compressed_bytes);
    Ok(format!("z{}", bs58::encode(&multicodec_key).into_string()))
}

pub async fn well_known_did(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let host_header = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or(&hostname);
    let host_without_port = host_header.split(':').next().unwrap_or(host_header);
    let hostname_without_port = hostname.split(':').next().unwrap_or(&hostname);
    if host_without_port != hostname_without_port
        && host_without_port.ends_with(&format!(".{}", hostname_without_port))
    {
        let handle = host_without_port
            .strip_suffix(&format!(".{}", hostname_without_port))
            .unwrap_or(host_without_port);
        return serve_subdomain_did_doc(&state, handle, &hostname).await;
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
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": format!("https://{}", hostname)
        }]
    }))
    .into_response()
}

async fn serve_subdomain_did_doc(state: &AppState, handle: &str, hostname: &str) -> Response {
    let full_handle = format!("{}.{}", handle, hostname);
    let user = sqlx::query!(
        "SELECT id, did, migrated_to_pds FROM users WHERE handle = $1",
        full_handle
    )
    .fetch_optional(&state.db)
    .await;
    let (user_id, did, migrated_to_pds) = match user {
        Ok(Some(row)) => (row.id, row.did, row.migrated_to_pds),
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(json!({"error": "NotFound"}))).into_response();
        }
        Err(e) => {
            error!("DB Error: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    if !did.starts_with("did:web:") {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "NotFound", "message": "User is not did:web"})),
        )
            .into_response();
    }
    let subdomain_host = format!("{}.{}", handle, hostname);
    let encoded_subdomain = subdomain_host.replace(':', "%3A");
    let expected_self_hosted = format!("did:web:{}", encoded_subdomain);
    if did != expected_self_hosted {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "NotFound", "message": "External did:web - DID document hosted by user"})),
        )
            .into_response();
    }
    let key_row = sqlx::query!(
        "SELECT key_bytes, encryption_version FROM user_keys WHERE user_id = $1",
        user_id
    )
    .fetch_optional(&state.db)
    .await;
    let key_bytes: Vec<u8> = match key_row {
        Ok(Some(row)) => match crate::config::decrypt_key(&row.key_bytes, row.encryption_version) {
            Ok(k) => k,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError"})),
                )
                    .into_response();
            }
        },
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let public_key_multibase = match get_public_key_multibase(&key_bytes) {
        Ok(pk) => pk,
        Err(e) => {
            tracing::error!("Failed to generate public key multibase: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let service_endpoint = migrated_to_pds.unwrap_or_else(|| format!("https://{}", hostname));
    Json(json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
            "https://w3id.org/security/suites/secp256k1-2019/v1"
        ],
        "id": did,
        "alsoKnownAs": [format!("at://{}", handle)],
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
    }))
    .into_response()
}

pub async fn user_did_doc(State(state): State<AppState>, Path(handle): Path<String>) -> Response {
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let full_handle = format!("{}.{}", handle, hostname);
    let user = sqlx::query!(
        "SELECT id, did, migrated_to_pds FROM users WHERE handle = $1",
        full_handle
    )
    .fetch_optional(&state.db)
    .await;
    let (user_id, did, migrated_to_pds) = match user {
        Ok(Some(row)) => (row.id, row.did, row.migrated_to_pds),
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(json!({"error": "NotFound"}))).into_response();
        }
        Err(e) => {
            error!("DB Error: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    if !did.starts_with("did:web:") {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "NotFound", "message": "User is not did:web"})),
        )
            .into_response();
    }
    let encoded_hostname = hostname.replace(':', "%3A");
    let old_path_format = format!("did:web:{}:u:{}", encoded_hostname, handle);
    let subdomain_host = format!("{}.{}", handle, hostname);
    let encoded_subdomain = subdomain_host.replace(':', "%3A");
    let new_subdomain_format = format!("did:web:{}", encoded_subdomain);
    if did != old_path_format && did != new_subdomain_format {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "NotFound", "message": "External did:web - DID document hosted by user"})),
        )
            .into_response();
    }
    let key_row = sqlx::query!(
        "SELECT key_bytes, encryption_version FROM user_keys WHERE user_id = $1",
        user_id
    )
    .fetch_optional(&state.db)
    .await;
    let key_bytes: Vec<u8> = match key_row {
        Ok(Some(row)) => match crate::config::decrypt_key(&row.key_bytes, row.encryption_version) {
            Ok(k) => k,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError"})),
                )
                    .into_response();
            }
        },
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let public_key_multibase = match get_public_key_multibase(&key_bytes) {
        Ok(pk) => pk,
        Err(e) => {
            tracing::error!("Failed to generate public key multibase: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let service_endpoint = migrated_to_pds.unwrap_or_else(|| format!("https://{}", hostname));
    Json(json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
            "https://w3id.org/security/suites/secp256k1-2019/v1"
        ],
        "id": did,
        "alsoKnownAs": [format!("at://{}", handle)],
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
    }))
    .into_response()
}

pub async fn verify_did_web(
    did: &str,
    hostname: &str,
    handle: &str,
    expected_signing_key: Option<&str>,
) -> Result<(), String> {
    let subdomain_host = format!("{}.{}", handle, hostname);
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
        if suffix == expected_suffix {
            return Ok(());
        } else {
            return Err(format!(
                "Invalid DID path for this PDS. Expected {}",
                expected_suffix
            ));
        }
    }
    let expected_signing_key = expected_signing_key.ok_or_else(|| {
        "External did:web requires a pre-reserved signing key. Call com.atproto.server.reserveSigningKey first, configure your DID document with the returned key, then provide the signingKey in createAccount.".to_string()
    })?;
    let parts: Vec<&str> = did.split(':').collect();
    if parts.len() < 3 || parts[0] != "did" || parts[1] != "web" {
        return Err("Invalid did:web format".into());
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
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| format!("Failed to create client: {}", e))?;
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch DID doc: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("Failed to fetch DID doc: HTTP {}", resp.status()));
    }
    let doc: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse DID doc: {}", e))?;
    let services = doc["service"]
        .as_array()
        .ok_or("No services found in DID doc")?;
    let pds_endpoint = format!("https://{}", hostname);
    let has_valid_service = services
        .iter()
        .any(|s| s["type"] == "AtprotoPersonalDataServer" && s["serviceEndpoint"] == pds_endpoint);
    if !has_valid_service {
        return Err(format!(
            "DID document does not list this PDS ({}) as AtprotoPersonalDataServer",
            pds_endpoint
        ));
    }
    let verification_methods = doc["verificationMethod"]
        .as_array()
        .ok_or("No verificationMethod found in DID doc")?;
    let expected_multibase = expected_signing_key
        .strip_prefix("did:key:")
        .ok_or("Invalid signing key format")?;
    let has_matching_key = verification_methods.iter().any(|vm| {
        vm["publicKeyMultibase"]
            .as_str()
            .map(|pk| pk == expected_multibase)
            .unwrap_or(false)
    });
    if !has_matching_key {
        return Err(format!(
            "DID document verification key does not match reserved signing key. Expected publicKeyMultibase: {}",
            expected_multibase
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
#[serde(rename_all = "camelCase")]
pub struct Services {
    #[serde(rename = "atproto_pds")]
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
    headers: axum::http::HeaderMap,
) -> Response {
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationRequired"})),
            )
                .into_response();
        }
    };
    let auth_user =
        match crate::auth::validate_bearer_token_allow_deactivated(&state.db, &token).await {
            Ok(user) => user,
            Err(e) => return ApiError::from(e).into_response(),
        };
    let user = match sqlx::query!(
        "SELECT handle FROM users u JOIN user_keys k ON u.id = k.user_id WHERE u.did = $1",
        auth_user.did
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(row)) => row,
        _ => return ApiError::InternalError.into_response(),
    };
    let key_bytes = match auth_user.key_bytes {
        Some(kb) => kb,
        None => {
            return ApiError::AuthenticationFailedMsg(
                "OAuth tokens cannot get DID credentials".into(),
            )
            .into_response();
        }
    };
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let pds_endpoint = format!("https://{}", hostname);
    let signing_key = match k256::ecdsa::SigningKey::from_slice(&key_bytes) {
        Ok(k) => k,
        Err(_) => return ApiError::InternalError.into_response(),
    };
    let did_key = signing_key_to_did_key(&signing_key);
    let rotation_keys = if auth_user.did.starts_with("did:web:") {
        vec![]
    } else {
        vec![did_key.clone()]
    };
    (
        StatusCode::OK,
        Json(GetRecommendedDidCredentialsOutput {
            rotation_keys,
            also_known_as: vec![format!("at://{}", user.handle)],
            verification_methods: VerificationMethods { atproto: did_key },
            services: Services {
                atproto_pds: AtprotoPds {
                    service_type: "AtprotoPersonalDataServer".to_string(),
                    endpoint: pds_endpoint,
                },
            },
        }),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct UpdateHandleInput {
    pub handle: String,
}

pub async fn update_handle(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(input): Json<UpdateHandleInput>,
) -> Response {
    let token = match crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => return ApiError::AuthenticationRequired.into_response(),
    };
    let auth_user =
        match crate::auth::validate_bearer_token_allow_deactivated(&state.db, &token).await {
            Ok(user) => user,
            Err(e) => return ApiError::from(e).into_response(),
        };
    if let Err(e) = crate::auth::scope_check::check_identity_scope(
        auth_user.is_oauth,
        auth_user.scope.as_deref(),
        crate::oauth::scopes::IdentityAttr::Handle,
    ) {
        return e;
    }
    let did = auth_user.did;
    let user_id = match sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", did)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(id)) => id,
        _ => return ApiError::InternalError.into_response(),
    };
    let new_handle = input.handle.trim();
    if new_handle.is_empty() {
        return ApiError::InvalidRequest("handle is required".into()).into_response();
    }
    if !new_handle
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({"error": "InvalidHandle", "message": "Handle contains invalid characters"}),
            ),
        )
            .into_response();
    }
    if crate::moderation::has_explicit_slur(new_handle) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidHandle", "message": "Inappropriate language in handle"})),
        )
            .into_response();
    }
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let suffix = format!(".{}", hostname);
    let is_service_domain = crate::handle::is_service_domain_handle(new_handle, &hostname);
    let handle = if is_service_domain {
        let short_part = if new_handle.ends_with(&suffix) {
            new_handle.strip_suffix(&suffix).unwrap_or(new_handle)
        } else {
            new_handle
        };
        if short_part.contains('.') {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "InvalidHandle",
                    "message": "Nested subdomains are not allowed. Use a simple handle without dots."
                })),
            )
                .into_response();
        }
        if new_handle.ends_with(&suffix) {
            new_handle.to_string()
        } else {
            format!("{}.{}", new_handle, hostname)
        }
    } else {
        match crate::handle::verify_handle_ownership(new_handle, &did).await {
            Ok(()) => {}
            Err(crate::handle::HandleResolutionError::NotFound) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "HandleNotAvailable",
                        "message": "Handle verification failed. Please set up DNS TXT record at _atproto.{} or serve your DID at https://{}/.well-known/atproto-did",
                        "handle": new_handle
                    })),
                )
                    .into_response();
            }
            Err(crate::handle::HandleResolutionError::DidMismatch { expected, actual }) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "HandleNotAvailable",
                        "message": format!("Handle points to different DID. Expected {}, got {}", expected, actual)
                    })),
                )
                    .into_response();
            }
            Err(e) => {
                warn!("Handle verification failed: {}", e);
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "HandleNotAvailable",
                        "message": format!("Handle verification failed: {}", e)
                    })),
                )
                    .into_response();
            }
        }
        new_handle.to_string()
    };
    let old_handle = sqlx::query_scalar!("SELECT handle FROM users WHERE id = $1", user_id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
    let existing = sqlx::query!(
        "SELECT id FROM users WHERE handle = $1 AND id != $2",
        handle,
        user_id
    )
    .fetch_optional(&state.db)
    .await;
    if let Ok(Some(_)) = existing {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "HandleTaken", "message": "Handle is already in use"})),
        )
            .into_response();
    }
    let result = sqlx::query!(
        "UPDATE users SET handle = $1 WHERE id = $2",
        handle,
        user_id
    )
    .execute(&state.db)
    .await;
    match result {
        Ok(_) => {
            if let Some(old) = old_handle {
                let _ = state.cache.delete(&format!("handle:{}", old)).await;
            }
            let _ = state.cache.delete(&format!("handle:{}", handle)).await;
            if let Err(e) =
                crate::api::repo::record::sequence_identity_event(&state, &did, Some(&handle)).await
            {
                warn!("Failed to sequence identity event for handle update: {}", e);
            }
            if let Err(e) = update_plc_handle(&state, &did, &handle).await {
                warn!("Failed to update PLC handle: {}", e);
            }
            (StatusCode::OK, Json(json!({}))).into_response()
        }
        Err(e) => {
            error!("DB error updating handle: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response()
        }
    }
}

async fn update_plc_handle(
    state: &AppState,
    did: &str,
    new_handle: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !did.starts_with("did:plc:") {
        return Ok(());
    }
    let user_row = sqlx::query!(
        r#"SELECT u.id, uk.key_bytes, uk.encryption_version
           FROM users u
           JOIN user_keys uk ON u.id = uk.user_id
           WHERE u.did = $1"#,
        did
    )
    .fetch_optional(&state.db)
    .await?;
    let user_row = match user_row {
        Some(r) => r,
        None => return Ok(()),
    };
    let key_bytes = crate::config::decrypt_key(&user_row.key_bytes, user_row.encryption_version)?;
    let signing_key = k256::ecdsa::SigningKey::from_slice(&key_bytes)?;
    let plc_client = crate::plc::PlcClient::new(None);
    let last_op = plc_client.get_last_op(did).await?;
    let new_also_known_as = vec![format!("at://{}", new_handle)];
    let update_op =
        crate::plc::create_update_op(&last_op, None, None, Some(new_also_known_as), None)?;
    let signed_op = crate::plc::sign_operation(&update_op, &signing_key)?;
    plc_client.send_operation(did, &signed_op).await?;
    Ok(())
}

pub async fn well_known_atproto_did(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let host = match headers.get("host").and_then(|h| h.to_str().ok()) {
        Some(h) => h,
        None => return (StatusCode::BAD_REQUEST, "Missing host header").into_response(),
    };
    let handle = host.split(':').next().unwrap_or(host);
    let user = sqlx::query!("SELECT did FROM users WHERE handle = $1", handle)
        .fetch_optional(&state.db)
        .await;
    match user {
        Ok(Some(row)) => row.did.into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "Handle not found").into_response(),
        Err(e) => {
            error!("DB error in well-known atproto-did: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response()
        }
    }
}
