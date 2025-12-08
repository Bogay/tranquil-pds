use crate::state::AppState;
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::Engine;
use k256::SecretKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use reqwest;
use serde::Deserialize;
use serde_json::json;
use sqlx::Row;
use tracing::error;

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

    let user = sqlx::query("SELECT did FROM users WHERE handle = $1")
        .bind(handle)
        .fetch_optional(&state.db)
        .await;

    match user {
        Ok(Some(row)) => {
            let did: String = row.get("did");
            (StatusCode::OK, Json(json!({ "did": did }))).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "HandleNotFound", "message": "Unable to resolve handle"})),
        )
            .into_response(),
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

pub fn get_jwk(key_bytes: &[u8]) -> serde_json::Value {
    let secret_key = SecretKey::from_slice(key_bytes).expect("Invalid key length");
    let public_key = secret_key.public_key();
    let encoded = public_key.to_encoded_point(false);
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(encoded.x().unwrap());
    let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(encoded.y().unwrap());

    json!({
        "kty": "EC",
        "crv": "secp256k1",
        "x": x,
        "y": y
    })
}

pub async fn well_known_did(State(_state): State<AppState>) -> impl IntoResponse {
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    // Kinda for local dev, encode hostname if it contains port
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
}

pub async fn user_did_doc(State(state): State<AppState>, Path(handle): Path<String>) -> Response {
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());

    let user = sqlx::query("SELECT id, did FROM users WHERE handle = $1")
        .bind(&handle)
        .fetch_optional(&state.db)
        .await;

    let (user_id, did) = match user {
        Ok(Some(row)) => {
            let id: uuid::Uuid = row.get("id");
            let d: String = row.get("did");
            (id, d)
        }
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

    let key_row = sqlx::query("SELECT key_bytes FROM user_keys WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await;

    let key_bytes: Vec<u8> = match key_row {
        Ok(Some(row)) => row.get("key_bytes"),
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let jwk = get_jwk(&key_bytes);

    Json(json!({
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
        "id": did,
        "alsoKnownAs": [format!("at://{}", handle)],
        "verificationMethod": [{
            "id": format!("{}#atproto", did),
            "type": "JsonWebKey2020",
            "controller": did,
            "publicKeyJwk": jwk
        }],
        "service": [{
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": format!("https://{}", hostname)
        }]
    })).into_response()
}

pub async fn verify_did_web(did: &str, hostname: &str, handle: &str) -> Result<(), String> {
    let expected_prefix = if hostname.contains(':') {
        format!("did:web:{}", hostname.replace(':', "%3A"))
    } else {
        format!("did:web:{}", hostname)
    };

    if did.starts_with(&expected_prefix) {
        let suffix = &did[expected_prefix.len()..];
        let expected_suffix = format!(":u:{}", handle);
        if suffix == expected_suffix {
            Ok(())
        } else {
            Err(format!(
                "Invalid DID path for this PDS. Expected {}",
                expected_suffix
            ))
        }
    } else {
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

        let has_valid_service = services.iter().any(|s| {
            s["type"] == "AtprotoPersonalDataServer" && s["serviceEndpoint"] == pds_endpoint
        });

        if has_valid_service {
            Ok(())
        } else {
            Err(format!(
                "DID document does not list this PDS ({}) as AtprotoPersonalDataServer",
                pds_endpoint
            ))
        }
    }
}
