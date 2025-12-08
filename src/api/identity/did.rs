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
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }

    let token = auth_header
        .unwrap()
        .to_str()
        .unwrap_or("")
        .replace("Bearer ", "");

    let session = sqlx::query(
        r#"
        SELECT s.did, k.key_bytes, u.handle
        FROM sessions s
        JOIN users u ON s.did = u.did
        JOIN user_keys k ON u.id = k.user_id
        WHERE s.access_jwt = $1
        "#,
    )
    .bind(&token)
    .fetch_optional(&state.db)
    .await;

    let (_did, key_bytes, handle) = match session {
        Ok(Some(row)) => (
            row.get::<String, _>("did"),
            row.get::<Vec<u8>, _>("key_bytes"),
            row.get::<String, _>("handle"),
        ),
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationFailed"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error in get_recommended_did_credentials: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    if let Err(_) = crate::auth::verify_token(&token, &key_bytes) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationFailed", "message": "Invalid token signature"})),
        )
            .into_response();
    }

    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let pds_endpoint = format!("https://{}", hostname);

    let secret_key = match k256::SecretKey::from_slice(&key_bytes) {
        Ok(k) => k,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let public_key = secret_key.public_key();
    let encoded = public_key.to_encoded_point(true);
    let did_key = format!(
        "did:key:zQ3sh{}",
        multibase::encode(multibase::Base::Base58Btc, encoded.as_bytes())
            .chars()
            .skip(1)
            .collect::<String>()
    );

    (
        StatusCode::OK,
        Json(GetRecommendedDidCredentialsOutput {
            rotation_keys: vec![did_key.clone()],
            also_known_as: vec![format!("at://{}", handle)],
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
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationRequired"})),
        )
            .into_response();
    }

    let token = auth_header
        .unwrap()
        .to_str()
        .unwrap_or("")
        .replace("Bearer ", "");

    let session = sqlx::query(
        r#"
        SELECT s.did, k.key_bytes, u.id as user_id
        FROM sessions s
        JOIN users u ON s.did = u.did
        JOIN user_keys k ON u.id = k.user_id
        WHERE s.access_jwt = $1
        "#,
    )
    .bind(&token)
    .fetch_optional(&state.db)
    .await;

    let (_did, key_bytes, user_id) = match session {
        Ok(Some(row)) => (
            row.get::<String, _>("did"),
            row.get::<Vec<u8>, _>("key_bytes"),
            row.get::<uuid::Uuid, _>("user_id"),
        ),
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "AuthenticationFailed"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("DB error in update_handle: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    if let Err(_) = crate::auth::verify_token(&token, &key_bytes) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "AuthenticationFailed", "message": "Invalid token signature"})),
        )
            .into_response();
    }

    let new_handle = input.handle.trim();
    if new_handle.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidRequest", "message": "handle is required"})),
        )
            .into_response();
    }

    if !new_handle
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidHandle", "message": "Handle contains invalid characters"})),
        )
            .into_response();
    }

    let existing = sqlx::query("SELECT id FROM users WHERE handle = $1 AND id != $2")
        .bind(new_handle)
        .bind(user_id)
        .fetch_optional(&state.db)
        .await;

    if let Ok(Some(_)) = existing {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "HandleTaken", "message": "Handle is already in use"})),
        )
            .into_response();
    }

    let result = sqlx::query("UPDATE users SET handle = $1 WHERE id = $2")
        .bind(new_handle)
        .bind(user_id)
        .execute(&state.db)
        .await;

    match result {
        Ok(_) => (StatusCode::OK, Json(json!({}))).into_response(),
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
