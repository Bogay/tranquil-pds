use crate::api::ApiError;
use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::Utc;
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
    headers: axum::http::HeaderMap,
    Json(input): Json<UpdateDidDocumentInput>,
) -> Response {
    let extracted = match crate::auth::extract_auth_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => return ApiError::AuthenticationRequired.into_response(),
    };
    let dpop_proof = headers.get("DPoP").and_then(|h| h.to_str().ok());
    let http_uri = format!(
        "https://{}/xrpc/_account.updateDidDocument",
        std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string())
    );
    let auth_user = match crate::auth::validate_token_with_dpop(
        &state.db,
        &extracted.token,
        extracted.is_dpop,
        dpop_proof,
        "POST",
        &http_uri,
        true,
    )
    .await
    {
        Ok(user) => user,
        Err(e) => return ApiError::from(e).into_response(),
    };

    if !auth_user.did.starts_with("did:web:") {
        return ApiError::InvalidRequest(
            "DID document updates are only available for did:web accounts".into(),
        )
        .into_response();
    }

    let user = match sqlx::query!(
        "SELECT id, handle, deactivated_at FROM users WHERE did = $1",
        &auth_user.did
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return ApiError::AccountNotFound.into_response(),
        Err(e) => {
            tracing::error!("DB error getting user: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };

    if user.deactivated_at.is_some() {
        return ApiError::AccountDeactivated.into_response();
    }

    if let Some(ref methods) = input.verification_methods {
        if methods.is_empty() {
            return ApiError::InvalidRequest("verification_methods cannot be empty".into())
                .into_response();
        }
        for method in methods {
            if method.id.is_empty() {
                return ApiError::InvalidRequest("verification method id is required".into())
                    .into_response();
            }
            if method.method_type != "Multikey" {
                return ApiError::InvalidRequest(
                    "verification method type must be 'Multikey'".into(),
                )
                .into_response();
            }
            if !method.public_key_multibase.starts_with('z') {
                return ApiError::InvalidRequest(
                    "publicKeyMultibase must start with 'z' (base58btc)".into(),
                )
                .into_response();
            }
            if method.public_key_multibase.len() < 40 {
                return ApiError::InvalidRequest(
                    "publicKeyMultibase appears too short for a valid key".into(),
                )
                .into_response();
            }
        }
    }

    if let Some(ref handles) = input.also_known_as {
        for handle in handles {
            if !handle.starts_with("at://") {
                return ApiError::InvalidRequest("alsoKnownAs entries must be at:// URIs".into())
                    .into_response();
            }
        }
    }

    if let Some(ref endpoint) = input.service_endpoint {
        let endpoint = endpoint.trim();
        if !endpoint.starts_with("https://") {
            return ApiError::InvalidRequest("serviceEndpoint must start with https://".into())
                .into_response();
        }
    }

    let verification_methods_json = input
        .verification_methods
        .as_ref()
        .map(|v| serde_json::to_value(v).unwrap_or_default());

    let also_known_as: Option<Vec<String>> = input.also_known_as.clone();

    let now = Utc::now();

    let upsert_result = sqlx::query!(
        r#"
        INSERT INTO did_web_overrides (user_id, verification_methods, also_known_as, updated_at)
        VALUES ($1, COALESCE($2, '[]'::jsonb), COALESCE($3, '{}'::text[]), $4)
        ON CONFLICT (user_id) DO UPDATE SET
            verification_methods = CASE WHEN $2 IS NOT NULL THEN $2 ELSE did_web_overrides.verification_methods END,
            also_known_as = CASE WHEN $3 IS NOT NULL THEN $3 ELSE did_web_overrides.also_known_as END,
            updated_at = $4
        "#,
        user.id,
        verification_methods_json,
        also_known_as.as_deref(),
        now
    )
    .execute(&state.db)
    .await;

    if let Err(e) = upsert_result {
        tracing::error!("DB error upserting did_web_overrides: {:?}", e);
        return ApiError::InternalError(None).into_response();
    }

    if let Some(ref endpoint) = input.service_endpoint {
        let endpoint_clean = endpoint.trim().trim_end_matches('/');
        let update_result = sqlx::query!(
            "UPDATE users SET migrated_to_pds = $1, migrated_at = $2 WHERE did = $3",
            endpoint_clean,
            now,
            &auth_user.did
        )
        .execute(&state.db)
        .await;

        if let Err(e) = update_result {
            tracing::error!("DB error updating service endpoint: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    }

    let did_doc = build_did_document(&state.db, &auth_user.did).await;

    tracing::info!("Updated DID document for {}", &auth_user.did);

    (
        StatusCode::OK,
        Json(UpdateDidDocumentOutput {
            success: true,
            did_document: did_doc,
        }),
    )
        .into_response()
}

pub async fn get_did_document(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let extracted = match crate::auth::extract_auth_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        Some(t) => t,
        None => return ApiError::AuthenticationRequired.into_response(),
    };
    let dpop_proof = headers.get("DPoP").and_then(|h| h.to_str().ok());
    let http_uri = format!(
        "https://{}/xrpc/_account.getDidDocument",
        std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string())
    );
    let auth_user = match crate::auth::validate_token_with_dpop(
        &state.db,
        &extracted.token,
        extracted.is_dpop,
        dpop_proof,
        "GET",
        &http_uri,
        true,
    )
    .await
    {
        Ok(user) => user,
        Err(e) => return ApiError::from(e).into_response(),
    };

    if !auth_user.did.starts_with("did:web:") {
        return ApiError::InvalidRequest(
            "This endpoint is only available for did:web accounts".into(),
        )
        .into_response();
    }

    let did_doc = build_did_document(&state.db, &auth_user.did).await;

    (StatusCode::OK, Json(json!({ "didDocument": did_doc }))).into_response()
}

async fn build_did_document(db: &sqlx::PgPool, did: &str) -> serde_json::Value {
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());

    let user = match sqlx::query!(
        "SELECT id, handle, migrated_to_pds FROM users WHERE did = $1",
        did
    )
    .fetch_optional(db)
    .await
    {
        Ok(Some(row)) => row,
        _ => {
            return json!({
                "error": "User not found"
            });
        }
    };

    let overrides = sqlx::query!(
        "SELECT verification_methods, also_known_as FROM did_web_overrides WHERE user_id = $1",
        user.id
    )
    .fetch_optional(db)
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

    let key_row = sqlx::query!(
        "SELECT key_bytes, encryption_version FROM user_keys WHERE user_id = $1",
        user.id
    )
    .fetch_optional(db)
    .await;

    let public_key_multibase = match key_row {
        Ok(Some(row)) => match crate::config::decrypt_key(&row.key_bytes, row.encryption_version) {
            Ok(key_bytes) => crate::api::identity::did::get_public_key_multibase(&key_bytes)
                .unwrap_or_else(|_| "error".to_string()),
            Err(_) => "error".to_string(),
        },
        _ => "error".to_string(),
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
