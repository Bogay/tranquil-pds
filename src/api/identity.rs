use axum::{
    extract::{State, Path},
    Json,
    response::{IntoResponse, Response},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use crate::state::AppState;
use sqlx::Row;
use bcrypt::{hash, DEFAULT_COST};
use tracing::{info, error};
use jacquard_repo::{mst::Mst, commit::Commit, storage::BlockStore};
use jacquard::types::{string::Tid, did::Did, integer::LimitedU32};
use std::sync::Arc;
use k256::SecretKey;
use rand::rngs::OsRng;
use base64::Engine;

#[derive(Deserialize)]
pub struct CreateAccountInput {
    pub handle: String,
    pub email: String,
    pub password: String,
    #[serde(rename = "inviteCode")]
    pub invite_code: Option<String>,
    pub did: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountOutput {
    pub access_jwt: String,
    pub refresh_jwt: String,
    pub handle: String,
    pub did: String,
}

pub async fn create_account(
    State(state): State<AppState>,
    Json(input): Json<CreateAccountInput>,
) -> Response {
    info!("create_account hit: {}", input.handle);
    if input.handle.contains('!') || input.handle.contains('@') {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "InvalidHandle", "message": "Handle contains invalid characters"}))).into_response();
    }

    let did = if let Some(d) = &input.did {
        if d.trim().is_empty() {
            format!("did:plc:{}", uuid::Uuid::new_v4())
        } else {
             let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
             let _expected_prefix = format!("did:web:{}", hostname);

             // TODO: should verify we are the authority for it if it matches our hostname.
             // TODO: if it's an external did:web, we should technically verify ownership via ServiceAuth, but skipping for now.
             d.clone()
        }
    } else {
        format!("did:plc:{}", uuid::Uuid::new_v4())
    };

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            error!("Error starting transaction: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
        }
    };

    let exists_query = sqlx::query("SELECT 1 FROM users WHERE handle = $1")
        .bind(&input.handle)
        .fetch_optional(&mut *tx)
        .await;

    match exists_query {
        Ok(Some(_)) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "HandleTaken", "message": "Handle already taken"}))).into_response(),
        Err(e) => {
            error!("Error checking handle: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
        }
        Ok(None) => {}
    }

    if let Some(code) = &input.invite_code {
        let invite_query = sqlx::query("SELECT available_uses FROM invite_codes WHERE code = $1 FOR UPDATE")
            .bind(code)
            .fetch_optional(&mut *tx)
            .await;

        match invite_query {
            Ok(Some(row)) => {
                let uses: i32 = row.get("available_uses");
                if uses <= 0 {
                    return (StatusCode::BAD_REQUEST, Json(json!({"error": "InvalidInviteCode", "message": "Invite code exhausted"}))).into_response();
                }

                let update_invite = sqlx::query("UPDATE invite_codes SET available_uses = available_uses - 1 WHERE code = $1")
                    .bind(code)
                    .execute(&mut *tx)
                    .await;

                if let Err(e) = update_invite {
                    error!("Error updating invite code: {:?}", e);
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
                }
            },
            Ok(None) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "InvalidInviteCode", "message": "Invite code not found"}))).into_response(),
            Err(e) => {
                error!("Error checking invite code: {:?}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
            }
        }
    }

    let password_hash = match hash(&input.password, DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            error!("Error hashing password: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
        }
    };

    let user_insert = sqlx::query("INSERT INTO users (handle, email, did, password_hash) VALUES ($1, $2, $3, $4) RETURNING id")
        .bind(&input.handle)
        .bind(&input.email)
        .bind(&did)
        .bind(&password_hash)
        .fetch_one(&mut *tx)
        .await;

    let user_id: uuid::Uuid = match user_insert {
        Ok(row) => row.get("id"),
        Err(e) => {
            error!("Error inserting user: {:?}", e);
             // TODO: Check for unique constraint violation on email/did specifically
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
        }
    };

    let secret_key = SecretKey::random(&mut OsRng);
    let secret_key_bytes = secret_key.to_bytes();

    let key_insert = sqlx::query("INSERT INTO user_keys (user_id, key_bytes) VALUES ($1, $2)")
        .bind(user_id)
        .bind(&secret_key_bytes[..])
        .execute(&mut *tx)
        .await;

    if let Err(e) = key_insert {
        error!("Error inserting user key: {:?}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
    }

    let mst = Mst::new(Arc::new(state.block_store.clone()));
    let mst_root = match mst.root().await {
        Ok(c) => c,
        Err(e) => {
            error!("Error creating MST root: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
        }
    };

    let did_obj = match Did::new(&did) {
        Ok(d) => d,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError", "message": "Invalid DID"}))).into_response(),
    };

    let rev = Tid::now(LimitedU32::MIN);

    let commit = Commit::new_unsigned(
        did_obj,
        mst_root,
        rev,
        None
    );

    let commit_bytes = match commit.to_cbor() {
        Ok(b) => b,
        Err(e) => {
            error!("Error serializing genesis commit: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
        }
    };

    let commit_cid = match state.block_store.put(&commit_bytes).await {
        Ok(c) => c,
        Err(e) => {
            error!("Error saving genesis commit: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
        }
    };

    let repo_insert = sqlx::query("INSERT INTO repos (user_id, repo_root_cid) VALUES ($1, $2)")
        .bind(user_id)
        .bind(commit_cid.to_string())
        .execute(&mut *tx)
        .await;

    if let Err(e) = repo_insert {
        error!("Error initializing repo: {:?}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
    }

    if let Some(code) = &input.invite_code {
        let use_insert = sqlx::query("INSERT INTO invite_code_uses (code, used_by_user) VALUES ($1, $2)")
            .bind(code)
            .bind(user_id)
            .execute(&mut *tx)
            .await;

        if let Err(e) = use_insert {
            error!("Error recording invite usage: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
        }
    }

    let access_jwt = crate::auth::create_access_token(&did, &secret_key_bytes[..]).map_err(|e| {
        error!("Error creating access token: {:?}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response()
    });
    let access_jwt = match access_jwt {
        Ok(t) => t,
        Err(r) => return r,
    };

    let refresh_jwt = crate::auth::create_refresh_token(&did, &secret_key_bytes[..]).map_err(|e| {
        error!("Error creating refresh token: {:?}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response()
    });
    let refresh_jwt = match refresh_jwt {
        Ok(t) => t,
        Err(r) => return r,
    };

    let session_insert = sqlx::query("INSERT INTO sessions (access_jwt, refresh_jwt, did) VALUES ($1, $2, $3)")
        .bind(&access_jwt)
        .bind(&refresh_jwt)
        .bind(&did)
        .execute(&mut *tx)
        .await;

    if let Err(e) = session_insert {
        error!("Error inserting session: {:?}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
    }

    if let Err(e) = tx.commit().await {
        error!("Error committing transaction: {:?}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
    }

    (StatusCode::OK, Json(CreateAccountOutput {
        access_jwt,
        refresh_jwt,
        handle: input.handle,
        did,
    })).into_response()
}

fn get_jwk(key_bytes: &[u8]) -> serde_json::Value {
    use k256::elliptic_curve::sec1::ToEncodedPoint;

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

pub async fn user_did_doc(
    State(state): State<AppState>,
    Path(handle): Path<String>,
) -> Response {
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
        },
        Ok(None) => return (StatusCode::NOT_FOUND, Json(json!({"error": "NotFound"}))).into_response(),
        Err(e) => {
            error!("DB Error: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response()
        },
    };

    if !did.starts_with("did:web:") {
         return (StatusCode::NOT_FOUND, Json(json!({"error": "NotFound", "message": "User is not did:web"}))).into_response();
    }

    let key_row = sqlx::query("SELECT key_bytes FROM user_keys WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await;

    let key_bytes: Vec<u8> = match key_row {
        Ok(Some(row)) => row.get("key_bytes"),
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response(),
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
