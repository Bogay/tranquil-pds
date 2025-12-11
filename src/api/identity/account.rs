use super::did::verify_did_web;
use crate::state::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use bcrypt::{DEFAULT_COST, hash};
use jacquard::types::{did::Did, integer::LimitedU32, string::Tid};
use jacquard_repo::{commit::Commit, mst::Mst, storage::BlockStore};
use k256::{ecdsa::SigningKey, SecretKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tracing::{error, info, warn};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountInput {
    pub handle: String,
    pub email: String,
    pub password: String,
    pub invite_code: Option<String>,
    pub did: Option<String>,
    pub signing_key: Option<String>,
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
    info!("create_account called");
    if input.handle.contains('!') || input.handle.contains('@') {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({"error": "InvalidHandle", "message": "Handle contains invalid characters"}),
            ),
        )
            .into_response();
    }

    if !crate::api::validation::is_valid_email(&input.email) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "InvalidEmail", "message": "Invalid email format"})),
        )
            .into_response();
    }

    let did = if let Some(d) = &input.did {
        if d.trim().is_empty() {
            format!("did:plc:{}", uuid::Uuid::new_v4())
        } else {
            let hostname =
                std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
            if let Err(e) = verify_did_web(d, &hostname, &input.handle).await {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "InvalidDid", "message": e})),
                )
                    .into_response();
            }
            d.clone()
        }
    } else {
        format!("did:plc:{}", uuid::Uuid::new_v4())
    };

    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            error!("Error starting transaction: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let exists_query = sqlx::query!("SELECT 1 as one FROM users WHERE handle = $1", input.handle)
        .fetch_optional(&mut *tx)
        .await;

    match exists_query {
        Ok(Some(_)) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "HandleTaken", "message": "Handle already taken"})),
            )
                .into_response();
        }
        Err(e) => {
            error!("Error checking handle: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
        Ok(None) => {}
    }

    if let Some(code) = &input.invite_code {
        let invite_query =
            sqlx::query!("SELECT available_uses FROM invite_codes WHERE code = $1 FOR UPDATE", code)
                .fetch_optional(&mut *tx)
                .await;

        match invite_query {
            Ok(Some(row)) => {
                if row.available_uses <= 0 {
                    return (StatusCode::BAD_REQUEST, Json(json!({"error": "InvalidInviteCode", "message": "Invite code exhausted"}))).into_response();
                }

                let update_invite = sqlx::query!(
                    "UPDATE invite_codes SET available_uses = available_uses - 1 WHERE code = $1",
                    code
                )
                .execute(&mut *tx)
                .await;

                if let Err(e) = update_invite {
                    error!("Error updating invite code: {:?}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "InternalError"})),
                    )
                        .into_response();
                }
            }
            Ok(None) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "InvalidInviteCode", "message": "Invite code not found"})),
                )
                    .into_response();
            }
            Err(e) => {
                error!("Error checking invite code: {:?}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "InternalError"})),
                )
                    .into_response();
            }
        }
    }

    let password_hash = match hash(&input.password, DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            error!("Error hashing password: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let user_insert = sqlx::query!(
        "INSERT INTO users (handle, email, did, password_hash) VALUES ($1, $2, $3, $4) RETURNING id",
        input.handle,
        input.email,
        did,
        password_hash
    )
        .fetch_one(&mut *tx)
        .await;

    let user_id = match user_insert {
        Ok(row) => row.id,
        Err(e) => {
            error!("Error inserting user: {:?}", e);
            // TODO: Check for unique constraint violation on email/did specifically
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let (secret_key_bytes, reserved_key_id): (Vec<u8>, Option<uuid::Uuid>) =
        if let Some(signing_key_did) = &input.signing_key {
            let reserved = sqlx::query!(
                r#"
                SELECT id, private_key_bytes
                FROM reserved_signing_keys
                WHERE public_key_did_key = $1
                  AND used_at IS NULL
                  AND expires_at > NOW()
                FOR UPDATE
                "#,
                signing_key_did
            )
            .fetch_optional(&mut *tx)
            .await;

            match reserved {
                Ok(Some(row)) => (row.private_key_bytes, Some(row.id)),
                Ok(None) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "InvalidSigningKey",
                            "message": "Signing key not found, already used, or expired"
                        })),
                    )
                        .into_response();
                }
                Err(e) => {
                    error!("Error looking up reserved signing key: {:?}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "InternalError"})),
                    )
                        .into_response();
                }
            }
        } else {
            let secret_key = SecretKey::random(&mut OsRng);
            (secret_key.to_bytes().to_vec(), None)
        };

    let encrypted_key_bytes = match crate::config::encrypt_key(&secret_key_bytes) {
        Ok(enc) => enc,
        Err(e) => {
            error!("Error encrypting user key: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let key_insert = sqlx::query!(
        "INSERT INTO user_keys (user_id, key_bytes, encryption_version, encrypted_at) VALUES ($1, $2, $3, NOW())",
        user_id,
        &encrypted_key_bytes[..],
        crate::config::ENCRYPTION_VERSION
    )
    .execute(&mut *tx)
    .await;

    if let Err(e) = key_insert {
        error!("Error inserting user key: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    if let Some(key_id) = reserved_key_id {
        let mark_used = sqlx::query!(
            "UPDATE reserved_signing_keys SET used_at = NOW() WHERE id = $1",
            key_id
        )
        .execute(&mut *tx)
        .await;

        if let Err(e) = mark_used {
            error!("Error marking reserved key as used: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    }

    let mst = Mst::new(Arc::new(state.block_store.clone()));
    let mst_root = match mst.persist().await {
        Ok(c) => c,
        Err(e) => {
            error!("Error persisting MST: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let did_obj = match Did::new(&did) {
        Ok(d) => d,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Invalid DID"})),
            )
                .into_response();
        }
    };

    let rev = Tid::now(LimitedU32::MIN);

    let unsigned_commit = Commit::new_unsigned(did_obj, mst_root, rev, None);

    let signing_key = match SigningKey::from_slice(&secret_key_bytes) {
        Ok(k) => k,
        Err(e) => {
            error!("Error creating signing key: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let signed_commit = match unsigned_commit.sign(&signing_key) {
        Ok(c) => c,
        Err(e) => {
            error!("Error signing genesis commit: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let commit_bytes = match signed_commit.to_cbor() {
        Ok(b) => b,
        Err(e) => {
            error!("Error serializing genesis commit: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let commit_cid = match state.block_store.put(&commit_bytes).await {
        Ok(c) => c,
        Err(e) => {
            error!("Error saving genesis commit: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };

    let commit_cid_str = commit_cid.to_string();
    let repo_insert = sqlx::query!("INSERT INTO repos (user_id, repo_root_cid) VALUES ($1, $2)", user_id, commit_cid_str)
        .execute(&mut *tx)
        .await;

    if let Err(e) = repo_insert {
        error!("Error initializing repo: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    if let Some(code) = &input.invite_code {
        let use_insert =
            sqlx::query!("INSERT INTO invite_code_uses (code, used_by_user) VALUES ($1, $2)", code, user_id)
                .execute(&mut *tx)
                .await;

        if let Err(e) = use_insert {
            error!("Error recording invite usage: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    }

    let access_meta = crate::auth::create_access_token_with_metadata(&did, &secret_key_bytes[..]).map_err(|e| {
        error!("Error creating access token: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response()
    });
    let access_meta = match access_meta {
        Ok(m) => m,
        Err(r) => return r,
    };

    let refresh_meta = crate::auth::create_refresh_token_with_metadata(&did, &secret_key_bytes[..]).map_err(|e| {
        error!("Error creating refresh token: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response()
    });
    let refresh_meta = match refresh_meta {
        Ok(m) => m,
        Err(r) => return r,
    };

    let session_insert =
        sqlx::query!(
            "INSERT INTO session_tokens (did, access_jti, refresh_jti, access_expires_at, refresh_expires_at) VALUES ($1, $2, $3, $4, $5)",
            did,
            access_meta.jti,
            refresh_meta.jti,
            access_meta.expires_at,
            refresh_meta.expires_at
        )
            .execute(&mut *tx)
            .await;

    if let Err(e) = session_insert {
        error!("Error inserting session: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    if let Err(e) = tx.commit().await {
        error!("Error committing transaction: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
    }

    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    if let Err(e) = crate::notifications::enqueue_welcome(&state.db, user_id, &hostname).await {
        warn!("Failed to enqueue welcome notification: {:?}", e);
    }

    (
        StatusCode::OK,
        Json(CreateAccountOutput {
            access_jwt: access_meta.token,
            refresh_jwt: refresh_meta.token,
            handle: input.handle,
            did,
        }),
    )
        .into_response()
}
