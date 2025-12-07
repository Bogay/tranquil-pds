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
use k256::SecretKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;
use std::sync::Arc;
use tracing::{error, info};

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
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({"error": "InvalidHandle", "message": "Handle contains invalid characters"}),
            ),
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

    let exists_query = sqlx::query("SELECT 1 FROM users WHERE handle = $1")
        .bind(&input.handle)
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
            sqlx::query("SELECT available_uses FROM invite_codes WHERE code = $1 FOR UPDATE")
                .bind(code)
                .fetch_optional(&mut *tx)
                .await;

        match invite_query {
            Ok(Some(row)) => {
                let uses: i32 = row.get("available_uses");
                if uses <= 0 {
                    return (StatusCode::BAD_REQUEST, Json(json!({"error": "InvalidInviteCode", "message": "Invite code exhausted"}))).into_response();
                }

                let update_invite = sqlx::query(
                    "UPDATE invite_codes SET available_uses = available_uses - 1 WHERE code = $1",
                )
                .bind(code)
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
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
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
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response();
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

    let commit = Commit::new_unsigned(did_obj, mst_root, rev, None);

    let commit_bytes = match commit.to_cbor() {
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

    let repo_insert = sqlx::query("INSERT INTO repos (user_id, repo_root_cid) VALUES ($1, $2)")
        .bind(user_id)
        .bind(commit_cid.to_string())
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
            sqlx::query("INSERT INTO invite_code_uses (code, used_by_user) VALUES ($1, $2)")
                .bind(code)
                .bind(user_id)
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

    let access_jwt = crate::auth::create_access_token(&did, &secret_key_bytes[..]).map_err(|e| {
        error!("Error creating access token: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response()
    });
    let access_jwt = match access_jwt {
        Ok(t) => t,
        Err(r) => return r,
    };

    let refresh_jwt = crate::auth::create_refresh_token(&did, &secret_key_bytes[..]).map_err(|e| {
        error!("Error creating refresh token: {:?}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "InternalError"})),
        )
            .into_response()
    });
    let refresh_jwt = match refresh_jwt {
        Ok(t) => t,
        Err(r) => return r,
    };

    let session_insert =
        sqlx::query("INSERT INTO sessions (access_jwt, refresh_jwt, did) VALUES ($1, $2, $3)")
            .bind(&access_jwt)
            .bind(&refresh_jwt)
            .bind(&did)
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

    (
        StatusCode::OK,
        Json(CreateAccountOutput {
            access_jwt,
            refresh_jwt,
            handle: input.handle,
            did,
        }),
    )
        .into_response()
}
