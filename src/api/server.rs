use axum::{
    extract::State,
    Json,
    response::{IntoResponse, Response},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use crate::state::AppState;
use sqlx::Row;
use bcrypt::{hash, verify, DEFAULT_COST};
use tracing::{info, error, warn};
use jacquard_repo::{mst::Mst, commit::Commit, storage::BlockStore};
use jacquard::types::{string::Tid, did::Did, integer::LimitedU32};
use std::sync::Arc;

#[derive(Deserialize)]
pub struct CreateAccountInput {
    pub handle: String,
    pub email: String,
    pub password: String,
    #[serde(rename = "inviteCode")]
    pub invite_code: Option<String>,
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

    let did = format!("did:plc:{}", uuid::Uuid::new_v4());

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
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
        }
    };

    let store = Arc::new(state.block_store.clone());
    let mst = Mst::new(store.clone());
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

    let access_jwt = crate::auth::create_access_token(&did).map_err(|e| {
        error!("Error creating access token: {:?}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response()
    });
    let access_jwt = match access_jwt {
        Ok(t) => t,
        Err(r) => return r,
    };

    let refresh_jwt = crate::auth::create_refresh_token(&did).map_err(|e| {
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

#[derive(Deserialize)]
pub struct CreateSessionInput {
    pub identifier: String,
    pub password: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSessionOutput {
    pub access_jwt: String,
    pub refresh_jwt: String,
    pub handle: String,
    pub did: String,
}

pub async fn create_session(
    State(state): State<AppState>,
    Json(input): Json<CreateSessionInput>,
) -> Response {
    info!("create_session: identifier='{}'", input.identifier);

    let user_row = sqlx::query("SELECT did, handle, password_hash FROM users WHERE handle = $1 OR email = $1")
        .bind(&input.identifier)
        .fetch_optional(&state.db)
        .await;

    match user_row {
        Ok(Some(row)) => {
            let stored_hash: String = row.get("password_hash");

            if verify(&input.password, &stored_hash).unwrap_or(false) {
                let did: String = row.get("did");
                let handle: String = row.get("handle");

                let access_jwt = match crate::auth::create_access_token(&did) {
                    Ok(t) => t,
                    Err(e) => {
                        error!("Failed to create access token: {:?}", e);
                        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
                    }
                };

                let refresh_jwt = match crate::auth::create_refresh_token(&did) {
                    Ok(t) => t,
                    Err(e) => {
                        error!("Failed to create refresh token: {:?}", e);
                        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
                    }
                };

                let session_insert = sqlx::query("INSERT INTO sessions (access_jwt, refresh_jwt, did) VALUES ($1, $2, $3)")
                    .bind(&access_jwt)
                    .bind(&refresh_jwt)
                    .bind(&did)
                    .execute(&state.db)
                    .await;

                match session_insert {
                    Ok(_) => {
                        return (StatusCode::OK, Json(CreateSessionOutput {
                            access_jwt,
                            refresh_jwt,
                            handle,
                            did,
                        })).into_response();
                    },
                    Err(e) => {
                        error!("Failed to insert session: {:?}", e);
                        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
                    }
                }
            } else {
                warn!("Password verification failed for identifier: {}", input.identifier);
            }
        },
        Ok(None) => {
            warn!("User not found for identifier: {}", input.identifier);
        },
        Err(e) => {
            error!("Database error fetching user: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
        }
    }

    (StatusCode::UNAUTHORIZED, Json(json!({"error": "AuthenticationFailed", "message": "Invalid identifier or password"}))).into_response()
}

pub async fn get_session(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "AuthenticationRequired"}))).into_response();
    }

    let token = auth_header.unwrap().to_str().unwrap_or("").replace("Bearer ", "");

    if let Err(_) = crate::auth::verify_token(&token) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "AuthenticationFailed", "message": "Invalid token"}))).into_response();
    }

    let result = sqlx::query(
        r#"
        SELECT u.handle, u.did, u.email
        FROM sessions s
        JOIN users u ON s.did = u.did
        WHERE s.access_jwt = $1
        "#
    )
    .bind(token)
    .fetch_optional(&state.db)
    .await;

    match result {
        Ok(Some(row)) => {
            let handle: String = row.get("handle");
            let did: String = row.get("did");
            let email: String = row.get("email");

            return (StatusCode::OK, Json(json!({
                "handle": handle,
                "did": did,
                "email": email,
                "didDoc": {}
            }))).into_response();
        },
        Ok(None) => {
            return (StatusCode::UNAUTHORIZED, Json(json!({"error": "AuthenticationFailed"}))).into_response();
        },
        Err(e) => {
            error!("Database error in get_session: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
        }
    }
}

pub async fn delete_session(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "AuthenticationRequired"}))).into_response();
    }

    let token = auth_header.unwrap().to_str().unwrap_or("").replace("Bearer ", "");

    let result = sqlx::query("DELETE FROM sessions WHERE access_jwt = $1")
        .bind(token)
        .execute(&state.db)
        .await;

    match result {
        Ok(res) => {
            if res.rows_affected() > 0 {
                return (StatusCode::OK, Json(json!({}))).into_response();
            }
        },
        Err(e) => {
            error!("Database error in delete_session: {:?}", e);
        }
    }

    (StatusCode::UNAUTHORIZED, Json(json!({"error": "AuthenticationFailed"}))).into_response()
}

pub async fn refresh_session(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let auth_header = headers.get("Authorization");
    if auth_header.is_none() {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "AuthenticationRequired"}))).into_response();
    }

    let refresh_token = auth_header.unwrap().to_str().unwrap_or("").replace("Bearer ", "");

    if let Err(_) = crate::auth::verify_token(&refresh_token) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "AuthenticationFailed", "message": "Invalid refresh token"}))).into_response();
    }

    let session = sqlx::query("SELECT did FROM sessions WHERE refresh_jwt = $1")
        .bind(&refresh_token)
        .fetch_optional(&state.db)
        .await;

    match session {
        Ok(Some(session_row)) => {
            let did: String = session_row.get("did");
            let new_access_jwt = match crate::auth::create_access_token(&did) {
                Ok(t) => t,
                Err(e) => {
                    error!("Failed to create access token: {:?}", e);
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
                }
            };
            let new_refresh_jwt = match crate::auth::create_refresh_token(&did) {
                Ok(t) => t,
                Err(e) => {
                    error!("Failed to create refresh token: {:?}", e);
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
                }
            };

            let update = sqlx::query("UPDATE sessions SET access_jwt = $1, refresh_jwt = $2 WHERE refresh_jwt = $3")
                .bind(&new_access_jwt)
                .bind(&new_refresh_jwt)
                .bind(&refresh_token)
                .execute(&state.db)
                .await;

            match update {
                Ok(_) => {
                     let user = sqlx::query("SELECT handle FROM users WHERE did = $1")
                        .bind(&did)
                        .fetch_optional(&state.db)
                        .await;

                    match user {
                        Ok(Some(u)) => {
                            let handle: String = u.get("handle");
                            return (StatusCode::OK, Json(json!({
                                "accessJwt": new_access_jwt,
                                "refreshJwt": new_refresh_jwt,
                                "handle": handle,
                                "did": did
                            }))).into_response();
                        },
                        Ok(None) => {
                            error!("User not found for existing session: {}", did);
                            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
                        },
                        Err(e) => {
                            error!("Database error fetching user: {:?}", e);
                            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
                        }
                    }
                },
                Err(e) => {
                    error!("Database error updating session: {:?}", e);
                    return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
                }
            }
        },
        Ok(None) => {
            return (StatusCode::UNAUTHORIZED, Json(json!({"error": "AuthenticationFailed", "message": "Invalid refresh token"}))).into_response();
        },
        Err(e) => {
            error!("Database error fetching session: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "InternalError"}))).into_response();
        }
    }
}
