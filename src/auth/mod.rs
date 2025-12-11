use serde::{Deserialize, Serialize};
use sqlx::PgPool;

pub mod extractor;
pub mod token;
pub mod verify;

pub use extractor::{BearerAuth, AuthError, extract_bearer_token_from_header};
pub use token::{
    create_access_token, create_refresh_token, create_service_token,
    create_access_token_with_metadata, create_refresh_token_with_metadata,
    TokenWithMetadata,
    TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH, TOKEN_TYPE_SERVICE,
    SCOPE_ACCESS, SCOPE_REFRESH, SCOPE_APP_PASS, SCOPE_APP_PASS_PRIVILEGED,
};
pub use verify::{get_did_from_token, get_jti_from_token, verify_token, verify_access_token, verify_refresh_token};

pub struct AuthenticatedUser {
    pub did: String,
    pub key_bytes: Option<Vec<u8>>,
    pub is_oauth: bool,
}

pub async fn validate_bearer_token(
    db: &PgPool,
    token: &str,
) -> Result<AuthenticatedUser, &'static str> {
    validate_bearer_token_with_options(db, token, false).await
}

pub async fn validate_bearer_token_allow_deactivated(
    db: &PgPool,
    token: &str,
) -> Result<AuthenticatedUser, &'static str> {
    validate_bearer_token_with_options(db, token, true).await
}

async fn validate_bearer_token_with_options(
    db: &PgPool,
    token: &str,
    allow_deactivated: bool,
) -> Result<AuthenticatedUser, &'static str> {
    let did_from_token = get_did_from_token(token).ok();

    if let Some(ref did) = did_from_token {
        if let Some(user) = sqlx::query!(
            "SELECT k.key_bytes, k.encryption_version, u.deactivated_at, u.takedown_ref
             FROM users u
             JOIN user_keys k ON u.id = k.user_id
             WHERE u.did = $1",
            did
        )
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        {
            if !allow_deactivated && user.deactivated_at.is_some() {
                return Err("AccountDeactivated");
            }
            if user.takedown_ref.is_some() {
                return Err("AccountTakedown");
            }

            let decrypted_key = match crate::config::decrypt_key(&user.key_bytes, user.encryption_version) {
                Ok(k) => k,
                Err(_) => return Err("KeyDecryptionFailed"),
            };

            if let Ok(token_data) = verify_access_token(token, &decrypted_key) {
                let session_exists = sqlx::query_scalar!(
                    "SELECT 1 as one FROM session_tokens WHERE did = $1 AND access_jti = $2 AND access_expires_at > NOW()",
                    did,
                    token_data.claims.jti
                )
                .fetch_optional(db)
                .await
                .ok()
                .flatten();

                if session_exists.is_some() {
                    return Ok(AuthenticatedUser {
                        did: did.clone(),
                        key_bytes: Some(decrypted_key),
                        is_oauth: false,
                    });
                }
            }
        }
    }

    if let Ok(oauth_info) = crate::oauth::verify::extract_oauth_token_info(token) {
        if let Some(oauth_token) = sqlx::query!(
            r#"SELECT t.did, t.expires_at, u.deactivated_at, u.takedown_ref
               FROM oauth_token t
               JOIN users u ON t.did = u.did
               WHERE t.token_id = $1"#,
            oauth_info.token_id
        )
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        {
            if !allow_deactivated && oauth_token.deactivated_at.is_some() {
                return Err("AccountDeactivated");
            }
            if oauth_token.takedown_ref.is_some() {
                return Err("AccountTakedown");
            }

            let now = chrono::Utc::now();
            if oauth_token.expires_at > now {
                return Ok(AuthenticatedUser {
                    did: oauth_token.did,
                    key_bytes: None,
                    is_oauth: true,
                });
            }
        }
    }

    Err("AuthenticationFailed")
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: usize,
    pub iat: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lxm: Option<String>,
    pub jti: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Header {
    pub alg: String,
    pub typ: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnsafeClaims {
    pub iss: String,
    pub sub: Option<String>,
}

// fancy boy TokenData equivalent for compatibility/structure
pub struct TokenData<T> {
    pub claims: T,
}
