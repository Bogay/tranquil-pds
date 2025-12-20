use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;
use webauthn_rs::prelude::*;

pub struct WebAuthnConfig {
    webauthn: Webauthn,
}

impl WebAuthnConfig {
    pub fn new(hostname: &str) -> Result<Self, String> {
        let rp_id = hostname.to_string();
        let rp_origin = Url::parse(&format!("https://{}", hostname))
            .map_err(|e| format!("Invalid origin URL: {}", e))?;

        let builder = WebauthnBuilder::new(&rp_id, &rp_origin)
            .map_err(|e| format!("Failed to create WebAuthn builder: {}", e))?
            .rp_name("Tranquil PDS")
            .danger_set_user_presence_only_security_keys(true);

        let webauthn = builder
            .build()
            .map_err(|e| format!("Failed to build WebAuthn: {}", e))?;

        Ok(Self { webauthn })
    }

    pub fn start_registration(
        &self,
        user_id: &str,
        username: &str,
        display_name: &str,
        exclude_credentials: Vec<CredentialID>,
    ) -> Result<(CreationChallengeResponse, SecurityKeyRegistration), String> {
        let user_unique_id = Uuid::new_v5(&Uuid::NAMESPACE_OID, user_id.as_bytes());

        self.webauthn
            .start_securitykey_registration(
                user_unique_id,
                username,
                display_name,
                if exclude_credentials.is_empty() {
                    None
                } else {
                    Some(exclude_credentials)
                },
                None,
                None,
            )
            .map_err(|e| format!("Failed to start registration: {}", e))
    }

    pub fn finish_registration(
        &self,
        reg: &RegisterPublicKeyCredential,
        state: &SecurityKeyRegistration,
    ) -> Result<SecurityKey, String> {
        self.webauthn
            .finish_securitykey_registration(reg, state)
            .map_err(|e| format!("Failed to finish registration: {}", e))
    }

    pub fn start_authentication(
        &self,
        credentials: Vec<SecurityKey>,
    ) -> Result<(RequestChallengeResponse, SecurityKeyAuthentication), String> {
        self.webauthn
            .start_securitykey_authentication(&credentials)
            .map_err(|e| format!("Failed to start authentication: {}", e))
    }

    pub fn finish_authentication(
        &self,
        auth: &PublicKeyCredential,
        state: &SecurityKeyAuthentication,
    ) -> Result<AuthenticationResult, String> {
        self.webauthn
            .finish_securitykey_authentication(auth, state)
            .map_err(|e| format!("Failed to finish authentication: {}", e))
    }
}

pub async fn save_registration_state(
    pool: &PgPool,
    did: &str,
    state: &SecurityKeyRegistration,
) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::new_v4();
    let state_json = serde_json::to_string(state)
        .map_err(|e| sqlx::Error::Protocol(format!("Failed to serialize state: {}", e)))?;
    let challenge = id.as_bytes().to_vec();
    let expires_at = Utc::now() + Duration::minutes(5);

    sqlx::query!(
        r#"
        INSERT INTO webauthn_challenges (id, did, challenge, challenge_type, state_json, expires_at)
        VALUES ($1, $2, $3, 'registration', $4, $5)
        "#,
        id,
        did,
        challenge,
        state_json,
        expires_at,
    )
    .execute(pool)
    .await?;

    Ok(id)
}

pub async fn load_registration_state(
    pool: &PgPool,
    did: &str,
) -> Result<Option<SecurityKeyRegistration>, sqlx::Error> {
    let row = sqlx::query!(
        r#"
        SELECT state_json FROM webauthn_challenges
        WHERE did = $1 AND challenge_type = 'registration' AND expires_at > NOW()
        ORDER BY created_at DESC
        LIMIT 1
        "#,
        did,
    )
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => {
            let state: SecurityKeyRegistration =
                serde_json::from_str(&r.state_json).map_err(|e| {
                    sqlx::Error::Protocol(format!("Failed to deserialize state: {}", e))
                })?;
            Ok(Some(state))
        }
        None => Ok(None),
    }
}

pub async fn delete_registration_state(pool: &PgPool, did: &str) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "DELETE FROM webauthn_challenges WHERE did = $1 AND challenge_type = 'registration'",
        did,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn save_authentication_state(
    pool: &PgPool,
    did: &str,
    state: &SecurityKeyAuthentication,
) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::new_v4();
    let state_json = serde_json::to_string(state)
        .map_err(|e| sqlx::Error::Protocol(format!("Failed to serialize state: {}", e)))?;
    let challenge = id.as_bytes().to_vec();
    let expires_at = Utc::now() + Duration::minutes(5);

    sqlx::query!(
        r#"
        INSERT INTO webauthn_challenges (id, did, challenge, challenge_type, state_json, expires_at)
        VALUES ($1, $2, $3, 'authentication', $4, $5)
        "#,
        id,
        did,
        challenge,
        state_json,
        expires_at,
    )
    .execute(pool)
    .await?;

    Ok(id)
}

pub async fn load_authentication_state(
    pool: &PgPool,
    did: &str,
) -> Result<Option<SecurityKeyAuthentication>, sqlx::Error> {
    let row = sqlx::query!(
        r#"
        SELECT state_json FROM webauthn_challenges
        WHERE did = $1 AND challenge_type = 'authentication' AND expires_at > NOW()
        ORDER BY created_at DESC
        LIMIT 1
        "#,
        did,
    )
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => {
            let state: SecurityKeyAuthentication =
                serde_json::from_str(&r.state_json).map_err(|e| {
                    sqlx::Error::Protocol(format!("Failed to deserialize state: {}", e))
                })?;
            Ok(Some(state))
        }
        None => Ok(None),
    }
}

pub async fn delete_authentication_state(pool: &PgPool, did: &str) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "DELETE FROM webauthn_challenges WHERE did = $1 AND challenge_type = 'authentication'",
        did,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn cleanup_expired_challenges(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query!("DELETE FROM webauthn_challenges WHERE expires_at < NOW()")
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

#[derive(Debug, Clone)]
pub struct StoredPasskey {
    pub id: Uuid,
    pub did: String,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: i32,
    pub created_at: chrono::DateTime<Utc>,
    pub last_used: Option<chrono::DateTime<Utc>>,
    pub friendly_name: Option<String>,
    pub aaguid: Option<Vec<u8>>,
    pub transports: Option<Vec<String>>,
}

impl StoredPasskey {
    pub fn to_security_key(&self) -> Result<SecurityKey, String> {
        serde_json::from_slice(&self.public_key)
            .map_err(|e| format!("Failed to deserialize security key: {}", e))
    }

    pub fn credential_id_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.credential_id)
    }
}

pub async fn save_passkey(
    pool: &PgPool,
    did: &str,
    security_key: &SecurityKey,
    friendly_name: Option<&str>,
) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::new_v4();
    let credential_id = security_key.cred_id().to_vec();
    let public_key = serde_json::to_vec(security_key)
        .map_err(|e| sqlx::Error::Protocol(format!("Failed to serialize security key: {}", e)))?;
    let aaguid: Option<Vec<u8>> = None;

    sqlx::query!(
        r#"
        INSERT INTO passkeys (id, did, credential_id, public_key, sign_count, friendly_name, aaguid)
        VALUES ($1, $2, $3, $4, 0, $5, $6)
        "#,
        id,
        did,
        credential_id,
        public_key,
        friendly_name,
        aaguid,
    )
    .execute(pool)
    .await?;

    Ok(id)
}

pub async fn get_passkeys_for_user(
    pool: &PgPool,
    did: &str,
) -> Result<Vec<StoredPasskey>, sqlx::Error> {
    let rows = sqlx::query!(
        r#"
        SELECT id, did, credential_id, public_key, sign_count, created_at, last_used, friendly_name, aaguid, transports
        FROM passkeys
        WHERE did = $1
        ORDER BY created_at DESC
        "#,
        did,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| StoredPasskey {
            id: r.id,
            did: r.did,
            credential_id: r.credential_id,
            public_key: r.public_key,
            sign_count: r.sign_count,
            created_at: r.created_at,
            last_used: r.last_used,
            friendly_name: r.friendly_name,
            aaguid: r.aaguid,
            transports: r.transports,
        })
        .collect())
}

pub async fn get_passkey_by_credential_id(
    pool: &PgPool,
    credential_id: &[u8],
) -> Result<Option<StoredPasskey>, sqlx::Error> {
    let row = sqlx::query!(
        r#"
        SELECT id, did, credential_id, public_key, sign_count, created_at, last_used, friendly_name, aaguid, transports
        FROM passkeys
        WHERE credential_id = $1
        "#,
        credential_id,
    )
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| StoredPasskey {
        id: r.id,
        did: r.did,
        credential_id: r.credential_id,
        public_key: r.public_key,
        sign_count: r.sign_count,
        created_at: r.created_at,
        last_used: r.last_used,
        friendly_name: r.friendly_name,
        aaguid: r.aaguid,
        transports: r.transports,
    }))
}

pub async fn update_passkey_counter(
    pool: &PgPool,
    credential_id: &[u8],
    new_counter: u32,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE passkeys SET sign_count = $1, last_used = NOW() WHERE credential_id = $2",
        new_counter as i32,
        credential_id,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete_passkey(pool: &PgPool, id: Uuid, did: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM passkeys WHERE id = $1 AND did = $2")
        .bind(id)
        .bind(did)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn update_passkey_name(
    pool: &PgPool,
    id: Uuid,
    did: &str,
    name: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("UPDATE passkeys SET friendly_name = $1 WHERE id = $2 AND did = $3")
        .bind(name)
        .bind(id)
        .bind(did)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn has_passkeys(pool: &PgPool, did: &str) -> Result<bool, sqlx::Error> {
    let row = sqlx::query("SELECT COUNT(*) as count FROM passkeys WHERE did = $1")
        .bind(did)
        .fetch_one(pool)
        .await?;
    let count: i64 = row.get("count");
    Ok(count > 0)
}
