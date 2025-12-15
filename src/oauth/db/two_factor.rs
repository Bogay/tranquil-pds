use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use sqlx::PgPool;
use uuid::Uuid;
use super::super::OAuthError;

pub struct TwoFactorChallenge {
    pub id: Uuid,
    pub did: String,
    pub request_uri: String,
    pub code: String,
    pub attempts: i32,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

pub fn generate_2fa_code() -> String {
    let mut rng = rand::thread_rng();
    let code: u32 = rng.gen_range(0..1_000_000);
    format!("{:06}", code)
}

pub async fn create_2fa_challenge(
    pool: &PgPool,
    did: &str,
    request_uri: &str,
) -> Result<TwoFactorChallenge, OAuthError> {
    let code = generate_2fa_code();
    let expires_at = Utc::now() + Duration::minutes(10);
    let row = sqlx::query!(
        r#"
        INSERT INTO oauth_2fa_challenge (did, request_uri, code, expires_at)
        VALUES ($1, $2, $3, $4)
        RETURNING id, did, request_uri, code, attempts, created_at, expires_at
        "#,
        did,
        request_uri,
        code,
        expires_at,
    )
    .fetch_one(pool)
    .await?;
    Ok(TwoFactorChallenge {
        id: row.id,
        did: row.did,
        request_uri: row.request_uri,
        code: row.code,
        attempts: row.attempts,
        created_at: row.created_at,
        expires_at: row.expires_at,
    })
}

pub async fn get_2fa_challenge(
    pool: &PgPool,
    request_uri: &str,
) -> Result<Option<TwoFactorChallenge>, OAuthError> {
    let row = sqlx::query!(
        r#"
        SELECT id, did, request_uri, code, attempts, created_at, expires_at
        FROM oauth_2fa_challenge
        WHERE request_uri = $1
        "#,
        request_uri
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| TwoFactorChallenge {
        id: r.id,
        did: r.did,
        request_uri: r.request_uri,
        code: r.code,
        attempts: r.attempts,
        created_at: r.created_at,
        expires_at: r.expires_at,
    }))
}

pub async fn increment_2fa_attempts(pool: &PgPool, id: Uuid) -> Result<i32, OAuthError> {
    let row = sqlx::query!(
        r#"
        UPDATE oauth_2fa_challenge
        SET attempts = attempts + 1
        WHERE id = $1
        RETURNING attempts
        "#,
        id
    )
    .fetch_one(pool)
    .await?;
    Ok(row.attempts)
}

pub async fn delete_2fa_challenge(pool: &PgPool, id: Uuid) -> Result<(), OAuthError> {
    sqlx::query!(
        r#"
        DELETE FROM oauth_2fa_challenge WHERE id = $1
        "#,
        id
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn delete_2fa_challenge_by_request_uri(
    pool: &PgPool,
    request_uri: &str,
) -> Result<(), OAuthError> {
    sqlx::query!(
        r#"
        DELETE FROM oauth_2fa_challenge WHERE request_uri = $1
        "#,
        request_uri
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn cleanup_expired_2fa_challenges(pool: &PgPool) -> Result<u64, OAuthError> {
    let result = sqlx::query!(
        r#"
        DELETE FROM oauth_2fa_challenge WHERE expires_at < NOW()
        "#
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

pub async fn check_user_2fa_enabled(pool: &PgPool, did: &str) -> Result<bool, OAuthError> {
    let row = sqlx::query!(
        r#"
        SELECT two_factor_enabled
        FROM users
        WHERE did = $1
        "#,
        did
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.two_factor_enabled).unwrap_or(false))
}
