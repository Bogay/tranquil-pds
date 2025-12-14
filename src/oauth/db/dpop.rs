use sqlx::PgPool;
use super::super::OAuthError;
pub async fn check_and_record_dpop_jti(
    pool: &PgPool,
    jti: &str,
) -> Result<bool, OAuthError> {
    let result = sqlx::query!(
        r#"
        INSERT INTO oauth_dpop_jti (jti)
        VALUES ($1)
        ON CONFLICT (jti) DO NOTHING
        "#,
        jti
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}
pub async fn cleanup_expired_dpop_jtis(
    pool: &PgPool,
    max_age_secs: i64,
) -> Result<u64, OAuthError> {
    let result = sqlx::query!(
        r#"
        DELETE FROM oauth_dpop_jti
        WHERE created_at < NOW() - INTERVAL '1 second' * $1
        "#,
        max_age_secs as f64
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}
