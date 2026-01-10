use super::super::OAuthError;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopePreference {
    pub scope: String,
    pub granted: bool,
}

pub async fn get_scope_preferences(
    pool: &PgPool,
    did: &str,
    client_id: &str,
) -> Result<Vec<ScopePreference>, OAuthError> {
    let rows = sqlx::query!(
        r#"
        SELECT scope, granted FROM oauth_scope_preference
        WHERE did = $1 AND client_id = $2
        "#,
        did,
        client_id
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| ScopePreference {
            scope: r.scope,
            granted: r.granted,
        })
        .collect())
}

pub async fn upsert_scope_preferences(
    pool: &PgPool,
    did: &str,
    client_id: &str,
    prefs: &[ScopePreference],
) -> Result<(), OAuthError> {
    for pref in prefs {
        sqlx::query!(
            r#"
            INSERT INTO oauth_scope_preference (did, client_id, scope, granted, created_at, updated_at)
            VALUES ($1, $2, $3, $4, NOW(), NOW())
            ON CONFLICT (did, client_id, scope) DO UPDATE SET granted = $4, updated_at = NOW()
            "#,
            did,
            client_id,
            pref.scope,
            pref.granted
        )
        .execute(pool)
        .await?;
    }
    Ok(())
}

pub async fn should_show_consent(
    pool: &PgPool,
    did: &str,
    client_id: &str,
    requested_scopes: &[String],
) -> Result<bool, OAuthError> {
    if requested_scopes.is_empty() {
        return Ok(false);
    }

    let stored_prefs = get_scope_preferences(pool, did, client_id).await?;
    if stored_prefs.is_empty() {
        return Ok(true);
    }

    let stored_scopes: std::collections::HashSet<&str> =
        stored_prefs.iter().map(|p| p.scope.as_str()).collect();

    for scope in requested_scopes {
        if !stored_scopes.contains(scope.as_str()) {
            return Ok(true);
        }
    }

    Ok(false)
}

pub async fn delete_scope_preferences(
    pool: &PgPool,
    did: &str,
    client_id: &str,
) -> Result<(), OAuthError> {
    sqlx::query!(
        r#"
        DELETE FROM oauth_scope_preference
        WHERE did = $1 AND client_id = $2
        "#,
        did,
        client_id
    )
    .execute(pool)
    .await?;
    Ok(())
}
