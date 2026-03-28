use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use sqlx::PgPool;
use tranquil_db_traits::{
    DbError, DeviceAccountRow, DeviceTrustInfo, OAuthRepository, OAuthSessionListItem,
    ScopePreference, TokenFamilyId, TrustedDeviceRow, TwoFactorChallenge,
};
use tranquil_oauth::{
    AuthorizationRequestParameters, AuthorizedClientData, ClientAuth, Code as OAuthCode,
    DeviceData, DeviceId as OAuthDeviceId, RefreshToken as OAuthRefreshToken, RequestData,
    SessionId as OAuthSessionId, TokenData, TokenId as OAuthTokenId,
};
use tranquil_types::{
    AuthorizationCode, ClientId, DPoPProofId, DeviceId, Did, Handle, RefreshToken, RequestId,
    TokenId,
};
use uuid::Uuid;

use super::user::map_sqlx_error;

const REGISTRATION_FLOW_EXTENDED_EXPIRY_SECS: i64 = 600;

fn to_json<T: serde::Serialize>(value: &T) -> Result<serde_json::Value, DbError> {
    serde_json::to_value(value).map_err(|e| {
        tracing::error!("JSON serialization error: {}", e);
        DbError::Serialization("Internal serialization error".to_string())
    })
}

fn from_json<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> Result<T, DbError> {
    serde_json::from_value(value).map_err(|e| {
        tracing::error!("JSON deserialization error: {}", e);
        DbError::Serialization("Internal data corruption".to_string())
    })
}

pub struct PostgresOAuthRepository {
    pool: PgPool,
}

impl PostgresOAuthRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

const REFRESH_GRACE_PERIOD_SECS: i64 = 60;

#[async_trait]
impl OAuthRepository for PostgresOAuthRepository {
    async fn create_token(&self, data: &TokenData) -> Result<TokenFamilyId, DbError> {
        let client_auth_json = to_json(&data.client_auth)?;
        let parameters_json = to_json(&data.parameters)?;
        let row = sqlx::query!(
            r#"
            INSERT INTO oauth_token
                (did, token_id, created_at, updated_at, expires_at, client_id, client_auth,
                 device_id, parameters, details, code, current_refresh_token, scope, controller_did)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            RETURNING id
            "#,
            data.did.as_str(),
            &data.token_id.0,
            data.created_at,
            data.updated_at,
            data.expires_at,
            data.client_id,
            client_auth_json,
            data.device_id.as_ref().map(|d| d.0.as_str()),
            parameters_json,
            data.details,
            data.code.as_ref().map(|c| c.0.as_str()),
            data.current_refresh_token.as_ref().map(|r| r.0.as_str()),
            data.scope,
            data.controller_did.as_ref().map(|d| d.as_str()),
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(TokenFamilyId::new(row.id))
    }

    async fn get_token_by_id(&self, token_id: &TokenId) -> Result<Option<TokenData>, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT did, token_id, created_at, updated_at, expires_at, client_id, client_auth,
                   device_id, parameters, details, code, current_refresh_token, scope, controller_did
            FROM oauth_token
            WHERE token_id = $1
            "#,
            token_id.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        match row {
            Some(r) => Ok(Some(TokenData {
                did: r
                    .did
                    .parse()
                    .map_err(|_| DbError::Other("Invalid DID in token".into()))?,
                token_id: OAuthTokenId(r.token_id),
                created_at: r.created_at,
                updated_at: r.updated_at,
                expires_at: r.expires_at,
                client_id: r.client_id,
                client_auth: from_json(r.client_auth)?,
                device_id: r.device_id.map(OAuthDeviceId),
                parameters: from_json(r.parameters)?,
                details: r.details,
                code: r.code.map(OAuthCode),
                current_refresh_token: r.current_refresh_token.map(OAuthRefreshToken),
                scope: r.scope,
                controller_did: r
                    .controller_did
                    .map(|s| s.parse())
                    .transpose()
                    .map_err(|_| DbError::Other("Invalid controller DID".into()))?,
            })),
            None => Ok(None),
        }
    }

    async fn get_token_by_refresh_token(
        &self,
        refresh_token: &RefreshToken,
    ) -> Result<Option<(TokenFamilyId, TokenData)>, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT id, did, token_id, created_at, updated_at, expires_at, client_id, client_auth,
                   device_id, parameters, details, code, current_refresh_token, scope, controller_did
            FROM oauth_token
            WHERE current_refresh_token = $1
            "#,
            refresh_token.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        match row {
            Some(r) => Ok(Some((
                TokenFamilyId::new(r.id),
                TokenData {
                    did: r
                        .did
                        .parse()
                        .map_err(|_| DbError::Other("Invalid DID in token".into()))?,
                    token_id: OAuthTokenId(r.token_id),
                    created_at: r.created_at,
                    updated_at: r.updated_at,
                    expires_at: r.expires_at,
                    client_id: r.client_id,
                    client_auth: from_json(r.client_auth)?,
                    device_id: r.device_id.map(OAuthDeviceId),
                    parameters: from_json(r.parameters)?,
                    details: r.details,
                    code: r.code.map(OAuthCode),
                    current_refresh_token: r.current_refresh_token.map(OAuthRefreshToken),
                    scope: r.scope,
                    controller_did: r
                        .controller_did
                        .map(|s| s.parse())
                        .transpose()
                        .map_err(|_| DbError::Other("Invalid controller DID".into()))?,
                },
            ))),
            None => Ok(None),
        }
    }

    async fn get_token_by_previous_refresh_token(
        &self,
        refresh_token: &RefreshToken,
    ) -> Result<Option<(TokenFamilyId, TokenData)>, DbError> {
        let grace_cutoff = Utc::now() - Duration::seconds(REFRESH_GRACE_PERIOD_SECS);
        let row = sqlx::query!(
            r#"
            SELECT id, did, token_id, created_at, updated_at, expires_at, client_id, client_auth,
                   device_id, parameters, details, code, current_refresh_token, scope, controller_did
            FROM oauth_token
            WHERE previous_refresh_token = $1 AND rotated_at > $2
            "#,
            refresh_token.as_str(),
            grace_cutoff
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        match row {
            Some(r) => Ok(Some((
                TokenFamilyId::new(r.id),
                TokenData {
                    did: r
                        .did
                        .parse()
                        .map_err(|_| DbError::Other("Invalid DID in token".into()))?,
                    token_id: OAuthTokenId(r.token_id),
                    created_at: r.created_at,
                    updated_at: r.updated_at,
                    expires_at: r.expires_at,
                    client_id: r.client_id,
                    client_auth: from_json(r.client_auth)?,
                    device_id: r.device_id.map(OAuthDeviceId),
                    parameters: from_json(r.parameters)?,
                    details: r.details,
                    code: r.code.map(OAuthCode),
                    current_refresh_token: r.current_refresh_token.map(OAuthRefreshToken),
                    scope: r.scope,
                    controller_did: r
                        .controller_did
                        .map(|s| s.parse())
                        .transpose()
                        .map_err(|_| DbError::Other("Invalid controller DID".into()))?,
                },
            ))),
            None => Ok(None),
        }
    }

    async fn rotate_token(
        &self,
        old_db_id: TokenFamilyId,
        new_refresh_token: &RefreshToken,
        new_expires_at: DateTime<Utc>,
    ) -> Result<(), DbError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
        let old_refresh = sqlx::query_scalar!(
            r#"
            SELECT current_refresh_token FROM oauth_token WHERE id = $1
            "#,
            old_db_id.as_i32()
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;
        if let Some(ref old_rt) = old_refresh {
            sqlx::query!(
                r#"
                INSERT INTO oauth_used_refresh_token (refresh_token, token_id)
                VALUES ($1, $2)
                "#,
                old_rt,
                old_db_id.as_i32()
            )
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
        }
        sqlx::query!(
            r#"
            UPDATE oauth_token
            SET current_refresh_token = $2, expires_at = $3, updated_at = NOW(),
                previous_refresh_token = $4, rotated_at = NOW()
            WHERE id = $1
            "#,
            old_db_id.as_i32(),
            new_refresh_token.as_str(),
            new_expires_at,
            old_refresh
        )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx_error)?;
        tx.commit().await.map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn check_refresh_token_used(
        &self,
        refresh_token: &RefreshToken,
    ) -> Result<Option<TokenFamilyId>, DbError> {
        let row = sqlx::query_scalar!(
            r#"
            SELECT token_id FROM oauth_used_refresh_token WHERE refresh_token = $1
            "#,
            refresh_token.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(row.map(TokenFamilyId::new))
    }

    async fn delete_token(&self, token_id: &TokenId) -> Result<(), DbError> {
        sqlx::query!(
            r#"
            DELETE FROM oauth_token WHERE token_id = $1
            "#,
            token_id.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn delete_token_family(&self, db_id: TokenFamilyId) -> Result<(), DbError> {
        sqlx::query!(
            r#"
            DELETE FROM oauth_token WHERE id = $1
            "#,
            db_id.as_i32()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn list_tokens_for_user(&self, did: &Did) -> Result<Vec<TokenData>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT did, token_id, created_at, updated_at, expires_at, client_id, client_auth,
                   device_id, parameters, details, code, current_refresh_token, scope, controller_did
            FROM oauth_token
            WHERE did = $1
            "#,
            did.as_str()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        rows.into_iter()
            .map(|r| {
                Ok(TokenData {
                    did: r
                        .did
                        .parse()
                        .map_err(|_| DbError::Other("Invalid DID in token".into()))?,
                    token_id: OAuthTokenId(r.token_id),
                    created_at: r.created_at,
                    updated_at: r.updated_at,
                    expires_at: r.expires_at,
                    client_id: r.client_id,
                    client_auth: from_json(r.client_auth)?,
                    device_id: r.device_id.map(OAuthDeviceId),
                    parameters: from_json(r.parameters)?,
                    details: r.details,
                    code: r.code.map(OAuthCode),
                    current_refresh_token: r.current_refresh_token.map(OAuthRefreshToken),
                    scope: r.scope,
                    controller_did: r
                        .controller_did
                        .map(|s| s.parse())
                        .transpose()
                        .map_err(|_| DbError::Other("Invalid controller DID".into()))?,
                })
            })
            .collect()
    }

    async fn count_tokens_for_user(&self, did: &Did) -> Result<i64, DbError> {
        let count = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!" FROM oauth_token WHERE did = $1
            "#,
            did.as_str()
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(count)
    }

    async fn delete_oldest_tokens_for_user(
        &self,
        did: &Did,
        keep_count: i64,
    ) -> Result<u64, DbError> {
        let result = sqlx::query!(
            r#"
            DELETE FROM oauth_token
            WHERE id IN (
                SELECT id FROM oauth_token
                WHERE did = $1
                ORDER BY updated_at ASC
                OFFSET $2
            )
            "#,
            did.as_str(),
            keep_count
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(result.rows_affected())
    }

    async fn revoke_tokens_for_client(
        &self,
        did: &Did,
        client_id: &ClientId,
    ) -> Result<u64, DbError> {
        let result = sqlx::query!(
            "DELETE FROM oauth_token WHERE did = $1 AND client_id = $2",
            did.as_str(),
            client_id.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(result.rows_affected())
    }

    async fn revoke_tokens_for_controller(
        &self,
        delegated_did: &Did,
        controller_did: &Did,
    ) -> Result<u64, DbError> {
        let result = sqlx::query!(
            "DELETE FROM oauth_token WHERE did = $1 AND controller_did = $2",
            delegated_did.as_str(),
            controller_did.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(result.rows_affected())
    }

    async fn create_authorization_request(
        &self,
        request_id: &RequestId,
        data: &RequestData,
    ) -> Result<(), DbError> {
        let client_auth_json = match &data.client_auth {
            Some(ca) => Some(to_json(ca)?),
            None => None,
        };
        let parameters_json = to_json(&data.parameters)?;
        sqlx::query!(
            r#"
            INSERT INTO oauth_authorization_request
                (id, did, device_id, client_id, client_auth, parameters, expires_at, code)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
            request_id.as_str(),
            data.did.as_ref().map(|d| d.as_str()),
            data.device_id.as_ref().map(|d| d.0.as_str()),
            data.client_id,
            client_auth_json,
            parameters_json,
            data.expires_at,
            data.code.as_ref().map(|c| c.0.as_str()),
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn get_authorization_request(
        &self,
        request_id: &RequestId,
    ) -> Result<Option<RequestData>, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT did, device_id, client_id, client_auth, parameters, expires_at, code, controller_did
            FROM oauth_authorization_request
            WHERE id = $1
            "#,
            request_id.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        match row {
            Some(r) => {
                let client_auth: Option<ClientAuth> = match r.client_auth {
                    Some(v) => Some(from_json(v)?),
                    None => None,
                };
                let parameters: AuthorizationRequestParameters = from_json(r.parameters)?;
                Ok(Some(RequestData {
                    client_id: r.client_id,
                    client_auth,
                    parameters,
                    expires_at: r.expires_at,
                    did: r
                        .did
                        .map(|s| s.parse())
                        .transpose()
                        .map_err(|_| DbError::Other("Invalid DID in DB".into()))?,
                    device_id: r.device_id.map(OAuthDeviceId),
                    code: r.code.map(OAuthCode),
                    controller_did: r
                        .controller_did
                        .map(|s| s.parse())
                        .transpose()
                        .map_err(|_| DbError::Other("Invalid controller DID in DB".into()))?,
                }))
            }
            None => Ok(None),
        }
    }

    async fn set_authorization_did(
        &self,
        request_id: &RequestId,
        did: &Did,
        device_id: Option<&DeviceId>,
    ) -> Result<(), DbError> {
        let extended_expiry =
            chrono::Utc::now() + chrono::Duration::seconds(REGISTRATION_FLOW_EXTENDED_EXPIRY_SECS);
        sqlx::query!(
            r#"
            UPDATE oauth_authorization_request
            SET did = $2, device_id = $3, expires_at = $4
            WHERE id = $1
            "#,
            request_id.as_str(),
            did.as_str(),
            device_id.map(|d| d.as_str()),
            extended_expiry
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn update_authorization_request(
        &self,
        request_id: &RequestId,
        did: &Did,
        device_id: Option<&DeviceId>,
        code: &AuthorizationCode,
    ) -> Result<(), DbError> {
        sqlx::query!(
            r#"
            UPDATE oauth_authorization_request
            SET did = $2, device_id = $3, code = $4
            WHERE id = $1
            "#,
            request_id.as_str(),
            did.as_str(),
            device_id.map(|d| d.as_str()),
            code.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn consume_authorization_request_by_code(
        &self,
        code: &AuthorizationCode,
    ) -> Result<Option<RequestData>, DbError> {
        let row = sqlx::query!(
            r#"
            DELETE FROM oauth_authorization_request
            WHERE code = $1
            RETURNING did, device_id, client_id, client_auth, parameters, expires_at, code, controller_did
            "#,
            code.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        match row {
            Some(r) => {
                let client_auth: Option<ClientAuth> = match r.client_auth {
                    Some(v) => Some(from_json(v)?),
                    None => None,
                };
                let parameters: AuthorizationRequestParameters = from_json(r.parameters)?;
                Ok(Some(RequestData {
                    client_id: r.client_id,
                    client_auth,
                    parameters,
                    expires_at: r.expires_at,
                    did: r
                        .did
                        .map(|s| s.parse())
                        .transpose()
                        .map_err(|_| DbError::Other("Invalid DID in DB".into()))?,
                    device_id: r.device_id.map(OAuthDeviceId),
                    code: r.code.map(OAuthCode),
                    controller_did: r
                        .controller_did
                        .map(|s| s.parse())
                        .transpose()
                        .map_err(|_| DbError::Other("Invalid controller DID in DB".into()))?,
                }))
            }
            None => Ok(None),
        }
    }

    async fn delete_authorization_request(&self, request_id: &RequestId) -> Result<(), DbError> {
        sqlx::query!(
            r#"
            DELETE FROM oauth_authorization_request WHERE id = $1
            "#,
            request_id.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn delete_expired_authorization_requests(&self) -> Result<u64, DbError> {
        let result = sqlx::query!(
            r#"
            DELETE FROM oauth_authorization_request
            WHERE expires_at < NOW()
            "#
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(result.rows_affected())
    }

    async fn extend_authorization_request_expiry(
        &self,
        request_id: &RequestId,
        new_expires_at: DateTime<Utc>,
    ) -> Result<bool, DbError> {
        let result = sqlx::query!(
            r#"
            UPDATE oauth_authorization_request
            SET expires_at = $2
            WHERE id = $1 AND did IS NOT NULL AND code IS NULL
            "#,
            request_id.as_str(),
            new_expires_at
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn mark_request_authenticated(
        &self,
        request_id: &RequestId,
        did: &Did,
        device_id: Option<&DeviceId>,
    ) -> Result<(), DbError> {
        sqlx::query!(
            r#"
            UPDATE oauth_authorization_request
            SET did = $2, device_id = $3
            WHERE id = $1
            "#,
            request_id.as_str(),
            did.as_str(),
            device_id.map(|d| d.as_str())
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn update_request_scope(
        &self,
        request_id: &RequestId,
        scope: &str,
    ) -> Result<(), DbError> {
        sqlx::query!(
            r#"
            UPDATE oauth_authorization_request
            SET parameters = jsonb_set(parameters, '{scope}', to_jsonb($2::text))
            WHERE id = $1
            "#,
            request_id.as_str(),
            scope
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn set_controller_did(
        &self,
        request_id: &RequestId,
        controller_did: &Did,
    ) -> Result<(), DbError> {
        sqlx::query!(
            r#"
            UPDATE oauth_authorization_request
            SET controller_did = $2
            WHERE id = $1
            "#,
            request_id.as_str(),
            controller_did.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn set_request_did(&self, request_id: &RequestId, did: &Did) -> Result<(), DbError> {
        sqlx::query!(
            r#"
            UPDATE oauth_authorization_request
            SET did = $2
            WHERE id = $1
            "#,
            request_id.as_str(),
            did.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn create_device(&self, device_id: &DeviceId, data: &DeviceData) -> Result<(), DbError> {
        sqlx::query!(
            r#"
            INSERT INTO oauth_device (id, session_id, user_agent, ip_address, last_seen_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
            device_id.as_str(),
            &data.session_id.0,
            data.user_agent,
            data.ip_address,
            data.last_seen_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn get_device(&self, device_id: &DeviceId) -> Result<Option<DeviceData>, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT session_id, user_agent, ip_address, last_seen_at
            FROM oauth_device
            WHERE id = $1
            "#,
            device_id.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(row.map(|r| DeviceData {
            session_id: OAuthSessionId(r.session_id),
            user_agent: r.user_agent,
            ip_address: r.ip_address,
            last_seen_at: r.last_seen_at,
        }))
    }

    async fn update_device_last_seen(&self, device_id: &DeviceId) -> Result<(), DbError> {
        sqlx::query!(
            r#"
            UPDATE oauth_device
            SET last_seen_at = NOW()
            WHERE id = $1
            "#,
            device_id.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn delete_device(&self, device_id: &DeviceId) -> Result<(), DbError> {
        sqlx::query!(
            r#"
            DELETE FROM oauth_device WHERE id = $1
            "#,
            device_id.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn upsert_account_device(&self, did: &Did, device_id: &DeviceId) -> Result<(), DbError> {
        sqlx::query!(
            r#"
            INSERT INTO oauth_account_device (did, device_id, created_at, updated_at)
            VALUES ($1, $2, NOW(), NOW())
            ON CONFLICT (did, device_id) DO UPDATE SET updated_at = NOW()
            "#,
            did.as_str(),
            device_id.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn get_device_accounts(
        &self,
        device_id: &DeviceId,
    ) -> Result<Vec<DeviceAccountRow>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT u.did, u.handle, u.email, ad.updated_at as last_used_at
            FROM oauth_account_device ad
            JOIN users u ON u.did = ad.did
            WHERE ad.device_id = $1
              AND u.deactivated_at IS NULL
              AND u.takedown_ref IS NULL
            ORDER BY ad.updated_at DESC
            "#,
            device_id.as_str()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(rows
            .into_iter()
            .map(|r| DeviceAccountRow {
                did: Did::from(r.did),
                handle: Handle::from(r.handle),
                email: r.email,
                last_used_at: r.last_used_at,
            })
            .collect())
    }

    async fn verify_account_on_device(
        &self,
        device_id: &DeviceId,
        did: &Did,
    ) -> Result<bool, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT 1 as "exists!"
            FROM oauth_account_device ad
            JOIN users u ON u.did = ad.did
            WHERE ad.device_id = $1
              AND ad.did = $2
              AND u.deactivated_at IS NULL
              AND u.takedown_ref IS NULL
            "#,
            device_id.as_str(),
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(row.is_some())
    }

    async fn check_and_record_dpop_jti(&self, jti: &DPoPProofId) -> Result<bool, DbError> {
        let result = sqlx::query!(
            r#"
            INSERT INTO oauth_dpop_jti (jti)
            VALUES ($1)
            ON CONFLICT (jti) DO NOTHING
            "#,
            jti.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn cleanup_expired_dpop_jtis(&self, max_age_secs: i64) -> Result<u64, DbError> {
        let result = sqlx::query!(
            r#"
            DELETE FROM oauth_dpop_jti
            WHERE created_at < NOW() - INTERVAL '1 second' * $1
            "#,
            max_age_secs as f64
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(result.rows_affected())
    }

    async fn create_2fa_challenge(
        &self,
        did: &Did,
        request_uri: &RequestId,
    ) -> Result<TwoFactorChallenge, DbError> {
        let code = {
            let mut rng = rand::thread_rng();
            let code_num: u32 = rng.gen_range(0..1_000_000);
            format!("{:06}", code_num)
        };
        let expires_at = Utc::now() + Duration::minutes(10);
        let row = sqlx::query!(
            r#"
            INSERT INTO oauth_2fa_challenge (did, request_uri, code, expires_at)
            VALUES ($1, $2, $3, $4)
            RETURNING id, did, request_uri, code, attempts, created_at, expires_at
            "#,
            did.as_str(),
            request_uri.as_str(),
            code,
            expires_at,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(TwoFactorChallenge {
            id: row.id,
            did: Did::from(row.did),
            request_uri: row.request_uri,
            code: row.code,
            attempts: row.attempts,
            created_at: row.created_at,
            expires_at: row.expires_at,
        })
    }

    async fn get_2fa_challenge(
        &self,
        request_uri: &RequestId,
    ) -> Result<Option<TwoFactorChallenge>, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT id, did, request_uri, code, attempts, created_at, expires_at
            FROM oauth_2fa_challenge
            WHERE request_uri = $1
            "#,
            request_uri.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(row.map(|r| TwoFactorChallenge {
            id: r.id,
            did: Did::from(r.did),
            request_uri: r.request_uri,
            code: r.code,
            attempts: r.attempts,
            created_at: r.created_at,
            expires_at: r.expires_at,
        }))
    }

    async fn increment_2fa_attempts(&self, id: Uuid) -> Result<i32, DbError> {
        let row = sqlx::query!(
            r#"
            UPDATE oauth_2fa_challenge
            SET attempts = attempts + 1
            WHERE id = $1
            RETURNING attempts
            "#,
            id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(row.attempts)
    }

    async fn delete_2fa_challenge(&self, id: Uuid) -> Result<(), DbError> {
        sqlx::query!(
            r#"
            DELETE FROM oauth_2fa_challenge WHERE id = $1
            "#,
            id
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn delete_2fa_challenge_by_request_uri(
        &self,
        request_uri: &RequestId,
    ) -> Result<(), DbError> {
        sqlx::query!(
            r#"
            DELETE FROM oauth_2fa_challenge WHERE request_uri = $1
            "#,
            request_uri.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn cleanup_expired_2fa_challenges(&self) -> Result<u64, DbError> {
        let result = sqlx::query!(
            r#"
            DELETE FROM oauth_2fa_challenge WHERE expires_at < NOW()
            "#
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(result.rows_affected())
    }

    async fn check_user_2fa_enabled(&self, did: &Did) -> Result<bool, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT two_factor_enabled
            FROM users
            WHERE did = $1
            "#,
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(row.map(|r| r.two_factor_enabled).unwrap_or(false))
    }

    async fn get_scope_preferences(
        &self,
        did: &Did,
        client_id: &ClientId,
    ) -> Result<Vec<ScopePreference>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT scope, granted FROM oauth_scope_preference
            WHERE did = $1 AND client_id = $2
            "#,
            did.as_str(),
            client_id.as_str()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(rows
            .into_iter()
            .map(|r| ScopePreference {
                scope: r.scope,
                granted: r.granted,
            })
            .collect())
    }

    async fn upsert_scope_preferences(
        &self,
        did: &Did,
        client_id: &ClientId,
        prefs: &[ScopePreference],
    ) -> Result<(), DbError> {
        for pref in prefs {
            sqlx::query!(
                r#"
                INSERT INTO oauth_scope_preference (did, client_id, scope, granted, created_at, updated_at)
                VALUES ($1, $2, $3, $4, NOW(), NOW())
                ON CONFLICT (did, client_id, scope) DO UPDATE SET granted = $4, updated_at = NOW()
                "#,
                did.as_str(),
                client_id.as_str(),
                pref.scope,
                pref.granted
            )
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        }
        Ok(())
    }

    async fn delete_scope_preferences(
        &self,
        did: &Did,
        client_id: &ClientId,
    ) -> Result<(), DbError> {
        sqlx::query!(
            r#"
            DELETE FROM oauth_scope_preference
            WHERE did = $1 AND client_id = $2
            "#,
            did.as_str(),
            client_id.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn upsert_authorized_client(
        &self,
        did: &Did,
        client_id: &ClientId,
        data: &AuthorizedClientData,
    ) -> Result<(), DbError> {
        let data_json = to_json(data)?;
        sqlx::query!(
            r#"
            INSERT INTO oauth_authorized_client (did, client_id, created_at, updated_at, data)
            VALUES ($1, $2, NOW(), NOW(), $3)
            ON CONFLICT (did, client_id) DO UPDATE SET updated_at = NOW(), data = $3
            "#,
            did.as_str(),
            client_id.as_str(),
            data_json
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn get_authorized_client(
        &self,
        did: &Did,
        client_id: &ClientId,
    ) -> Result<Option<AuthorizedClientData>, DbError> {
        let row = sqlx::query_scalar!(
            r#"
            SELECT data FROM oauth_authorized_client
            WHERE did = $1 AND client_id = $2
            "#,
            did.as_str(),
            client_id.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        match row {
            Some(v) => Ok(Some(from_json(v)?)),
            None => Ok(None),
        }
    }

    async fn list_trusted_devices(&self, did: &Did) -> Result<Vec<TrustedDeviceRow>, DbError> {
        let rows = sqlx::query!(
            r#"SELECT od.id, od.user_agent, od.friendly_name, od.trusted_at, od.trusted_until, od.last_seen_at
               FROM oauth_device od
               JOIN oauth_account_device oad ON od.id = oad.device_id
               WHERE oad.did = $1 AND od.trusted_until IS NOT NULL AND od.trusted_until > NOW()
               ORDER BY od.last_seen_at DESC"#,
            did.as_str()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(rows
            .into_iter()
            .map(|r| TrustedDeviceRow {
                id: r.id,
                user_agent: r.user_agent,
                friendly_name: r.friendly_name,
                trusted_at: r.trusted_at,
                trusted_until: r.trusted_until,
                last_seen_at: r.last_seen_at,
            })
            .collect())
    }

    async fn get_device_trust_info(
        &self,
        device_id: &DeviceId,
        did: &Did,
    ) -> Result<Option<DeviceTrustInfo>, DbError> {
        let row = sqlx::query!(
            r#"SELECT trusted_at, trusted_until FROM oauth_device od
               JOIN oauth_account_device oad ON od.id = oad.device_id
               WHERE od.id = $1 AND oad.did = $2"#,
            device_id.as_str(),
            did.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(row.map(|r| DeviceTrustInfo {
            trusted_at: r.trusted_at,
            trusted_until: r.trusted_until,
        }))
    }

    async fn device_belongs_to_user(
        &self,
        device_id: &DeviceId,
        did: &Did,
    ) -> Result<bool, DbError> {
        let exists = sqlx::query_scalar!(
            r#"SELECT 1 as "one!" FROM oauth_device od
               JOIN oauth_account_device oad ON od.id = oad.device_id
               WHERE oad.did = $1 AND od.id = $2"#,
            did.as_str(),
            device_id.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(exists.is_some())
    }

    async fn revoke_device_trust(&self, device_id: &DeviceId, _did: &Did) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE oauth_device SET trusted_at = NULL, trusted_until = NULL WHERE id = $1",
            device_id.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn update_device_friendly_name(
        &self,
        device_id: &DeviceId,
        _did: &Did,
        friendly_name: Option<&str>,
    ) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE oauth_device SET friendly_name = $1 WHERE id = $2",
            friendly_name,
            device_id.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn trust_device(
        &self,
        device_id: &DeviceId,
        _did: &Did,
        trusted_at: DateTime<Utc>,
        trusted_until: DateTime<Utc>,
    ) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE oauth_device SET trusted_at = $1, trusted_until = $2 WHERE id = $3",
            trusted_at,
            trusted_until,
            device_id.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn extend_device_trust(
        &self,
        device_id: &DeviceId,
        _did: &Did,
        trusted_until: DateTime<Utc>,
    ) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE oauth_device SET trusted_until = $1 WHERE id = $2 AND trusted_until IS NOT NULL",
            trusted_until,
            device_id.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(())
    }

    async fn list_sessions_by_did(&self, did: &Did) -> Result<Vec<OAuthSessionListItem>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, token_id, created_at, expires_at, client_id
            FROM oauth_token
            WHERE did = $1 AND expires_at > NOW()
            ORDER BY created_at DESC
            "#,
            did.as_str()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        Ok(rows
            .into_iter()
            .map(|r| OAuthSessionListItem {
                id: TokenFamilyId::new(r.id),
                token_id: TokenId::from(r.token_id),
                created_at: r.created_at,
                expires_at: r.expires_at,
                client_id: ClientId::from(r.client_id),
            })
            .collect())
    }

    async fn delete_session_by_id(
        &self,
        session_id: TokenFamilyId,
        did: &Did,
    ) -> Result<u64, DbError> {
        let result = sqlx::query!(
            "DELETE FROM oauth_token WHERE id = $1 AND did = $2",
            session_id.as_i32(),
            did.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(result.rows_affected())
    }

    async fn delete_sessions_by_did(&self, did: &Did) -> Result<u64, DbError> {
        let result = sqlx::query!("DELETE FROM oauth_token WHERE did = $1", did.as_str())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
        Ok(result.rows_affected())
    }

    async fn delete_sessions_by_did_except(
        &self,
        did: &Did,
        except_token_id: &TokenId,
    ) -> Result<u64, DbError> {
        let result = sqlx::query!(
            "DELETE FROM oauth_token WHERE did = $1 AND token_id != $2",
            did.as_str(),
            except_token_id.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;
        Ok(result.rows_affected())
    }
}
