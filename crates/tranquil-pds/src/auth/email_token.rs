use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::cache::Cache;
use crate::types::Did;
use crate::util::{generate_token_code, normalize_token_code};

const TOKEN_TTL_SECS: u64 = 900;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailTokenPurpose {
    UpdateEmail,
    ConfirmEmail,
    DeleteAccount,
    ResetPassword,
    PlcOperation,
}

impl EmailTokenPurpose {
    fn as_str(&self) -> &'static str {
        match self {
            Self::UpdateEmail => "update_email",
            Self::ConfirmEmail => "confirm_email",
            Self::DeleteAccount => "delete_account",
            Self::ResetPassword => "reset_password",
            Self::PlcOperation => "plc_operation",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenData {
    token: String,
    created_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    CacheUnavailable,
    CacheError,
    InvalidToken,
    ExpiredToken,
}

fn cache_key(did: &Did, purpose: EmailTokenPurpose) -> String {
    format!("email_token:{}:{}", purpose.as_str(), did)
}

fn current_timestamp() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0)
}

pub async fn create_email_token(
    cache: &dyn Cache,
    did: &Did,
    purpose: EmailTokenPurpose,
) -> Result<String, TokenError> {
    if !cache.is_available() {
        return Err(TokenError::CacheUnavailable);
    }

    let token = generate_token_code();
    let data = TokenData {
        token: normalize_token_code(&token),
        created_at: current_timestamp(),
    };

    let json = serde_json::to_string(&data).map_err(|_| TokenError::CacheError)?;

    cache
        .set(
            &cache_key(did, purpose),
            &json,
            Duration::from_secs(TOKEN_TTL_SECS),
        )
        .await
        .map_err(|_| TokenError::CacheError)?;

    Ok(token)
}

pub async fn validate_email_token(
    cache: &dyn Cache,
    did: &Did,
    purpose: EmailTokenPurpose,
    token: &str,
) -> Result<(), TokenError> {
    if !cache.is_available() {
        return Err(TokenError::CacheUnavailable);
    }

    let key = cache_key(did, purpose);
    let json = cache.get(&key).await.ok_or(TokenError::InvalidToken)?;

    let data: TokenData = serde_json::from_str(&json).map_err(|_| TokenError::InvalidToken)?;

    let elapsed = current_timestamp().saturating_sub(data.created_at);
    if elapsed > TOKEN_TTL_SECS {
        let _ = cache.delete(&key).await;
        return Err(TokenError::ExpiredToken);
    }

    let normalized_input = normalize_token_code(token);

    if !constant_time_eq(normalized_input.as_bytes(), data.token.as_bytes()) {
        return Err(TokenError::InvalidToken);
    }

    let _ = cache.delete(&key).await;

    Ok(())
}

pub async fn delete_email_token(cache: &dyn Cache, did: &Did, purpose: EmailTokenPurpose) {
    let _ = cache.delete(&cache_key(did, purpose)).await;
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::CacheError;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct MockCache {
        data: Mutex<HashMap<String, (String, u64)>>,
    }

    impl MockCache {
        fn new() -> Self {
            Self {
                data: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl Cache for MockCache {
        async fn get(&self, key: &str) -> Option<String> {
            let data = self.data.lock().unwrap();
            let now = current_timestamp();
            data.get(key)
                .filter(|(_, exp)| *exp > now)
                .map(|(v, _)| v.clone())
        }

        async fn set(&self, key: &str, value: &str, ttl: Duration) -> Result<(), CacheError> {
            let mut data = self.data.lock().unwrap();
            let expires = current_timestamp() + ttl.as_secs();
            data.insert(key.to_string(), (value.to_string(), expires));
            Ok(())
        }

        async fn delete(&self, key: &str) -> Result<(), CacheError> {
            let mut data = self.data.lock().unwrap();
            data.remove(key);
            Ok(())
        }

        async fn get_bytes(&self, _key: &str) -> Option<Vec<u8>> {
            None
        }

        async fn set_bytes(
            &self,
            _key: &str,
            _value: &[u8],
            _ttl: Duration,
        ) -> Result<(), CacheError> {
            Ok(())
        }

        fn is_available(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn test_create_and_validate_token() {
        let cache = MockCache::new();
        let did = Did::from("did:plc:teq".to_string());

        let token = create_email_token(&cache, &did, EmailTokenPurpose::UpdateEmail)
            .await
            .unwrap();

        assert_eq!(token.len(), 11);
        assert!(token.contains('-'));

        let result =
            validate_email_token(&cache, &did, EmailTokenPurpose::UpdateEmail, &token).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_token_consumed_after_use() {
        let cache = MockCache::new();
        let did = Did::from("did:plc:teq".to_string());

        let token = create_email_token(&cache, &did, EmailTokenPurpose::UpdateEmail)
            .await
            .unwrap();

        validate_email_token(&cache, &did, EmailTokenPurpose::UpdateEmail, &token)
            .await
            .unwrap();

        let result =
            validate_email_token(&cache, &did, EmailTokenPurpose::UpdateEmail, &token).await;
        assert_eq!(result.unwrap_err(), TokenError::InvalidToken);
    }

    #[tokio::test]
    async fn test_invalid_token_rejected() {
        let cache = MockCache::new();
        let did = Did::from("did:plc:teq".to_string());

        let _token = create_email_token(&cache, &did, EmailTokenPurpose::UpdateEmail)
            .await
            .unwrap();

        let result =
            validate_email_token(&cache, &did, EmailTokenPurpose::UpdateEmail, "XXXXX-XXXXX").await;
        assert_eq!(result.unwrap_err(), TokenError::InvalidToken);
    }

    #[tokio::test]
    async fn test_wrong_purpose_rejected() {
        let cache = MockCache::new();
        let did = Did::from("did:plc:teq".to_string());

        let token = create_email_token(&cache, &did, EmailTokenPurpose::UpdateEmail)
            .await
            .unwrap();

        let result =
            validate_email_token(&cache, &did, EmailTokenPurpose::ConfirmEmail, &token).await;
        assert_eq!(result.unwrap_err(), TokenError::InvalidToken);
    }

    #[tokio::test]
    async fn test_token_format() {
        // The emitted token is the display form: uppercase `XXXXX-XXXXX`.
        let cache = MockCache::new();
        let did = Did::from("did:plc:teq".to_string());
        (0..50).for_each(|_| {
            let token = futures::executor::block_on(create_email_token(
                &cache,
                &did,
                EmailTokenPurpose::UpdateEmail,
            ))
            .unwrap();
            assert_eq!(token.len(), 11);
            assert_eq!(&token[5..6], "-");
            assert_eq!(token, token.to_uppercase());
        });
    }

    #[tokio::test]
    async fn test_case_insensitive_validation() {
        let cache = MockCache::new();
        let did = Did::from("did:plc:teq".to_string());

        let token = create_email_token(&cache, &did, EmailTokenPurpose::UpdateEmail)
            .await
            .unwrap();

        let lowercase = token.to_lowercase();
        let result =
            validate_email_token(&cache, &did, EmailTokenPurpose::UpdateEmail, &lowercase).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_hyphen_insensitive_validation() {
        let cache = MockCache::new();
        let did = Did::from("did:plc:teq".to_string());

        let token = create_email_token(&cache, &did, EmailTokenPurpose::UpdateEmail)
            .await
            .unwrap();

        let no_hyphen = token.replace('-', "");
        let result =
            validate_email_token(&cache, &did, EmailTokenPurpose::UpdateEmail, &no_hyphen).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_noop_cache_returns_unavailable() {
        let cache = crate::cache::NoOpCache;
        let did = Did::from("did:plc:whelk".to_string());

        let result = create_email_token(&cache, &did, EmailTokenPurpose::UpdateEmail).await;
        assert_eq!(result.unwrap_err(), TokenError::CacheUnavailable);
    }
}
