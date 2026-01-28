use rand::Rng;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::cache::Cache;

const TOKEN_TTL_SECS: u64 = 900;
const BASE32_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

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

fn cache_key(did: &str, purpose: EmailTokenPurpose) -> String {
    format!("email_token:{}:{}", purpose.as_str(), did)
}

fn generate_short_token() -> String {
    let mut rng = rand::thread_rng();
    let token: String = (0..10)
        .map(|_| BASE32_CHARS[rng.gen_range(0..BASE32_CHARS.len())] as char)
        .collect();
    format!("{}-{}", &token[0..5], &token[5..10])
}

fn current_timestamp() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

pub async fn create_email_token(
    cache: &dyn Cache,
    did: &str,
    purpose: EmailTokenPurpose,
) -> Result<String, TokenError> {
    if !cache.is_available() {
        return Err(TokenError::CacheUnavailable);
    }

    let token = generate_short_token();
    let data = TokenData {
        token: token.clone(),
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
    did: &str,
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

    let normalized_input = token.to_uppercase().replace('-', "");
    let normalized_stored = data.token.to_uppercase().replace('-', "");

    if !constant_time_eq(normalized_input.as_bytes(), normalized_stored.as_bytes()) {
        return Err(TokenError::InvalidToken);
    }

    let _ = cache.delete(&key).await;

    Ok(())
}

pub async fn delete_email_token(cache: &dyn Cache, did: &str, purpose: EmailTokenPurpose) {
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
        let did = "did:plc:test123";

        let token = create_email_token(&cache, did, EmailTokenPurpose::UpdateEmail)
            .await
            .unwrap();

        assert_eq!(token.len(), 11);
        assert!(token.contains('-'));

        let result =
            validate_email_token(&cache, did, EmailTokenPurpose::UpdateEmail, &token).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_token_consumed_after_use() {
        let cache = MockCache::new();
        let did = "did:plc:test123";

        let token = create_email_token(&cache, did, EmailTokenPurpose::UpdateEmail)
            .await
            .unwrap();

        validate_email_token(&cache, did, EmailTokenPurpose::UpdateEmail, &token)
            .await
            .unwrap();

        let result =
            validate_email_token(&cache, did, EmailTokenPurpose::UpdateEmail, &token).await;
        assert_eq!(result.unwrap_err(), TokenError::InvalidToken);
    }

    #[tokio::test]
    async fn test_invalid_token_rejected() {
        let cache = MockCache::new();
        let did = "did:plc:test123";

        let _token = create_email_token(&cache, did, EmailTokenPurpose::UpdateEmail)
            .await
            .unwrap();

        let result =
            validate_email_token(&cache, did, EmailTokenPurpose::UpdateEmail, "XXXXX-XXXXX").await;
        assert_eq!(result.unwrap_err(), TokenError::InvalidToken);
    }

    #[tokio::test]
    async fn test_wrong_purpose_rejected() {
        let cache = MockCache::new();
        let did = "did:plc:test123";

        let token = create_email_token(&cache, did, EmailTokenPurpose::UpdateEmail)
            .await
            .unwrap();

        let result =
            validate_email_token(&cache, did, EmailTokenPurpose::ConfirmEmail, &token).await;
        assert_eq!(result.unwrap_err(), TokenError::InvalidToken);
    }

    #[tokio::test]
    async fn test_token_format() {
        (0..100).for_each(|_| {
            let token = generate_short_token();
            assert_eq!(token.len(), 11);
            assert_eq!(&token[5..6], "-");
            assert!(
                token[0..5]
                    .chars()
                    .all(|c| BASE32_CHARS.contains(&(c as u8)))
            );
            assert!(
                token[6..11]
                    .chars()
                    .all(|c| BASE32_CHARS.contains(&(c as u8)))
            );
        });
    }

    #[tokio::test]
    async fn test_case_insensitive_validation() {
        let cache = MockCache::new();
        let did = "did:plc:test123";

        let token = create_email_token(&cache, did, EmailTokenPurpose::UpdateEmail)
            .await
            .unwrap();

        let lowercase = token.to_lowercase();
        let result =
            validate_email_token(&cache, did, EmailTokenPurpose::UpdateEmail, &lowercase).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_noop_cache_returns_unavailable() {
        let cache = crate::cache::NoOpCache;
        let did = "did:plc:test";

        let result = create_email_token(&cache, did, EmailTokenPurpose::UpdateEmail).await;
        assert_eq!(result.unwrap_err(), TokenError::CacheUnavailable);
    }
}
