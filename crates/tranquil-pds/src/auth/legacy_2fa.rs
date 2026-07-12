use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::cache::Cache;
use crate::types::Did;
use crate::util::{generate_token_code, normalize_token_code};

const CHALLENGE_TTL_SECS: u64 = 300;
const MIN_REMAINING_TTL_SECS: u64 = 10;
const MAX_ATTEMPTS: u8 = 5;
const COOLDOWN_SECS: u64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChallengeData {
    code: String,
    attempts: u8,
    created_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeError {
    CacheUnavailable,
    RateLimited,
    CacheError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationError {
    InvalidCode,
    TooManyAttempts,
    ChallengeNotFound,
    ChallengeExpired,
    CacheUnavailable,
    CacheError,
}

#[derive(Debug)]
pub struct ChallengeCode(String);

impl ChallengeCode {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ChallengeCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub async fn create_challenge(
    cache: &dyn Cache,
    did: &Did,
) -> Result<ChallengeCode, ChallengeError> {
    create_challenge_code(cache, did).await
}

pub async fn clear_challenge(cache: &dyn Cache, did: &Did) {
    let _ = cache.delete(&challenge_key(did)).await;
    let _ = cache.delete(&cooldown_key(did)).await;
}

async fn validate_challenge_internal(
    cache: &dyn Cache,
    did: &Did,
    code: &str,
) -> Result<(), ValidationError> {
    if !cache.is_available() {
        return Err(ValidationError::CacheUnavailable);
    }

    let challenge_k = challenge_key(did);

    let json = cache
        .get(&challenge_k)
        .await
        .ok_or(ValidationError::ChallengeNotFound)?;

    let data: ChallengeData =
        serde_json::from_str(&json).map_err(|_| ValidationError::ChallengeNotFound)?;

    if data.attempts >= MAX_ATTEMPTS {
        let _ = cache.delete(&challenge_k).await;
        return Err(ValidationError::TooManyAttempts);
    }

    let elapsed = current_timestamp().saturating_sub(data.created_at);
    let remaining_ttl = CHALLENGE_TTL_SECS.saturating_sub(elapsed);
    if remaining_ttl < MIN_REMAINING_TTL_SECS {
        let _ = cache.delete(&challenge_k).await;
        return Err(ValidationError::ChallengeExpired);
    }

    let normalized_input = normalize_token_code(code);
    if !constant_time_eq(normalized_input.as_bytes(), data.code.as_bytes()) {
        let updated = ChallengeData {
            code: data.code,
            attempts: data.attempts + 1,
            created_at: data.created_at,
        };
        let updated_json =
            serde_json::to_string(&updated).map_err(|_| ValidationError::CacheError)?;
        cache
            .set(
                &challenge_k,
                &updated_json,
                Duration::from_secs(remaining_ttl),
            )
            .await
            .map_err(|_| ValidationError::CacheError)?;
        return Err(ValidationError::InvalidCode);
    }

    let _ = cache.delete(&challenge_k).await;
    let _ = cache.delete(&cooldown_key(did)).await;

    Ok(())
}

fn challenge_key(did: &Did) -> String {
    format!("legacy_2fa:{}", did)
}

fn cooldown_key(did: &Did) -> String {
    format!("legacy_2fa_cooldown:{}", did)
}

fn current_timestamp() -> u64 {
    u64::try_from(Utc::now().timestamp()).unwrap_or(0)
}

pub fn looks_like_totp_token(code: &str) -> bool {
    let c = code.trim();
    (c.len() == 6 && c.bytes().all(|b| b.is_ascii_digit())) || crate::auth::is_backup_code_format(c)
}

pub fn used_totp_factor(has_totp: bool, auth_factor_token: Option<&str>) -> bool {
    has_totp && auth_factor_token.is_some_and(looks_like_totp_token)
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

#[derive(Debug)]
pub enum Legacy2faOutcome {
    NotRequired,
    Blocked,
    ChallengeSent(ChallengeCode),
    Verified,
}

pub struct Legacy2faContext {
    pub is_app_password: bool,
    pub email_2fa_enabled: bool,
    pub has_totp: bool,
    pub allow_legacy_login: bool,
}

impl Legacy2faContext {
    pub fn requires_2fa(&self) -> bool {
        !self.is_app_password && (self.email_2fa_enabled || self.has_totp)
    }

    pub fn is_blocked(&self) -> bool {
        self.has_totp && !self.allow_legacy_login && !self.email_2fa_enabled
    }
}

pub async fn process_legacy_2fa(
    cache: &dyn Cache,
    did: &Did,
    ctx: &Legacy2faContext,
    auth_factor_token: Option<&str>,
    verify_totp: impl AsyncFnOnce(&str) -> bool,
) -> Result<Legacy2faOutcome, Legacy2faFlowError> {
    if !ctx.requires_2fa() {
        return Ok(Legacy2faOutcome::NotRequired);
    }

    if ctx.is_blocked() {
        return Ok(Legacy2faOutcome::Blocked);
    }

    match auth_factor_token.filter(|t| !t.is_empty()) {
        None => {
            let code = create_challenge_code(cache, did).await?;
            Ok(Legacy2faOutcome::ChallengeSent(code))
        }
        Some(token) => {
            if ctx.has_totp && looks_like_totp_token(token) {
                if verify_totp(token).await {
                    Ok(Legacy2faOutcome::Verified)
                } else {
                    Err(Legacy2faFlowError::Validation(ValidationError::InvalidCode))
                }
            } else {
                validate_challenge(cache, did, token).await?;
                Ok(Legacy2faOutcome::Verified)
            }
        }
    }
}

pub async fn validate_challenge(
    cache: &dyn Cache,
    did: &Did,
    code: &str,
) -> Result<(), ValidationError> {
    validate_challenge_internal(cache, did, code).await
}

async fn create_challenge_code(
    cache: &dyn Cache,
    did: &Did,
) -> Result<ChallengeCode, ChallengeError> {
    if !cache.is_available() {
        return Err(ChallengeError::CacheUnavailable);
    }

    let cooldown = cooldown_key(did);
    if cache.get(&cooldown).await.is_some() {
        return Err(ChallengeError::RateLimited);
    }

    let display = generate_token_code();
    let now = current_timestamp();

    let data = ChallengeData {
        code: normalize_token_code(&display),
        attempts: 0,
        created_at: now,
    };

    let json = serde_json::to_string(&data).map_err(|_| ChallengeError::CacheError)?;

    cache
        .set(
            &challenge_key(did),
            &json,
            Duration::from_secs(CHALLENGE_TTL_SECS),
        )
        .await
        .map_err(|_| ChallengeError::CacheError)?;

    cache
        .set(&cooldown, "1", Duration::from_secs(COOLDOWN_SECS))
        .await
        .map_err(|_| ChallengeError::CacheError)?;

    Ok(ChallengeCode(display))
}

#[derive(Debug)]
pub enum Legacy2faFlowError {
    Challenge(ChallengeError),
    Validation(ValidationError),
}

impl From<ChallengeError> for Legacy2faFlowError {
    fn from(e: ChallengeError) -> Self {
        Self::Challenge(e)
    }
}

impl From<ValidationError> for Legacy2faFlowError {
    fn from(e: ValidationError) -> Self {
        Self::Validation(e)
    }
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
    async fn test_create_and_validate_challenge() {
        let cache = MockCache::new();
        let did = Did::new("did:plc:test123".to_string()).unwrap();

        let code = create_challenge(&cache, &did).await.unwrap();
        assert_eq!(code.as_str().len(), 11);

        let result = validate_challenge(&cache, &did, code.as_str()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_challenge_code_format() {
        let cache = MockCache::new();
        let did = Did::new("did:plc:test123".to_string()).unwrap();

        let code = create_challenge(&cache, &did).await.unwrap();
        let code = code.as_str();
        assert_eq!(code.len(), 11);
        assert_eq!(&code[5..6], "-");
        assert_eq!(code, code.to_uppercase());
    }

    #[tokio::test]
    async fn test_case_insensitive_validation() {
        let cache = MockCache::new();
        let did = Did::new("did:plc:test123".to_string()).unwrap();

        let code = create_challenge(&cache, &did).await.unwrap();
        let lowercase = code.as_str().to_lowercase();
        let result = validate_challenge(&cache, &did, &lowercase).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_hyphen_insensitive_validation() {
        let cache = MockCache::new();
        let did = Did::new("did:plc:test123".to_string()).unwrap();

        let code = create_challenge(&cache, &did).await.unwrap();
        let no_hyphen = code.as_str().replace('-', "");
        let result = validate_challenge(&cache, &did, &no_hyphen).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_invalid_code_rejected() {
        let cache = MockCache::new();
        let did = Did::new("did:plc:test123".to_string()).unwrap();

        let _code = create_challenge(&cache, &did).await.unwrap();
        let result = validate_challenge(&cache, &did, "00000000").await;
        assert_eq!(result.unwrap_err(), ValidationError::InvalidCode);
    }

    #[tokio::test]
    async fn test_challenge_consumed_on_success() {
        let cache = MockCache::new();
        let did = Did::new("did:plc:test123".to_string()).unwrap();

        let code = create_challenge(&cache, &did).await.unwrap();
        validate_challenge(&cache, &did, code.as_str())
            .await
            .unwrap();

        let result = validate_challenge(&cache, &did, code.as_str()).await;
        assert_eq!(result.unwrap_err(), ValidationError::ChallengeNotFound);
    }

    #[tokio::test]
    async fn test_max_attempts_exceeded() {
        let cache = MockCache::new();
        let did = Did::new("did:plc:test123".to_string()).unwrap();

        let _code = create_challenge(&cache, &did).await.unwrap();

        (0..MAX_ATTEMPTS).for_each(|_| {
            let _ = futures::executor::block_on(validate_challenge(&cache, &did, "wrong123"));
        });

        let result = validate_challenge(&cache, &did, "anything").await;
        assert_eq!(result.unwrap_err(), ValidationError::TooManyAttempts);
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let cache = MockCache::new();
        let did = Did::new("did:plc:test123".to_string()).unwrap();

        let _first = create_challenge(&cache, &did).await.unwrap();
        let result = create_challenge(&cache, &did).await;
        assert_eq!(result.unwrap_err(), ChallengeError::RateLimited);
    }

    #[tokio::test]
    async fn test_noop_cache_returns_unavailable() {
        let cache = crate::cache::NoOpCache;
        let did = Did::new("did:plc:test".to_string()).unwrap();

        let result = create_challenge(&cache, &did).await;
        assert_eq!(result.unwrap_err(), ChallengeError::CacheUnavailable);
    }

    #[tokio::test]
    async fn test_constant_time_eq() {
        assert!(constant_time_eq(b"12345678", b"12345678"));
        assert!(!constant_time_eq(b"12345678", b"12345679"));
        assert!(!constant_time_eq(b"12345678", b"1234567"));
        assert!(!constant_time_eq(b"", b"1"));
        assert!(constant_time_eq(b"", b""));
    }

    #[tokio::test]
    async fn test_process_flow_not_required() {
        let cache = MockCache::new();
        let did = Did::new("did:plc:test".to_string()).unwrap();
        let ctx = Legacy2faContext {
            is_app_password: false,
            email_2fa_enabled: false,
            has_totp: false,
            allow_legacy_login: true,
        };

        let outcome = process_legacy_2fa(&cache, &did, &ctx, None, reject_totp)
            .await
            .unwrap();
        assert!(matches!(outcome, Legacy2faOutcome::NotRequired));
    }

    #[tokio::test]
    async fn test_process_flow_not_required_because_app_password() {
        let cache = MockCache::new();
        let did = Did::new("did:plc:test".to_string()).unwrap();
        let ctx = Legacy2faContext {
            is_app_password: true,
            email_2fa_enabled: false,
            has_totp: true,
            allow_legacy_login: true,
        };

        let outcome = process_legacy_2fa(&cache, &did, &ctx, None, reject_totp)
            .await
            .unwrap();
        assert!(matches!(outcome, Legacy2faOutcome::NotRequired));
    }

    #[tokio::test]
    async fn test_process_flow_blocked() {
        let cache = MockCache::new();
        let did = Did::new("did:plc:test".to_string()).unwrap();
        let ctx = Legacy2faContext {
            is_app_password: false,
            email_2fa_enabled: false,
            has_totp: true,
            allow_legacy_login: false,
        };

        let outcome = process_legacy_2fa(&cache, &did, &ctx, None, reject_totp)
            .await
            .unwrap();
        assert!(matches!(outcome, Legacy2faOutcome::Blocked));
    }

    #[tokio::test]
    async fn test_process_flow_challenge_sent_totp() {
        let cache = MockCache::new();
        let did = Did::new("did:plc:test".to_string()).unwrap();
        let ctx = Legacy2faContext {
            is_app_password: false,
            email_2fa_enabled: false,
            has_totp: true,
            allow_legacy_login: true,
        };

        let outcome = process_legacy_2fa(&cache, &did, &ctx, None, reject_totp)
            .await
            .unwrap();
        assert!(matches!(outcome, Legacy2faOutcome::ChallengeSent(_)));
    }

    #[tokio::test]
    async fn test_process_flow_challenge_sent_email_2fa_enabled() {
        let cache = MockCache::new();
        let did = Did::new("did:plc:test2".to_string()).unwrap();
        let ctx = Legacy2faContext {
            is_app_password: false,
            email_2fa_enabled: true,
            has_totp: false,
            allow_legacy_login: false,
        };

        let outcome = process_legacy_2fa(&cache, &did, &ctx, None, reject_totp)
            .await
            .unwrap();
        assert!(matches!(outcome, Legacy2faOutcome::ChallengeSent(_)));
    }

    #[tokio::test]
    async fn test_process_flow_verified() {
        let cache = MockCache::new();
        let did = Did::new("did:plc:test".to_string()).unwrap();
        let ctx = Legacy2faContext {
            is_app_password: false,
            email_2fa_enabled: true,
            has_totp: false,
            allow_legacy_login: false,
        };

        let code = create_challenge(&cache, &did).await.unwrap();

        let outcome = process_legacy_2fa(&cache, &did, &ctx, Some(code.as_str()), reject_totp)
            .await
            .unwrap();
        assert!(matches!(outcome, Legacy2faOutcome::Verified));
    }

    #[tokio::test]
    async fn test_attempts_persist_across_failures() {
        let cache = MockCache::new();
        let did = Did::new("did:plc:test123".to_string()).unwrap();

        let code = create_challenge(&cache, &did).await.unwrap();

        (0..3).for_each(|_| {
            let result = futures::executor::block_on(validate_challenge(&cache, &did, "wrong123"));
            assert_eq!(result.unwrap_err(), ValidationError::InvalidCode);
        });

        let result = validate_challenge(&cache, &did, code.as_str()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validation_on_noop_cache_returns_unavailable() {
        let cache = crate::cache::NoOpCache;
        let did = Did::new("did:plc:test".to_string()).unwrap();

        let result = validate_challenge(&cache, &did, "12345678").await;
        assert_eq!(result.unwrap_err(), ValidationError::CacheUnavailable);
    }

    async fn reject_totp(_code: &str) -> bool {
        false
    }

    async fn accept_totp(_code: &str) -> bool {
        true
    }

    #[tokio::test]
    async fn test_totp_shaped_token_accepted_via_verifier() {
        let cache = MockCache::new();
        let did = Did::new("did:plc:totp1".to_string()).unwrap();
        let ctx = Legacy2faContext {
            is_app_password: false,
            email_2fa_enabled: false,
            has_totp: true,
            allow_legacy_login: true,
        };

        let outcome = process_legacy_2fa(&cache, &did, &ctx, Some("123456"), accept_totp)
            .await
            .unwrap();
        assert!(matches!(outcome, Legacy2faOutcome::Verified));
    }

    #[tokio::test]
    async fn test_totp_shaped_token_rejected_does_not_touch_email_challenge() {
        let cache = MockCache::new();
        let did = Did::new("did:plc:totp2".to_string()).unwrap();
        let ctx = Legacy2faContext {
            is_app_password: false,
            email_2fa_enabled: true,
            has_totp: true,
            allow_legacy_login: true,
        };

        // An email challenge exists for this user.
        let email_code = create_challenge(&cache, &did).await.unwrap();

        // Five wrong TOTP-shaped attempts. If these incremented the email attempt
        // counter, the email challenge would be exhausted (MAX_ATTEMPTS = 5).
        for _ in 0..5 {
            let err = process_legacy_2fa(&cache, &did, &ctx, Some("000000"), reject_totp)
                .await
                .unwrap_err();
            assert!(matches!(
                err,
                Legacy2faFlowError::Validation(ValidationError::InvalidCode)
            ));
        }

        // The email challenge is still valid and consumable.
        let outcome =
            process_legacy_2fa(&cache, &did, &ctx, Some(email_code.as_str()), reject_totp)
                .await
                .unwrap();
        assert!(matches!(outcome, Legacy2faOutcome::Verified));
    }

    #[tokio::test]
    async fn test_email_shaped_token_routes_to_email_path_when_totp_present() {
        let cache = MockCache::new();
        let did = Did::new("did:plc:totp3".to_string()).unwrap();
        let ctx = Legacy2faContext {
            is_app_password: false,
            email_2fa_enabled: true,
            has_totp: true,
            allow_legacy_login: true,
        };

        let email_code = create_challenge(&cache, &did).await.unwrap();

        // reject_totp would fail if this routed to the verifier; it must route to email.
        let outcome =
            process_legacy_2fa(&cache, &did, &ctx, Some(email_code.as_str()), reject_totp)
                .await
                .unwrap();
        assert!(matches!(outcome, Legacy2faOutcome::Verified));
    }

    #[tokio::test]
    async fn test_backup_code_shaped_token_routes_to_verifier() {
        let cache = MockCache::new();
        let did = Did::new("did:plc:totp4".to_string()).unwrap();
        let ctx = Legacy2faContext {
            is_app_password: false,
            email_2fa_enabled: false,
            has_totp: true,
            allow_legacy_login: true,
        };

        // No email challenge created. If this routed to email it would be
        // ChallengeNotFound; Verified proves it went to the verifier.
        let outcome = process_legacy_2fa(&cache, &did, &ctx, Some("ABCD2345"), accept_totp)
            .await
            .unwrap();
        assert!(matches!(outcome, Legacy2faOutcome::Verified));
    }

    #[tokio::test]
    async fn test_totp_shaped_token_ignored_when_no_totp() {
        let cache = MockCache::new();
        let did = Did::new("did:plc:totp5".to_string()).unwrap();
        let ctx = Legacy2faContext {
            is_app_password: false,
            email_2fa_enabled: true,
            has_totp: false,
            allow_legacy_login: false,
        };

        // has_totp = false -> 6-digit token routes to email path; no challenge -> NotFound.
        let err = process_legacy_2fa(&cache, &did, &ctx, Some("123456"), reject_totp)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            Legacy2faFlowError::Validation(ValidationError::ChallengeNotFound)
        ));
    }

    #[tokio::test]
    async fn test_looks_like_totp_token() {
        // 6-digit TOTP codes
        assert!(looks_like_totp_token("123456"));
        assert!(looks_like_totp_token("  000000  "));
        // backup-code format (8 chars, backup alphabet)
        assert!(looks_like_totp_token("ABCD2345"));
        // email challenge codes normalize to 10 alphanumeric chars -> not TOTP-shaped
        assert!(!looks_like_totp_token("ABCDEFGHIJ"));
        assert!(!looks_like_totp_token("ABCDE-FGHIJ"));
        // wrong lengths / non-digits
        assert!(!looks_like_totp_token("12345"));
        assert!(!looks_like_totp_token("1234567"));
        assert!(!looks_like_totp_token("12345A"));
        assert!(!looks_like_totp_token(""));
    }

    #[test]
    fn test_used_totp_factor() {
        // strong MFA factors completed the login -> true
        assert!(used_totp_factor(true, Some("123456")));
        assert!(used_totp_factor(true, Some("ABCD2345")));
        // email-shaped code, or no token, or no TOTP on the account -> false
        assert!(!used_totp_factor(true, Some("ABCDEFGHIJ")));
        assert!(!used_totp_factor(true, None));
        assert!(!used_totp_factor(false, Some("123456")));
        assert!(!used_totp_factor(true, Some("")));
    }
}
