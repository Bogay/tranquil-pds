mod extractor;

pub use extractor::*;

use crate::state::RateLimitKind;
use governor::{
    RateLimiter,
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed, keyed::DefaultKeyedStateStore},
};
use std::sync::Arc;

pub type KeyedRateLimiter = RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>;
pub type GlobalRateLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

fn keyed_limiter(kind: RateLimitKind) -> Arc<KeyedRateLimiter> {
    Arc::new(RateLimiter::keyed(kind.params().to_governor_quota()))
}

#[derive(Clone)]
pub struct RateLimiters {
    pub login: Arc<KeyedRateLimiter>,
    pub oauth_token: Arc<KeyedRateLimiter>,
    pub oauth_authorize: Arc<KeyedRateLimiter>,
    pub password_reset: Arc<KeyedRateLimiter>,
    pub account_creation: Arc<KeyedRateLimiter>,
    pub refresh_session: Arc<KeyedRateLimiter>,
    pub reset_password: Arc<KeyedRateLimiter>,
    pub oauth_par: Arc<KeyedRateLimiter>,
    pub oauth_introspect: Arc<KeyedRateLimiter>,
    pub app_password: Arc<KeyedRateLimiter>,
    pub email_update: Arc<KeyedRateLimiter>,
    pub totp_verify: Arc<KeyedRateLimiter>,
    pub handle_update: Arc<KeyedRateLimiter>,
    pub handle_update_daily: Arc<KeyedRateLimiter>,
    pub verification_check: Arc<KeyedRateLimiter>,
    pub sso_initiate: Arc<KeyedRateLimiter>,
    pub sso_callback: Arc<KeyedRateLimiter>,
    pub sso_unlink: Arc<KeyedRateLimiter>,
    pub oauth_register_complete: Arc<KeyedRateLimiter>,
    pub handle_verification: Arc<KeyedRateLimiter>,
}

impl Default for RateLimiters {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiters {
    pub fn new() -> Self {
        Self {
            login: keyed_limiter(RateLimitKind::Login),
            oauth_token: keyed_limiter(RateLimitKind::OAuthToken),
            oauth_authorize: keyed_limiter(RateLimitKind::OAuthAuthorize),
            password_reset: keyed_limiter(RateLimitKind::PasswordReset),
            account_creation: keyed_limiter(RateLimitKind::AccountCreation),
            refresh_session: keyed_limiter(RateLimitKind::RefreshSession),
            reset_password: keyed_limiter(RateLimitKind::ResetPassword),
            oauth_par: keyed_limiter(RateLimitKind::OAuthPar),
            oauth_introspect: keyed_limiter(RateLimitKind::OAuthIntrospect),
            app_password: keyed_limiter(RateLimitKind::AppPassword),
            email_update: keyed_limiter(RateLimitKind::EmailUpdate),
            totp_verify: keyed_limiter(RateLimitKind::TotpVerify),
            handle_update: keyed_limiter(RateLimitKind::HandleUpdate),
            handle_update_daily: keyed_limiter(RateLimitKind::HandleUpdateDaily),
            verification_check: keyed_limiter(RateLimitKind::VerificationCheck),
            sso_initiate: keyed_limiter(RateLimitKind::SsoInitiate),
            sso_callback: keyed_limiter(RateLimitKind::SsoCallback),
            sso_unlink: keyed_limiter(RateLimitKind::SsoUnlink),
            oauth_register_complete: keyed_limiter(RateLimitKind::OAuthRegisterComplete),
            handle_verification: keyed_limiter(RateLimitKind::HandleVerification),
        }
    }

    pub fn override_limit(kind: RateLimitKind, limit: u32) -> Arc<KeyedRateLimiter> {
        let mut params = kind.params();
        params.limit = limit;
        Arc::new(RateLimiter::keyed(params.to_governor_quota()))
    }

    pub fn with_login_limit(mut self, per_minute: u32) -> Self {
        self.login = Self::override_limit(RateLimitKind::Login, per_minute);
        self
    }

    pub fn with_oauth_token_limit(mut self, per_minute: u32) -> Self {
        self.oauth_token = Self::override_limit(RateLimitKind::OAuthToken, per_minute);
        self
    }

    pub fn with_oauth_authorize_limit(mut self, per_minute: u32) -> Self {
        self.oauth_authorize = Self::override_limit(RateLimitKind::OAuthAuthorize, per_minute);
        self
    }

    pub fn with_password_reset_limit(mut self, per_hour: u32) -> Self {
        self.password_reset = Self::override_limit(RateLimitKind::PasswordReset, per_hour);
        self
    }

    pub fn with_account_creation_limit(mut self, per_hour: u32) -> Self {
        self.account_creation = Self::override_limit(RateLimitKind::AccountCreation, per_hour);
        self
    }

    pub fn with_email_update_limit(mut self, per_hour: u32) -> Self {
        self.email_update = Self::override_limit(RateLimitKind::EmailUpdate, per_hour);
        self
    }

    pub fn with_sso_initiate_limit(mut self, per_minute: u32) -> Self {
        self.sso_initiate = Self::override_limit(RateLimitKind::SsoInitiate, per_minute);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiters_creation() {
        let limiters = RateLimiters::new();
        assert!(limiters.login.check_key(&"test".to_string()).is_ok());
    }

    #[test]
    fn test_rate_limiter_exhaustion() {
        use governor::Quota;
        use std::num::NonZeroU32;
        let limiter = RateLimiter::keyed(Quota::per_minute(const { NonZeroU32::new(2).unwrap() }));
        let key = "test_ip".to_string();

        assert!(limiter.check_key(&key).is_ok());
        assert!(limiter.check_key(&key).is_ok());
        assert!(limiter.check_key(&key).is_err());
    }

    #[test]
    fn test_different_keys_have_separate_limits() {
        use governor::Quota;
        use std::num::NonZeroU32;
        let limiter = RateLimiter::keyed(Quota::per_minute(const { NonZeroU32::new(1).unwrap() }));

        assert!(limiter.check_key(&"ip1".to_string()).is_ok());
        assert!(limiter.check_key(&"ip1".to_string()).is_err());
        assert!(limiter.check_key(&"ip2".to_string()).is_ok());
    }

    #[test]
    fn test_builder_pattern() {
        let limiters = RateLimiters::new()
            .with_login_limit(20)
            .with_oauth_token_limit(60)
            .with_password_reset_limit(3)
            .with_account_creation_limit(5);

        assert!(limiters.login.check_key(&"test".to_string()).is_ok());
    }
}
