mod extractor;

pub use extractor::*;

use governor::{
    Quota, RateLimiter,
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed, keyed::DefaultKeyedStateStore},
};
use std::{num::NonZeroU32, sync::Arc};

pub type KeyedRateLimiter = RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>;
pub type GlobalRateLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

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
}

impl Default for RateLimiters {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiters {
    pub fn new() -> Self {
        Self {
            login: Arc::new(RateLimiter::keyed(Quota::per_minute(
                NonZeroU32::new(10).unwrap(),
            ))),
            oauth_token: Arc::new(RateLimiter::keyed(Quota::per_minute(
                NonZeroU32::new(300).unwrap(),
            ))),
            oauth_authorize: Arc::new(RateLimiter::keyed(Quota::per_minute(
                NonZeroU32::new(10).unwrap(),
            ))),
            password_reset: Arc::new(RateLimiter::keyed(Quota::per_hour(
                NonZeroU32::new(5).unwrap(),
            ))),
            account_creation: Arc::new(RateLimiter::keyed(Quota::per_hour(
                NonZeroU32::new(10).unwrap(),
            ))),
            refresh_session: Arc::new(RateLimiter::keyed(Quota::per_minute(
                NonZeroU32::new(60).unwrap(),
            ))),
            reset_password: Arc::new(RateLimiter::keyed(Quota::per_minute(
                NonZeroU32::new(10).unwrap(),
            ))),
            oauth_par: Arc::new(RateLimiter::keyed(Quota::per_minute(
                NonZeroU32::new(30).unwrap(),
            ))),
            oauth_introspect: Arc::new(RateLimiter::keyed(Quota::per_minute(
                NonZeroU32::new(30).unwrap(),
            ))),
            app_password: Arc::new(RateLimiter::keyed(Quota::per_minute(
                NonZeroU32::new(10).unwrap(),
            ))),
            email_update: Arc::new(RateLimiter::keyed(Quota::per_hour(
                NonZeroU32::new(5).unwrap(),
            ))),
            totp_verify: Arc::new(RateLimiter::keyed(
                Quota::with_period(std::time::Duration::from_secs(60))
                    .unwrap()
                    .allow_burst(NonZeroU32::new(5).unwrap()),
            )),
            handle_update: Arc::new(RateLimiter::keyed(
                Quota::with_period(std::time::Duration::from_secs(30))
                    .unwrap()
                    .allow_burst(NonZeroU32::new(10).unwrap()),
            )),
            handle_update_daily: Arc::new(RateLimiter::keyed(
                Quota::with_period(std::time::Duration::from_secs(1728))
                    .unwrap()
                    .allow_burst(NonZeroU32::new(50).unwrap()),
            )),
            verification_check: Arc::new(RateLimiter::keyed(Quota::per_minute(
                NonZeroU32::new(60).unwrap(),
            ))),
            sso_initiate: Arc::new(RateLimiter::keyed(Quota::per_minute(
                NonZeroU32::new(10).unwrap(),
            ))),
            sso_callback: Arc::new(RateLimiter::keyed(Quota::per_minute(
                NonZeroU32::new(30).unwrap(),
            ))),
            sso_unlink: Arc::new(RateLimiter::keyed(Quota::per_minute(
                NonZeroU32::new(10).unwrap(),
            ))),
            oauth_register_complete: Arc::new(RateLimiter::keyed(
                Quota::with_period(std::time::Duration::from_secs(60))
                    .unwrap()
                    .allow_burst(NonZeroU32::new(5).unwrap()),
            )),
        }
    }

    pub fn with_login_limit(mut self, per_minute: u32) -> Self {
        self.login = Arc::new(RateLimiter::keyed(Quota::per_minute(
            NonZeroU32::new(per_minute).unwrap_or(NonZeroU32::new(10).unwrap()),
        )));
        self
    }

    pub fn with_oauth_token_limit(mut self, per_minute: u32) -> Self {
        self.oauth_token = Arc::new(RateLimiter::keyed(Quota::per_minute(
            NonZeroU32::new(per_minute).unwrap_or(NonZeroU32::new(30).unwrap()),
        )));
        self
    }

    pub fn with_oauth_authorize_limit(mut self, per_minute: u32) -> Self {
        self.oauth_authorize = Arc::new(RateLimiter::keyed(Quota::per_minute(
            NonZeroU32::new(per_minute).unwrap_or(NonZeroU32::new(10).unwrap()),
        )));
        self
    }

    pub fn with_password_reset_limit(mut self, per_hour: u32) -> Self {
        self.password_reset = Arc::new(RateLimiter::keyed(Quota::per_hour(
            NonZeroU32::new(per_hour).unwrap_or(NonZeroU32::new(5).unwrap()),
        )));
        self
    }

    pub fn with_account_creation_limit(mut self, per_hour: u32) -> Self {
        self.account_creation = Arc::new(RateLimiter::keyed(Quota::per_hour(
            NonZeroU32::new(per_hour).unwrap_or(NonZeroU32::new(10).unwrap()),
        )));
        self
    }

    pub fn with_email_update_limit(mut self, per_hour: u32) -> Self {
        self.email_update = Arc::new(RateLimiter::keyed(Quota::per_hour(
            NonZeroU32::new(per_hour).unwrap_or(NonZeroU32::new(5).unwrap()),
        )));
        self
    }

    pub fn with_sso_initiate_limit(mut self, per_minute: u32) -> Self {
        self.sso_initiate = Arc::new(RateLimiter::keyed(Quota::per_minute(
            NonZeroU32::new(per_minute).unwrap_or(NonZeroU32::new(10).unwrap()),
        )));
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
        let limiter = RateLimiter::keyed(Quota::per_minute(NonZeroU32::new(2).unwrap()));
        let key = "test_ip".to_string();

        assert!(limiter.check_key(&key).is_ok());
        assert!(limiter.check_key(&key).is_ok());
        assert!(limiter.check_key(&key).is_err());
    }

    #[test]
    fn test_different_keys_have_separate_limits() {
        let limiter = RateLimiter::keyed(Quota::per_minute(NonZeroU32::new(1).unwrap()));

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
