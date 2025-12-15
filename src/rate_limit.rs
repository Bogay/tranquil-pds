use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{HeaderMap, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use governor::{
    Quota, RateLimiter,
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed, keyed::DefaultKeyedStateStore},
};
use std::{
    net::SocketAddr,
    num::NonZeroU32,
    sync::Arc,
};

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
}

impl Default for RateLimiters {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiters {
    pub fn new() -> Self {
        Self {
            login: Arc::new(RateLimiter::keyed(
                Quota::per_minute(NonZeroU32::new(10).unwrap())
            )),
            oauth_token: Arc::new(RateLimiter::keyed(
                Quota::per_minute(NonZeroU32::new(30).unwrap())
            )),
            oauth_authorize: Arc::new(RateLimiter::keyed(
                Quota::per_minute(NonZeroU32::new(10).unwrap())
            )),
            password_reset: Arc::new(RateLimiter::keyed(
                Quota::per_hour(NonZeroU32::new(5).unwrap())
            )),
            account_creation: Arc::new(RateLimiter::keyed(
                Quota::per_hour(NonZeroU32::new(10).unwrap())
            )),
            refresh_session: Arc::new(RateLimiter::keyed(
                Quota::per_minute(NonZeroU32::new(60).unwrap())
            )),
            reset_password: Arc::new(RateLimiter::keyed(
                Quota::per_minute(NonZeroU32::new(10).unwrap())
            )),
            oauth_par: Arc::new(RateLimiter::keyed(
                Quota::per_minute(NonZeroU32::new(30).unwrap())
            )),
            oauth_introspect: Arc::new(RateLimiter::keyed(
                Quota::per_minute(NonZeroU32::new(30).unwrap())
            )),
            app_password: Arc::new(RateLimiter::keyed(
                Quota::per_minute(NonZeroU32::new(10).unwrap())
            )),
            email_update: Arc::new(RateLimiter::keyed(
                Quota::per_hour(NonZeroU32::new(5).unwrap())
            )),
        }
    }

    pub fn with_login_limit(mut self, per_minute: u32) -> Self {
        self.login = Arc::new(RateLimiter::keyed(
            Quota::per_minute(NonZeroU32::new(per_minute).unwrap_or(NonZeroU32::new(10).unwrap()))
        ));
        self
    }

    pub fn with_oauth_token_limit(mut self, per_minute: u32) -> Self {
        self.oauth_token = Arc::new(RateLimiter::keyed(
            Quota::per_minute(NonZeroU32::new(per_minute).unwrap_or(NonZeroU32::new(30).unwrap()))
        ));
        self
    }

    pub fn with_oauth_authorize_limit(mut self, per_minute: u32) -> Self {
        self.oauth_authorize = Arc::new(RateLimiter::keyed(
            Quota::per_minute(NonZeroU32::new(per_minute).unwrap_or(NonZeroU32::new(10).unwrap()))
        ));
        self
    }

    pub fn with_password_reset_limit(mut self, per_hour: u32) -> Self {
        self.password_reset = Arc::new(RateLimiter::keyed(
            Quota::per_hour(NonZeroU32::new(per_hour).unwrap_or(NonZeroU32::new(5).unwrap()))
        ));
        self
    }

    pub fn with_account_creation_limit(mut self, per_hour: u32) -> Self {
        self.account_creation = Arc::new(RateLimiter::keyed(
            Quota::per_hour(NonZeroU32::new(per_hour).unwrap_or(NonZeroU32::new(10).unwrap()))
        ));
        self
    }

    pub fn with_email_update_limit(mut self, per_hour: u32) -> Self {
        self.email_update = Arc::new(RateLimiter::keyed(
            Quota::per_hour(NonZeroU32::new(per_hour).unwrap_or(NonZeroU32::new(5).unwrap()))
        ));
        self
    }
}

pub fn extract_client_ip(headers: &HeaderMap, addr: Option<SocketAddr>) -> String {
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(value) = forwarded.to_str() {
            if let Some(first_ip) = value.split(',').next() {
                return first_ip.trim().to_string();
            }
        }
    }

    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(value) = real_ip.to_str() {
            return value.trim().to_string();
        }
    }

    addr.map(|a| a.ip().to_string()).unwrap_or_else(|| "unknown".to_string())
}

fn rate_limit_response() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(serde_json::json!({
            "error": "RateLimitExceeded",
            "message": "Too many requests. Please try again later."
        })),
    )
        .into_response()
}

pub async fn login_rate_limit(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    axum::extract::State(limiters): axum::extract::State<Arc<RateLimiters>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let client_ip = extract_client_ip(request.headers(), Some(addr));

    if limiters.login.check_key(&client_ip).is_err() {
        tracing::warn!(ip = %client_ip, "Login rate limit exceeded");
        return rate_limit_response();
    }

    next.run(request).await
}

pub async fn oauth_token_rate_limit(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    axum::extract::State(limiters): axum::extract::State<Arc<RateLimiters>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let client_ip = extract_client_ip(request.headers(), Some(addr));

    if limiters.oauth_token.check_key(&client_ip).is_err() {
        tracing::warn!(ip = %client_ip, "OAuth token rate limit exceeded");
        return rate_limit_response();
    }

    next.run(request).await
}

pub async fn password_reset_rate_limit(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    axum::extract::State(limiters): axum::extract::State<Arc<RateLimiters>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let client_ip = extract_client_ip(request.headers(), Some(addr));

    if limiters.password_reset.check_key(&client_ip).is_err() {
        tracing::warn!(ip = %client_ip, "Password reset rate limit exceeded");
        return rate_limit_response();
    }

    next.run(request).await
}

pub async fn account_creation_rate_limit(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    axum::extract::State(limiters): axum::extract::State<Arc<RateLimiters>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let client_ip = extract_client_ip(request.headers(), Some(addr));

    if limiters.account_creation.check_key(&client_ip).is_err() {
        tracing::warn!(ip = %client_ip, "Account creation rate limit exceeded");
        return rate_limit_response();
    }

    next.run(request).await
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
