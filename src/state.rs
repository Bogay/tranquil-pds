use crate::appview::AppViewRegistry;
use crate::cache::{Cache, DistributedRateLimiter, create_cache};
use crate::circuit_breaker::CircuitBreakers;
use crate::config::AuthConfig;
use crate::rate_limit::RateLimiters;
use crate::repo::PostgresBlockStore;
use crate::storage::{BlobStorage, S3BlobStorage};
use crate::sync::firehose::SequencedEvent;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::broadcast;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub block_store: PostgresBlockStore,
    pub blob_store: Arc<dyn BlobStorage>,
    pub firehose_tx: broadcast::Sender<SequencedEvent>,
    pub rate_limiters: Arc<RateLimiters>,
    pub circuit_breakers: Arc<CircuitBreakers>,
    pub cache: Arc<dyn Cache>,
    pub distributed_rate_limiter: Arc<dyn DistributedRateLimiter>,
    pub appview_registry: Arc<AppViewRegistry>,
}

pub enum RateLimitKind {
    Login,
    AccountCreation,
    PasswordReset,
    ResetPassword,
    RefreshSession,
    OAuthToken,
    OAuthAuthorize,
    OAuthPar,
    OAuthIntrospect,
    AppPassword,
    EmailUpdate,
}

impl RateLimitKind {
    fn key_prefix(&self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::AccountCreation => "account_creation",
            Self::PasswordReset => "password_reset",
            Self::ResetPassword => "reset_password",
            Self::RefreshSession => "refresh_session",
            Self::OAuthToken => "oauth_token",
            Self::OAuthAuthorize => "oauth_authorize",
            Self::OAuthPar => "oauth_par",
            Self::OAuthIntrospect => "oauth_introspect",
            Self::AppPassword => "app_password",
            Self::EmailUpdate => "email_update",
        }
    }

    fn limit_and_window_ms(&self) -> (u32, u64) {
        match self {
            Self::Login => (10, 60_000),
            Self::AccountCreation => (10, 3_600_000),
            Self::PasswordReset => (5, 3_600_000),
            Self::ResetPassword => (10, 60_000),
            Self::RefreshSession => (60, 60_000),
            Self::OAuthToken => (30, 60_000),
            Self::OAuthAuthorize => (10, 60_000),
            Self::OAuthPar => (30, 60_000),
            Self::OAuthIntrospect => (30, 60_000),
            Self::AppPassword => (10, 60_000),
            Self::EmailUpdate => (5, 3_600_000),
        }
    }
}

impl AppState {
    pub async fn new(db: PgPool) -> Self {
        AuthConfig::init();

        let block_store = PostgresBlockStore::new(db.clone());
        let blob_store = S3BlobStorage::new().await;

        let firehose_buffer_size: usize = std::env::var("FIREHOSE_BUFFER_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10000);

        let (firehose_tx, _) = broadcast::channel(firehose_buffer_size);
        let rate_limiters = Arc::new(RateLimiters::new());
        let circuit_breakers = Arc::new(CircuitBreakers::new());
        let (cache, distributed_rate_limiter) = create_cache().await;
        let appview_registry = Arc::new(AppViewRegistry::new());

        Self {
            db,
            block_store,
            blob_store: Arc::new(blob_store),
            firehose_tx,
            rate_limiters,
            circuit_breakers,
            cache,
            distributed_rate_limiter,
            appview_registry,
        }
    }

    pub fn with_rate_limiters(mut self, rate_limiters: RateLimiters) -> Self {
        self.rate_limiters = Arc::new(rate_limiters);
        self
    }

    pub fn with_circuit_breakers(mut self, circuit_breakers: CircuitBreakers) -> Self {
        self.circuit_breakers = Arc::new(circuit_breakers);
        self
    }

    pub async fn check_rate_limit(&self, kind: RateLimitKind, client_ip: &str) -> bool {
        if std::env::var("DISABLE_RATE_LIMITING").is_ok() {
            return true;
        }

        let key = format!("{}:{}", kind.key_prefix(), client_ip);
        let limiter_name = kind.key_prefix();
        let (limit, window_ms) = kind.limit_and_window_ms();

        if !self
            .distributed_rate_limiter
            .check_rate_limit(&key, limit, window_ms)
            .await
        {
            crate::metrics::record_rate_limit_rejection(limiter_name);
            return false;
        }

        let limiter = match kind {
            RateLimitKind::Login => &self.rate_limiters.login,
            RateLimitKind::AccountCreation => &self.rate_limiters.account_creation,
            RateLimitKind::PasswordReset => &self.rate_limiters.password_reset,
            RateLimitKind::ResetPassword => &self.rate_limiters.reset_password,
            RateLimitKind::RefreshSession => &self.rate_limiters.refresh_session,
            RateLimitKind::OAuthToken => &self.rate_limiters.oauth_token,
            RateLimitKind::OAuthAuthorize => &self.rate_limiters.oauth_authorize,
            RateLimitKind::OAuthPar => &self.rate_limiters.oauth_par,
            RateLimitKind::OAuthIntrospect => &self.rate_limiters.oauth_introspect,
            RateLimitKind::AppPassword => &self.rate_limiters.app_password,
            RateLimitKind::EmailUpdate => &self.rate_limiters.email_update,
        };

        let ok = limiter.check_key(&client_ip.to_string()).is_ok();
        if !ok {
            crate::metrics::record_rate_limit_rejection(limiter_name);
        }
        ok
    }
}
