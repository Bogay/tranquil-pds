use crate::appview::DidResolver;
use crate::cache::{Cache, DistributedRateLimiter, create_cache};
use crate::circuit_breaker::CircuitBreakers;
use crate::config::AuthConfig;
use crate::rate_limit::RateLimiters;
use crate::repo::PostgresBlockStore;
use crate::sso::{SsoConfig, SsoManager};
use crate::storage::{BackupStorage, BlobStorage, S3BlobStorage};
use crate::sync::firehose::SequencedEvent;
use sqlx::PgPool;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::broadcast;
use tranquil_db::{
    BacklinkRepository, BackupRepository, BlobRepository, DelegationRepository, InfraRepository,
    OAuthRepository, PostgresRepositories, RepoEventNotifier, RepoRepository, SessionRepository,
    SsoRepository, UserRepository,
};

#[derive(Clone)]
pub struct AppState {
    pub repos: Arc<PostgresRepositories>,
    pub user_repo: Arc<dyn UserRepository>,
    pub oauth_repo: Arc<dyn OAuthRepository>,
    pub session_repo: Arc<dyn SessionRepository>,
    pub delegation_repo: Arc<dyn DelegationRepository>,
    pub repo_repo: Arc<dyn RepoRepository>,
    pub blob_repo: Arc<dyn BlobRepository>,
    pub infra_repo: Arc<dyn InfraRepository>,
    pub backup_repo: Arc<dyn BackupRepository>,
    pub backlink_repo: Arc<dyn BacklinkRepository>,
    pub event_notifier: Arc<dyn RepoEventNotifier>,
    pub block_store: PostgresBlockStore,
    pub blob_store: Arc<dyn BlobStorage>,
    pub backup_storage: Option<Arc<BackupStorage>>,
    pub firehose_tx: broadcast::Sender<SequencedEvent>,
    pub rate_limiters: Arc<RateLimiters>,
    pub circuit_breakers: Arc<CircuitBreakers>,
    pub cache: Arc<dyn Cache>,
    pub distributed_rate_limiter: Arc<dyn DistributedRateLimiter>,
    pub did_resolver: Arc<DidResolver>,
    pub sso_repo: Arc<dyn SsoRepository>,
    pub sso_manager: SsoManager,
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
    TotpVerify,
    HandleUpdate,
    HandleUpdateDaily,
    VerificationCheck,
    SsoInitiate,
    SsoCallback,
    SsoUnlink,
    OAuthRegisterComplete,
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
            Self::TotpVerify => "totp_verify",
            Self::HandleUpdate => "handle_update",
            Self::HandleUpdateDaily => "handle_update_daily",
            Self::VerificationCheck => "verification_check",
            Self::SsoInitiate => "sso_initiate",
            Self::SsoCallback => "sso_callback",
            Self::SsoUnlink => "sso_unlink",
            Self::OAuthRegisterComplete => "oauth_register_complete",
        }
    }

    fn limit_and_window_ms(&self) -> (u32, u64) {
        match self {
            Self::Login => (10, 60_000),
            Self::AccountCreation => (10, 3_600_000),
            Self::PasswordReset => (5, 3_600_000),
            Self::ResetPassword => (10, 60_000),
            Self::RefreshSession => (60, 60_000),
            Self::OAuthToken => (300, 60_000),
            Self::OAuthAuthorize => (10, 60_000),
            Self::OAuthPar => (30, 60_000),
            Self::OAuthIntrospect => (30, 60_000),
            Self::AppPassword => (10, 60_000),
            Self::EmailUpdate => (5, 3_600_000),
            Self::TotpVerify => (5, 300_000),
            Self::HandleUpdate => (10, 300_000),
            Self::HandleUpdateDaily => (50, 86_400_000),
            Self::VerificationCheck => (60, 60_000),
            Self::SsoInitiate => (10, 60_000),
            Self::SsoCallback => (30, 60_000),
            Self::SsoUnlink => (10, 60_000),
            Self::OAuthRegisterComplete => (5, 300_000),
        }
    }
}

impl AppState {
    pub async fn new() -> Result<Self, Box<dyn Error>> {
        let database_url = std::env::var("DATABASE_URL")
            .map_err(|_| "DATABASE_URL environment variable must be set")?;

        let max_connections: u32 = std::env::var("DATABASE_MAX_CONNECTIONS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);

        let min_connections: u32 = std::env::var("DATABASE_MIN_CONNECTIONS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10);

        let acquire_timeout_secs: u64 = std::env::var("DATABASE_ACQUIRE_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10);

        tracing::info!(
            "Configuring database pool: max={}, min={}, acquire_timeout={}s",
            max_connections,
            min_connections,
            acquire_timeout_secs
        );

        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(max_connections)
            .min_connections(min_connections)
            .acquire_timeout(std::time::Duration::from_secs(acquire_timeout_secs))
            .idle_timeout(std::time::Duration::from_secs(300))
            .max_lifetime(std::time::Duration::from_secs(1800))
            .connect(&database_url)
            .await
            .map_err(|e| format!("Failed to connect to Postgres: {}", e))?;

        sqlx::migrate!("./migrations")
            .run(&db)
            .await
            .map_err(|e| format!("Failed to run migrations: {}", e))?;

        Ok(Self::from_db(db).await)
    }

    pub async fn from_db(db: PgPool) -> Self {
        AuthConfig::init();

        let repos = Arc::new(PostgresRepositories::new(db.clone()));
        let block_store = PostgresBlockStore::new(db);
        let blob_store = S3BlobStorage::new().await;
        let backup_storage = BackupStorage::new().await.map(Arc::new);

        let firehose_buffer_size: usize = std::env::var("FIREHOSE_BUFFER_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10000);

        let (firehose_tx, _) = broadcast::channel(firehose_buffer_size);
        let rate_limiters = Arc::new(RateLimiters::new());
        let circuit_breakers = Arc::new(CircuitBreakers::new());
        let (cache, distributed_rate_limiter) = create_cache().await;
        let did_resolver = Arc::new(DidResolver::new());
        let sso_config = SsoConfig::init();
        let sso_manager = SsoManager::from_config(sso_config);

        Self {
            user_repo: repos.user.clone(),
            oauth_repo: repos.oauth.clone(),
            session_repo: repos.session.clone(),
            delegation_repo: repos.delegation.clone(),
            repo_repo: repos.repo.clone(),
            blob_repo: repos.blob.clone(),
            infra_repo: repos.infra.clone(),
            backup_repo: repos.backup.clone(),
            backlink_repo: repos.backlink.clone(),
            event_notifier: repos.event_notifier.clone(),
            sso_repo: repos.sso.clone(),
            repos,
            block_store,
            blob_store: Arc::new(blob_store),
            backup_storage,
            firehose_tx,
            rate_limiters,
            circuit_breakers,
            cache,
            distributed_rate_limiter,
            did_resolver,
            sso_manager,
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
            RateLimitKind::TotpVerify => &self.rate_limiters.totp_verify,
            RateLimitKind::HandleUpdate => &self.rate_limiters.handle_update,
            RateLimitKind::HandleUpdateDaily => &self.rate_limiters.handle_update_daily,
            RateLimitKind::VerificationCheck => &self.rate_limiters.verification_check,
            RateLimitKind::SsoInitiate => &self.rate_limiters.sso_initiate,
            RateLimitKind::SsoCallback => &self.rate_limiters.sso_callback,
            RateLimitKind::SsoUnlink => &self.rate_limiters.sso_unlink,
            RateLimitKind::OAuthRegisterComplete => &self.rate_limiters.oauth_register_complete,
        };

        let ok = limiter.check_key(&client_ip.to_string()).is_ok();
        if !ok {
            crate::metrics::record_rate_limit_rejection(limiter_name);
        }
        ok
    }
}
