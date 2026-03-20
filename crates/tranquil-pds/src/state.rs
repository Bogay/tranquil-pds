use crate::appview::DidResolver;
use crate::auth::webauthn::WebAuthnConfig;
use crate::cache::{Cache, DistributedRateLimiter, create_cache};
use crate::circuit_breaker::CircuitBreakers;
use crate::config::AuthConfig;
use crate::oauth::client::CrossPdsOAuthClient;
use crate::plc::PlcClient;
use crate::rate_limit::RateLimiters;
use crate::repo::PostgresBlockStore;
use crate::repo_write_lock::RepoWriteLocks;
use crate::sso::{SsoConfig, SsoManager};
use crate::storage::{BlobStorage, create_blob_storage};
use sqlx::PgPool;
use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use tranquil_db::PostgresRepositories;
use tranquil_db_traits::SequencedEvent;

static RATE_LIMITING_DISABLED: AtomicBool = AtomicBool::new(false);

pub fn init_rate_limit_override() {
    let disabled = tranquil_config::get().server.disable_rate_limiting;
    RATE_LIMITING_DISABLED.store(disabled, Ordering::Relaxed);
    if disabled {
        tracing::warn!("rate limiting is DISABLED via configuration");
    }
}

#[derive(Clone)]
pub struct AppState {
    pub repos: Arc<PostgresRepositories>,
    pub block_store: PostgresBlockStore,
    pub blob_store: Arc<dyn BlobStorage>,
    pub firehose_tx: broadcast::Sender<SequencedEvent>,
    pub rate_limiters: Arc<RateLimiters>,
    pub repo_write_locks: Arc<RepoWriteLocks>,
    pub circuit_breakers: Arc<CircuitBreakers>,
    pub cache: Arc<dyn Cache>,
    pub distributed_rate_limiter: Arc<dyn DistributedRateLimiter>,
    pub did_resolver: Arc<DidResolver>,
    pub sso_manager: SsoManager,
    pub webauthn_config: Arc<WebAuthnConfig>,
    pub cross_pds_oauth: Arc<CrossPdsOAuthClient>,
    pub shutdown: CancellationToken,
    pub bootstrap_invite_code: Option<String>,
    pub signal_sender: Option<Arc<tranquil_signal::SignalSlot>>,
}

#[derive(Debug, Clone, Copy)]
pub struct RateLimitParams {
    pub limit: u32,
    pub window_ms: u64,
}

impl RateLimitParams {
    pub fn to_governor_quota(self) -> governor::Quota {
        use std::num::NonZeroU32;
        let burst = NonZeroU32::new(self.limit).unwrap_or(NonZeroU32::MIN);
        let period = std::time::Duration::from_millis(self.window_ms);
        governor::Quota::with_period(period)
            .expect("rate limit window must be non-zero")
            .allow_burst(burst)
    }
}

#[derive(Debug, Clone, Copy)]
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
    HandleVerification,
}

impl RateLimitKind {
    const fn key_prefix(&self) -> &'static str {
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
            Self::HandleVerification => "handle_verification",
        }
    }

    pub const fn params(&self) -> RateLimitParams {
        match self {
            Self::Login => RateLimitParams {
                limit: 10,
                window_ms: 60_000,
            },
            Self::AccountCreation => RateLimitParams {
                limit: 10,
                window_ms: 3_600_000,
            },
            Self::PasswordReset => RateLimitParams {
                limit: 5,
                window_ms: 3_600_000,
            },
            Self::ResetPassword => RateLimitParams {
                limit: 10,
                window_ms: 60_000,
            },
            Self::RefreshSession => RateLimitParams {
                limit: 60,
                window_ms: 60_000,
            },
            Self::OAuthToken => RateLimitParams {
                limit: 300,
                window_ms: 60_000,
            },
            Self::OAuthAuthorize => RateLimitParams {
                limit: 10,
                window_ms: 60_000,
            },
            Self::OAuthPar => RateLimitParams {
                limit: 30,
                window_ms: 60_000,
            },
            Self::OAuthIntrospect => RateLimitParams {
                limit: 30,
                window_ms: 60_000,
            },
            Self::AppPassword => RateLimitParams {
                limit: 10,
                window_ms: 60_000,
            },
            Self::EmailUpdate => RateLimitParams {
                limit: 5,
                window_ms: 3_600_000,
            },
            Self::TotpVerify => RateLimitParams {
                limit: 5,
                window_ms: 300_000,
            },
            Self::HandleUpdate => RateLimitParams {
                limit: 10,
                window_ms: 300_000,
            },
            Self::HandleUpdateDaily => RateLimitParams {
                limit: 50,
                window_ms: 86_400_000,
            },
            Self::VerificationCheck => RateLimitParams {
                limit: 60,
                window_ms: 60_000,
            },
            Self::SsoInitiate => RateLimitParams {
                limit: 10,
                window_ms: 60_000,
            },
            Self::SsoCallback => RateLimitParams {
                limit: 30,
                window_ms: 60_000,
            },
            Self::SsoUnlink => RateLimitParams {
                limit: 10,
                window_ms: 60_000,
            },
            Self::OAuthRegisterComplete => RateLimitParams {
                limit: 5,
                window_ms: 300_000,
            },
            Self::HandleVerification => RateLimitParams {
                limit: 10,
                window_ms: 60_000,
            },
        }
    }
}

impl AppState {
    pub fn plc_client(&self) -> PlcClient {
        PlcClient::with_cache(None, Some(self.cache.clone()))
    }

    pub async fn new(shutdown: CancellationToken) -> Result<Self, Box<dyn Error>> {
        let cfg = tranquil_config::get();
        let database_url = &cfg.database.url;
        let max_connections = cfg.database.max_connections;
        let min_connections = cfg.database.min_connections;
        let acquire_timeout_secs = cfg.database.acquire_timeout_secs;

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
            .connect(database_url)
            .await
            .map_err(|e| format!("Failed to connect to Postgres: {}", e))?;

        sqlx::migrate!("./migrations")
            .run(&db)
            .await
            .map_err(|e| format!("Failed to run migrations: {}", e))?;

        let bootstrap_invite_code = match (
            cfg.server.invite_code_required,
            sqlx::query_scalar!("SELECT COUNT(*) FROM users")
                .fetch_one(&db)
                .await,
        ) {
            (true, Ok(Some(0))) => {
                let code = crate::util::gen_invite_code();
                tracing::info!(
                    "No users exist and invite codes are required. Bootstrap invite code: {}",
                    code
                );
                Some(code)
            }
            _ => None,
        };

        let mut state = Self::from_db(db, shutdown).await;
        state.bootstrap_invite_code = bootstrap_invite_code;
        Ok(state)
    }

    pub async fn from_db(db: PgPool, shutdown: CancellationToken) -> Self {
        AuthConfig::init();
        init_rate_limit_override();

        let repos = Arc::new(PostgresRepositories::new(db.clone()));
        let block_store = PostgresBlockStore::new(db);
        let blob_store = create_blob_storage().await;

        let firehose_buffer_size = tranquil_config::get().firehose.buffer_size;

        let (firehose_tx, _) = broadcast::channel(firehose_buffer_size);
        let rate_limiters = Arc::new(RateLimiters::new());
        let repo_write_locks = Arc::new(RepoWriteLocks::new());
        let circuit_breakers = Arc::new(CircuitBreakers::new());
        let (cache, distributed_rate_limiter) = create_cache(shutdown.clone()).await;
        let did_resolver = Arc::new(DidResolver::new());
        let cross_pds_oauth = Arc::new(CrossPdsOAuthClient::new(cache.clone()));
        let sso_config = SsoConfig::init();
        let sso_manager = SsoManager::from_config(sso_config);
        let webauthn_config = Arc::new(
            WebAuthnConfig::new(&tranquil_config::get().server.hostname)
                .expect("Failed to create WebAuthn config at startup"),
        );

        Self {
            repos,
            block_store,
            blob_store,
            firehose_tx,
            rate_limiters,
            repo_write_locks,
            circuit_breakers,
            cache,
            distributed_rate_limiter,
            did_resolver,
            cross_pds_oauth,
            sso_manager,
            webauthn_config,
            shutdown,
            bootstrap_invite_code: None,
            signal_sender: None,
        }
    }

    pub fn with_rate_limiters(mut self, rate_limiters: RateLimiters) -> Self {
        self.rate_limiters = Arc::new(rate_limiters);
        self
    }

    pub fn with_cache(
        mut self,
        cache: Arc<dyn Cache>,
        distributed_rate_limiter: Arc<dyn DistributedRateLimiter>,
    ) -> Self {
        self.cache = cache;
        self.distributed_rate_limiter = distributed_rate_limiter;
        self
    }

    pub fn with_signal_sender(mut self, slot: Arc<tranquil_signal::SignalSlot>) -> Self {
        self.signal_sender = Some(slot);
        self
    }

    pub fn with_circuit_breakers(mut self, circuit_breakers: CircuitBreakers) -> Self {
        self.circuit_breakers = Arc::new(circuit_breakers);
        self
    }

    pub async fn check_rate_limit(&self, kind: RateLimitKind, client_ip: &str) -> bool {
        if RATE_LIMITING_DISABLED.load(Ordering::Relaxed) {
            return true;
        }

        let limiter_name = kind.key_prefix();

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
            RateLimitKind::HandleVerification => &self.rate_limiters.handle_verification,
        };

        if limiter.check_key(&client_ip.to_string()).is_err() {
            crate::metrics::record_rate_limit_rejection(limiter_name);
            return false;
        }

        let key = format!("{}:{}", kind.key_prefix(), client_ip);
        let params = kind.params();

        if !self
            .distributed_rate_limiter
            .check_rate_limit(&key, params.limit, params.window_ms)
            .await
        {
            crate::metrics::record_rate_limit_rejection(limiter_name);
            return false;
        }

        true
    }
}
