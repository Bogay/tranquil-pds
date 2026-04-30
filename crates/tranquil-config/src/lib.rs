use confique::Config;
use std::fmt;
use std::path::PathBuf;
use std::sync::OnceLock;

static CONFIG: OnceLock<TranquilConfig> = OnceLock::new();

const REMOVED_ENV_VARS: &[(&str, &str)] = &[(
    "SENDMAIL_PATH",
    "the sendmail-binary transport was replaced with native SMTP. \
     Configure MAIL_SMARTHOST_HOST for relay delivery, or leave it unset to \
     deliver directly via recipient MX records. See example.toml for the full \
     MAIL_* surface.",
)];

/// Errors discovered during configuration validation.
#[derive(Debug)]
pub struct ConfigError {
    pub errors: Vec<String>,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "configuration validation failed:")?;
        for err in &self.errors {
            writeln!(f, "  - {err}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigError {}

/// Initialize the global configuration. Must be called once at startup before
/// any other code accesses the configuration. Panics if called more than once.
pub fn init(config: TranquilConfig) {
    CONFIG
        .set(config)
        .expect("tranquil-config: configuration already initialized");
}

/// Returns a reference to the global configuration.
/// Panics if [`init`] has not been called yet.
pub fn get() -> &'static TranquilConfig {
    CONFIG
        .get()
        .expect("tranquil-config: not initialized - call tranquil_config::init() first")
}

/// Returns a reference to the global configuration if it has been initialized.
pub fn try_get() -> Option<&'static TranquilConfig> {
    CONFIG.get()
}

/// Initialize with minimal defaults for unit tests.
/// Noop if already initialized.
pub fn ensure_test_defaults() {
    use std::env;
    let _ = CONFIG.get_or_init(|| {
        unsafe {
            if env::var("PDS_HOSTNAME").is_err() {
                env::set_var("PDS_HOSTNAME", "test.local");
            }
            if env::var("DATABASE_URL").is_err() {
                env::set_var("DATABASE_URL", "postgres://localhost/test");
            }
            if env::var("TRANQUIL_PDS_ALLOW_INSECURE_SECRETS").is_err() {
                env::set_var("TRANQUIL_PDS_ALLOW_INSECURE_SECRETS", "1");
            }
            if env::var("INVITE_CODE_REQUIRED").is_err() {
                env::set_var("INVITE_CODE_REQUIRED", "false");
            }
            if env::var("ENABLE_PDS_HOSTED_DID_WEB").is_err() {
                env::set_var("ENABLE_PDS_HOSTED_DID_WEB", "true");
            }
            if env::var("TRANQUIL_LEXICON_OFFLINE").is_err() {
                env::set_var("TRANQUIL_LEXICON_OFFLINE", "1");
            }
        }
        TranquilConfig::builder()
            .env()
            .load()
            .expect("failed to load test config defaults")
    });
}

/// Load configuration from an optional TOML file path, with environment
/// variable overrides applied on top. Fields annotated with `#[config(env)]`
/// are read from the corresponding environment variables when the `.env()`
/// layer is active.
///
/// Precedence (highest to lowest):
/// 1. Environment variables
/// 2. Toml config file passed as `config_path`, if provided
/// 3. `/etc/tranquil-pds/config.toml` - hardcoded fallback, silently skipped if absent
/// 4. Built-in defaults
pub fn load(config_path: Option<&PathBuf>) -> Result<TranquilConfig, confique::Error> {
    let mut builder = TranquilConfig::builder().env();
    if let Some(path) = config_path {
        builder = builder.file(path);
    }
    builder.file("/etc/tranquil-pds/config.toml").load()
}

// Root configuration
#[derive(Debug, Config)]
pub struct TranquilConfig {
    #[config(nested)]
    pub server: ServerConfig,

    #[config(nested)]
    pub frontend: FrontendConfig,

    #[config(nested)]
    pub database: DatabaseConfig,

    #[config(nested)]
    pub secrets: SecretsConfig,

    #[config(nested)]
    pub storage: StorageConfig,

    #[config(nested)]
    pub tranquil_store: TranquilStoreConfig,

    #[config(nested)]
    pub cache: CacheConfig,

    #[config(nested)]
    pub plc: PlcConfig,

    #[config(nested)]
    pub firehose: FirehoseConfig,

    #[config(nested)]
    pub email: EmailConfig,

    #[config(nested)]
    pub discord: DiscordConfig,

    #[config(nested)]
    pub telegram: TelegramConfig,

    #[config(nested)]
    pub signal: SignalConfig,

    #[config(nested)]
    pub notifications: NotificationConfig,

    #[config(nested)]
    pub sso: SsoConfig,

    #[config(nested)]
    pub moderation: ModerationConfig,

    #[config(nested)]
    pub import: ImportConfig,

    #[config(nested)]
    pub scheduled: ScheduledConfig,
}

impl TranquilConfig {
    /// Validate cross-field constraints that cannot be expressed through
    /// confique's declarative defaults alone.  Call this once after loading
    /// the configuration and before [`init`].
    ///
    /// Returns `Ok(())` when the configuration is consistent, or a
    /// [`ConfigError`] listing every problem found.
    pub fn validate(&self, ignore_secrets: bool) -> Result<(), ConfigError> {
        let mut errors = Vec::new();

        // -- removed config ---------------------------------------------------
        errors.extend(
            REMOVED_ENV_VARS
                .iter()
                .filter(|(var, _)| std::env::var_os(var).is_some())
                .map(|(var, guidance)| format!("{var} is no longer supported: {guidance}")),
        );

        // -- secrets ----------------------------------------------------------
        if !ignore_secrets && !self.secrets.allow_insecure && !cfg!(test) {
            if let Some(ref s) = self.secrets.jwt_secret {
                if s.len() < 32 {
                    errors.push(
                        "secrets.jwt_secret (JWT_SECRET) must be at least 32 characters"
                            .to_string(),
                    );
                }
            } else {
                errors.push(
                    "secrets.jwt_secret (JWT_SECRET) is required in production \
                     (set TRANQUIL_PDS_ALLOW_INSECURE_SECRETS=true for development)"
                        .to_string(),
                );
            }

            if let Some(ref s) = self.secrets.dpop_secret {
                if s.len() < 32 {
                    errors.push(
                        "secrets.dpop_secret (DPOP_SECRET) must be at least 32 characters"
                            .to_string(),
                    );
                }
            } else {
                errors.push(
                    "secrets.dpop_secret (DPOP_SECRET) is required in production \
                     (set TRANQUIL_PDS_ALLOW_INSECURE_SECRETS=true for development)"
                        .to_string(),
                );
            }

            if let Some(ref s) = self.secrets.master_key {
                if s.len() < 32 {
                    errors.push(
                        "secrets.master_key (MASTER_KEY) must be at least 32 characters"
                            .to_string(),
                    );
                }
            } else {
                errors.push(
                    "secrets.master_key (MASTER_KEY) is required in production \
                     (set TRANQUIL_PDS_ALLOW_INSECURE_SECRETS=true for development)"
                        .to_string(),
                );
            }
        }

        // -- email smarthost --------------------------------------------------
        match self.email.smarthost.tls.to_ascii_lowercase().as_str() {
            "implicit" | "starttls" => {}
            "none" => {
                if self.email.smarthost.password.is_some() {
                    errors.push(
                        "email.smarthost.tls = \"none\" with email.smarthost.password set \
                         would transmit credentials in plaintext; use \"starttls\" or \"implicit\""
                            .to_string(),
                    );
                }
            }
            other => errors.push(format!(
                "email.smarthost.tls must be \"implicit\", \"starttls\", or \"none\", got \"{other}\""
            )),
        }

        let smarthost_host_set = self
            .email
            .smarthost
            .host
            .as_deref()
            .is_some_and(|h| !h.is_empty());
        let username_set = self.email.smarthost.username.is_some();
        let password_set = self.email.smarthost.password.is_some();
        if !smarthost_host_set && (username_set || password_set) {
            errors.push(
                "email.smarthost.username or email.smarthost.password is set but \
                 email.smarthost.host is empty; credentials would be silently ignored"
                    .to_string(),
            );
        }
        if smarthost_host_set && username_set != password_set {
            errors.push(
                "email.smarthost.username and email.smarthost.password must both be set or \
                 both unset; otherwise authentication would silently degrade to anonymous"
                    .to_string(),
            );
        }

        if self.email.smarthost.command_timeout_secs == 0 {
            errors.push("email.smarthost.command_timeout_secs must be at least 1".to_string());
        }
        if self.email.smarthost.total_timeout_secs == 0 {
            errors.push("email.smarthost.total_timeout_secs must be at least 1".to_string());
        }
        if self.email.smarthost.pool_size == 0 {
            errors.push("email.smarthost.pool_size must be at least 1".to_string());
        }

        if self.email.direct_mx.max_concurrent_sends == 0 {
            errors.push("email.direct_mx.max_concurrent_sends must be at least 1".to_string());
        }
        if self.email.direct_mx.command_timeout_secs == 0 {
            errors.push("email.direct_mx.command_timeout_secs must be at least 1".to_string());
        }
        if self.email.direct_mx.total_timeout_secs == 0 {
            errors.push("email.direct_mx.total_timeout_secs must be at least 1".to_string());
        }

        let dkim_set = self.email.dkim.selector.is_some()
            || self.email.dkim.domain.is_some()
            || self.email.dkim.private_key_path.is_some();
        if dkim_set {
            if self.email.dkim.selector.is_none() {
                errors
                    .push("email.dkim.selector is required when any DKIM field is set".to_string());
            }
            if self.email.dkim.domain.is_none() {
                errors.push("email.dkim.domain is required when any DKIM field is set".to_string());
            }
            if self.email.dkim.private_key_path.is_none() {
                errors.push(
                    "email.dkim.private_key_path is required when any DKIM field is set"
                        .to_string(),
                );
            }
        }

        // -- telegram ---------------------------------------------------------
        if self.telegram.bot_token.is_some() && self.telegram.webhook_secret.is_none() {
            errors.push(
                "telegram.bot_token is set but telegram.webhook_secret is missing; \
                 both are required for secure Telegram integration"
                    .to_string(),
            );
        }

        // -- blob storage -----------------------------------------------------
        match self.storage.backend.as_str() {
            "s3" => {
                if self.storage.s3_bucket.is_none() {
                    errors.push(
                        "storage.backend is \"s3\" but storage.s3_bucket (S3_BUCKET) \
                         is not set"
                            .to_string(),
                    );
                }
            }
            "filesystem" => {}
            other => {
                errors.push(format!(
                    "storage.backend must be \"filesystem\" or \"s3\", got \"{other}\""
                ));
            }
        }

        // -- SSO providers ----------------------------------------------------
        self.validate_sso_provider("sso.github", &self.sso.github, &mut errors);
        self.validate_sso_provider("sso.google", &self.sso.google, &mut errors);
        self.validate_sso_provider("sso.discord", &self.sso.discord, &mut errors);
        self.validate_sso_with_issuer("sso.gitlab", &self.sso.gitlab, &mut errors);
        self.validate_sso_with_issuer("sso.oidc", &self.sso.oidc, &mut errors);
        self.validate_sso_apple(&mut errors);

        // -- moderation -------------------------------------------------------
        let has_url = self.moderation.report_service_url.is_some();
        let has_did = self.moderation.report_service_did.is_some();
        if has_url != has_did {
            errors.push(
                "moderation.report_service_url and moderation.report_service_did \
                 must both be set or both be unset"
                    .to_string(),
            );
        }

        // -- repo backend -----------------------------------------------------
        if let Err(e) = self.storage.repo_backend.parse::<RepoBackend>() {
            errors.push(e);
        }

        // -- tranquil-store ---------------------------------------------------
        if let Some(mb) = self.tranquil_store.memory_budget_mb
            && mb == 0
        {
            errors.push("tranquil_store.memory_budget_mb must be at least 1".to_string());
        }
        if let Some(threads) = self.tranquil_store.handler_threads
            && threads == 0
        {
            errors.push("tranquil_store.handler_threads must be at least 1".to_string());
        }
        if self.tranquil_store.eventlog_max_event_payload == 0 {
            errors.push(
                "tranquil_store.eventlog_max_event_payload \
                 (TRANQUIL_STORE_EVENTLOG_MAX_EVENT_PAYLOAD) must be at least 1; \
                 a value of 0 would reject every event"
                    .to_string(),
            );
        }

        // -- scheduled / event retention --------------------------------------
        const MAX_RETENTION_SECS: u64 = (i64::MAX / 1000) as u64;
        if self.scheduled.event_retention_max_age_secs > MAX_RETENTION_SECS {
            errors.push(format!(
                "scheduled.event_retention_max_age_secs (EVENT_RETENTION_MAX_AGE_SECS) \
                 must be at most {MAX_RETENTION_SECS} (chrono::Duration limit); got {}",
                self.scheduled.event_retention_max_age_secs
            ));
        }
        if self.scheduled.event_retention_interval_secs > 0 {
            let backfill_secs = u64::try_from(self.firehose.backfill_hours.max(0))
                .unwrap_or(0)
                .saturating_mul(3600);
            if self.scheduled.event_retention_max_age_secs < backfill_secs {
                errors.push(format!(
                    "scheduled.event_retention_max_age_secs ({}) is shorter than \
                     firehose.backfill_hours ({}h = {backfill_secs}s): \
                     relays would receive cursor responses pointing at pruned events. \
                     Increase event_retention_max_age_secs or decrease firehose.backfill_hours.",
                    self.scheduled.event_retention_max_age_secs, self.firehose.backfill_hours,
                ));
            }
        }

        // -- cache ------------------------------------------------------------
        match self.cache.backend.as_str() {
            "valkey" => {
                if self.cache.valkey_url.is_none() {
                    errors.push(
                        "cache.backend is \"valkey\" but cache.valkey_url (VALKEY_URL) \
                         is not set"
                            .to_string(),
                    );
                }
            }
            "ripple" => {}
            other => {
                errors.push(format!(
                    "cache.backend must be \"ripple\" or \"valkey\", got \"{other}\""
                ));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ConfigError { errors })
        }
    }

    fn validate_sso_provider(
        &self,
        prefix: &str,
        p: &impl SsoProviderConfig,
        errors: &mut Vec<String>,
    ) {
        if p.get_enabled() {
            if p.get_client_id().is_none() {
                errors.push(format!(
                    "{prefix}.client_id is required when {prefix}.enabled = true"
                ));
            }
            if p.get_client_secret().is_none() {
                errors.push(format!(
                    "{prefix}.client_secret is required when {prefix}.enabled = true"
                ));
            }
        }
    }

    fn validate_sso_with_issuer(
        &self,
        prefix: &str,
        p: &(impl SsoProviderConfig + SsoProviderIssuerConfig),
        errors: &mut Vec<String>,
    ) {
        self.validate_sso_provider(prefix, p, errors);
        if p.get_enabled() && p.get_issuer().is_none() {
            errors.push(format!(
                "{prefix}.issuer is required when {prefix}.enabled = true"
            ));
        }
    }

    fn validate_sso_apple(&self, errors: &mut Vec<String>) {
        let p = &self.sso.apple;
        if p.enabled {
            if p.client_id.is_none() {
                errors.push(
                    "sso.apple.client_id is required when sso.apple.enabled = true".to_string(),
                );
            }
            if p.team_id.is_none() {
                errors.push(
                    "sso.apple.team_id is required when sso.apple.enabled = true".to_string(),
                );
            }
            if p.key_id.is_none() {
                errors
                    .push("sso.apple.key_id is required when sso.apple.enabled = true".to_string());
            }
            if p.private_key.is_none() {
                errors.push(
                    "sso.apple.private_key is required when sso.apple.enabled = true".to_string(),
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

#[derive(Debug, Config)]
pub struct ServerConfig {
    /// Public hostname of the PDS, such as `pds.example.com`.
    #[config(env = "PDS_HOSTNAME")]
    pub hostname: String,

    /// Address to bind the HTTP server to.
    #[config(env = "SERVER_HOST", default = "127.0.0.1")]
    pub host: String,

    /// Port to bind the HTTP server to.
    #[config(env = "SERVER_PORT", default = 3000)]
    pub port: u16,

    /// List of domains for user handles.
    /// Defaults to the PDS hostname when not set.
    #[config(env = "PDS_USER_HANDLE_DOMAINS", parse_env = split_comma_list)]
    pub user_handle_domains: Option<Vec<String>>,

    /// Enable PDS-hosted did:web identities.  Hosting did:web requires a
    /// long-term commitment to serve DID documents; opt-in only.
    #[config(env = "ENABLE_PDS_HOSTED_DID_WEB", default = false)]
    pub enable_pds_hosted_did_web: bool,

    /// When set to true, skip age-assurance birthday prompt for all accounts.
    #[config(env = "PDS_AGE_ASSURANCE_OVERRIDE", default = false)]
    pub age_assurance_override: bool,

    /// Require an invite code for new account registration.
    #[config(env = "INVITE_CODE_REQUIRED", default = true)]
    pub invite_code_required: bool,

    /// Allow HTTP (non-TLS) proxy requests. Only useful during development.
    #[config(env = "ALLOW_HTTP_PROXY", default = false)]
    pub allow_http_proxy: bool,

    /// Disable all rate limiting. Should only be used in testing.
    #[config(env = "DISABLE_RATE_LIMITING", default = false)]
    pub disable_rate_limiting: bool,

    /// List of additional banned words for handle validation.
    #[config(env = "PDS_BANNED_WORDS", parse_env = split_comma_list)]
    pub banned_words: Option<Vec<String>>,

    /// URL to a privacy policy page.
    #[config(env = "PRIVACY_POLICY_URL")]
    pub privacy_policy_url: Option<String>,

    /// URL to terms of service page.
    #[config(env = "TERMS_OF_SERVICE_URL")]
    pub terms_of_service_url: Option<String>,

    /// Operator contact email address.
    #[config(env = "CONTACT_EMAIL")]
    pub contact_email: Option<String>,

    /// Maximum allowed blob size in bytes (default 10 GiB).
    #[config(env = "MAX_BLOB_SIZE", default = 10_737_418_240u64)]
    pub max_blob_size: u64,

    /// Maximum allowed number of preferences
    #[config(env = "MAX_PREFERENCES_COUNT", default = 1000)]
    pub max_preferences_count: usize,
}

impl ServerConfig {
    /// The public HTTPS URL for this PDS.
    pub fn public_url(&self) -> String {
        format!("https://{}", self.hostname)
    }

    /// Hostname without port suffix. Returns `pds.example.com` from `pds.example.com:443`.
    pub fn hostname_without_port(&self) -> &str {
        self.hostname.split(':').next().unwrap_or(&self.hostname)
    }

    /// Returns the extra banned words list, or an empty vec when unset.
    pub fn banned_word_list(&self) -> Vec<String> {
        self.banned_words.clone().unwrap_or_default()
    }

    /// Returns the user handle domains, falling back to `[hostname_without_port]`.
    pub fn user_handle_domain_list(&self) -> Vec<String> {
        self.user_handle_domains
            .as_deref()
            .filter(|v| !v.is_empty())
            .map(|v| v.to_vec())
            .unwrap_or_else(|| vec![self.hostname_without_port().to_string()])
    }

    /// Alias for `user_handle_domain_list` (for callers that were using the now-removed `available_user_domains` field).
    pub fn available_user_domain_list(&self) -> Vec<String> {
        self.user_handle_domain_list()
    }
}

#[derive(Debug, Config)]
pub struct FrontendConfig {
    /// Whether to enable the built in serving of the frontend.
    #[config(env = "FRONTEND_ENABLED", default = true)]
    pub enabled: bool,

    /// Directory to serve as the frontend. The oauth_client_metadata.json will have any references to
    /// the frontend hostname replaced by the configured frontend hostname.
    #[config(env = "FRONTEND_DIR", default = "/var/lib/tranquil-pds/frontend")]
    pub dir: String,
}

#[derive(Debug, Config)]
pub struct DatabaseConfig {
    /// PostgreSQL connection URL.
    #[config(env = "DATABASE_URL")]
    pub url: String,

    /// Maximum number of connections in the pool.
    #[config(env = "DATABASE_MAX_CONNECTIONS", default = 100)]
    pub max_connections: u32,

    /// Minimum number of idle connections kept in the pool.
    #[config(env = "DATABASE_MIN_CONNECTIONS", default = 10)]
    pub min_connections: u32,

    /// Timeout in seconds when acquiring a connection from the pool.
    #[config(env = "DATABASE_ACQUIRE_TIMEOUT_SECS", default = 10)]
    pub acquire_timeout_secs: u64,
}

#[derive(Config)]
pub struct SecretsConfig {
    /// Secret used for signing JWTs. Must be at least 32 characters in
    /// production.
    #[config(env = "JWT_SECRET")]
    pub jwt_secret: Option<String>,

    /// Secret used for DPoP proof validation. Must be at least 32 characters
    /// in production.
    #[config(env = "DPOP_SECRET")]
    pub dpop_secret: Option<String>,

    /// Master key used for key-encryption and HKDF derivation. Must be at
    /// least 32 characters in production.
    #[config(env = "MASTER_KEY")]
    pub master_key: Option<String>,

    /// PLC rotation key (DID key). If not set, user-level keys are used.
    #[config(env = "PLC_ROTATION_KEY")]
    pub plc_rotation_key: Option<String>,

    /// Allow insecure/test secrets. NEVER enable in production.
    #[config(env = "TRANQUIL_PDS_ALLOW_INSECURE_SECRETS", default = false)]
    pub allow_insecure: bool,
}

impl std::fmt::Debug for SecretsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretsConfig")
            .field(
                "jwt_secret",
                &self.jwt_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "dpop_secret",
                &self.dpop_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "master_key",
                &self.master_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "plc_rotation_key",
                &self.plc_rotation_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("allow_insecure", &self.allow_insecure)
            .finish()
    }
}

impl SecretsConfig {
    /// Resolve the JWT secret, falling back to an insecure default if
    /// `allow_insecure` is true.
    pub fn jwt_secret_or_default(&self) -> String {
        self.jwt_secret.clone().unwrap_or_else(|| {
            if cfg!(test) || self.allow_insecure {
                "test-jwt-secret-not-for-production".to_string()
            } else {
                panic!(
                    "JWT_SECRET must be set in production. \
                     Set TRANQUIL_PDS_ALLOW_INSECURE_SECRETS=true for development/testing."
                );
            }
        })
    }

    /// Resolve the DPoP secret, falling back to an insecure default if
    /// `allow_insecure` is true.
    pub fn dpop_secret_or_default(&self) -> String {
        self.dpop_secret.clone().unwrap_or_else(|| {
            if cfg!(test) || self.allow_insecure {
                "test-dpop-secret-not-for-production".to_string()
            } else {
                panic!(
                    "DPOP_SECRET must be set in production. \
                     Set TRANQUIL_PDS_ALLOW_INSECURE_SECRETS=true for development/testing."
                );
            }
        })
    }

    /// Resolve the master key, falling back to an insecure default if
    /// `allow_insecure` is true.
    pub fn master_key_or_default(&self) -> String {
        self.master_key.clone().unwrap_or_else(|| {
            if cfg!(test) || self.allow_insecure {
                "test-master-key-not-for-production".to_string()
            } else {
                panic!(
                    "MASTER_KEY must be set in production. \
                     Set TRANQUIL_PDS_ALLOW_INSECURE_SECRETS=true for development/testing."
                );
            }
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoBackend {
    Postgres,
    TranquilStore,
}

impl std::str::FromStr for RepoBackend {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "postgres" => Ok(Self::Postgres),
            "tranquil-store" => Ok(Self::TranquilStore),
            other => Err(format!(
                "unknown repo backend \"{other}\", expected \"postgres\" or \"tranquil-store\""
            )),
        }
    }
}

impl fmt::Display for RepoBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Postgres => f.write_str("postgres"),
            Self::TranquilStore => f.write_str("tranquil-store"),
        }
    }
}

#[derive(Debug, Config)]
pub struct StorageConfig {
    /// Storage backend: `filesystem` or `s3`.
    #[config(env = "BLOB_STORAGE_BACKEND", default = "filesystem")]
    pub backend: String,

    /// Path on disk for the filesystem blob backend.
    #[config(env = "BLOB_STORAGE_PATH", default = "/var/lib/tranquil-pds/blobs")]
    pub path: String,

    /// S3 bucket name for blob storage.
    #[config(env = "S3_BUCKET")]
    pub s3_bucket: Option<String>,

    /// Custom S3 endpoint URL.
    #[config(env = "S3_ENDPOINT")]
    pub s3_endpoint: Option<String>,

    /// Repository backend: `postgres` by default, or `tranquil-store`, our embedded db.
    /// tranquil-store is EXPERIMENTAL!!!! RISK OF TOTAL DATA LOSS.
    #[config(env = "REPO_BACKEND", default = "postgres")]
    pub repo_backend: String,
}

impl StorageConfig {
    pub fn repo_backend(&self) -> RepoBackend {
        self.repo_backend
            .parse()
            .expect("repo_backend must be validated before use")
    }
}

#[derive(Debug, Config)]
pub struct CacheConfig {
    /// Cache backend: `ripple` by default, or `valkey`.
    #[config(env = "CACHE_BACKEND", default = "ripple")]
    pub backend: String,

    /// Valkey / Redis connection URL.  Required when `backend = "valkey"`.
    #[config(env = "VALKEY_URL")]
    pub valkey_url: Option<String>,

    #[config(nested)]
    pub ripple: RippleCacheConfig,
}

#[derive(Debug, Config)]
pub struct PlcConfig {
    /// Base URL of the PLC directory.
    #[config(env = "PLC_DIRECTORY_URL", default = "https://plc.directory")]
    pub directory_url: String,

    /// HTTP request timeout in seconds.
    #[config(env = "PLC_TIMEOUT_SECS", default = 10)]
    pub timeout_secs: u64,

    /// TCP connect timeout in seconds.
    #[config(env = "PLC_CONNECT_TIMEOUT_SECS", default = 5)]
    pub connect_timeout_secs: u64,

    /// Seconds to cache DID documents in memory.
    #[config(env = "DID_CACHE_TTL_SECS", default = 300)]
    pub did_cache_ttl_secs: u64,
}

#[derive(Debug, Config)]
pub struct FirehoseConfig {
    /// Size of the in-memory broadcast buffer for firehose events.
    #[config(env = "FIREHOSE_BUFFER_SIZE", default = 10000)]
    pub buffer_size: usize,

    /// How many hours of historical events to replay for cursor-based
    /// firehose connections.
    #[config(env = "FIREHOSE_BACKFILL_HOURS", default = 72)]
    pub backfill_hours: i64,

    /// Maximum concurrent full-repo exports, eg. getRepo without `since`.
    #[config(env = "MAX_CONCURRENT_REPO_EXPORTS", default = 4)]
    pub max_concurrent_repo_exports: usize,

    /// List of relay / crawler notification URLs.
    #[config(env = "CRAWLERS", parse_env = split_comma_list)]
    pub crawlers: Option<Vec<String>>,
}

impl FirehoseConfig {
    /// Returns the list of crawler URLs, falling back to `["https://bsky.network"]`
    /// when none are configured.
    pub fn crawler_list(&self) -> Vec<String> {
        self.crawlers
            .clone()
            .unwrap_or_else(|| vec!["https://bsky.network".to_string()])
    }
}

#[derive(Debug, Config)]
pub struct EmailConfig {
    /// Sender email address. When unset, email sending is disabled.
    #[config(env = "MAIL_FROM_ADDRESS")]
    pub from_address: Option<String>,

    /// Display name used in the `From` header.
    #[config(env = "MAIL_FROM_NAME", default = "Tranquil PDS")]
    pub from_name: String,

    /// HELO/EHLO name announced to remote SMTP servers. Applies to both
    /// smarthost and direct-MX modes. Defaults to the server hostname.
    #[config(env = "MAIL_HELO_NAME")]
    pub helo_name: Option<String>,

    #[config(nested)]
    pub smarthost: SmarthostConfig,

    #[config(nested)]
    pub direct_mx: DirectMxConfig,

    #[config(nested)]
    pub dkim: DkimConfig,
}

#[derive(Debug, Config)]
pub struct SmarthostConfig {
    /// SMTP relay host. When set, mail is delivered through this host
    /// instead of resolving recipient MX records directly.
    #[config(env = "MAIL_SMARTHOST_HOST")]
    pub host: Option<String>,

    /// SMTP relay port.
    #[config(env = "MAIL_SMARTHOST_PORT", default = 587)]
    pub port: u16,

    /// SMTP authentication username.
    #[config(env = "MAIL_SMARTHOST_USERNAME")]
    pub username: Option<String>,

    /// SMTP authentication password.
    #[config(env = "MAIL_SMARTHOST_PASSWORD")]
    pub password: Option<String>,

    /// TLS mode. Valid values: "implicit", "starttls", "none". Setting "none"
    /// alongside a password is rejected at startup to prevent transmitting
    /// credentials in plaintext.
    #[config(env = "MAIL_SMARTHOST_TLS", default = "starttls")]
    pub tls: String,

    /// Max size of the connection pool.
    #[config(env = "MAIL_SMARTHOST_POOL_SIZE", default = 4)]
    pub pool_size: u32,

    /// Per-command SMTP timeout in seconds. Bounds the security handshake.
    #[config(env = "MAIL_SMARTHOST_COMMAND_TIMEOUT_SECS", default = 30)]
    pub command_timeout_secs: u64,

    /// Total per-message timeout in seconds. Wraps the entire send so a
    /// stuck relay cannot stall the comms queue.
    #[config(env = "MAIL_SMARTHOST_TOTAL_TIMEOUT_SECS", default = 60)]
    pub total_timeout_secs: u64,
}

#[derive(Debug, Config)]
pub struct DirectMxConfig {
    /// Per-command SMTP timeout in seconds.
    #[config(env = "MAIL_COMMAND_TIMEOUT_SECS", default = 30)]
    pub command_timeout_secs: u64,

    /// Total per-message timeout across all MX attempts in seconds.
    #[config(env = "MAIL_TOTAL_TIMEOUT_SECS", default = 60)]
    pub total_timeout_secs: u64,

    /// Max number of concurrent direct-MX sends. Limits the load placed
    /// on any single recipient MX during a backlog drain.
    #[config(env = "MAIL_MAX_CONCURRENT_SENDS", default = 8)]
    pub max_concurrent_sends: usize,

    /// Require STARTTLS on every MX hop. When false, TLS is
    /// attempted opportunistically and the session falls back to plaintext
    /// if the remote does not advertise STARTTLS. Set true to refuse
    /// plaintext delivery, at the cost of failing sends to MX hosts that
    /// do not support TLS.
    #[config(env = "MAIL_REQUIRE_TLS", default = false)]
    pub require_tls: bool,
}

#[derive(Debug, Config)]
pub struct DkimConfig {
    /// DKIM selector. When unset, outgoing mail is not signed.
    #[config(env = "MAIL_DKIM_SELECTOR")]
    pub selector: Option<String>,

    /// DKIM signing domain.
    #[config(env = "MAIL_DKIM_DOMAIN")]
    pub domain: Option<String>,

    /// Path to the DKIM private key in PEM format. Supports RSA and
    /// Ed25519 keys.
    #[config(env = "MAIL_DKIM_KEY_PATH")]
    pub private_key_path: Option<String>,
}

#[derive(Debug, Config)]
pub struct DiscordConfig {
    /// Discord bot token. When unset, Discord integration is disabled.
    #[config(env = "DISCORD_BOT_TOKEN")]
    pub bot_token: Option<String>,
}

#[derive(Debug, Config)]
pub struct TelegramConfig {
    /// Telegram bot token. When unset, Telegram integration is disabled.
    #[config(env = "TELEGRAM_BOT_TOKEN")]
    pub bot_token: Option<String>,

    /// Secret token for incoming webhook verification.
    #[config(env = "TELEGRAM_WEBHOOK_SECRET")]
    pub webhook_secret: Option<String>,
}

#[derive(Debug, Config)]
pub struct SignalConfig {
    /// Protocol state is stored in postgres' signal_* tables.
    /// Link a device via the admin API before enabling.
    #[config(env = "SIGNAL_ENABLED", default = false)]
    pub enabled: bool,
}

#[derive(Debug, Config)]
pub struct NotificationConfig {
    /// Polling interval in milliseconds for the comms queue.
    #[config(env = "NOTIFICATION_POLL_INTERVAL_MS", default = 1000)]
    pub poll_interval_ms: u64,

    /// Number of notifications to process per batch.
    #[config(env = "NOTIFICATION_BATCH_SIZE", default = 100)]
    pub batch_size: i64,
}

pub trait SsoProviderConfig {
    fn get_enabled(&self) -> bool;
    fn get_client_id(&self) -> &Option<String>;
    fn get_client_secret(&self) -> &Option<String>;
    fn get_display_name(&self) -> &Option<String>;
}

pub trait SsoProviderIssuerConfig {
    fn get_issuer(&self) -> &Option<String>;
}

#[derive(Debug, Config)]
pub struct SsoConfig {
    #[config(nested)]
    pub github: SsoGitHubConfig,

    #[config(nested)]
    pub discord: SsoDiscordConfig,

    #[config(nested)]
    pub google: SsoGoogleConfig,

    #[config(nested)]
    pub gitlab: SsoGitLabConfig,

    #[config(nested)]
    pub oidc: SsoOidcConfig,

    #[config(nested)]
    pub apple: SsoAppleConfig,
}

#[derive(Debug, Config)]
pub struct SsoGitHubConfig {
    #[config(env = "SSO_GITHUB_ENABLED", default = false)]
    pub enabled: bool,

    #[config(env = "SSO_GITHUB_CLIENT_ID")]
    pub client_id: Option<String>,

    #[config(env = "SSO_GITHUB_CLIENT_SECRET")]
    pub client_secret: Option<String>,

    #[config(env = "SSO_GITHUB_DISPLAY_NAME")]
    pub display_name: Option<String>,
}

impl SsoProviderConfig for SsoGitHubConfig {
    fn get_enabled(&self) -> bool {
        self.enabled
    }

    fn get_client_id(&self) -> &Option<String> {
        &self.client_id
    }

    fn get_client_secret(&self) -> &Option<String> {
        &self.client_secret
    }

    fn get_display_name(&self) -> &Option<String> {
        &self.display_name
    }
}

#[derive(Debug, Config)]
pub struct SsoDiscordConfig {
    #[config(env = "SSO_DISCORD_ENABLED", default = false)]
    pub enabled: bool,

    #[config(env = "SSO_DISCORD_CLIENT_ID")]
    pub client_id: Option<String>,

    #[config(env = "SSO_DISCORD_CLIENT_SECRET")]
    pub client_secret: Option<String>,

    #[config(env = "SSO_DISCORD_DISPLAY_NAME")]
    pub display_name: Option<String>,
}

impl SsoProviderConfig for SsoDiscordConfig {
    fn get_enabled(&self) -> bool {
        self.enabled
    }

    fn get_client_id(&self) -> &Option<String> {
        &self.client_id
    }

    fn get_client_secret(&self) -> &Option<String> {
        &self.client_secret
    }

    fn get_display_name(&self) -> &Option<String> {
        &self.display_name
    }
}

#[derive(Debug, Config)]
pub struct SsoGoogleConfig {
    #[config(env = "SSO_GOOGLE_ENABLED", default = false)]
    pub enabled: bool,

    #[config(env = "SSO_GOOGLE_CLIENT_ID")]
    pub client_id: Option<String>,

    #[config(env = "SSO_GOOGLE_CLIENT_SECRET")]
    pub client_secret: Option<String>,

    #[config(env = "SSO_GOOGLE_DISPLAY_NAME")]
    pub display_name: Option<String>,
}

impl SsoProviderConfig for SsoGoogleConfig {
    fn get_enabled(&self) -> bool {
        self.enabled
    }

    fn get_client_id(&self) -> &Option<String> {
        &self.client_id
    }

    fn get_client_secret(&self) -> &Option<String> {
        &self.client_secret
    }

    fn get_display_name(&self) -> &Option<String> {
        &self.display_name
    }
}

#[derive(Debug, Config)]
pub struct SsoGitLabConfig {
    #[config(env = "SSO_GITLAB_ENABLED", default = false)]
    pub enabled: bool,

    #[config(env = "SSO_GITLAB_CLIENT_ID")]
    pub client_id: Option<String>,

    #[config(env = "SSO_GITLAB_CLIENT_SECRET")]
    pub client_secret: Option<String>,

    #[config(env = "SSO_GITLAB_ISSUER")]
    pub issuer: Option<String>,

    #[config(env = "SSO_GITLAB_DISPLAY_NAME")]
    pub display_name: Option<String>,
}

impl SsoProviderConfig for SsoGitLabConfig {
    fn get_enabled(&self) -> bool {
        self.enabled
    }

    fn get_client_id(&self) -> &Option<String> {
        &self.client_id
    }

    fn get_client_secret(&self) -> &Option<String> {
        &self.client_secret
    }

    fn get_display_name(&self) -> &Option<String> {
        &self.display_name
    }
}

impl SsoProviderIssuerConfig for SsoGitLabConfig {
    fn get_issuer(&self) -> &Option<String> {
        &self.issuer
    }
}

#[derive(Debug, Config)]
pub struct SsoOidcConfig {
    #[config(env = "SSO_OIDC_ENABLED", default = false)]
    pub enabled: bool,

    #[config(env = "SSO_OIDC_CLIENT_ID")]
    pub client_id: Option<String>,

    #[config(env = "SSO_OIDC_CLIENT_SECRET")]
    pub client_secret: Option<String>,

    #[config(env = "SSO_OIDC_ISSUER")]
    pub issuer: Option<String>,

    #[config(env = "SSO_OIDC_DISPLAY_NAME")]
    pub display_name: Option<String>,
}

impl SsoProviderConfig for SsoOidcConfig {
    fn get_enabled(&self) -> bool {
        self.enabled
    }

    fn get_client_id(&self) -> &Option<String> {
        &self.client_id
    }

    fn get_client_secret(&self) -> &Option<String> {
        &self.client_secret
    }

    fn get_display_name(&self) -> &Option<String> {
        &self.display_name
    }
}

impl SsoProviderIssuerConfig for SsoOidcConfig {
    fn get_issuer(&self) -> &Option<String> {
        &self.issuer
    }
}

#[derive(Debug, Config)]
pub struct SsoAppleConfig {
    #[config(env = "SSO_APPLE_ENABLED", default = false)]
    pub enabled: bool,

    #[config(env = "SSO_APPLE_CLIENT_ID")]
    pub client_id: Option<String>,

    #[config(env = "SSO_APPLE_TEAM_ID")]
    pub team_id: Option<String>,

    #[config(env = "SSO_APPLE_KEY_ID")]
    pub key_id: Option<String>,

    #[config(env = "SSO_APPLE_PRIVATE_KEY")]
    pub private_key: Option<String>,
}

#[derive(Debug, Config)]
pub struct ModerationConfig {
    /// External report-handling service URL.
    #[config(env = "REPORT_SERVICE_URL")]
    pub report_service_url: Option<String>,

    /// DID of the external report-handling service.
    #[config(env = "REPORT_SERVICE_DID")]
    pub report_service_did: Option<String>,
}

#[derive(Debug, Config)]
pub struct ImportConfig {
    /// Whether the PDS accepts repo imports.
    #[config(env = "ACCEPTING_REPO_IMPORTS", default = true)]
    pub accepting: bool,

    /// Maximum allowed import archive size in bytes (default 1 GiB).
    #[config(env = "MAX_IMPORT_SIZE", default = 1_073_741_824)]
    pub max_size: u64,

    /// Maximum number of blocks allowed in an import.
    #[config(env = "MAX_IMPORT_BLOCKS", default = 500000)]
    pub max_blocks: u64,

    /// Skip CAR verification during import. Only for development/debugging.
    #[config(env = "SKIP_IMPORT_VERIFICATION", default = false)]
    pub skip_verification: bool,
}

/// Parse a comma-separated environment variable into a `Vec<String>`,
/// trimming whitespace and dropping empty entries.
///
/// Signature matches confique's `parse_env` expectation: `fn(&str) -> Result<T, E>`.
fn split_comma_list(value: &str) -> Result<Vec<String>, std::convert::Infallible> {
    Ok(value
        .split(',')
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .collect())
}

#[derive(Debug, Config)]
pub struct RippleCacheConfig {
    /// Address to bind the Ripple gossip protocol listener.
    #[config(env = "RIPPLE_BIND", default = "0.0.0.0:0")]
    pub bind_addr: String,

    /// List of seed peer addresses.
    #[config(env = "RIPPLE_PEERS", parse_env = split_comma_list)]
    pub peers: Option<Vec<String>>,

    /// Unique machine identifier. Auto-derived from hostname when not set.
    #[config(env = "RIPPLE_MACHINE_ID")]
    pub machine_id: Option<u64>,

    /// Gossip protocol interval in milliseconds.
    #[config(env = "RIPPLE_GOSSIP_INTERVAL_MS", default = 200)]
    pub gossip_interval_ms: u64,

    /// Maximum cache size in megabytes.
    #[config(env = "RIPPLE_CACHE_MAX_MB", default = 256)]
    pub cache_max_mb: usize,
}

#[derive(Debug, Config)]
pub struct ScheduledConfig {
    /// Interval in seconds between scheduled delete checks.
    #[config(env = "SCHEDULED_DELETE_CHECK_INTERVAL_SECS", default = 3600)]
    pub delete_check_interval_secs: u64,

    /// Interval in seconds between data file compaction scans (tranquil-store only).
    /// Set to 0 to disable.
    #[config(env = "COMPACTION_INTERVAL_SECS", default = 3600)]
    pub compaction_interval_secs: u64,

    /// Liveness ratio threshold below which a data file is compacted (0.0-1.0).
    #[config(env = "COMPACTION_LIVENESS_THRESHOLD", default = 0.7)]
    pub compaction_liveness_threshold: f64,

    /// Grace period in milliseconds before a zero-refcount block can be removed by compaction.
    #[config(env = "COMPACTION_GRACE_PERIOD_MS", default = 600000)]
    pub compaction_grace_period_ms: u64,

    /// Interval in seconds between reachability walk runs (tranquil-store only).
    /// Set to 0 to disable. Default: weekly.
    #[config(env = "REACHABILITY_WALK_INTERVAL_SECS", default = 604800)]
    pub reachability_walk_interval_secs: u64,

    /// Interval in seconds between continuous archival passes (tranquil-store only).
    /// Sealed eventlog segments are copied to the archival destination each tick.
    /// Set to 0 to disable. Default: 60 seconds.
    #[config(env = "ARCHIVAL_INTERVAL_SECS", default = 60)]
    pub archival_interval_secs: u64,

    /// Archival destination directory for sealed eventlog segments.
    /// If unset, archival is disabled.
    #[config(env = "ARCHIVAL_DEST_DIR")]
    pub archival_dest_dir: Option<String>,

    /// Maximum age of events retained in the eventlog before pruning.
    /// Per the atproto firehose spec, the relay backfill window only needs
    /// to cover "hours or days".
    #[config(env = "EVENT_RETENTION_MAX_AGE_SECS", default = 604800)]
    pub event_retention_max_age_secs: u64,

    /// Interval in seconds between event retention prune passes.
    /// Set to 0 to disable.
    #[config(env = "EVENT_RETENTION_INTERVAL_SECS", default = 3600)]
    pub event_retention_interval_secs: u64,
}

#[derive(Debug, Config)]
pub struct TranquilStoreConfig {
    /// Directory for tranquil-store data: the metastore, eventlog, and blockstore.
    #[config(
        env = "TRANQUIL_STORE_DATA_DIR",
        default = "/var/lib/tranquil-pds/store"
    )]
    pub data_dir: String,

    /// Fjall block cache size in megabytes. Defaults to 20% of system RAM when unset.
    #[config(env = "TRANQUIL_STORE_MEMORY_BUDGET_MB")]
    pub memory_budget_mb: Option<u64>,

    /// Number of handler threads. Defaults to available_parallelism / 2.
    #[config(env = "TRANQUIL_STORE_HANDLER_THREADS")]
    pub handler_threads: Option<usize>,

    /// Maximum total bytes of pending (unsynced) eventlog payloads. Appenders block
    /// once this budget is exhausted until in-flight events drain via fsync. Set to
    /// 0 to disable backpressure. Default: 1 GiB.
    #[config(
        env = "TRANQUIL_STORE_EVENTLOG_PENDING_BYTES_BUDGET",
        default = 1_073_741_824
    )]
    pub eventlog_pending_bytes_budget: u64,

    /// Maximum size of an individual eventlog payload in bytes. Single events
    /// larger than this are rejected at append time. Default: 256 MiB.
    #[config(
        env = "TRANQUIL_STORE_EVENTLOG_MAX_EVENT_PAYLOAD",
        default = 268_435_456
    )]
    pub eventlog_max_event_payload: u32,

    /// Maximum size of an individual blockstore data file in bytes. When the
    /// active data file reaches this size it is rolled over and becomes
    /// eligible for compaction. Default: 256 MiB.
    #[config(env = "TRANQUIL_STORE_MAX_BLOCKSTORE_FILE_SIZE", default = 268_435_456)]
    pub max_blockstore_file_size: u64,

    /// Maximum size of an individual eventlog segment file in bytes. When the
    /// active segment reaches this size it is sealed and a new one is created.
    /// Safe to change on a running instance. Default: 256 MiB.
    #[config(
        env = "TRANQUIL_STORE_MAX_EVENTLOG_SEGMENT_SIZE",
        default = 268_435_456
    )]
    pub max_eventlog_segment_size: u64,
}

/// Generate a TOML configuration template with all available options,
/// defaults, and documentation comments.
pub fn template() -> String {
    confique::toml::template::<TranquilConfig>(confique::toml::FormatOptions::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_required_env() {
        let required = [
            ("PDS_HOSTNAME", "test.local"),
            ("DATABASE_URL", "postgres://localhost/test"),
            ("TRANQUIL_PDS_ALLOW_INSECURE_SECRETS", "1"),
            ("INVITE_CODE_REQUIRED", "false"),
            ("ENABLE_PDS_HOSTED_DID_WEB", "true"),
            ("TRANQUIL_LEXICON_OFFLINE", "1"),
        ];
        required
            .iter()
            .filter(|(k, _)| std::env::var_os(k).is_none())
            .for_each(|(k, v)| unsafe { std::env::set_var(k, v) });
    }

    #[test]
    fn serial_validate_rejects_legacy_sendmail_path() {
        seed_required_env();
        unsafe { std::env::set_var("SENDMAIL_PATH", "/usr/sbin/sendmail") };
        let config = TranquilConfig::builder()
            .env()
            .load()
            .expect("load fresh config");
        let result = config.validate(true);
        unsafe { std::env::remove_var("SENDMAIL_PATH") };

        let err = result.expect_err("validate must reject SENDMAIL_PATH");
        let mentions_sendmail = err.errors.iter().any(|e| e.contains("SENDMAIL_PATH"));
        assert!(
            mentions_sendmail,
            "errors did not mention SENDMAIL_PATH: {:?}",
            err.errors
        );
    }

    #[test]
    fn serial_validate_passes_when_no_legacy_env_set() {
        seed_required_env();
        unsafe { std::env::remove_var("SENDMAIL_PATH") };
        let config = TranquilConfig::builder()
            .env()
            .load()
            .expect("load fresh config");
        let result = config.validate(true);
        let leaked_legacy = result
            .as_ref()
            .err()
            .map(|e| e.errors.iter().any(|s| s.contains("SENDMAIL_PATH")))
            .unwrap_or(false);
        assert!(
            !leaked_legacy,
            "validate spuriously flagged SENDMAIL_PATH when unset: {:?}",
            result
        );
    }
}
