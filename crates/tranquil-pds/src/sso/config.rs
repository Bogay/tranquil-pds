use std::sync::OnceLock;
use tranquil_db_traits::SsoProviderType;

static SSO_CONFIG: OnceLock<SsoConfig> = OnceLock::new();
static SSO_REDIRECT_URI: OnceLock<String> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub client_id: String,
    pub client_secret: String,
    pub issuer: Option<String>,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AppleProviderConfig {
    pub client_id: String,
    pub team_id: String,
    pub key_id: String,
    pub private_key_pem: String,
}

#[derive(Debug, Clone, Default)]
pub struct SsoConfig {
    pub github: Option<ProviderConfig>,
    pub discord: Option<ProviderConfig>,
    pub google: Option<ProviderConfig>,
    pub gitlab: Option<ProviderConfig>,
    pub oidc: Option<ProviderConfig>,
    pub apple: Option<AppleProviderConfig>,
}

impl SsoConfig {
    pub fn init() -> &'static Self {
        SSO_CONFIG.get_or_init(|| {
            let github = Self::load_provider("GITHUB", false);
            let discord = Self::load_provider("DISCORD", false);
            let google = Self::load_provider("GOOGLE", false);
            let gitlab = Self::load_provider("GITLAB", true);
            let oidc = Self::load_provider("OIDC", true);
            let apple = Self::load_apple_provider();

            let config = SsoConfig {
                github,
                discord,
                google,
                gitlab,
                oidc,
                apple,
            };

            if config.is_any_enabled() {
                let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_default();
                if hostname.is_empty() || hostname == "localhost" {
                    panic!(
                        "PDS_HOSTNAME must be set to a valid hostname when SSO is enabled. \
                        SSO redirect URIs require a proper hostname for security."
                    );
                }
                SSO_REDIRECT_URI
                    .set(format!("https://{}/oauth/sso/callback", hostname))
                    .expect("SSO_REDIRECT_URI already set");
                tracing::info!(
                    hostname = %hostname,
                    providers = ?config.enabled_providers().iter().map(|p| p.as_str()).collect::<Vec<_>>(),
                    "SSO initialized"
                );
            }

            config
        })
    }

    pub fn get_redirect_uri() -> &'static str {
        SSO_REDIRECT_URI
            .get()
            .map(|s| s.as_str())
            .expect("SSO redirect URI not initialized - call SsoConfig::init() first")
    }

    fn load_provider(name: &str, needs_issuer: bool) -> Option<ProviderConfig> {
        let enabled = std::env::var(format!("SSO_{}_ENABLED", name))
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        if !enabled {
            return None;
        }

        let client_id = std::env::var(format!("SSO_{}_CLIENT_ID", name)).ok()?;
        let client_secret = std::env::var(format!("SSO_{}_CLIENT_SECRET", name)).ok()?;

        if client_id.is_empty() || client_secret.is_empty() {
            tracing::warn!(
                "SSO_{} enabled but missing client_id or client_secret",
                name
            );
            return None;
        }

        let issuer = if needs_issuer {
            let issuer_val = std::env::var(format!("SSO_{}_ISSUER", name)).ok();
            if issuer_val.is_none() || issuer_val.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
                tracing::warn!("SSO_{} requires ISSUER but none provided", name);
                return None;
            }
            issuer_val
        } else {
            None
        };

        let display_name = std::env::var(format!("SSO_{}_NAME", name)).ok();

        Some(ProviderConfig {
            client_id,
            client_secret,
            issuer,
            display_name,
        })
    }

    fn load_apple_provider() -> Option<AppleProviderConfig> {
        let enabled = std::env::var("SSO_APPLE_ENABLED")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        if !enabled {
            return None;
        }

        let client_id = std::env::var("SSO_APPLE_CLIENT_ID").ok()?;
        let team_id = std::env::var("SSO_APPLE_TEAM_ID").ok()?;
        let key_id = std::env::var("SSO_APPLE_KEY_ID").ok()?;
        let private_key_pem = std::env::var("SSO_APPLE_PRIVATE_KEY").ok()?;

        if client_id.is_empty() {
            tracing::warn!("SSO_APPLE enabled but missing CLIENT_ID");
            return None;
        }
        if team_id.is_empty() || team_id.len() != 10 {
            tracing::warn!("SSO_APPLE enabled but TEAM_ID is invalid (must be 10 characters)");
            return None;
        }
        if key_id.is_empty() {
            tracing::warn!("SSO_APPLE enabled but missing KEY_ID");
            return None;
        }
        if private_key_pem.is_empty() || !private_key_pem.contains("PRIVATE KEY") {
            tracing::warn!("SSO_APPLE enabled but PRIVATE_KEY is invalid");
            return None;
        }

        Some(AppleProviderConfig {
            client_id,
            team_id,
            key_id,
            private_key_pem,
        })
    }

    pub fn get() -> &'static Self {
        SSO_CONFIG.get_or_init(SsoConfig::default)
    }

    pub fn get_provider_config(&self, provider: SsoProviderType) -> Option<&ProviderConfig> {
        match provider {
            SsoProviderType::Github => self.github.as_ref(),
            SsoProviderType::Discord => self.discord.as_ref(),
            SsoProviderType::Google => self.google.as_ref(),
            SsoProviderType::Gitlab => self.gitlab.as_ref(),
            SsoProviderType::Oidc => self.oidc.as_ref(),
            SsoProviderType::Apple => None,
        }
    }

    pub fn get_apple_config(&self) -> Option<&AppleProviderConfig> {
        self.apple.as_ref()
    }

    pub fn enabled_providers(&self) -> Vec<SsoProviderType> {
        let mut providers = Vec::new();
        if self.github.is_some() {
            providers.push(SsoProviderType::Github);
        }
        if self.discord.is_some() {
            providers.push(SsoProviderType::Discord);
        }
        if self.google.is_some() {
            providers.push(SsoProviderType::Google);
        }
        if self.gitlab.is_some() {
            providers.push(SsoProviderType::Gitlab);
        }
        if self.oidc.is_some() {
            providers.push(SsoProviderType::Oidc);
        }
        if self.apple.is_some() {
            providers.push(SsoProviderType::Apple);
        }
        providers
    }

    pub fn is_any_enabled(&self) -> bool {
        self.github.is_some()
            || self.discord.is_some()
            || self.google.is_some()
            || self.gitlab.is_some()
            || self.oidc.is_some()
            || self.apple.is_some()
    }
}
