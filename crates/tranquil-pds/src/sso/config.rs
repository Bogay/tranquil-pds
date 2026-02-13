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
            let sso = &tranquil_config::get().sso;
           let config = SsoConfig {
               github: Self::provider_from_config(
                   sso.github.enabled,
                   sso.github.client_id.as_deref(),
                   sso.github.client_secret.as_deref(),
                   None,
                   sso.github.display_name.as_deref(),
                   "GITHUB",
                   false,
               ),
               discord: Self::provider_from_config(
                   sso.discord.enabled,
                   sso.discord.client_id.as_deref(),
                   sso.discord.client_secret.as_deref(),
                   None,
                   sso.discord.display_name.as_deref(),
                   "DISCORD",
                   false,
               ),
               google: Self::provider_from_config(
                   sso.google.enabled,
                   sso.google.client_id.as_deref(),
                   sso.google.client_secret.as_deref(),
                   None,
                   sso.google.display_name.as_deref(),
                   "GOOGLE",
                   false,
               ),
               gitlab: Self::provider_from_config(
                   sso.gitlab.enabled,
                   sso.gitlab.client_id.as_deref(),
                   sso.gitlab.client_secret.as_deref(),
                   sso.gitlab.issuer.as_deref(),
                   sso.gitlab.display_name.as_deref(),
                   "GITLAB",
                   true,
               ),
               oidc: Self::provider_from_config(
                   sso.oidc.enabled,
                   sso.oidc.client_id.as_deref(),
                   sso.oidc.client_secret.as_deref(),
                   sso.oidc.issuer.as_deref(),
                   sso.oidc.display_name.as_deref(),
                   "OIDC",
                   true,
               ),
               apple: Self::apple_from_config(&sso.apple),
            };

            if config.is_any_enabled() {
                let hostname = &tranquil_config::get().server.hostname;
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

    fn provider_from_config(
        enabled: bool,
        client_id: Option<&str>,
        client_secret: Option<&str>,
        issuer: Option<&str>,
        display_name: Option<&str>,
        name: &str,
        needs_issuer: bool,
    ) -> Option<ProviderConfig> {
        if !enabled {
            return None;
        }
        let client_id = client_id.filter(|s| !s.is_empty())?;
        let client_secret = client_secret.filter(|s| !s.is_empty())?;

        if needs_issuer {
            let issuer_val = issuer.filter(|s| !s.is_empty());
            if issuer_val.is_none() {
                tracing::warn!("SSO_{} requires ISSUER but none provided", name);
                return None;
            }
        }

        Some(ProviderConfig {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            issuer: issuer.map(|s| s.to_string()),
            display_name: display_name.map(|s| s.to_string()),
        })
    }

    fn apple_from_config(cfg: &tranquil_config::SsoAppleConfig) -> Option<AppleProviderConfig> {
        if !cfg.enabled {
            return None;
        }
        let client_id = cfg.client_id.as_deref().filter(|s| !s.is_empty())?;
        let team_id = cfg.team_id.as_deref().filter(|s| !s.is_empty())?;
        let key_id = cfg.key_id.as_deref().filter(|s| !s.is_empty())?;
        let private_key_pem = cfg.private_key.as_deref().filter(|s| !s.is_empty())?;

        if team_id.len() != 10 {
            tracing::warn!("SSO_APPLE enabled but TEAM_ID is invalid (must be 10 characters)");
            return None;
        }
        if !private_key_pem.contains("PRIVATE KEY") {
            tracing::warn!("SSO_APPLE enabled but PRIVATE_KEY is invalid");
            return None;
        }

        Some(AppleProviderConfig {
            client_id: client_id.to_string(),
            team_id: team_id.to_string(),
            key_id: key_id.to_string(),
            private_key_pem: private_key_pem.to_string(),
        })
    }

    pub fn get_redirect_uri() -> &'static str {
        SSO_REDIRECT_URI
            .get()
            .map(|s| s.as_str())
            .expect("SSO redirect URI not initialized - call SsoConfig::init() first")
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

    fn provider_configs(&self) -> [(SsoProviderType, bool); 6] {
        [
            (SsoProviderType::Github, self.github.is_some()),
            (SsoProviderType::Discord, self.discord.is_some()),
            (SsoProviderType::Google, self.google.is_some()),
            (SsoProviderType::Gitlab, self.gitlab.is_some()),
            (SsoProviderType::Oidc, self.oidc.is_some()),
            (SsoProviderType::Apple, self.apple.is_some()),
        ]
    }

    pub fn enabled_providers(&self) -> Vec<SsoProviderType> {
        self.provider_configs()
            .into_iter()
            .filter_map(|(p, enabled)| enabled.then_some(p))
            .collect()
    }

    pub fn is_any_enabled(&self) -> bool {
        self.provider_configs().into_iter().any(|(_, e)| e)
    }
}
