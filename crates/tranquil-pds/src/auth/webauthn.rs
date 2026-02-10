use uuid::Uuid;
use webauthn_rs::prelude::*;

#[derive(Debug, thiserror::Error)]
pub enum WebauthnError {
    #[error("Invalid origin URL: {0}")]
    InvalidOrigin(String),
    #[error("Failed to create WebAuthn builder: {0}")]
    BuilderFailed(String),
    #[error("Registration failed: {0}")]
    RegistrationFailed(String),
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
}

pub struct WebAuthnConfig {
    webauthn: Webauthn,
}

impl WebAuthnConfig {
    pub fn new(hostname: &str) -> Result<Self, WebauthnError> {
        let rp_id = hostname.split(':').next().unwrap_or(hostname).to_string();
        let rp_origin = Url::parse(&format!("https://{}", hostname))
            .map_err(|e| WebauthnError::InvalidOrigin(e.to_string()))?;

        let builder = WebauthnBuilder::new(&rp_id, &rp_origin)
            .map_err(|e| WebauthnError::BuilderFailed(e.to_string()))?
            .rp_name("Tranquil PDS")
            .danger_set_user_presence_only_security_keys(true);

        let webauthn = builder
            .build()
            .map_err(|e| WebauthnError::BuilderFailed(e.to_string()))?;

        Ok(Self { webauthn })
    }

    pub fn start_registration(
        &self,
        user_id: &str,
        username: &str,
        display_name: &str,
        exclude_credentials: Vec<CredentialID>,
    ) -> Result<(CreationChallengeResponse, SecurityKeyRegistration), WebauthnError> {
        let user_unique_id = Uuid::new_v5(&Uuid::NAMESPACE_OID, user_id.as_bytes());

        self.webauthn
            .start_securitykey_registration(
                user_unique_id,
                username,
                display_name,
                if exclude_credentials.is_empty() {
                    None
                } else {
                    Some(exclude_credentials)
                },
                None,
                None,
            )
            .map_err(|e| WebauthnError::RegistrationFailed(e.to_string()))
    }

    pub fn finish_registration(
        &self,
        reg: &RegisterPublicKeyCredential,
        state: &SecurityKeyRegistration,
    ) -> Result<SecurityKey, WebauthnError> {
        self.webauthn
            .finish_securitykey_registration(reg, state)
            .map_err(|e| WebauthnError::RegistrationFailed(e.to_string()))
    }

    pub fn start_authentication(
        &self,
        credentials: Vec<SecurityKey>,
    ) -> Result<(RequestChallengeResponse, SecurityKeyAuthentication), WebauthnError> {
        self.webauthn
            .start_securitykey_authentication(&credentials)
            .map_err(|e| WebauthnError::AuthenticationFailed(e.to_string()))
    }

    pub fn finish_authentication(
        &self,
        auth: &PublicKeyCredential,
        state: &SecurityKeyAuthentication,
    ) -> Result<AuthenticationResult, WebauthnError> {
        self.webauthn
            .finish_securitykey_authentication(auth, state)
            .map_err(|e| WebauthnError::AuthenticationFailed(e.to_string()))
    }
}
