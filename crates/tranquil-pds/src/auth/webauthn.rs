use uuid::Uuid;
use webauthn_rs::prelude::*;

pub struct WebAuthnConfig {
    webauthn: Webauthn,
}

impl WebAuthnConfig {
    pub fn new(hostname: &str) -> Result<Self, String> {
        let rp_id = hostname.split(':').next().unwrap_or(hostname).to_string();
        let rp_origin = Url::parse(&format!("https://{}", hostname))
            .map_err(|e| format!("Invalid origin URL: {}", e))?;

        let builder = WebauthnBuilder::new(&rp_id, &rp_origin)
            .map_err(|e| format!("Failed to create WebAuthn builder: {}", e))?
            .rp_name("Tranquil PDS")
            .danger_set_user_presence_only_security_keys(true);

        let webauthn = builder
            .build()
            .map_err(|e| format!("Failed to build WebAuthn: {}", e))?;

        Ok(Self { webauthn })
    }

    pub fn start_registration(
        &self,
        user_id: &str,
        username: &str,
        display_name: &str,
        exclude_credentials: Vec<CredentialID>,
    ) -> Result<(CreationChallengeResponse, SecurityKeyRegistration), String> {
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
            .map_err(|e| format!("Failed to start registration: {}", e))
    }

    pub fn finish_registration(
        &self,
        reg: &RegisterPublicKeyCredential,
        state: &SecurityKeyRegistration,
    ) -> Result<SecurityKey, String> {
        self.webauthn
            .finish_securitykey_registration(reg, state)
            .map_err(|e| format!("Failed to finish registration: {}", e))
    }

    pub fn start_authentication(
        &self,
        credentials: Vec<SecurityKey>,
    ) -> Result<(RequestChallengeResponse, SecurityKeyAuthentication), String> {
        self.webauthn
            .start_securitykey_authentication(&credentials)
            .map_err(|e| format!("Failed to start authentication: {}", e))
    }

    pub fn finish_authentication(
        &self,
        auth: &PublicKeyCredential,
        state: &SecurityKeyAuthentication,
    ) -> Result<AuthenticationResult, String> {
        self.webauthn
            .finish_securitykey_authentication(auth, state)
            .map_err(|e| format!("Failed to finish authentication: {}", e))
    }
}
