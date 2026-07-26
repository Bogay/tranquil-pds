use tranquil_types::{
    CidLink, ClientId, CrossPdsState, Did, EmailTokenPurpose, Handle, Jti, JwksUri, Nsid, PdsUrl,
    SsoIssuer, SsoJwksUri,
};

pub fn session_key(did: &Did, jti: &Jti) -> String {
    format!("auth:session:{}:{}", did, jti)
}

pub fn signing_key_key(did: &Did) -> String {
    format!("auth:key:{}", did)
}

pub fn user_status_key(did: &Did) -> String {
    format!("auth:status:{}", did)
}

pub fn handle_key(handle: &Handle) -> String {
    format!("handle:{}", handle)
}

pub fn reauth_key(did: &Did) -> String {
    format!("reauth:{}", did)
}

pub fn plc_doc_key(did: &Did) -> String {
    format!("plc:doc:{}", did)
}

pub fn plc_data_key(did: &Did) -> String {
    format!("plc:data:{}", did)
}

pub fn did_web_doc_key(did: &Did) -> String {
    format!("did:web:doc:{}", did)
}

pub fn email_update_key(did: &Did) -> String {
    format!("email_update:{}", did)
}

pub fn email_token_key(did: &Did, purpose: EmailTokenPurpose) -> String {
    format!("email_token:{}:{}", purpose, did)
}

pub fn legacy_2fa_challenge_key(did: &Did) -> String {
    format!("legacy_2fa:{}", did)
}

pub fn legacy_2fa_cooldown_key(did: &Did) -> String {
    format!("legacy_2fa_cooldown:{}", did)
}

pub fn scope_ref_key(cid: &CidLink) -> String {
    format!("scope_ref:{}", cid)
}

pub fn auto_verify_sent_key(did: &Did) -> String {
    format!("auto_verify_sent:{}", did)
}

pub fn permission_set_key(nsid: &Nsid, aud: Option<&str>) -> String {
    match aud {
        Some(a) => format!("permset:{}:{}", nsid, a),
        None => format!("permset:{}", nsid),
    }
}

pub fn oauth_client_meta_key(client_id: &ClientId) -> String {
    format!("oauth:client_meta:{}", client_id)
}

pub fn oauth_client_jwks_key(jwks_uri: &JwksUri) -> String {
    format!("oauth:jwks:{}", jwks_uri.canonical())
}

pub fn oauth_client_jwks_cooldown_key(jwks_uri: &JwksUri) -> String {
    format!("oauth:jwks_cooldown:{}", jwks_uri.canonical())
}

pub fn sso_jwks_key(jwks_uri: &SsoJwksUri) -> String {
    format!("sso:jwks:{}", jwks_uri.canonical())
}

pub fn oidc_discovery_key(issuer: &SsoIssuer) -> String {
    format!("oidc:discovery:{}", issuer.canonical())
}

pub fn cross_pds_state_key(state: &CrossPdsState) -> String {
    format!("cross_pds_state:{}", state)
}

pub fn cross_pds_oauth_meta_key(pds_url: &PdsUrl) -> String {
    format!("cross_pds_oauth_meta:v2:{}", pds_url.canonical())
}

pub fn lexicon_doc_key(nsid: &Nsid) -> String {
    format!("lexicon:doc:{}", nsid)
}

pub fn lexicon_negative_key(nsid: &Nsid) -> String {
    format!("lexicon:neg:{}", nsid)
}
