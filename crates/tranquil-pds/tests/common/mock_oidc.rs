use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const KID: &str = "mock-oidc-key-1";

const TEST_PRIVATE_KEY_PEM: &str = "\
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA4FdeE6oHN2pSG3oHChZ0op6KnAppN3VoG7hAfzLHGPUpZ+ge
Rm9CrLs5+qRc+ZHoMgVBQ6XISZ6IHRqFG4Iq5bMdBxecFlxAtkcMcEzD5nJ17k+v
v7igdRFI2Y40glrUja26aXqHNZ+X63va7SutVe++8/YDsi4orT2dhnnEudGJHVVv
2ms6jQre56DfTQswoX4KgczAhXDDy/4N+Qm8A6gQ7GMg2SLgRTN52t9xIc5YP5bY
WBCyI5sWeRsZaVCgWJlDgWtNQ3wOeCnPJTH0Yw1jd6qP4D1gvIIIygNF5pxz+eH3
VVlgat25rb41wfW77dmD1UBzzYQMnholeIcXhwIDAQABAoIBABOdT+pkOVFNCHTC
jI8DO5tkRTYzatOgfkO+LlVwuRujg8VD9DGwVKIJlJ4ndMGVUjndX8FsY0CcjcYN
pYmsLdf7exQ9qjYCRt4pBBtletNROqJlcTZQDCdwJXBwEIM9McxZXi0Ou3eixoOe
Rpvp77PNzGJEJjqT8paDBpzVVK/yShxeeNuOma/aDCmNxlc6kAywOOv7Z+utYfkc
3WrSW+nvqbG8OMh+gnuLRqor+Upo2Bxyxxy6E5Vw7h3UPhvdteu5BAkkLMZK5lQ4
l5yFkR0PS4L7z7Ed2xpSlebT+HNqyhb8mTQJTcI/olGNh3213TENzO/MMBiQI0mZ
dqxn7eECgYEA+UlBnLCszV50pBzrD+m7vlG8yfvqHyZwCicjgmbcm+j2uCqTeyNO
oPoMlljH1bvZUFHqWK31gO+DO7DtBg06v8Qcdu9ZtTdwBGWMrK0lBfMZ4z6VGfO8
yAcFql+2DJEhuMSqV3UiVWXowwEmlOd2FUIhdv3Ijf4dg700El2Ni08CgYEA5mIf
7BdzUDYD3eGWc5OFcuGRpMT0aoxtCcXJuRD64B0I7i8vO7RAlyBcq6+5Rd59c6HF
t1q03iAk64vwbIfJqudG7eSIhzpB+0d4auKv1y1dLnONQSnRz0viC0CrFALcVAOB
bDNhlbeabB89mhi30Ilzsc7AMKfOXvur5I7AQkkCgYEAjeE3yqpzb193G4Cp+KCb
DjMPNBaApcIGuoCUIT/SB5qL8T2qOsdZlR071MYq1mbXxHMa4eYAeKXZFzwXav5U
lZhUawzHDfDDfH0fl5fkHoLCFSglTGQA6ge1Hcbjojtn6fVkzeoI5HngBDy/bLhf
6LF+wm6mmsoqmjQxUtKUINkCgYEAuTuJ+RQ9xe84Gq0nf5PMBzswE++7qPNxNBtP
/rmVTJ5rsL5FVtat3BTMDcqCx5eE/HTEeJC4vaPQq4Zfb5OZ5QyBLgLCdx+zL2se
ean7waGaux9zIkKSi/6yJ2P+aV+HcRFEfQ+u1WbDBU31BLH9EPGDESJvym8RcbMe
WO0hzekCgYEAiDvTf9+TwMTkiPjsm+J/9gE2+zKtHjrlAkxpf1qDCkOf/xrs+D3O
gs+tLXVQ9lBRwhmfm9YcuPJrXDVMjo+7X2M/QU4yGWcJmmHFpmDrPt9KeUpi028A
pKS3Zmty2AMaMFzcyr3f00mdK5r051QYLngR2hU7DQOxLAPUnxsViHQ=
-----END RSA PRIVATE KEY-----
";
const TEST_JWKS_N_B64URL: &str = "4FdeE6oHN2pSG3oHChZ0op6KnAppN3VoG7hAfzLHGPUpZ-geRm9CrLs5-qRc-ZHoMgVBQ6XISZ6IHRqFG4Iq5bMdBxecFlxAtkcMcEzD5nJ17k-vv7igdRFI2Y40glrUja26aXqHNZ-X63va7SutVe--8_YDsi4orT2dhnnEudGJHVVv2ms6jQre56DfTQswoX4KgczAhXDDy_4N-Qm8A6gQ7GMg2SLgRTN52t9xIc5YP5bYWBCyI5sWeRsZaVCgWJlDgWtNQ3wOeCnPJTH0Yw1jd6qP4D1gvIIIygNF5pxz-eH3VVlgat25rb41wfW77dmD1UBzzYQMnholeIcXhw";
const TEST_JWKS_E_B64URL: &str = "AQAB";

pub struct MockOidcProvider {
    pub server: MockServer,
    pub client_id: String,
    pub client_secret: String,
    signing_key: Arc<EncodingKey>,
    state: Arc<RwLock<OidcState>>,
}

#[derive(Default)]
struct OidcState {
    codes: HashMap<String, PendingCode>,
    users: HashMap<String, MockUser>,
    active_tokens: HashMap<String, String>,
}

#[derive(Clone)]
struct PendingCode {
    subject: String,
    nonce: Option<String>,
    redirect_uri: String,
    code_challenge: String,
}

#[derive(Clone)]
pub struct MockUser {
    pub subject: String,
    pub email: String,
    pub email_verified: bool,
    pub username: Option<String>,
}

impl MockOidcProvider {
    pub async fn start() -> Self {
        let server = MockServer::start().await;
        let signing_key =
            EncodingKey::from_rsa_pem(TEST_PRIVATE_KEY_PEM.as_bytes()).expect("encoding key");
        let state = Arc::new(RwLock::new(OidcState::default()));

        let provider = MockOidcProvider {
            server,
            client_id: "mock-oidc-client".to_string(),
            client_secret: "mock-oidc-secret".to_string(),
            signing_key: Arc::new(signing_key),
            state,
        };

        provider.mount_discovery().await;
        provider.mount_jwks().await;
        provider.mount_authorize().await;
        provider.mount_token().await;
        provider.mount_userinfo().await;
        provider
    }

    pub fn issuer(&self) -> String {
        self.server.uri()
    }

    #[allow(dead_code)]
    pub fn register_user(&self, user: MockUser) {
        let mut state = self.state.write().unwrap();
        state.users.insert(user.subject.clone(), user);
    }

    async fn mount_discovery(&self) {
        let issuer = self.issuer();
        let body = json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{}/authorize", issuer),
            "token_endpoint": format!("{}/token", issuer),
            "userinfo_endpoint": format!("{}/userinfo", issuer),
            "jwks_uri": format!("{}/jwks", issuer),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "email", "profile"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        });
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&self.server)
            .await;
    }

    async fn mount_jwks(&self) {
        let body = json!({
            "keys": [{
                "kty": "RSA",
                "kid": KID,
                "use": "sig",
                "alg": "RS256",
                "n": TEST_JWKS_N_B64URL,
                "e": TEST_JWKS_E_B64URL,
            }],
        });
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&self.server)
            .await;
    }

    async fn mount_authorize(&self) {
        Mock::given(method("GET"))
            .and(path("/authorize"))
            .respond_with(AuthorizeResponder {
                state: self.state.clone(),
            })
            .mount(&self.server)
            .await;
    }

    async fn mount_token(&self) {
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(TokenResponder {
                state: self.state.clone(),
                signing_key: self.signing_key.clone(),
                issuer: self.issuer(),
                client_id: self.client_id.clone(),
                client_secret: self.client_secret.clone(),
            })
            .mount(&self.server)
            .await;
    }

    async fn mount_userinfo(&self) {
        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .respond_with(UserInfoResponder {
                state: self.state.clone(),
            })
            .mount(&self.server)
            .await;
    }
}

struct AuthorizeResponder {
    state: Arc<RwLock<OidcState>>,
}

impl Respond for AuthorizeResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let params: HashMap<String, String> = request.url.query_pairs().into_owned().collect();
        let redirect_uri = match params.get("redirect_uri") {
            Some(u) => u.clone(),
            None => return ResponseTemplate::new(400),
        };
        let state_param = params.get("state").cloned().unwrap_or_default();
        let nonce = params.get("nonce").cloned();
        let login_hint = params.get("login_hint").cloned();
        let code_challenge = match (
            params.get("code_challenge"),
            params.get("code_challenge_method").map(String::as_str),
        ) {
            (Some(challenge), Some("S256")) => challenge.clone(),
            _ => {
                return ResponseTemplate::new(400)
                    .set_body_json(json!({"error": "invalid_request"}));
            }
        };

        let subject = match login_hint {
            Some(hint) if self.state.read().unwrap().users.contains_key(&hint) => hint,
            Some(_) => {
                return ResponseTemplate::new(400)
                    .set_body_string("login_hint does not match a registered mock user");
            }
            None => {
                return ResponseTemplate::new(400).set_body_string(
                    "mock OIDC requires login_hint to identify the intended subject",
                );
            }
        };

        let code = format!("mock-code-{}", uuid::Uuid::new_v4().simple());
        self.state.write().unwrap().codes.insert(
            code.clone(),
            PendingCode {
                subject,
                nonce,
                redirect_uri: redirect_uri.clone(),
                code_challenge,
            },
        );

        let separator = if redirect_uri.contains('?') { '&' } else { '?' };
        let location = format!(
            "{}{}code={}&state={}",
            redirect_uri,
            separator,
            urlencoding::encode(&code),
            urlencoding::encode(&state_param),
        );
        ResponseTemplate::new(302).insert_header("location", location.as_str())
    }
}

struct TokenResponder {
    state: Arc<RwLock<OidcState>>,
    signing_key: Arc<EncodingKey>,
    issuer: String,
    client_id: String,
    client_secret: String,
}

#[derive(Serialize)]
struct IdTokenClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    exp: i64,
    iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preferred_username: Option<&'a str>,
}

impl Respond for TokenResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body = std::str::from_utf8(request.body.as_slice()).unwrap_or_default();
        let params: HashMap<String, String> = url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect();

        if params.get("client_id") != Some(&self.client_id)
            || params.get("client_secret") != Some(&self.client_secret)
        {
            return ResponseTemplate::new(401).set_body_json(json!({"error": "invalid_client"}));
        }

        let code = match params.get("code") {
            Some(c) => c.clone(),
            None => {
                return ResponseTemplate::new(400)
                    .set_body_json(json!({"error": "invalid_request"}));
            }
        };

        let (pending, user) = {
            let mut state = self.state.write().unwrap();
            let pending = match state.codes.remove(&code) {
                Some(p) => p,
                None => {
                    return ResponseTemplate::new(400)
                        .set_body_json(json!({"error": "invalid_grant"}));
                }
            };
            let user = state.users.get(&pending.subject).cloned();
            (pending, user)
        };
        let verifier_challenge = params
            .get("code_verifier")
            .map(|verifier| URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())));
        if params.get("redirect_uri") != Some(&pending.redirect_uri)
            || verifier_challenge.as_ref() != Some(&pending.code_challenge)
        {
            return ResponseTemplate::new(400).set_body_json(json!({"error": "invalid_grant"}));
        }
        let user = match user {
            Some(u) => u,
            None => return ResponseTemplate::new(500).set_body_string("user disappeared"),
        };

        let now = chrono::Utc::now().timestamp();
        let claims = IdTokenClaims {
            iss: &self.issuer,
            sub: &user.subject,
            aud: &self.client_id,
            exp: now + 300,
            iat: now,
            nonce: pending.nonce.as_deref(),
            email: Some(user.email.as_str()),
            email_verified: Some(user.email_verified),
            preferred_username: user.username.as_deref(),
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(KID.to_string());
        let id_token =
            jsonwebtoken::encode(&header, &claims, &self.signing_key).expect("sign id token");

        let access_token = format!("mock-access-{}", uuid::Uuid::new_v4().simple());
        self.state
            .write()
            .unwrap()
            .active_tokens
            .insert(access_token.clone(), user.subject.clone());
        ResponseTemplate::new(200).set_body_json(json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": id_token,
        }))
    }
}

struct UserInfoResponder {
    state: Arc<RwLock<OidcState>>,
}

impl Respond for UserInfoResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let auth = request
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let token = match auth.strip_prefix("Bearer ") {
            Some(t) => t,
            None => return ResponseTemplate::new(401),
        };
        let state = self.state.read().unwrap();
        let subject = match state.active_tokens.get(token) {
            Some(s) => s,
            None => return ResponseTemplate::new(401),
        };
        let user = match state.users.get(subject).cloned() {
            Some(u) => u,
            None => return ResponseTemplate::new(500),
        };
        ResponseTemplate::new(200).set_body_json(json!({
            "sub": user.subject,
            "email": user.email,
            "email_verified": user.email_verified,
            "preferred_username": user.username,
        }))
    }
}
