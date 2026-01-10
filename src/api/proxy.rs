use std::convert::Infallible;

use crate::api::error::ApiError;
use crate::api::proxy_client::proxy_client;
use crate::state::AppState;
use axum::{
    body::Bytes,
    extract::{RawQuery, Request, State},
    handler::Handler,
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
};
use futures_util::future::Either;
use tower::{Service, util::BoxCloneSyncService};
use tracing::{error, info, warn};

const PROTECTED_METHODS: &[&str] = &[
    "app.bsky.actor.getPreferences",
    "app.bsky.actor.putPreferences",
    "com.atproto.admin.deleteAccount",
    "com.atproto.admin.disableAccountInvites",
    "com.atproto.admin.disableInviteCodes",
    "com.atproto.admin.enableAccountInvites",
    "com.atproto.admin.getAccountInfo",
    "com.atproto.admin.getAccountInfos",
    "com.atproto.admin.getInviteCodes",
    "com.atproto.admin.getSubjectStatus",
    "com.atproto.admin.searchAccounts",
    "com.atproto.admin.sendEmail",
    "com.atproto.admin.updateAccountEmail",
    "com.atproto.admin.updateAccountHandle",
    "com.atproto.admin.updateAccountPassword",
    "com.atproto.admin.updateSubjectStatus",
    "com.atproto.identity.getRecommendedDidCredentials",
    "com.atproto.identity.requestPlcOperationSignature",
    "com.atproto.identity.signPlcOperation",
    "com.atproto.identity.submitPlcOperation",
    "com.atproto.identity.updateHandle",
    "com.atproto.repo.applyWrites",
    "com.atproto.repo.createRecord",
    "com.atproto.repo.deleteRecord",
    "com.atproto.repo.importRepo",
    "com.atproto.repo.putRecord",
    "com.atproto.repo.uploadBlob",
    "com.atproto.server.activateAccount",
    "com.atproto.server.checkAccountStatus",
    "com.atproto.server.confirmEmail",
    "com.atproto.server.confirmSignup",
    "com.atproto.server.createAccount",
    "com.atproto.server.createAppPassword",
    "com.atproto.server.createInviteCode",
    "com.atproto.server.createInviteCodes",
    "com.atproto.server.createSession",
    "com.atproto.server.createTotpSecret",
    "com.atproto.server.deactivateAccount",
    "com.atproto.server.deleteAccount",
    "com.atproto.server.deletePasskey",
    "com.atproto.server.deleteSession",
    "com.atproto.server.describeServer",
    "com.atproto.server.disableTotp",
    "com.atproto.server.enableTotp",
    "com.atproto.server.finishPasskeyRegistration",
    "com.atproto.server.getAccountInviteCodes",
    "com.atproto.server.getServiceAuth",
    "com.atproto.server.getSession",
    "com.atproto.server.getTotpStatus",
    "com.atproto.server.listAppPasswords",
    "com.atproto.server.listPasskeys",
    "com.atproto.server.refreshSession",
    "com.atproto.server.regenerateBackupCodes",
    "com.atproto.server.requestAccountDelete",
    "com.atproto.server.requestEmailConfirmation",
    "com.atproto.server.requestEmailUpdate",
    "com.atproto.server.requestPasswordReset",
    "com.atproto.server.resendMigrationVerification",
    "com.atproto.server.resendVerification",
    "com.atproto.server.reserveSigningKey",
    "com.atproto.server.resetPassword",
    "com.atproto.server.revokeAppPassword",
    "com.atproto.server.startPasskeyRegistration",
    "com.atproto.server.updateEmail",
    "com.atproto.server.updatePasskey",
    "com.atproto.server.verifyMigrationEmail",
    "com.atproto.sync.getBlob",
    "com.atproto.sync.getBlocks",
    "com.atproto.sync.getCheckout",
    "com.atproto.sync.getHead",
    "com.atproto.sync.getLatestCommit",
    "com.atproto.sync.getRecord",
    "com.atproto.sync.getRepo",
    "com.atproto.sync.getRepoStatus",
    "com.atproto.sync.listBlobs",
    "com.atproto.sync.listRepos",
    "com.atproto.sync.notifyOfUpdate",
    "com.atproto.sync.requestCrawl",
    "com.atproto.sync.subscribeRepos",
    "com.atproto.temp.checkSignupQueue",
    "com.atproto.temp.dereferenceScope",
];

fn is_protected_method(method: &str) -> bool {
    PROTECTED_METHODS.contains(&method)
}

pub struct XrpcProxyLayer {
    state: AppState,
}

impl XrpcProxyLayer {
    pub fn new(state: AppState) -> Self {
        XrpcProxyLayer { state }
    }
}

impl<S> tower_layer::Layer<S> for XrpcProxyLayer {
    type Service = XrpcProxyingService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        XrpcProxyingService {
            inner,
            // TODO(nel): make our own service here instead of boxing a HandlerService
            handler: BoxCloneSyncService::new(proxy_handler.with_state(self.state.clone())),
        }
    }
}

#[derive(Clone)]
pub struct XrpcProxyingService<S> {
    inner: S,
    handler: BoxCloneSyncService<Request, Response, Infallible>,
}

impl<S: Service<Request, Response = Response, Error = Infallible>> Service<Request>
    for XrpcProxyingService<S>
{
    type Response = Response;

    type Error = Infallible;

    type Future = Either<
        <BoxCloneSyncService<Request, Response, Infallible> as Service<Request>>::Future,
        S::Future,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        if req
            .headers()
            .contains_key(http::HeaderName::from(jacquard::xrpc::Header::AtprotoProxy))
        {
            let path = req.uri().path();
            let method = path.trim_start_matches("/");

            if is_protected_method(method) {
                return Either::Right(self.inner.call(req));
            }

            // If the age assurance override is set and this is an age assurance call then we dont want to proxy even if the client requests it
            if std::env::var("PDS_AGE_ASSURANCE_OVERRIDE").is_ok()
                && (path.ends_with("app.bsky.ageassurance.getState")
                    || path.ends_with("app.bsky.unspecced.getAgeAssuranceState"))
            {
                return Either::Right(self.inner.call(req));
            }

            Either::Left(self.handler.call(req))
        } else {
            Either::Right(self.inner.call(req))
        }
    }
}

async fn proxy_handler(
    State(state): State<AppState>,
    uri: http::Uri,
    method_verb: Method,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    // This layer is nested under /xrpc in an axum router so the extracted uri will look like /<method> and thus we can just strip the /
    let method = uri.path().trim_start_matches("/");
    if is_protected_method(method) {
        warn!(method = %method, "Attempted to proxy protected method");
        return ApiError::InvalidRequest(format!("Cannot proxy protected method: {}", method))
            .into_response();
    }

    let Some(proxy_header) = headers
        .get("atproto-proxy")
        .and_then(|h| h.to_str().ok())
        .map(String::from)
    else {
        return ApiError::InvalidRequest("Missing required atproto-proxy header".into())
            .into_response();
    };

    let did = proxy_header.split('#').next().unwrap_or(&proxy_header);
    let Some(resolved) = state.did_resolver.resolve_did(did).await else {
        error!(did = %did, "Could not resolve service DID");
        return ApiError::UpstreamFailure.into_response();
    };

    let target_url = match &query {
        Some(q) => format!("{}/xrpc/{}?{}", resolved.url, method, q),
        None => format!("{}/xrpc/{}", resolved.url, method),
    };
    info!("Proxying {} request to {}", method_verb, target_url);

    let client = proxy_client();
    let mut request_builder = client.request(method_verb.clone(), &target_url);

    let mut auth_header_val = headers.get("Authorization").cloned();
    if let Some(extracted) = crate::auth::extract_auth_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        let token = extracted.token;
        let dpop_proof = headers.get("DPoP").and_then(|h| h.to_str().ok());
        let http_uri = uri.to_string();

        match crate::auth::validate_token_with_dpop(
            &state.db,
            &token,
            extracted.is_dpop,
            dpop_proof,
            method_verb.as_str(),
            &http_uri,
            false,
            false,
        )
        .await
        {
            Ok(auth_user) => {
                if let Err(e) = crate::auth::scope_check::check_rpc_scope(
                    auth_user.is_oauth,
                    auth_user.scope.as_deref(),
                    &resolved.did,
                    method,
                ) {
                    return e;
                }

                if let Some(key_bytes) = auth_user.key_bytes {
                    match crate::auth::create_service_token(
                        &auth_user.did,
                        &resolved.did,
                        method,
                        &key_bytes,
                    ) {
                        Ok(new_token) => {
                            if let Ok(val) =
                                axum::http::HeaderValue::from_str(&format!("Bearer {}", new_token))
                            {
                                auth_header_val = Some(val);
                            }
                        }
                        Err(e) => {
                            warn!("Failed to create service token: {:?}", e);
                        }
                    }
                }
            }
            Err(e) => {
                warn!("Token validation failed: {:?}", e);
                if matches!(e, crate::auth::TokenValidationError::TokenExpired)
                    && extracted.is_dpop
                {
                    let www_auth =
                        "DPoP error=\"invalid_token\", error_description=\"Token has expired\"";
                    let mut response =
                        ApiError::ExpiredToken(Some("Token has expired".into())).into_response();
                    *response.status_mut() = axum::http::StatusCode::UNAUTHORIZED;
                    response
                        .headers_mut()
                        .insert("WWW-Authenticate", www_auth.parse().unwrap());
                    let nonce = crate::oauth::verify::generate_dpop_nonce();
                    response
                        .headers_mut()
                        .insert("DPoP-Nonce", nonce.parse().unwrap());
                    return response;
                }
            }
        }
    }

    if let Some(val) = auth_header_val {
        request_builder = request_builder.header("Authorization", val);
    }
    for header_name in crate::api::proxy_client::HEADERS_TO_FORWARD {
        if let Some(val) = headers.get(*header_name) {
            request_builder = request_builder.header(*header_name, val);
        }
    }
    if !body.is_empty() {
        request_builder = request_builder.body(body);
    }

    match request_builder.send().await {
        Ok(resp) => {
            let status = resp.status();
            let headers = resp.headers().clone();
            let body = match resp.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    error!("Error reading proxy response body: {:?}", e);
                    return (StatusCode::BAD_GATEWAY, "Error reading upstream response")
                        .into_response();
                }
            };
            let mut response_builder = Response::builder().status(status);
            for header_name in crate::api::proxy_client::RESPONSE_HEADERS_TO_FORWARD {
                if let Some(val) = headers.get(*header_name) {
                    response_builder = response_builder.header(*header_name, val);
                }
            }
            match response_builder.body(axum::body::Body::from(body)) {
                Ok(r) => r,
                Err(e) => {
                    error!("Error building proxy response: {:?}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
                }
            }
        }
        Err(e) => {
            error!("Error sending proxy request: {:?}", e);
            if e.is_timeout() {
                (StatusCode::GATEWAY_TIMEOUT, "Upstream Timeout").into_response()
            } else {
                (StatusCode::BAD_GATEWAY, "Upstream Error").into_response()
            }
        }
    }
}
