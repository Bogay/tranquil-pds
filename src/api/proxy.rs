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
    "com.atproto.admin.sendEmail",
    "com.atproto.identity.requestPlcOperationSignature",
    "com.atproto.identity.signPlcOperation",
    "com.atproto.identity.updateHandle",
    "com.atproto.server.activateAccount",
    "com.atproto.server.confirmEmail",
    "com.atproto.server.createAppPassword",
    "com.atproto.server.deactivateAccount",
    "com.atproto.server.getAccountInviteCodes",
    "com.atproto.server.getSession",
    "com.atproto.server.listAppPasswords",
    "com.atproto.server.requestAccountDelete",
    "com.atproto.server.requestEmailConfirmation",
    "com.atproto.server.requestEmailUpdate",
    "com.atproto.server.revokeAppPassword",
    "com.atproto.server.updateEmail",
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
            // If the age assurance override is set and this is an age assurance call then we dont want to proxy even if the client requests it.
            if !std::env::var("PDS_AGE_ASSURANCE_OVERRIDE").is_err()
                && (req.uri().path().ends_with("app.bsky.ageassurance.getState")
                    || req
                        .uri()
                        .path()
                        .ends_with("app.bsky.unspecced.getAgeAssuranceState"))
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
    if is_protected_method(&method) {
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
    let mut request_builder = client.request(method_verb, &target_url);

    let mut auth_header_val = headers.get("Authorization").cloned();
    if let Some(token) = crate::auth::extract_bearer_token_from_header(
        headers.get("Authorization").and_then(|h| h.to_str().ok()),
    ) {
        match crate::auth::validate_bearer_token(&state.db, &token).await {
            Ok(auth_user) => {
                if let Err(e) = crate::auth::scope_check::check_rpc_scope(
                    auth_user.is_oauth,
                    auth_user.scope.as_deref(),
                    &resolved.did,
                    &method,
                ) {
                    return e;
                }

                if let Some(key_bytes) = auth_user.key_bytes {
                    match crate::auth::create_service_token(
                        &auth_user.did,
                        &resolved.did,
                        &method,
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
                if matches!(e, crate::auth::TokenValidationError::TokenExpired) {
                    let auth_header_str = headers
                        .get("Authorization")
                        .and_then(|h| h.to_str().ok())
                        .unwrap_or("");
                    let is_dpop = auth_header_str
                        .trim()
                        .get(..5)
                        .is_some_and(|s| s.eq_ignore_ascii_case("dpop "));
                    let scheme = if is_dpop { "DPoP" } else { "Bearer" };
                    let www_auth = format!(
                        "{} error=\"invalid_token\", error_description=\"Token has expired\"",
                        scheme
                    );
                    let mut response =
                        ApiError::ExpiredToken(Some("Token has expired".into())).into_response();
                    response
                        .headers_mut()
                        .insert("WWW-Authenticate", www_auth.parse().unwrap());
                    if is_dpop {
                        let nonce = crate::oauth::verify::generate_dpop_nonce();
                        response
                            .headers_mut()
                            .insert("DPoP-Nonce", nonce.parse().unwrap());
                    }
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
