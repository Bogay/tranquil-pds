pub mod endpoints;
pub mod jwks;
pub mod sso_endpoints;

use tranquil_pds::state::AppState;

pub fn oauth_routes() -> axum::Router<AppState> {
    use axum::{middleware, routing::{get, post}};

    axum::Router::new()
        .route("/jwks", get(endpoints::oauth_jwks))
        .route("/par", post(endpoints::pushed_authorization_request))
        .route("/authorize", get(endpoints::authorize_get))
        .route("/authorize", post(endpoints::authorize_post))
        .route(
            "/authorize/accounts",
            get(endpoints::authorize_accounts),
        )
        .route(
            "/authorize/select",
            post(endpoints::authorize_select),
        )
        .route("/authorize/2fa", get(endpoints::authorize_2fa_get))
        .route("/authorize/2fa", post(endpoints::authorize_2fa_post))
        .route(
            "/authorize/passkey",
            get(endpoints::authorize_passkey_start),
        )
        .route(
            "/authorize/passkey",
            post(endpoints::authorize_passkey_finish),
        )
        .route(
            "/passkey/check",
            get(endpoints::check_user_has_passkeys),
        )
        .route(
            "/security-status",
            get(endpoints::check_user_security_status),
        )
        .route("/passkey/start", post(endpoints::passkey_start))
        .route("/passkey/finish", post(endpoints::passkey_finish))
        .route("/authorize/deny", post(endpoints::authorize_deny))
        .route(
            "/register/complete",
            post(endpoints::register_complete),
        )
        .route(
            "/establish-session",
            post(endpoints::establish_session),
        )
        .route("/authorize/consent", get(endpoints::consent_get))
        .route("/authorize/consent", post(endpoints::consent_post))
        .route("/authorize/renew", post(endpoints::authorize_renew))
        .route(
            "/authorize/redirect",
            get(endpoints::authorize_redirect),
        )
        .route("/delegation/auth", post(endpoints::delegation_auth))
        .route(
            "/delegation/auth-token",
            post(endpoints::delegation_auth_token),
        )
        .route(
            "/delegation/totp",
            post(endpoints::delegation_totp_verify),
        )
        .route(
            "/delegation/callback",
            get(endpoints::delegation_callback),
        )
        .route(
            "/delegation/client-metadata",
            get(endpoints::delegation_client_metadata),
        )
        .route("/token", post(endpoints::token_endpoint))
        .route("/revoke", post(endpoints::revoke_token))
        .route("/introspect", post(endpoints::introspect_token))
        .route("/sso/providers", get(sso_endpoints::get_sso_providers))
        .route("/sso/initiate", post(sso_endpoints::sso_initiate))
        .route(
            "/sso/callback",
            get(sso_endpoints::sso_callback).post(sso_endpoints::sso_callback_post),
        )
        .route("/sso/linked", get(sso_endpoints::get_linked_accounts))
        .route("/sso/unlink", post(sso_endpoints::unlink_account))
        .route(
            "/sso/pending-registration",
            get(sso_endpoints::get_pending_registration),
        )
        .route(
            "/sso/complete-registration",
            post(sso_endpoints::complete_registration),
        )
        .route(
            "/sso/check-handle-available",
            get(sso_endpoints::check_handle_available),
        )
        .layer(middleware::from_fn(tranquil_pds::oauth::verify::dpop_nonce_middleware))
}

pub fn well_known_oauth_routes() -> axum::Router<AppState> {
    use axum::routing::get;

    axum::Router::new()
        .route(
            "/oauth-protected-resource",
            get(endpoints::oauth_protected_resource),
        )
        .route(
            "/oauth-authorization-server",
            get(endpoints::oauth_authorization_server),
        )
}

pub fn frontend_client_metadata_route() -> axum::Router<AppState> {
    use axum::routing::get;

    axum::Router::new()
        .route(
            "/oauth-client-metadata.json",
            get(endpoints::frontend_client_metadata),
        )
}
