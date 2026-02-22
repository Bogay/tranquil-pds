pub mod api;
pub mod appview;
pub mod auth;
pub mod cache;
pub mod cache_keys;
pub mod cid_types;
pub mod circuit_breaker;
pub mod comms;
pub mod config;
pub mod crawlers;
pub mod delegation;
pub mod handle;
pub mod image;
pub mod metrics;
pub mod moderation;
pub mod oauth;
pub mod plc;
pub mod rate_limit;
pub mod repo;
pub mod repo_write_lock;
pub mod scheduled;
pub mod sso;
pub mod state;
pub mod storage;
pub mod sync;
pub mod types;
pub mod util;
pub mod validation;

use api::proxy::XrpcProxyLayer;
use axum::{
    Json, Router,
    extract::DefaultBodyLimit,
    http::Method,
    middleware,
    routing::{get, post},
};
use http::StatusCode;
use serde_json::json;
use state::AppState;
use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    services::{ServeDir, ServeFile},
};
pub use tranquil_db_traits::AccountStatus;
pub use types::{AccountState, AtIdentifier, AtUri, Did, Handle, Nsid, Rkey};

#[cfg(debug_assertions)]
pub const BUILD_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (built ",
    env!("BUILD_TIMESTAMP"),
    ")"
);
#[cfg(not(debug_assertions))]
pub const BUILD_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn app(state: AppState) -> Router {
    let xrpc_router = Router::new()
        .route("/_health", get(api::server::health))
        .route(
            "/com.atproto.server.describeServer",
            get(api::server::describe_server),
        )
        .route(
            "/com.atproto.server.createAccount",
            post(api::identity::create_account),
        )
        .route(
            "/com.atproto.server.createSession",
            post(api::server::create_session),
        )
        .route(
            "/com.atproto.server.getSession",
            get(api::server::get_session),
        )
        .route("/_account.listSessions", get(api::server::list_sessions))
        .route("/_account.revokeSession", post(api::server::revoke_session))
        .route(
            "/_account.revokeAllSessions",
            post(api::server::revoke_all_sessions),
        )
        .route(
            "/com.atproto.server.deleteSession",
            post(api::server::delete_session),
        )
        .route(
            "/com.atproto.server.refreshSession",
            post(api::server::refresh_session),
        )
        .route(
            "/com.atproto.server.confirmSignup",
            post(api::server::confirm_signup),
        )
        .route(
            "/com.atproto.server.resendVerification",
            post(api::server::resend_verification),
        )
        .route(
            "/com.atproto.server.getServiceAuth",
            get(api::server::get_service_auth),
        )
        .route(
            "/com.atproto.identity.resolveHandle",
            get(api::identity::resolve_handle),
        )
        .route(
            "/com.atproto.repo.createRecord",
            post(api::repo::create_record),
        )
        .route("/com.atproto.repo.putRecord", post(api::repo::put_record))
        .route("/com.atproto.repo.getRecord", get(api::repo::get_record))
        .route(
            "/com.atproto.repo.deleteRecord",
            post(api::repo::delete_record),
        )
        .route(
            "/com.atproto.repo.listRecords",
            get(api::repo::list_records),
        )
        .route(
            "/com.atproto.repo.describeRepo",
            get(api::repo::describe_repo),
        )
        .route("/com.atproto.repo.uploadBlob", post(api::repo::upload_blob))
        .route(
            "/com.atproto.repo.applyWrites",
            post(api::repo::apply_writes),
        )
        .route(
            "/com.atproto.sync.getLatestCommit",
            get(sync::get_latest_commit),
        )
        .route("/com.atproto.sync.listRepos", get(sync::list_repos))
        .route("/com.atproto.sync.getBlob", get(sync::get_blob))
        .route("/com.atproto.sync.listBlobs", get(sync::list_blobs))
        .route(
            "/com.atproto.sync.getRepoStatus",
            get(sync::get_repo_status),
        )
        .route(
            "/com.atproto.server.checkAccountStatus",
            get(api::server::check_account_status),
        )
        .route(
            "/com.atproto.identity.getRecommendedDidCredentials",
            get(api::identity::get_recommended_did_credentials),
        )
        .route(
            "/com.atproto.repo.listMissingBlobs",
            get(api::repo::list_missing_blobs),
        )
        .route(
            "/com.atproto.sync.notifyOfUpdate",
            post(sync::notify_of_update),
        )
        .route("/com.atproto.sync.requestCrawl", post(sync::request_crawl))
        .route("/com.atproto.sync.getBlocks", get(sync::get_blocks))
        .route("/com.atproto.sync.getRepo", get(sync::get_repo))
        .route("/com.atproto.sync.getRecord", get(sync::get_record))
        .route(
            "/com.atproto.sync.subscribeRepos",
            get(sync::subscribe_repos),
        )
        .route("/com.atproto.sync.getHead", get(sync::get_head))
        .route("/com.atproto.sync.getCheckout", get(sync::get_checkout))
        .route(
            "/com.atproto.moderation.createReport",
            post(api::moderation::create_report),
        )
        .route(
            "/com.atproto.admin.getAccountInfo",
            get(api::admin::get_account_info),
        )
        .route(
            "/com.atproto.admin.getAccountInfos",
            get(api::admin::get_account_infos),
        )
        .route(
            "/com.atproto.admin.searchAccounts",
            get(api::admin::search_accounts),
        )
        .route(
            "/com.atproto.server.activateAccount",
            post(api::server::activate_account),
        )
        .route(
            "/com.atproto.server.deactivateAccount",
            post(api::server::deactivate_account),
        )
        .route(
            "/com.atproto.server.requestAccountDelete",
            post(api::server::request_account_delete),
        )
        .route(
            "/com.atproto.server.deleteAccount",
            post(api::server::delete_account),
        )
        .route(
            "/com.atproto.server.requestPasswordReset",
            post(api::server::request_password_reset),
        )
        .route(
            "/com.atproto.server.resetPassword",
            post(api::server::reset_password),
        )
        .route(
            "/_account.changePassword",
            post(api::server::change_password),
        )
        .route(
            "/_account.removePassword",
            post(api::server::remove_password),
        )
        .route(
            "/_account.setPassword",
            post(api::server::set_password),
        )
        .route(
            "/_account.getPasswordStatus",
            get(api::server::get_password_status),
        )
        .route(
            "/_account.getReauthStatus",
            get(api::server::get_reauth_status),
        )
        .route(
            "/_account.reauthPassword",
            post(api::server::reauth_password),
        )
        .route("/_account.reauthTotp", post(api::server::reauth_totp))
        .route(
            "/_account.reauthPasskeyStart",
            post(api::server::reauth_passkey_start),
        )
        .route(
            "/_account.reauthPasskeyFinish",
            post(api::server::reauth_passkey_finish),
        )
        .route(
            "/_account.getLegacyLoginPreference",
            get(api::server::get_legacy_login_preference),
        )
        .route(
            "/_account.updateLegacyLoginPreference",
            post(api::server::update_legacy_login_preference),
        )
        .route("/_account.updateLocale", post(api::server::update_locale))
        .route(
            "/_account.listTrustedDevices",
            get(api::server::list_trusted_devices),
        )
        .route(
            "/_account.revokeTrustedDevice",
            post(api::server::revoke_trusted_device),
        )
        .route(
            "/_account.updateTrustedDevice",
            post(api::server::update_trusted_device),
        )
        .route(
            "/_account.createPasskeyAccount",
            post(api::server::create_passkey_account),
        )
        .route(
            "/_account.startPasskeyRegistrationForSetup",
            post(api::server::start_passkey_registration_for_setup),
        )
        .route(
            "/_account.completePasskeySetup",
            post(api::server::complete_passkey_setup),
        )
        .route(
            "/_account.requestPasskeyRecovery",
            post(api::server::request_passkey_recovery),
        )
        .route(
            "/_account.recoverPasskeyAccount",
            post(api::server::recover_passkey_account),
        )
        .route(
            "/_account.updateDidDocument",
            post(api::server::update_did_document),
        )
        .route(
            "/_account.getDidDocument",
            get(api::server::get_did_document),
        )
        .route(
            "/com.atproto.server.requestEmailUpdate",
            post(api::server::request_email_update),
        )
        .route(
            "/_checkEmailVerified",
            post(api::server::check_email_verified),
        )
        .route(
            "/_checkChannelVerified",
            post(api::server::check_channel_verified),
        )
        .route(
            "/com.atproto.server.confirmEmail",
            post(api::server::confirm_email),
        )
        .route(
            "/com.atproto.server.updateEmail",
            post(api::server::update_email),
        )
        .route(
            "/_account.authorizeEmailUpdate",
            get(api::server::authorize_email_update),
        )
        .route(
            "/_account.checkEmailUpdateStatus",
            get(api::server::check_email_update_status),
        )
        .route(
            "/_account.checkEmailInUse",
            post(api::server::check_email_in_use),
        )
        .route(
            "/_account.checkCommsChannelInUse",
            post(api::server::check_comms_channel_in_use),
        )
        .route(
            "/com.atproto.server.reserveSigningKey",
            post(api::server::reserve_signing_key),
        )
        .route(
            "/com.atproto.server.verifyMigrationEmail",
            post(api::server::verify_migration_email),
        )
        .route(
            "/com.atproto.server.resendMigrationVerification",
            post(api::server::resend_migration_verification),
        )
        .route(
            "/com.atproto.identity.updateHandle",
            post(api::identity::update_handle),
        )
        .route(
            "/com.atproto.identity.requestPlcOperationSignature",
            post(api::identity::request_plc_operation_signature),
        )
        .route(
            "/com.atproto.identity.signPlcOperation",
            post(api::identity::sign_plc_operation),
        )
        .route(
            "/com.atproto.identity.submitPlcOperation",
            post(api::identity::submit_plc_operation),
        )
        .route(
            "/_identity.verifyHandleOwnership",
            post(api::identity::verify_handle_ownership),
        )
        .route("/com.atproto.repo.importRepo", post(api::repo::import_repo))
        .route(
            "/com.atproto.admin.deleteAccount",
            post(api::admin::delete_account),
        )
        .route(
            "/com.atproto.admin.updateAccountEmail",
            post(api::admin::update_account_email),
        )
        .route(
            "/com.atproto.admin.updateAccountHandle",
            post(api::admin::update_account_handle),
        )
        .route(
            "/com.atproto.admin.updateAccountPassword",
            post(api::admin::update_account_password),
        )
        .route(
            "/com.atproto.server.listAppPasswords",
            get(api::server::list_app_passwords),
        )
        .route(
            "/com.atproto.server.createAppPassword",
            post(api::server::create_app_password),
        )
        .route(
            "/com.atproto.server.revokeAppPassword",
            post(api::server::revoke_app_password),
        )
        .route(
            "/com.atproto.server.createInviteCode",
            post(api::server::create_invite_code),
        )
        .route(
            "/com.atproto.server.createInviteCodes",
            post(api::server::create_invite_codes),
        )
        .route(
            "/com.atproto.server.getAccountInviteCodes",
            get(api::server::get_account_invite_codes),
        )
        .route(
            "/com.atproto.server.createTotpSecret",
            post(api::server::create_totp_secret),
        )
        .route(
            "/com.atproto.server.enableTotp",
            post(api::server::enable_totp),
        )
        .route(
            "/com.atproto.server.disableTotp",
            post(api::server::disable_totp),
        )
        .route(
            "/com.atproto.server.getTotpStatus",
            get(api::server::get_totp_status),
        )
        .route(
            "/com.atproto.server.regenerateBackupCodes",
            post(api::server::regenerate_backup_codes),
        )
        .route(
            "/com.atproto.server.startPasskeyRegistration",
            post(api::server::start_passkey_registration),
        )
        .route(
            "/com.atproto.server.finishPasskeyRegistration",
            post(api::server::finish_passkey_registration),
        )
        .route(
            "/com.atproto.server.listPasskeys",
            get(api::server::list_passkeys),
        )
        .route(
            "/com.atproto.server.deletePasskey",
            post(api::server::delete_passkey),
        )
        .route(
            "/com.atproto.server.updatePasskey",
            post(api::server::update_passkey),
        )
        .route(
            "/com.atproto.admin.getInviteCodes",
            get(api::admin::get_invite_codes),
        )
        .route("/_admin.getServerStats", get(api::admin::get_server_stats))
        .route("/_server.getConfig", get(api::admin::get_server_config))
        .route(
            "/_admin.updateServerConfig",
            post(api::admin::update_server_config),
        )
        .route(
            "/com.atproto.admin.disableAccountInvites",
            post(api::admin::disable_account_invites),
        )
        .route(
            "/com.atproto.admin.enableAccountInvites",
            post(api::admin::enable_account_invites),
        )
        .route(
            "/com.atproto.admin.disableInviteCodes",
            post(api::admin::disable_invite_codes),
        )
        .route(
            "/com.atproto.admin.getSubjectStatus",
            get(api::admin::get_subject_status),
        )
        .route(
            "/com.atproto.admin.updateSubjectStatus",
            post(api::admin::update_subject_status),
        )
        .route("/com.atproto.admin.sendEmail", post(api::admin::send_email))
        .route(
            "/app.bsky.actor.getPreferences",
            get(api::actor::get_preferences),
        )
        .route(
            "/app.bsky.actor.putPreferences",
            post(api::actor::put_preferences),
        )
        .route(
            "/com.atproto.temp.checkSignupQueue",
            get(api::temp::check_signup_queue),
        )
        .route(
            "/com.atproto.temp.dereferenceScope",
            post(api::temp::dereference_scope),
        )
        .route(
            "/_account.getNotificationPrefs",
            get(api::notification_prefs::get_notification_prefs),
        )
        .route(
            "/_account.updateNotificationPrefs",
            post(api::notification_prefs::update_notification_prefs),
        )
        .route(
            "/_account.getNotificationHistory",
            get(api::notification_prefs::get_notification_history),
        )
        .route(
            "/_account.confirmChannelVerification",
            post(api::verification::confirm_channel_verification),
        )
        .route("/_account.verifyToken", post(api::server::verify_token))
        .route(
            "/_delegation.listControllers",
            get(api::delegation::list_controllers),
        )
        .route(
            "/_delegation.addController",
            post(api::delegation::add_controller),
        )
        .route(
            "/_delegation.removeController",
            post(api::delegation::remove_controller),
        )
        .route(
            "/_delegation.updateControllerScopes",
            post(api::delegation::update_controller_scopes),
        )
        .route(
            "/_delegation.listControlledAccounts",
            get(api::delegation::list_controlled_accounts),
        )
        .route(
            "/_delegation.getAuditLog",
            get(api::delegation::get_audit_log),
        )
        .route(
            "/_delegation.getScopePresets",
            get(api::delegation::get_scope_presets),
        )
        .route(
            "/_delegation.createDelegatedAccount",
            post(api::delegation::create_delegated_account),
        )
        .route("/_backup.listBackups", get(api::backup::list_backups))
        .route("/_backup.getBackup", get(api::backup::get_backup))
        .route("/_backup.createBackup", post(api::backup::create_backup))
        .route("/_backup.deleteBackup", post(api::backup::delete_backup))
        .route("/_backup.setEnabled", post(api::backup::set_backup_enabled))
        .route("/_backup.exportBlobs", get(api::backup::export_blobs))
        .route(
            "/app.bsky.ageassurance.getState",
            get(api::age_assurance::get_state),
        )
        .route(
            "/app.bsky.unspecced.getAgeAssuranceState",
            get(api::age_assurance::get_age_assurance_state),
        )
        .fallback(async || (
            StatusCode::NOT_IMPLEMENTED,
            Json(json!({"error": "MethodNotImplemented", "message": "Method not implemented. For app.bsky.* methods, include an atproto-proxy header specifying your AppView."})),
        ));
    let xrpc_service = ServiceBuilder::new()
        .layer(XrpcProxyLayer::new(state.clone()))
        .service(
            xrpc_router
                .layer(middleware::from_fn(oauth::verify::dpop_nonce_middleware))
                .with_state(state.clone()),
        );

    let oauth_router = Router::new()
        .route("/jwks", get(oauth::endpoints::oauth_jwks))
        .route("/par", post(oauth::endpoints::pushed_authorization_request))
        .route("/authorize", get(oauth::endpoints::authorize_get))
        .route("/authorize", post(oauth::endpoints::authorize_post))
        .route(
            "/authorize/accounts",
            get(oauth::endpoints::authorize_accounts),
        )
        .route(
            "/authorize/select",
            post(oauth::endpoints::authorize_select),
        )
        .route("/authorize/2fa", get(oauth::endpoints::authorize_2fa_get))
        .route("/authorize/2fa", post(oauth::endpoints::authorize_2fa_post))
        .route(
            "/authorize/passkey",
            get(oauth::endpoints::authorize_passkey_start),
        )
        .route(
            "/authorize/passkey",
            post(oauth::endpoints::authorize_passkey_finish),
        )
        .route(
            "/passkey/check",
            get(oauth::endpoints::check_user_has_passkeys),
        )
        .route(
            "/security-status",
            get(oauth::endpoints::check_user_security_status),
        )
        .route("/passkey/start", post(oauth::endpoints::passkey_start))
        .route("/passkey/finish", post(oauth::endpoints::passkey_finish))
        .route("/authorize/deny", post(oauth::endpoints::authorize_deny))
        .route(
            "/register/complete",
            post(oauth::endpoints::register_complete),
        )
        .route(
            "/establish-session",
            post(oauth::endpoints::establish_session),
        )
        .route("/authorize/consent", get(oauth::endpoints::consent_get))
        .route("/authorize/consent", post(oauth::endpoints::consent_post))
        .route("/authorize/renew", post(oauth::endpoints::authorize_renew))
        .route(
            "/authorize/redirect",
            get(oauth::endpoints::authorize_redirect),
        )
        .route("/delegation/auth", post(oauth::endpoints::delegation_auth))
        .route(
            "/delegation/auth-token",
            post(oauth::endpoints::delegation_auth_token),
        )
        .route(
            "/delegation/totp",
            post(oauth::endpoints::delegation_totp_verify),
        )
        .route("/token", post(oauth::endpoints::token_endpoint))
        .route("/revoke", post(oauth::endpoints::revoke_token))
        .route("/introspect", post(oauth::endpoints::introspect_token))
        .route("/sso/providers", get(sso::endpoints::get_sso_providers))
        .route("/sso/initiate", post(sso::endpoints::sso_initiate))
        .route(
            "/sso/callback",
            get(sso::endpoints::sso_callback).post(sso::endpoints::sso_callback_post),
        )
        .route("/sso/linked", get(sso::endpoints::get_linked_accounts))
        .route("/sso/unlink", post(sso::endpoints::unlink_account))
        .route(
            "/sso/pending-registration",
            get(sso::endpoints::get_pending_registration),
        )
        .route(
            "/sso/complete-registration",
            post(sso::endpoints::complete_registration),
        )
        .route(
            "/sso/check-handle-available",
            get(sso::endpoints::check_handle_available),
        )
        .layer(middleware::from_fn(oauth::verify::dpop_nonce_middleware));

    let well_known_router = Router::new()
        .route("/did.json", get(api::identity::well_known_did))
        .route("/atproto-did", get(api::identity::well_known_atproto_did))
        .route(
            "/oauth-protected-resource",
            get(oauth::endpoints::oauth_protected_resource),
        )
        .route(
            "/oauth-authorization-server",
            get(oauth::endpoints::oauth_authorization_server),
        );

    if cfg!(feature = "frontend") {}

    let router = Router::new()
        .nest_service("/xrpc", xrpc_service)
        .nest("/oauth", oauth_router)
        .nest("/.well-known", well_known_router)
        .route("/metrics", get(metrics::metrics_handler))
        .route("/health", get(api::server::health))
        .route("/robots.txt", get(api::server::robots_txt))
        .route("/logo", get(api::server::get_logo))
        .route("/u/{handle}/did.json", get(api::identity::user_did_doc))
        .route(
            "/webhook/telegram",
            post(api::telegram_webhook::handle_telegram_webhook)
                .layer(DefaultBodyLimit::max(64 * 1024)),
        )
        .route(
            "/webhook/discord",
            post(api::discord_webhook::handle_discord_webhook)
                .layer(DefaultBodyLimit::max(64 * 1024)),
        )
        .layer(DefaultBodyLimit::max(
            tranquil_config::get().server.max_blob_size as usize,
        ))
        .layer(axum::middleware::map_response(rewrite_422_to_400))
        .layer(middleware::from_fn(metrics::metrics_middleware))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([
                    http::header::AUTHORIZATION,
                    http::header::CONTENT_TYPE,
                    http::header::CONTENT_ENCODING,
                    http::header::ACCEPT_ENCODING,
                    util::HEADER_DPOP,
                    util::HEADER_ATPROTO_PROXY,
                    util::HEADER_ATPROTO_ACCEPT_LABELERS,
                    util::HEADER_X_BSKY_TOPICS,
                ])
                .expose_headers([
                    http::header::WWW_AUTHENTICATE,
                    util::HEADER_DPOP_NONCE,
                    util::HEADER_ATPROTO_REPO_REV,
                    util::HEADER_ATPROTO_CONTENT_LABELERS,
                ]),
        )
        .with_state(state);

    if cfg!(feature = "frontend") && tranquil_config::get().frontend.enabled {
        let frontend_dir = &tranquil_config::get().frontend.dir;
        let index_path = format!("{}/index.html", frontend_dir);
        let homepage_path = format!("{}/homepage.html", frontend_dir);

        let homepage_exists = std::path::Path::new(&homepage_path).exists();
        let homepage_file = if homepage_exists {
            homepage_path
        } else {
            index_path.clone()
        };

        let spa_router = Router::new().fallback_service(ServeFile::new(&index_path));

        let serve_dir = ServeDir::new(&frontend_dir).not_found_service(ServeFile::new(&index_path));

        return router
            .route(
                "/oauth-client-metadata.json",
                get(oauth::endpoints::frontend_client_metadata),
            )
            .route_service("/", ServeFile::new(&homepage_file))
            .nest("/app", spa_router)
            .fallback_service(serve_dir);
    }

    router
}

async fn rewrite_422_to_400(response: axum::response::Response) -> axum::response::Response {
    if response.status() != StatusCode::UNPROCESSABLE_ENTITY {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    let bytes = match axum::body::to_bytes(body, 64 * 1024).await {
        Ok(b) => b,
        Err(_) => {
            parts.status = StatusCode::BAD_REQUEST;
            parts.headers.remove(http::header::CONTENT_LENGTH);
            let fallback = json!({"error": "InvalidRequest", "message": "Invalid request body"});
            return axum::response::Response::from_parts(
                parts,
                axum::body::Body::from(serde_json::to_vec(&fallback).unwrap_or_default()),
            );
        }
    };
    let raw = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(String::from))
        .unwrap_or_else(|| {
            String::from_utf8(bytes.to_vec()).unwrap_or_else(|_| "Invalid request body".into())
        });
    let message = humanize_json_error(&raw);

    parts.status = StatusCode::BAD_REQUEST;
    parts.headers.remove(http::header::CONTENT_LENGTH);
    let error_name = classify_deserialization_error(&raw);
    let new_body = json!({
        "error": error_name,
        "message": message
    });
    axum::response::Response::from_parts(
        parts,
        axum::body::Body::from(serde_json::to_vec(&new_body).unwrap_or_default()),
    )
}

fn humanize_json_error(raw: &str) -> String {
    if raw.contains("missing field") {
        raw.split("missing field `")
            .nth(1)
            .and_then(|s| s.split('`').next())
            .map(|field| format!("Missing required field: {}", field))
            .unwrap_or_else(|| raw.to_string())
    } else if raw.contains("invalid type") {
        format!("Invalid field type: {}", raw)
    } else if raw.contains("Invalid JSON") || raw.contains("syntax") {
        "Invalid JSON syntax".to_string()
    } else if raw.contains("Content-Type") || raw.contains("content type") {
        "Content-Type must be application/json".to_string()
    } else {
        raw.to_string()
    }
}

fn classify_deserialization_error(raw: &str) -> &'static str {
    match raw {
        s if s.contains("invalid handle") => "InvalidHandle",
        _ => "InvalidRequest",
    }
}
