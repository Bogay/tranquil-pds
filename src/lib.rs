pub mod api;
pub mod appview;
pub mod auth;
pub mod cache;
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
pub mod scheduled;
pub mod state;
pub mod storage;
pub mod sync;
pub mod types;
pub mod util;
pub mod validation;

use api::proxy::XrpcProxyLayer;
pub use sync::util::AccountStatus;
pub use types::{AccountState, AtIdentifier, AtUri, Did, Handle, Nsid, Rkey};
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
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};

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
            "/com.atproto.server.confirmEmail",
            post(api::server::confirm_email),
        )
        .route(
            "/com.atproto.server.updateEmail",
            post(api::server::update_email),
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
            Json(json!({"error": "MethodNotImplemented", "message": "XRPC method not implemented"})),
        ));
    let xrpc_service = ServiceBuilder::new()
        .layer(XrpcProxyLayer::new(state.clone()))
        .service(xrpc_router.with_state(state.clone()));

    let oauth_router = Router::new()
        .route("/jwks", get(oauth::endpoints::oauth_jwks))
        .route(
            "/client-metadata.json",
            get(oauth::endpoints::frontend_client_metadata),
        )
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
        .route("/authorize/consent", get(oauth::endpoints::consent_get))
        .route("/authorize/consent", post(oauth::endpoints::consent_post))
        .route("/delegation/auth", post(oauth::endpoints::delegation_auth))
        .route(
            "/delegation/totp",
            post(oauth::endpoints::delegation_totp_verify),
        )
        .route("/token", post(oauth::endpoints::token_endpoint))
        .route("/revoke", post(oauth::endpoints::revoke_token))
        .route("/introspect", post(oauth::endpoints::introspect_token));

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

    let router = Router::new()
        .nest_service("/xrpc", xrpc_service)
        .nest("/oauth", oauth_router)
        .nest("/.well-known", well_known_router)
        .route("/metrics", get(metrics::metrics_handler))
        .route("/health", get(api::server::health))
        .route("/robots.txt", get(api::server::robots_txt))
        .route("/logo", get(api::server::get_logo))
        .route("/u/{handle}/did.json", get(api::identity::user_did_doc))
        .layer(DefaultBodyLimit::max(util::get_max_blob_size()))
        .layer(middleware::from_fn(metrics::metrics_middleware))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers(Any),
        )
        .with_state(state);

    let frontend_dir =
        std::env::var("FRONTEND_DIR").unwrap_or_else(|_| "./frontend/dist".to_string());
    if std::path::Path::new(&frontend_dir)
        .join("index.html")
        .exists()
    {
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
            .route_service("/", ServeFile::new(&homepage_file))
            .nest("/app", spa_router)
            .fallback_service(serve_dir);
    }

    router
}
