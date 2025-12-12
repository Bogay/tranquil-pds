pub mod api;
pub mod auth;
pub mod cache;
pub mod circuit_breaker;
pub mod config;
pub mod crawlers;
pub mod image;
pub mod notifications;
pub mod oauth;
pub mod plc;
pub mod rate_limit;
pub mod repo;
pub mod state;
pub mod storage;
pub mod sync;
pub mod util;
pub mod validation;

use axum::{
    Router,
    routing::{any, get, post},
};
use state::AppState;
use tower_http::services::{ServeDir, ServeFile};

pub fn app(state: AppState) -> Router {
    let router = Router::new()
        .route("/health", get(api::server::health))
        .route("/xrpc/_health", get(api::server::health))
        .route("/robots.txt", get(api::server::robots_txt))
        .route(
            "/xrpc/com.atproto.server.describeServer",
            get(api::server::describe_server),
        )
        .route(
            "/xrpc/com.atproto.server.createAccount",
            post(api::identity::create_account),
        )
        .route(
            "/xrpc/com.atproto.server.createSession",
            post(api::server::create_session),
        )
        .route(
            "/xrpc/com.atproto.server.getSession",
            get(api::server::get_session),
        )
        .route(
            "/xrpc/com.atproto.server.deleteSession",
            post(api::server::delete_session),
        )
        .route(
            "/xrpc/com.atproto.server.refreshSession",
            post(api::server::refresh_session),
        )
        .route(
            "/xrpc/com.atproto.server.confirmSignup",
            post(api::server::confirm_signup),
        )
        .route(
            "/xrpc/com.atproto.server.resendVerification",
            post(api::server::resend_verification),
        )
        .route(
            "/xrpc/com.atproto.server.getServiceAuth",
            get(api::server::get_service_auth),
        )
        .route(
            "/xrpc/com.atproto.identity.resolveHandle",
            get(api::identity::resolve_handle),
        )
        .route(
            "/xrpc/com.atproto.repo.createRecord",
            post(api::repo::create_record),
        )
        .route(
            "/xrpc/com.atproto.repo.putRecord",
            post(api::repo::put_record),
        )
        .route(
            "/xrpc/com.atproto.repo.getRecord",
            get(api::repo::get_record),
        )
        .route(
            "/xrpc/com.atproto.repo.deleteRecord",
            post(api::repo::delete_record),
        )
        .route(
            "/xrpc/com.atproto.repo.listRecords",
            get(api::repo::list_records),
        )
        .route(
            "/xrpc/com.atproto.repo.describeRepo",
            get(api::repo::describe_repo),
        )
        .route(
            "/xrpc/com.atproto.repo.uploadBlob",
            post(api::repo::upload_blob),
        )
        .route(
            "/xrpc/com.atproto.repo.applyWrites",
            post(api::repo::apply_writes),
        )
        .route(
            "/xrpc/com.atproto.sync.getLatestCommit",
            get(sync::get_latest_commit),
        )
        .route(
            "/xrpc/com.atproto.sync.listRepos",
            get(sync::list_repos),
        )
        .route(
            "/xrpc/com.atproto.sync.getBlob",
            get(sync::get_blob),
        )
        .route(
            "/xrpc/com.atproto.sync.listBlobs",
            get(sync::list_blobs),
        )
        .route(
            "/xrpc/com.atproto.sync.getRepoStatus",
            get(sync::get_repo_status),
        )
        .route(
            "/xrpc/com.atproto.server.checkAccountStatus",
            get(api::server::check_account_status),
        )
        .route(
            "/xrpc/com.atproto.identity.getRecommendedDidCredentials",
            get(api::identity::get_recommended_did_credentials),
        )
        .route(
            "/xrpc/com.atproto.repo.listMissingBlobs",
            get(api::repo::list_missing_blobs),
        )
        .route(
            "/xrpc/com.atproto.sync.notifyOfUpdate",
            post(sync::notify_of_update),
        )
        .route(
            "/xrpc/com.atproto.sync.requestCrawl",
            post(sync::request_crawl),
        )
        .route(
            "/xrpc/com.atproto.sync.getBlocks",
            get(sync::get_blocks),
        )
        .route(
            "/xrpc/com.atproto.sync.getRepo",
            get(sync::get_repo),
        )
        .route(
            "/xrpc/com.atproto.sync.getRecord",
            get(sync::get_record),
        )
        .route(
            "/xrpc/com.atproto.sync.subscribeRepos",
            get(sync::subscribe_repos),
        )
        .route(
            "/xrpc/com.atproto.sync.getHead",
            get(sync::get_head),
        )
        .route(
            "/xrpc/com.atproto.sync.getCheckout",
            get(sync::get_checkout),
        )
        .route(
            "/xrpc/com.atproto.moderation.createReport",
            post(api::moderation::create_report),
        )
        .route(
            "/xrpc/com.atproto.admin.getAccountInfo",
            get(api::admin::get_account_info),
        )
        .route(
            "/xrpc/com.atproto.admin.getAccountInfos",
            get(api::admin::get_account_infos),
        )
        .route(
            "/xrpc/com.atproto.server.activateAccount",
            post(api::server::activate_account),
        )
        .route(
            "/xrpc/com.atproto.server.deactivateAccount",
            post(api::server::deactivate_account),
        )
        .route(
            "/xrpc/com.atproto.server.requestAccountDelete",
            post(api::server::request_account_delete),
        )
        .route(
            "/xrpc/com.atproto.server.deleteAccount",
            post(api::server::delete_account),
        )
        .route(
            "/xrpc/com.atproto.server.requestPasswordReset",
            post(api::server::request_password_reset),
        )
        .route(
            "/xrpc/com.atproto.server.resetPassword",
            post(api::server::reset_password),
        )
        .route(
            "/xrpc/com.atproto.server.requestEmailUpdate",
            post(api::server::request_email_update),
        )
        .route(
            "/xrpc/com.atproto.server.confirmEmail",
            post(api::server::confirm_email),
        )
        .route(
            "/xrpc/com.atproto.server.updateEmail",
            post(api::server::update_email),
        )
        .route(
            "/xrpc/com.atproto.server.reserveSigningKey",
            post(api::server::reserve_signing_key),
        )
        .route(
            "/xrpc/com.atproto.identity.updateHandle",
            post(api::identity::update_handle),
        )
        .route(
            "/xrpc/com.atproto.identity.requestPlcOperationSignature",
            post(api::identity::request_plc_operation_signature),
        )
        .route(
            "/xrpc/com.atproto.identity.signPlcOperation",
            post(api::identity::sign_plc_operation),
        )
        .route(
            "/xrpc/com.atproto.identity.submitPlcOperation",
            post(api::identity::submit_plc_operation),
        )
        .route(
            "/xrpc/com.atproto.repo.importRepo",
            post(api::repo::import_repo),
        )
        .route(
            "/xrpc/com.atproto.admin.deleteAccount",
            post(api::admin::delete_account),
        )
        .route(
            "/xrpc/com.atproto.admin.updateAccountEmail",
            post(api::admin::update_account_email),
        )
        .route(
            "/xrpc/com.atproto.admin.updateAccountHandle",
            post(api::admin::update_account_handle),
        )
        .route(
            "/xrpc/com.atproto.admin.updateAccountPassword",
            post(api::admin::update_account_password),
        )
        .route(
            "/xrpc/com.atproto.server.listAppPasswords",
            get(api::server::list_app_passwords),
        )
        .route(
            "/xrpc/com.atproto.server.createAppPassword",
            post(api::server::create_app_password),
        )
        .route(
            "/xrpc/com.atproto.server.revokeAppPassword",
            post(api::server::revoke_app_password),
        )
        .route(
            "/xrpc/com.atproto.server.createInviteCode",
            post(api::server::create_invite_code),
        )
        .route(
            "/xrpc/com.atproto.server.createInviteCodes",
            post(api::server::create_invite_codes),
        )
        .route(
            "/xrpc/com.atproto.server.getAccountInviteCodes",
            get(api::server::get_account_invite_codes),
        )
        .route(
            "/xrpc/com.atproto.admin.getInviteCodes",
            get(api::admin::get_invite_codes),
        )
        .route(
            "/xrpc/com.atproto.admin.disableAccountInvites",
            post(api::admin::disable_account_invites),
        )
        .route(
            "/xrpc/com.atproto.admin.enableAccountInvites",
            post(api::admin::enable_account_invites),
        )
        .route(
            "/xrpc/com.atproto.admin.disableInviteCodes",
            post(api::admin::disable_invite_codes),
        )
        .route(
            "/xrpc/com.atproto.admin.getSubjectStatus",
            get(api::admin::get_subject_status),
        )
        .route(
            "/xrpc/com.atproto.admin.updateSubjectStatus",
            post(api::admin::update_subject_status),
        )
        .route(
            "/xrpc/com.atproto.admin.sendEmail",
            post(api::admin::send_email),
        )
        .route(
            "/xrpc/app.bsky.actor.getPreferences",
            get(api::actor::get_preferences),
        )
        .route(
            "/xrpc/app.bsky.actor.putPreferences",
            post(api::actor::put_preferences),
        )
        .route(
            "/xrpc/app.bsky.actor.getProfile",
            get(api::actor::get_profile),
        )
        .route(
            "/xrpc/app.bsky.actor.getProfiles",
            get(api::actor::get_profiles),
        )
        .route(
            "/xrpc/app.bsky.feed.getTimeline",
            get(api::feed::get_timeline),
        )
        .route(
            "/xrpc/app.bsky.feed.getAuthorFeed",
            get(api::feed::get_author_feed),
        )
        .route(
            "/xrpc/app.bsky.feed.getActorLikes",
            get(api::feed::get_actor_likes),
        )
        .route(
            "/xrpc/app.bsky.feed.getPostThread",
            get(api::feed::get_post_thread),
        )
        .route(
            "/xrpc/app.bsky.feed.getFeed",
            get(api::feed::get_feed),
        )
        .route(
            "/xrpc/app.bsky.notification.registerPush",
            post(api::notification::register_push),
        )
        .route("/.well-known/did.json", get(api::identity::well_known_did))
        .route("/u/{handle}/did.json", get(api::identity::user_did_doc))
        // OAuth 2.1 endpoints
        .route(
            "/.well-known/oauth-protected-resource",
            get(oauth::endpoints::oauth_protected_resource),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth::endpoints::oauth_authorization_server),
        )
        .route("/oauth/jwks", get(oauth::endpoints::oauth_jwks))
        .route(
            "/oauth/par",
            post(oauth::endpoints::pushed_authorization_request),
        )
        .route("/oauth/authorize", get(oauth::endpoints::authorize_get))
        .route("/oauth/authorize", post(oauth::endpoints::authorize_post))
        .route("/oauth/authorize/select", post(oauth::endpoints::authorize_select))
        .route("/oauth/authorize/2fa", get(oauth::endpoints::authorize_2fa_get))
        .route("/oauth/authorize/2fa", post(oauth::endpoints::authorize_2fa_post))
        .route("/oauth/authorize/deny", post(oauth::endpoints::authorize_deny))
        .route("/oauth/token", post(oauth::endpoints::token_endpoint))
        .route("/oauth/revoke", post(oauth::endpoints::revoke_token))
        .route("/oauth/introspect", post(oauth::endpoints::introspect_token))
        .route(
            "/xrpc/com.atproto.temp.checkSignupQueue",
            get(api::temp::check_signup_queue),
        )
        .route(
            "/xrpc/com.bspds.account.getNotificationPrefs",
            get(api::notification_prefs::get_notification_prefs),
        )
        .route(
            "/xrpc/com.bspds.account.updateNotificationPrefs",
            post(api::notification_prefs::update_notification_prefs),
        )
        .route("/xrpc/{*method}", any(api::proxy::proxy_handler))
        .with_state(state);

    let frontend_dir = std::env::var("FRONTEND_DIR")
        .unwrap_or_else(|_| "./frontend/dist".to_string());

    if std::path::Path::new(&frontend_dir).join("index.html").exists() {
        let index_path = format!("{}/index.html", frontend_dir);
        let serve_dir = ServeDir::new(&frontend_dir)
            .not_found_service(ServeFile::new(index_path));
        router.fallback_service(serve_dir)
    } else {
        router
    }
}
