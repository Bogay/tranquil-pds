pub mod actor;
pub mod admin;
pub mod age_assurance;
pub mod common;
pub mod delegation;
pub mod discord_webhook;
pub mod identity;
pub mod moderation;
pub mod notification_prefs;
pub mod repo;
pub mod server;
pub mod telegram_webhook;
pub mod temp;

use tranquil_pds::state::AppState;

pub fn api_routes() -> axum::Router<AppState> {
    use axum::routing::{get, post};

    axum::Router::new()
        .route("/_health", get(server::health))
        .route(
            "/com.atproto.server.describeServer",
            get(server::describe_server),
        )
        .route(
            "/com.atproto.server.createAccount",
            post(identity::create_account),
        )
        .route(
            "/com.atproto.server.createSession",
            post(server::create_session),
        )
        .route("/com.atproto.server.getSession", get(server::get_session))
        .route("/_account.listSessions", get(server::list_sessions))
        .route("/_account.revokeSession", post(server::revoke_session))
        .route(
            "/_account.revokeAllSessions",
            post(server::revoke_all_sessions),
        )
        .route(
            "/com.atproto.server.deleteSession",
            post(server::delete_session),
        )
        .route(
            "/com.atproto.server.refreshSession",
            post(server::refresh_session),
        )
        .route(
            "/com.atproto.server.confirmSignup",
            post(server::confirm_signup),
        )
        .route(
            "/com.atproto.server.resendVerification",
            post(server::resend_verification),
        )
        .route(
            "/com.atproto.server.getServiceAuth",
            get(server::get_service_auth),
        )
        .route(
            "/com.atproto.identity.resolveHandle",
            get(identity::resolve_handle),
        )
        .route("/com.atproto.repo.createRecord", post(repo::create_record))
        .route("/com.atproto.repo.putRecord", post(repo::put_record))
        .route("/com.atproto.repo.getRecord", get(repo::get_record))
        .route("/com.atproto.repo.deleteRecord", post(repo::delete_record))
        .route("/com.atproto.repo.listRecords", get(repo::list_records))
        .route("/com.atproto.repo.describeRepo", get(repo::describe_repo))
        .route("/com.atproto.repo.uploadBlob", post(repo::upload_blob))
        .route("/com.atproto.repo.applyWrites", post(repo::apply_writes))
        .route(
            "/com.atproto.server.checkAccountStatus",
            get(server::check_account_status),
        )
        .route(
            "/com.atproto.identity.getRecommendedDidCredentials",
            get(identity::get_recommended_did_credentials),
        )
        .route(
            "/com.atproto.repo.listMissingBlobs",
            get(repo::list_missing_blobs),
        )
        .route(
            "/com.atproto.moderation.createReport",
            post(moderation::create_report),
        )
        .route(
            "/com.atproto.admin.getAccountInfo",
            get(admin::get_account_info),
        )
        .route(
            "/com.atproto.admin.getAccountInfos",
            get(admin::get_account_infos),
        )
        .route(
            "/com.atproto.admin.searchAccounts",
            get(admin::search_accounts),
        )
        .route(
            "/com.atproto.server.activateAccount",
            post(server::activate_account),
        )
        .route(
            "/com.atproto.server.deactivateAccount",
            post(server::deactivate_account),
        )
        .route(
            "/com.atproto.server.requestAccountDelete",
            post(server::request_account_delete),
        )
        .route(
            "/com.atproto.server.deleteAccount",
            post(server::delete_account),
        )
        .route(
            "/com.atproto.server.requestPasswordReset",
            post(server::request_password_reset),
        )
        .route(
            "/com.atproto.server.resetPassword",
            post(server::reset_password),
        )
        .route("/_account.changePassword", post(server::change_password))
        .route("/_account.removePassword", post(server::remove_password))
        .route("/_account.setPassword", post(server::set_password))
        .route(
            "/_account.getPasswordStatus",
            get(server::get_password_status),
        )
        .route("/_account.getReauthStatus", get(server::get_reauth_status))
        .route("/_account.reauthPassword", post(server::reauth_password))
        .route("/_account.reauthTotp", post(server::reauth_totp))
        .route(
            "/_account.reauthPasskeyStart",
            post(server::reauth_passkey_start),
        )
        .route(
            "/_account.reauthPasskeyFinish",
            post(server::reauth_passkey_finish),
        )
        .route(
            "/_account.getLegacyLoginPreference",
            get(server::get_legacy_login_preference),
        )
        .route(
            "/_account.updateLegacyLoginPreference",
            post(server::update_legacy_login_preference),
        )
        .route("/_account.updateLocale", post(server::update_locale))
        .route(
            "/_account.listTrustedDevices",
            get(server::list_trusted_devices),
        )
        .route(
            "/_account.revokeTrustedDevice",
            post(server::revoke_trusted_device),
        )
        .route(
            "/_account.updateTrustedDevice",
            post(server::update_trusted_device),
        )
        .route(
            "/_account.createPasskeyAccount",
            post(server::create_passkey_account),
        )
        .route(
            "/_account.startPasskeyRegistrationForSetup",
            post(server::start_passkey_registration_for_setup),
        )
        .route(
            "/_account.completePasskeySetup",
            post(server::complete_passkey_setup),
        )
        .route(
            "/_account.requestPasskeyRecovery",
            post(server::request_passkey_recovery),
        )
        .route(
            "/_account.recoverPasskeyAccount",
            post(server::recover_passkey_account),
        )
        .route(
            "/_account.updateDidDocument",
            post(server::update_did_document),
        )
        .route("/_account.getDidDocument", get(server::get_did_document))
        .route(
            "/com.atproto.server.requestEmailUpdate",
            post(server::request_email_update),
        )
        .route("/_checkEmailVerified", post(server::check_email_verified))
        .route(
            "/_checkChannelVerified",
            post(server::check_channel_verified),
        )
        .route(
            "/com.atproto.server.confirmEmail",
            post(server::confirm_email),
        )
        .route(
            "/com.atproto.server.updateEmail",
            post(server::update_email),
        )
        .route(
            "/_account.authorizeEmailUpdate",
            get(server::authorize_email_update),
        )
        .route(
            "/_account.checkEmailUpdateStatus",
            get(server::check_email_update_status),
        )
        .route(
            "/_account.checkEmailInUse",
            post(server::check_email_in_use),
        )
        .route(
            "/com.atproto.server.reserveSigningKey",
            post(server::reserve_signing_key),
        )
        .route(
            "/com.atproto.server.verifyMigrationEmail",
            post(server::verify_migration_email),
        )
        .route(
            "/com.atproto.server.resendMigrationVerification",
            post(server::resend_migration_verification),
        )
        .route(
            "/com.atproto.identity.updateHandle",
            post(identity::update_handle),
        )
        .route(
            "/com.atproto.identity.requestPlcOperationSignature",
            post(identity::request_plc_operation_signature),
        )
        .route(
            "/com.atproto.identity.signPlcOperation",
            post(identity::sign_plc_operation),
        )
        .route(
            "/com.atproto.identity.submitPlcOperation",
            post(identity::submit_plc_operation),
        )
        .route(
            "/_identity.verifyHandleOwnership",
            post(identity::verify_handle_ownership),
        )
        .route("/com.atproto.repo.importRepo", post(repo::import_repo))
        .route(
            "/com.atproto.admin.deleteAccount",
            post(admin::delete_account),
        )
        .route(
            "/com.atproto.admin.updateAccountEmail",
            post(admin::update_account_email),
        )
        .route(
            "/com.atproto.admin.updateAccountHandle",
            post(admin::update_account_handle),
        )
        .route(
            "/com.atproto.admin.updateAccountPassword",
            post(admin::update_account_password),
        )
        .route(
            "/com.atproto.server.listAppPasswords",
            get(server::list_app_passwords),
        )
        .route(
            "/com.atproto.server.createAppPassword",
            post(server::create_app_password),
        )
        .route(
            "/com.atproto.server.revokeAppPassword",
            post(server::revoke_app_password),
        )
        .route(
            "/com.atproto.server.createInviteCode",
            post(server::create_invite_code),
        )
        .route(
            "/com.atproto.server.createInviteCodes",
            post(server::create_invite_codes),
        )
        .route(
            "/com.atproto.server.getAccountInviteCodes",
            get(server::get_account_invite_codes),
        )
        .route(
            "/com.atproto.server.createTotpSecret",
            post(server::create_totp_secret),
        )
        .route("/com.atproto.server.enableTotp", post(server::enable_totp))
        .route(
            "/com.atproto.server.disableTotp",
            post(server::disable_totp),
        )
        .route(
            "/com.atproto.server.getTotpStatus",
            get(server::get_totp_status),
        )
        .route(
            "/com.atproto.server.regenerateBackupCodes",
            post(server::regenerate_backup_codes),
        )
        .route(
            "/com.atproto.server.startPasskeyRegistration",
            post(server::start_passkey_registration),
        )
        .route(
            "/com.atproto.server.finishPasskeyRegistration",
            post(server::finish_passkey_registration),
        )
        .route(
            "/com.atproto.server.listPasskeys",
            get(server::list_passkeys),
        )
        .route(
            "/com.atproto.server.deletePasskey",
            post(server::delete_passkey),
        )
        .route(
            "/com.atproto.server.updatePasskey",
            post(server::update_passkey),
        )
        .route(
            "/com.atproto.admin.getInviteCodes",
            get(admin::get_invite_codes),
        )
        .route("/_admin.getServerStats", get(admin::get_server_stats))
        .route("/_admin.getSignalStatus", get(admin::get_signal_status))
        .route("/_admin.linkSignalDevice", post(admin::link_signal_device))
        .route(
            "/_admin.unlinkSignalDevice",
            post(admin::unlink_signal_device),
        )
        .route("/_server.getConfig", get(admin::get_server_config))
        .route(
            "/_admin.updateServerConfig",
            post(admin::update_server_config),
        )
        .route(
            "/com.atproto.admin.disableAccountInvites",
            post(admin::disable_account_invites),
        )
        .route(
            "/com.atproto.admin.enableAccountInvites",
            post(admin::enable_account_invites),
        )
        .route(
            "/com.atproto.admin.disableInviteCodes",
            post(admin::disable_invite_codes),
        )
        .route(
            "/com.atproto.admin.getSubjectStatus",
            get(admin::get_subject_status),
        )
        .route(
            "/com.atproto.admin.updateSubjectStatus",
            post(admin::update_subject_status),
        )
        .route("/com.atproto.admin.sendEmail", post(admin::send_email))
        .route(
            "/app.bsky.actor.getPreferences",
            get(actor::get_preferences),
        )
        .route(
            "/app.bsky.actor.putPreferences",
            post(actor::put_preferences),
        )
        .route(
            "/com.atproto.temp.checkSignupQueue",
            get(temp::check_signup_queue),
        )
        .route(
            "/com.atproto.temp.dereferenceScope",
            post(temp::dereference_scope),
        )
        .route(
            "/_account.getNotificationPrefs",
            get(notification_prefs::get_notification_prefs),
        )
        .route(
            "/_account.updateNotificationPrefs",
            post(notification_prefs::update_notification_prefs),
        )
        .route(
            "/_account.getNotificationHistory",
            get(notification_prefs::get_notification_history),
        )
        .route(
            "/_account.confirmChannelVerification",
            post(server::confirm_channel_verification),
        )
        .route("/_account.verifyToken", post(server::verify_token))
        .route(
            "/_delegation.listControllers",
            get(delegation::list_controllers),
        )
        .route(
            "/_delegation.addController",
            post(delegation::add_controller),
        )
        .route(
            "/_delegation.removeController",
            post(delegation::remove_controller),
        )
        .route(
            "/_delegation.updateControllerScopes",
            post(delegation::update_controller_scopes),
        )
        .route(
            "/_delegation.listControlledAccounts",
            get(delegation::list_controlled_accounts),
        )
        .route("/_delegation.getAuditLog", get(delegation::get_audit_log))
        .route(
            "/_delegation.getScopePresets",
            get(delegation::get_scope_presets),
        )
        .route(
            "/_delegation.createDelegatedAccount",
            post(delegation::create_delegated_account),
        )
        .route(
            "/_delegation.resolveController",
            get(delegation::resolve_controller),
        )
        .route(
            "/app.bsky.ageassurance.getState",
            get(age_assurance::get_state),
        )
        .route(
            "/app.bsky.unspecced.getAgeAssuranceState",
            get(age_assurance::get_age_assurance_state),
        )
}

pub fn well_known_api_routes() -> axum::Router<AppState> {
    use axum::routing::get;

    axum::Router::new()
        .route("/did.json", get(identity::well_known_did))
        .route("/atproto-did", get(identity::well_known_atproto_did))
}

pub fn webhook_routes() -> axum::Router<AppState> {
    use axum::{extract::DefaultBodyLimit, routing::post};

    axum::Router::new()
        .route(
            "/webhook/telegram",
            post(telegram_webhook::handle_telegram_webhook).layer(DefaultBodyLimit::max(64 * 1024)),
        )
        .route(
            "/webhook/discord",
            post(discord_webhook::handle_discord_webhook).layer(DefaultBodyLimit::max(64 * 1024)),
        )
}

pub fn misc_routes() -> axum::Router<AppState> {
    use axum::routing::get;

    axum::Router::new()
        .route("/health", get(server::health))
        .route("/robots.txt", get(server::robots_txt))
        .route("/favicon.ico", get(server::get_logo))
        .route("/u/{handle}/did.json", get(identity::user_did_doc))
}
