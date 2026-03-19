use crate::api::error::ApiError;
use crate::oauth::scopes::{
    AccountAction, AccountAttr, IdentityAttr, RepoAction, ScopePermissions,
};

use super::{AuthSource, TokenScope};

fn requires_scope_check(auth_source: &AuthSource, scope: Option<&str>) -> bool {
    match auth_source {
        AuthSource::OAuth => true,
        _ => match scope {
            None => false,
            Some(s) => s != TokenScope::Access.as_str(),
        },
    }
}

pub fn check_repo_scope(
    auth_source: &AuthSource,
    scope: Option<&str>,
    action: RepoAction,
    collection: &str,
) -> Result<(), ApiError> {
    if !requires_scope_check(auth_source, scope) {
        return Ok(());
    }

    let permissions = ScopePermissions::from_scope_string(scope);
    permissions
        .assert_repo(action, collection)
        .map_err(|e| ApiError::InsufficientScope(Some(e.to_string())))
}

pub fn check_blob_scope(
    auth_source: &AuthSource,
    scope: Option<&str>,
    mime: &str,
) -> Result<(), ApiError> {
    if !requires_scope_check(auth_source, scope) {
        return Ok(());
    }

    let permissions = ScopePermissions::from_scope_string(scope);
    permissions
        .assert_blob(mime)
        .map_err(|e| ApiError::InsufficientScope(Some(e.to_string())))
}

pub fn check_rpc_scope(
    auth_source: &AuthSource,
    scope: Option<&str>,
    aud: &str,
    lxm: &str,
) -> Result<(), ApiError> {
    if !requires_scope_check(auth_source, scope) {
        return Ok(());
    }

    let permissions = ScopePermissions::from_scope_string(scope);
    permissions
        .assert_rpc(aud, lxm)
        .map_err(|e| ApiError::InsufficientScope(Some(e.to_string())))
}

pub fn check_account_scope(
    auth_source: &AuthSource,
    scope: Option<&str>,
    attr: AccountAttr,
    action: AccountAction,
) -> Result<(), ApiError> {
    if !requires_scope_check(auth_source, scope) {
        return Ok(());
    }

    let permissions = ScopePermissions::from_scope_string(scope);
    permissions
        .assert_account(attr, action)
        .map_err(|e| ApiError::InsufficientScope(Some(e.to_string())))
}

pub fn check_identity_scope(
    auth_source: &AuthSource,
    scope: Option<&str>,
    attr: IdentityAttr,
) -> Result<(), ApiError> {
    if !requires_scope_check(auth_source, scope) {
        return Ok(());
    }

    let permissions = ScopePermissions::from_scope_string(scope);
    permissions
        .assert_identity(attr)
        .map_err(|e| ApiError::InsufficientScope(Some(e.to_string())))
}
