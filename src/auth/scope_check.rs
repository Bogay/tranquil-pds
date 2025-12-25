#![allow(clippy::result_large_err)]

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::oauth::scopes::{
    AccountAction, AccountAttr, IdentityAttr, RepoAction, ScopePermissions,
};

use super::token::SCOPE_ACCESS;

fn has_custom_scope(scope: Option<&str>) -> bool {
    match scope {
        None => false,
        Some(s) => s != SCOPE_ACCESS,
    }
}

pub fn check_repo_scope(
    is_oauth: bool,
    scope: Option<&str>,
    action: RepoAction,
    collection: &str,
) -> Result<(), Response> {
    if !is_oauth && !has_custom_scope(scope) {
        return Ok(());
    }

    let permissions = ScopePermissions::from_scope_string(scope);
    permissions.assert_repo(action, collection).map_err(|e| {
        (
            StatusCode::FORBIDDEN,
            axum::Json(json!({
                "error": "InsufficientScope",
                "message": e.to_string()
            })),
        )
            .into_response()
    })
}

pub fn check_blob_scope(is_oauth: bool, scope: Option<&str>, mime: &str) -> Result<(), Response> {
    if !is_oauth && !has_custom_scope(scope) {
        return Ok(());
    }

    let permissions = ScopePermissions::from_scope_string(scope);
    permissions.assert_blob(mime).map_err(|e| {
        (
            StatusCode::FORBIDDEN,
            axum::Json(json!({
                "error": "InsufficientScope",
                "message": e.to_string()
            })),
        )
            .into_response()
    })
}

pub fn check_rpc_scope(
    is_oauth: bool,
    scope: Option<&str>,
    aud: &str,
    lxm: &str,
) -> Result<(), Response> {
    if !is_oauth && !has_custom_scope(scope) {
        return Ok(());
    }

    let permissions = ScopePermissions::from_scope_string(scope);
    permissions.assert_rpc(aud, lxm).map_err(|e| {
        (
            StatusCode::FORBIDDEN,
            axum::Json(json!({
                "error": "InsufficientScope",
                "message": e.to_string()
            })),
        )
            .into_response()
    })
}

pub fn check_account_scope(
    is_oauth: bool,
    scope: Option<&str>,
    attr: AccountAttr,
    action: AccountAction,
) -> Result<(), Response> {
    if !is_oauth && !has_custom_scope(scope) {
        return Ok(());
    }

    let permissions = ScopePermissions::from_scope_string(scope);
    permissions.assert_account(attr, action).map_err(|e| {
        (
            StatusCode::FORBIDDEN,
            axum::Json(json!({
                "error": "InsufficientScope",
                "message": e.to_string()
            })),
        )
            .into_response()
    })
}

pub fn check_identity_scope(
    is_oauth: bool,
    scope: Option<&str>,
    attr: IdentityAttr,
) -> Result<(), Response> {
    if !is_oauth && !has_custom_scope(scope) {
        return Ok(());
    }

    let permissions = ScopePermissions::from_scope_string(scope);
    permissions.assert_identity(attr).map_err(|e| {
        (
            StatusCode::FORBIDDEN,
            axum::Json(json!({
                "error": "InsufficientScope",
                "message": e.to_string()
            })),
        )
            .into_response()
    })
}
