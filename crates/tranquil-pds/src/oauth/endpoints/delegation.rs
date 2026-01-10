use crate::delegation;
use crate::oauth::db;
use crate::state::{AppState, RateLimitKind};
use crate::types::PlainPassword;
use crate::util::extract_client_ip;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct DelegationAuthSubmit {
    pub request_uri: String,
    pub delegated_did: Option<String>,
    pub controller_did: String,
    pub password: PlainPassword,
    #[serde(default)]
    pub remember_device: bool,
}

#[derive(Debug, Serialize)]
pub struct DelegationAuthResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub needs_totp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn delegation_auth(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(form): Json<DelegationAuthSubmit>,
) -> Response {
    let client_ip = extract_client_ip(&headers);
    if !state
        .check_rate_limit(RateLimitKind::Login, &client_ip)
        .await
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(DelegationAuthResponse {
                success: false,
                needs_totp: None,
                redirect_uri: None,
                error: Some("Too many login attempts. Please try again later.".to_string()),
            }),
        )
            .into_response();
    }

    let request = match db::get_authorization_request(&state.db, &form.request_uri).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Json(DelegationAuthResponse {
                success: false,
                needs_totp: None,
                redirect_uri: None,
                error: Some("Authorization request not found".to_string()),
            })
            .into_response();
        }
        Err(_) => {
            return Json(DelegationAuthResponse {
                success: false,
                needs_totp: None,
                redirect_uri: None,
                error: Some("Server error".to_string()),
            })
            .into_response();
        }
    };

    let delegated_did = match form.delegated_did.as_ref().or(request.did.as_ref()) {
        Some(did) => did.clone(),
        None => {
            return Json(DelegationAuthResponse {
                success: false,
                needs_totp: None,
                redirect_uri: None,
                error: Some("No delegated account selected".to_string()),
            })
            .into_response();
        }
    };

    if db::set_request_did(&state.db, &form.request_uri, &delegated_did)
        .await
        .is_err()
    {
        tracing::warn!("Failed to set delegated DID on authorization request");
    }

    let grant =
        match delegation::get_delegation(&state.db, &delegated_did, &form.controller_did).await {
            Ok(Some(g)) => g,
            Ok(None) => {
                return Json(DelegationAuthResponse {
                    success: false,
                    needs_totp: None,
                    redirect_uri: None,
                    error: Some("No delegation grant found for this controller".to_string()),
                })
                .into_response();
            }
            Err(_) => {
                return Json(DelegationAuthResponse {
                    success: false,
                    needs_totp: None,
                    redirect_uri: None,
                    error: Some("Server error".to_string()),
                })
                .into_response();
            }
        };

    let controller = match sqlx::query!(
        r#"
        SELECT id, did, password_hash, deactivated_at, takedown_ref,
               email_verified, discord_verified, telegram_verified, signal_verified
        FROM users
        WHERE did = $1
        "#,
        form.controller_did
    )
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(u)) => u,
        Ok(None) => {
            return Json(DelegationAuthResponse {
                success: false,
                needs_totp: None,
                redirect_uri: None,
                error: Some("Controller account not found".to_string()),
            })
            .into_response();
        }
        Err(_) => {
            return Json(DelegationAuthResponse {
                success: false,
                needs_totp: None,
                redirect_uri: None,
                error: Some("Server error".to_string()),
            })
            .into_response();
        }
    };

    if controller.deactivated_at.is_some() {
        return Json(DelegationAuthResponse {
            success: false,
            needs_totp: None,
            redirect_uri: None,
            error: Some("Controller account is deactivated".to_string()),
        })
        .into_response();
    }

    if controller.takedown_ref.is_some() {
        return Json(DelegationAuthResponse {
            success: false,
            needs_totp: None,
            redirect_uri: None,
            error: Some("Controller account has been taken down".to_string()),
        })
        .into_response();
    }

    let password_valid = controller
        .password_hash
        .as_ref()
        .map(|hash| bcrypt::verify(&form.password, hash).unwrap_or_default())
        .unwrap_or_default();

    if !password_valid {
        return Json(DelegationAuthResponse {
            success: false,
            needs_totp: None,
            redirect_uri: None,
            error: Some("Invalid password".to_string()),
        })
        .into_response();
    }

    if db::set_controller_did(&state.db, &form.request_uri, &form.controller_did)
        .await
        .is_err()
    {
        return Json(DelegationAuthResponse {
            success: false,
            needs_totp: None,
            redirect_uri: None,
            error: Some("Failed to update authorization request".to_string()),
        })
        .into_response();
    }

    let has_totp = crate::api::server::has_totp_enabled(&state, &form.controller_did).await;
    if has_totp {
        return Json(DelegationAuthResponse {
            success: true,
            needs_totp: Some(true),
            redirect_uri: Some(format!(
                "/app/oauth/delegation-totp?request_uri={}",
                urlencoding::encode(&form.request_uri)
            )),
            error: None,
        })
        .into_response();
    }

    let ip = extract_client_ip(&headers);
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let _ = delegation::log_delegation_action(
        &state.db,
        &delegated_did,
        &form.controller_did,
        Some(&form.controller_did),
        delegation::DelegationActionType::TokenIssued,
        Some(serde_json::json!({
            "client_id": request.client_id,
            "granted_scopes": grant.granted_scopes
        })),
        Some(&ip),
        user_agent.as_deref(),
    )
    .await;

    Json(DelegationAuthResponse {
        success: true,
        needs_totp: None,
        redirect_uri: Some(format!(
            "/app/oauth/consent?request_uri={}",
            urlencoding::encode(&form.request_uri)
        )),
        error: None,
    })
    .into_response()
}

#[derive(Debug, Deserialize)]
pub struct DelegationTotpSubmit {
    pub request_uri: String,
    pub code: String,
}

pub async fn delegation_totp_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(form): Json<DelegationTotpSubmit>,
) -> Response {
    let client_ip = extract_client_ip(&headers);
    if !state
        .check_rate_limit(RateLimitKind::TotpVerify, &client_ip)
        .await
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(DelegationAuthResponse {
                success: false,
                needs_totp: None,
                redirect_uri: None,
                error: Some("Too many verification attempts. Please try again later.".to_string()),
            }),
        )
            .into_response();
    }

    let request = match db::get_authorization_request(&state.db, &form.request_uri).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Json(DelegationAuthResponse {
                success: false,
                needs_totp: None,
                redirect_uri: None,
                error: Some("Authorization request not found".to_string()),
            })
            .into_response();
        }
        Err(_) => {
            return Json(DelegationAuthResponse {
                success: false,
                needs_totp: None,
                redirect_uri: None,
                error: Some("Server error".to_string()),
            })
            .into_response();
        }
    };

    let controller_did = match &request.controller_did {
        Some(did) => did.clone(),
        None => {
            return Json(DelegationAuthResponse {
                success: false,
                needs_totp: None,
                redirect_uri: None,
                error: Some("Controller not authenticated".to_string()),
            })
            .into_response();
        }
    };

    let delegated_did = match &request.did {
        Some(did) => did.clone(),
        None => {
            return Json(DelegationAuthResponse {
                success: false,
                needs_totp: None,
                redirect_uri: None,
                error: Some("No delegated account".to_string()),
            })
            .into_response();
        }
    };

    let grant = match delegation::get_delegation(&state.db, &delegated_did, &controller_did).await {
        Ok(Some(g)) => g,
        _ => {
            return Json(DelegationAuthResponse {
                success: false,
                needs_totp: None,
                redirect_uri: None,
                error: Some("Delegation grant not found".to_string()),
            })
            .into_response();
        }
    };

    let totp_valid =
        crate::api::server::verify_totp_or_backup_for_user(&state, &controller_did, &form.code)
            .await;
    if !totp_valid {
        return Json(DelegationAuthResponse {
            success: false,
            needs_totp: Some(true),
            redirect_uri: None,
            error: Some("Invalid TOTP code".to_string()),
        })
        .into_response();
    }

    let ip = extract_client_ip(&headers);
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let _ = delegation::log_delegation_action(
        &state.db,
        &delegated_did,
        &controller_did,
        Some(&controller_did),
        delegation::DelegationActionType::TokenIssued,
        Some(serde_json::json!({
            "client_id": request.client_id,
            "granted_scopes": grant.granted_scopes
        })),
        Some(&ip),
        user_agent.as_deref(),
    )
    .await;

    Json(DelegationAuthResponse {
        success: true,
        needs_totp: None,
        redirect_uri: Some(format!(
            "/app/oauth/consent?request_uri={}",
            urlencoding::encode(&form.request_uri)
        )),
        error: None,
    })
    .into_response()
}
