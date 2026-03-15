use tranquil_pds::auth::{Active, Auth};
use tranquil_pds::delegation::DelegationActionType;
use tranquil_pds::rate_limit::{LoginLimit, OAuthRateLimited, TotpVerifyLimit};
use tranquil_pds::state::AppState;
use tranquil_pds::types::PlainPassword;
use tranquil_pds::util::extract_client_ip;
use axum::{
    Json,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tranquil_types::{Did, RequestId};

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
    rate_limit: OAuthRateLimited<LoginLimit>,
    headers: HeaderMap,
    Json(form): Json<DelegationAuthSubmit>,
) -> Response {
    let client_ip = rate_limit.client_ip();
    let request_id = RequestId::from(form.request_uri.clone());
    let request = match state
        .oauth_repo
        .get_authorization_request(&request_id)
        .await
    {
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

    let delegated_did: Did = if let Some(did_str) = form.delegated_did.as_ref() {
        match did_str.parse() {
            Ok(d) => d,
            Err(_) => {
                return Json(DelegationAuthResponse {
                    success: false,
                    needs_totp: None,
                    redirect_uri: None,
                    error: Some("Invalid delegated DID".to_string()),
                })
                .into_response();
            }
        }
    } else if let Some(did) = request.did.as_ref() {
        did.clone()
    } else {
        return Json(DelegationAuthResponse {
            success: false,
            needs_totp: None,
            redirect_uri: None,
            error: Some("No delegated account selected".to_string()),
        })
        .into_response();
    };

    let controller_did: Did = match form.controller_did.parse() {
        Ok(d) => d,
        Err(_) => {
            return Json(DelegationAuthResponse {
                success: false,
                needs_totp: None,
                redirect_uri: None,
                error: Some("Invalid controller DID".to_string()),
            })
            .into_response();
        }
    };

    if state
        .oauth_repo
        .set_request_did(&request_id, &delegated_did)
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

    let grant = match state
        .delegation_repo
        .get_delegation(&delegated_did, &controller_did)
        .await
    {
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

    let controller = match state.user_repo.get_auth_info_by_did(&controller_did).await {
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

    if state
        .oauth_repo
        .set_controller_did(&request_id, &controller_did)
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

    let has_totp = tranquil_api::server::has_totp_enabled(&state, &controller_did).await;
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

    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let _ = state
        .delegation_repo
        .log_delegation_action(
            &delegated_did,
            &controller_did,
            Some(&controller_did),
            DelegationActionType::TokenIssued,
            Some(serde_json::json!({
                "client_id": request.client_id,
                "granted_scopes": grant.granted_scopes
            })),
            Some(client_ip),
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
    rate_limit: OAuthRateLimited<TotpVerifyLimit>,
    headers: HeaderMap,
    Json(form): Json<DelegationTotpSubmit>,
) -> Response {
    let client_ip = rate_limit.client_ip();
    let totp_request_id = RequestId::from(form.request_uri.clone());
    let request = match state
        .oauth_repo
        .get_authorization_request(&totp_request_id)
        .await
    {
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

    let controller_did_str = match &request.controller_did {
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

    let controller_did: Did = match controller_did_str.parse() {
        Ok(d) => d,
        Err(_) => {
            return Json(DelegationAuthResponse {
                success: false,
                needs_totp: None,
                redirect_uri: None,
                error: Some("Invalid controller DID".to_string()),
            })
            .into_response();
        }
    };

    let delegated_did_str = match &request.did {
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

    let delegated_did: Did = match delegated_did_str.parse() {
        Ok(d) => d,
        Err(_) => {
            return Json(DelegationAuthResponse {
                success: false,
                needs_totp: None,
                redirect_uri: None,
                error: Some("Invalid delegated DID".to_string()),
            })
            .into_response();
        }
    };

    let grant = match state
        .delegation_repo
        .get_delegation(&delegated_did, &controller_did)
        .await
    {
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
        tranquil_api::server::verify_totp_or_backup_for_user(&state, &controller_did, &form.code)
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

    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let _ = state
        .delegation_repo
        .log_delegation_action(
            &delegated_did,
            &controller_did,
            Some(&controller_did),
            DelegationActionType::TokenIssued,
            Some(serde_json::json!({
                "client_id": request.client_id,
                "granted_scopes": grant.granted_scopes
            })),
            Some(client_ip),
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
pub struct DelegationTokenAuthSubmit {
    pub request_uri: String,
    pub delegated_did: String,
}

pub async fn delegation_auth_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    auth: Auth<Active>,
    Json(form): Json<DelegationTokenAuthSubmit>,
) -> Response {
    let controller_did = &auth.did;

    let delegated_did: Did = match form.delegated_did.parse() {
        Ok(d) => d,
        Err(_) => {
            return Json(DelegationAuthResponse {
                success: false,
                needs_totp: None,
                redirect_uri: None,
                error: Some("Invalid delegated DID".to_string()),
            })
            .into_response();
        }
    };

    let request_id = RequestId::from(form.request_uri.clone());
    let request = match state
        .oauth_repo
        .get_authorization_request(&request_id)
        .await
    {
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

    let grant = match state
        .delegation_repo
        .get_delegation(&delegated_did, controller_did)
        .await
    {
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

    if state
        .oauth_repo
        .set_request_did(&request_id, &delegated_did)
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

    if state
        .oauth_repo
        .set_controller_did(&request_id, controller_did)
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

    let ip = extract_client_ip(&headers, None);
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let _ = state
        .delegation_repo
        .log_delegation_action(
            &delegated_did,
            controller_did,
            Some(controller_did),
            DelegationActionType::TokenIssued,
            Some(serde_json::json!({
                "client_id": request.client_id,
                "granted_scopes": grant.granted_scopes,
                "auth_method": "token"
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
