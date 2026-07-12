use tranquil_db_traits::InviteCodeError;

use crate::api::error::ApiError;
use crate::state::AppState;
use crate::types::InviteCode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteRegistration {
    Bootstrap,
    Standard(Option<InviteCode>),
}

impl InviteRegistration {
    pub fn into_invite_code(self) -> Option<InviteCode> {
        match self {
            InviteRegistration::Bootstrap => None,
            InviteRegistration::Standard(code) => code,
        }
    }
}

fn bootstrap_registration(
    expected_code: &str,
    user_count: i64,
    invite_code: Option<&str>,
) -> Option<Result<InviteRegistration, ApiError>> {
    if user_count != 0 {
        return None;
    }
    Some(match invite_code {
        Some(code) if code == expected_code => Ok(InviteRegistration::Bootstrap),
        _ => Err(ApiError::InvalidInviteCode),
    })
}

pub async fn check_registration_invite(
    state: &AppState,
    invite_code: Option<&str>,
) -> Result<InviteRegistration, ApiError> {
    if let Some(expected) = state.bootstrap_invite_code.as_deref() {
        let user_count = state.repos.user.count_users().await.unwrap_or(1);
        if let Some(decision) = bootstrap_registration(expected, user_count, invite_code) {
            return decision;
        }
    }

    match invite_code
        .map(str::trim)
        .filter(|code| !code.is_empty())
        .map(InviteCode::new)
    {
        Some(code) => match state.repos.infra.validate_invite_code(&code).await {
            Ok(_) => Ok(InviteRegistration::Standard(Some(code))),
            Err(InviteCodeError::DatabaseError(e)) => {
                tracing::error!("failed to validate invite code: {e:?}");
                Err(ApiError::InternalError(None))
            }
            Err(_) => Err(ApiError::InvalidInviteCode),
        },
        None => match tranquil_config::get().server.invite_code_required {
            true => Err(ApiError::InviteCodeRequired),
            false => Ok(InviteRegistration::Standard(None)),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_taken_for_matching_code_on_empty_instance() {
        assert!(matches!(
            bootstrap_registration("squid-bootstrap", 0, Some("squid-bootstrap")),
            Some(Ok(InviteRegistration::Bootstrap))
        ));
    }

    #[test]
    fn bootstrap_rejects_wrong_code_on_empty_instance() {
        assert!(matches!(
            bootstrap_registration("squid-bootstrap", 0, Some("whelk")),
            Some(Err(ApiError::InvalidInviteCode))
        ));
    }

    #[test]
    fn bootstrap_rejects_missing_code_on_empty_instance() {
        assert!(matches!(
            bootstrap_registration("squid-bootstrap", 0, None),
            Some(Err(ApiError::InvalidInviteCode))
        ));
    }

    #[test]
    fn bootstrap_falls_through_once_users_exist() {
        assert!(bootstrap_registration("squid-bootstrap", 1, Some("squid-bootstrap")).is_none());
    }
}
