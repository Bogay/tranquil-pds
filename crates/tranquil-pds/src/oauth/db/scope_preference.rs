use super::super::OAuthError;
use tranquil_db_traits::OAuthRepository;
use tranquil_types::{ClientId, Did};

pub use tranquil_db_traits::ScopePreference;

pub async fn should_show_consent(
    oauth_repo: &dyn OAuthRepository,
    did: &Did,
    client_id: &ClientId,
    requested_scopes: &[String],
) -> Result<bool, OAuthError> {
    if requested_scopes.is_empty() {
        return Ok(false);
    }

    let stored_prefs = oauth_repo
        .get_scope_preferences(did, client_id)
        .await
        .map_err(crate::oauth::db_err_to_oauth)?;
    if stored_prefs.is_empty() {
        return Ok(true);
    }

    let stored_scopes: std::collections::HashSet<&str> =
        stored_prefs.iter().map(|p| p.scope.as_str()).collect();

    Ok(requested_scopes
        .iter()
        .any(|scope| !stored_scopes.contains(scope.as_str())))
}
