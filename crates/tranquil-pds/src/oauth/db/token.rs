use super::super::OAuthError;
use tranquil_db_traits::OAuthRepository;
pub use tranquil_db_traits::RefreshTokenLookup;
use tranquil_types::{Did, RefreshToken};

pub async fn lookup_refresh_token(
    oauth_repo: &dyn OAuthRepository,
    refresh_token: &RefreshToken,
) -> Result<RefreshTokenLookup, OAuthError> {
    let token_id = oauth_repo
        .check_refresh_token_used(refresh_token)
        .await
        .map_err(crate::oauth::db_err_to_oauth)?;
    if let Some(token_id) = token_id {
        let prev_token = oauth_repo
            .get_token_by_previous_refresh_token(refresh_token)
            .await
            .map_err(crate::oauth::db_err_to_oauth)?;
        if let Some((db_id, token_data)) = prev_token {
            let rotated_at = token_data.updated_at;
            return Ok(RefreshTokenLookup::InGracePeriod {
                db_id,
                token_data,
                rotated_at,
            });
        }
        return Ok(RefreshTokenLookup::Used {
            original_token_id: token_id,
        });
    }

    let token = oauth_repo
        .get_token_by_refresh_token(refresh_token)
        .await
        .map_err(crate::oauth::db_err_to_oauth)?;
    match token {
        Some((db_id, token_data)) => {
            if token_data.expires_at < chrono::Utc::now() {
                Ok(RefreshTokenLookup::Expired { db_id })
            } else {
                Ok(RefreshTokenLookup::Valid { db_id, token_data })
            }
        }
        None => Ok(RefreshTokenLookup::NotFound),
    }
}

const MAX_TOKENS_PER_USER: i64 = 100;

pub async fn enforce_token_limit_for_user(
    oauth_repo: &dyn OAuthRepository,
    did: &Did,
) -> Result<(), OAuthError> {
    let count = oauth_repo
        .count_tokens_for_user(did)
        .await
        .map_err(crate::oauth::db_err_to_oauth)?;
    if count > MAX_TOKENS_PER_USER {
        let to_keep = MAX_TOKENS_PER_USER - 1;
        oauth_repo
            .delete_oldest_tokens_for_user(did, to_keep)
            .await
            .map_err(crate::oauth::db_err_to_oauth)?;
    }
    Ok(())
}
