use axum::extract::{Query, State};
use axum::http::StatusCode;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer};
use tracing::error;
use tranquil_pds::handle::ServiceDomains;
use tranquil_pds::state::AppState;
use tranquil_pds::types::Handle;

pub struct AskedDomain(Handle);

impl<'de> Deserialize<'de> for AskedDomain {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let without_root_dot = raw.strip_suffix('.').unwrap_or(&raw);
        Handle::new(without_root_dot)
            .map(Self)
            .map_err(D::Error::custom)
    }
}

#[derive(Deserialize)]
pub struct CaddyAskQuery {
    pub domain: AskedDomain,
}

pub async fn caddy_ask(
    State(state): State<AppState>,
    Query(ask): Query<CaddyAskQuery>,
) -> StatusCode {
    let AskedDomain(handle) = ask.domain;
    if ServiceDomains::served().contains(handle.as_str()) {
        return StatusCode::OK;
    }
    match state.repos.user.get_by_handle(&handle).await {
        Ok(Some(_)) => StatusCode::OK,
        Ok(None) => StatusCode::NOT_FOUND,
        Err(e) => {
            error!("caddy ask couldn't look up handle {handle}: {e:?}");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}
