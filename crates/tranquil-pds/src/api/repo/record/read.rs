use crate::api::error::ApiError;
use crate::state::AppState;
use crate::types::{AtIdentifier, Nsid, Rkey};
use axum::{
    Json,
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use base64::Engine;
use cid::Cid;
use ipld_core::ipld::Ipld;
use jacquard_repo::storage::BlockStore;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::str::FromStr;
use tracing::error;

fn ipld_to_json(ipld: Ipld) -> Value {
    match ipld {
        Ipld::Null => Value::Null,
        Ipld::Bool(b) => Value::Bool(b),
        Ipld::Integer(i) => {
            if let Ok(n) = i64::try_from(i) {
                Value::Number(n.into())
            } else {
                Value::String(i.to_string())
            }
        }
        Ipld::Float(f) => serde_json::Number::from_f64(f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        Ipld::String(s) => Value::String(s),
        Ipld::Bytes(b) => {
            let encoded = base64::engine::general_purpose::STANDARD.encode(&b);
            json!({ "$bytes": encoded })
        }
        Ipld::List(arr) => Value::Array(arr.into_iter().map(ipld_to_json).collect()),
        Ipld::Map(map) => {
            let obj: Map<String, Value> =
                map.into_iter().map(|(k, v)| (k, ipld_to_json(v))).collect();
            Value::Object(obj)
        }
        Ipld::Link(cid) => json!({ "$link": cid.to_string() }),
    }
}

#[derive(Deserialize)]
pub struct GetRecordInput {
    pub repo: AtIdentifier,
    pub collection: Nsid,
    pub rkey: Rkey,
    pub cid: Option<String>,
}

pub async fn get_record(
    State(state): State<AppState>,
    _headers: HeaderMap,
    Query(input): Query<GetRecordInput>,
) -> Response {
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let hostname_for_handles = hostname.split(':').next().unwrap_or(&hostname);
    let user_id_opt = if input.repo.is_did() {
        let did: crate::types::Did = match input.repo.as_str().parse() {
            Ok(d) => d,
            Err(_) => return ApiError::InvalidRequest("Invalid DID format".into()).into_response(),
        };
        state
            .user_repo
            .get_id_by_did(&did)
            .await
            .map_err(|_| ())
    } else {
        let repo_str = input.repo.as_str();
        let handle_str = if !repo_str.contains('.') {
            format!("{}.{}", repo_str, hostname_for_handles)
        } else {
            repo_str.to_string()
        };
        let handle: crate::types::Handle = match handle_str.parse() {
            Ok(h) => h,
            Err(_) => return ApiError::InvalidRequest("Invalid handle format".into()).into_response(),
        };
        state
            .user_repo
            .get_id_by_handle(&handle)
            .await
            .map_err(|_| ())
    };
    let user_id: uuid::Uuid = match user_id_opt {
        Ok(Some(id)) => id,
        Ok(None) => {
            return ApiError::RepoNotFound(Some("Repo not found".into())).into_response();
        }
        Err(_) => {
            return ApiError::InternalError(None).into_response();
        }
    };
    let record_row = state
        .repo_repo
        .get_record_cid(user_id, &input.collection, &input.rkey)
        .await;
    let record_cid_link = match record_row {
        Ok(Some(cid)) => cid,
        _ => {
            return ApiError::RecordNotFound.into_response();
        }
    };
    let record_cid_str = record_cid_link.to_string();
    if let Some(expected_cid) = &input.cid
        && &record_cid_str != expected_cid
    {
        return ApiError::RecordNotFound.into_response();
    }
    let Ok(cid) = Cid::from_str(&record_cid_str) else {
        return ApiError::InternalError(Some("Invalid CID in DB".into())).into_response();
    };
    let block = match state.block_store.get(&cid).await {
        Ok(Some(b)) => b,
        _ => {
            return ApiError::InternalError(Some("Record block not found".into())).into_response();
        }
    };
    let ipld: Ipld = match serde_ipld_dagcbor::from_slice(&block) {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to deserialize record: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let value = ipld_to_json(ipld);
    Json(json!({
        "uri": format!("at://{}/{}/{}", input.repo, input.collection, input.rkey),
        "cid": record_cid_str,
        "value": value
    }))
    .into_response()
}
#[derive(Deserialize)]
pub struct ListRecordsInput {
    pub repo: AtIdentifier,
    pub collection: Nsid,
    pub limit: Option<i32>,
    pub cursor: Option<String>,
    #[serde(rename = "rkeyStart")]
    pub rkey_start: Option<Rkey>,
    #[serde(rename = "rkeyEnd")]
    pub rkey_end: Option<Rkey>,
    pub reverse: Option<bool>,
}
#[derive(Serialize)]
pub struct ListRecordsOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    pub records: Vec<serde_json::Value>,
}

pub async fn list_records(
    State(state): State<AppState>,
    Query(input): Query<ListRecordsInput>,
) -> Response {
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let hostname_for_handles = hostname.split(':').next().unwrap_or(&hostname);
    let user_id_opt = if input.repo.is_did() {
        let did: crate::types::Did = match input.repo.as_str().parse() {
            Ok(d) => d,
            Err(_) => return ApiError::InvalidRequest("Invalid DID format".into()).into_response(),
        };
        state
            .user_repo
            .get_id_by_did(&did)
            .await
            .map_err(|_| ())
    } else {
        let repo_str = input.repo.as_str();
        let handle_str = if !repo_str.contains('.') {
            format!("{}.{}", repo_str, hostname_for_handles)
        } else {
            repo_str.to_string()
        };
        let handle: crate::types::Handle = match handle_str.parse() {
            Ok(h) => h,
            Err(_) => return ApiError::InvalidRequest("Invalid handle format".into()).into_response(),
        };
        state
            .user_repo
            .get_id_by_handle(&handle)
            .await
            .map_err(|_| ())
    };
    let user_id: uuid::Uuid = match user_id_opt {
        Ok(Some(id)) => id,
        Ok(None) => {
            return ApiError::RepoNotFound(Some("Repo not found".into())).into_response();
        }
        Err(_) => {
            return ApiError::InternalError(None).into_response();
        }
    };
    let limit = input.limit.unwrap_or(50).clamp(1, 100);
    let reverse = input.reverse.unwrap_or(false);
    let limit_i64 = limit as i64;
    let cursor_rkey = input.cursor.as_ref().and_then(|c| c.parse::<crate::types::Rkey>().ok());
    let rows = match state
        .repo_repo
        .list_records(
            user_id,
            &input.collection,
            cursor_rkey.as_ref(),
            limit_i64,
            reverse,
            input.rkey_start.as_ref(),
            input.rkey_end.as_ref(),
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            error!("Error listing records: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let last_rkey = rows.last().map(|r| r.rkey.to_string());
    let parsed_rows: Vec<(Cid, String, String)> = rows
        .iter()
        .filter_map(|row| {
            Cid::from_str(row.record_cid.as_str())
                .ok()
                .map(|cid| (cid, row.rkey.to_string(), row.record_cid.to_string()))
        })
        .collect();
    let cids: Vec<Cid> = parsed_rows.iter().map(|(cid, _, _)| *cid).collect();
    let blocks = match state.block_store.get_many(&cids).await {
        Ok(b) => b,
        Err(e) => {
            error!("Error fetching blocks: {:?}", e);
            return ApiError::InternalError(None).into_response();
        }
    };
    let records: Vec<Value> = parsed_rows
        .iter()
        .zip(blocks.into_iter())
        .filter_map(|((_, rkey, cid_str), block_opt)| {
            block_opt.and_then(|block| {
                serde_ipld_dagcbor::from_slice::<Ipld>(&block)
                    .ok()
                    .map(|ipld| {
                        json!({
                            "uri": format!("at://{}/{}/{}", input.repo, input.collection, rkey),
                            "cid": cid_str,
                            "value": ipld_to_json(ipld)
                        })
                    })
            })
        })
        .collect();
    Json(ListRecordsOutput {
        cursor: last_rkey,
        records,
    })
    .into_response()
}
