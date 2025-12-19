use crate::api::proxy_client::proxy_client;
use crate::state::AppState;
use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cid::Cid;
use jacquard_repo::storage::BlockStore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::str::FromStr;
use tracing::{error, info};

#[derive(Deserialize)]
pub struct GetRecordInput {
    pub repo: String,
    pub collection: String,
    pub rkey: String,
    pub cid: Option<String>,
}

pub async fn get_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(input): Query<GetRecordInput>,
) -> Response {
    let hostname = std::env::var("PDS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let user_id_opt = if input.repo.starts_with("did:") {
        sqlx::query!("SELECT id FROM users WHERE did = $1", input.repo)
            .fetch_optional(&state.db)
            .await
            .map(|opt| opt.map(|r| r.id))
    } else {
        let suffix = format!(".{}", hostname);
        let short_handle = if input.repo.ends_with(&suffix) {
            input.repo.strip_suffix(&suffix).unwrap_or(&input.repo)
        } else {
            &input.repo
        };
        sqlx::query!("SELECT id FROM users WHERE handle = $1", short_handle)
            .fetch_optional(&state.db)
            .await
            .map(|opt| opt.map(|r| r.id))
    };
    let user_id: uuid::Uuid = match user_id_opt {
        Ok(Some(id)) => id,
        Ok(None) => {
            if let Some(proxy_header) = headers
                .get("atproto-proxy")
                .and_then(|h| h.to_str().ok())
            {
                let did = proxy_header.split('#').next().unwrap_or(proxy_header);
                if let Some(resolved) = state.did_resolver.resolve_did(did).await {
                    let mut url = format!(
                        "{}/xrpc/com.atproto.repo.getRecord?repo={}&collection={}&rkey={}",
                        resolved.url.trim_end_matches('/'),
                        urlencoding::encode(&input.repo),
                        urlencoding::encode(&input.collection),
                        urlencoding::encode(&input.rkey)
                    );
                    if let Some(cid) = &input.cid {
                        url.push_str(&format!("&cid={}", urlencoding::encode(cid)));
                    }
                    info!("Proxying getRecord to {}: {}", did, url);
                    match proxy_client().get(&url).send().await {
                        Ok(resp) => {
                            let status = resp.status();
                            let body = match resp.bytes().await {
                                Ok(b) => b,
                                Err(e) => {
                                    error!("Error reading proxy response: {:?}", e);
                                    return (
                                        StatusCode::BAD_GATEWAY,
                                        Json(json!({"error": "UpstreamFailure", "message": "Error reading upstream response"})),
                                    )
                                        .into_response();
                                }
                            };
                            return Response::builder()
                                .status(status)
                                .header("content-type", "application/json")
                                .body(axum::body::Body::from(body))
                                .unwrap_or_else(|_| {
                                    (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response()
                                });
                        }
                        Err(e) => {
                            error!("Error proxying request: {:?}", e);
                            return (
                                StatusCode::BAD_GATEWAY,
                                Json(json!({"error": "UpstreamFailure", "message": "Failed to reach upstream service"})),
                            )
                                .into_response();
                        }
                    }
                } else {
                    error!("Could not resolve DID from atproto-proxy header: {}", did);
                    return (
                        StatusCode::BAD_GATEWAY,
                        Json(json!({"error": "UpstreamFailure", "message": "Could not resolve proxy DID"})),
                    )
                        .into_response();
                }
            }
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "RepoNotFound", "message": "Repo not found"})),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let record_row = sqlx::query!(
        "SELECT record_cid FROM records WHERE repo_id = $1 AND collection = $2 AND rkey = $3",
        user_id,
        input.collection,
        input.rkey
    )
    .fetch_optional(&state.db)
    .await;
    let record_cid_str: String = match record_row {
        Ok(Some(row)) => row.record_cid,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "NotFound", "message": "Record not found"})),
            )
                .into_response();
        }
    };
    if let Some(expected_cid) = &input.cid
        && &record_cid_str != expected_cid {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "NotFound", "message": "Record CID mismatch"})),
            )
                .into_response();
        }
    let cid = match Cid::from_str(&record_cid_str) {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Invalid CID in DB"})),
            )
                .into_response();
        }
    };
    let block = match state.block_store.get(&cid).await {
        Ok(Some(b)) => b,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError", "message": "Record block not found"})),
            )
                .into_response();
        }
    };
    let value: serde_json::Value = match serde_ipld_dagcbor::from_slice(&block) {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to deserialize record: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    Json(json!({
        "uri": format!("at://{}/{}/{}", input.repo, input.collection, input.rkey),
        "cid": record_cid_str,
        "value": value
    }))
    .into_response()
}
#[derive(Deserialize)]
pub struct ListRecordsInput {
    pub repo: String,
    pub collection: String,
    pub limit: Option<i32>,
    pub cursor: Option<String>,
    #[serde(rename = "rkeyStart")]
    pub rkey_start: Option<String>,
    #[serde(rename = "rkeyEnd")]
    pub rkey_end: Option<String>,
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
    let user_id_opt = if input.repo.starts_with("did:") {
        sqlx::query!("SELECT id FROM users WHERE did = $1", input.repo)
            .fetch_optional(&state.db)
            .await
            .map(|opt| opt.map(|r| r.id))
    } else {
        let suffix = format!(".{}", hostname);
        let short_handle = if input.repo.ends_with(&suffix) {
            input.repo.strip_suffix(&suffix).unwrap_or(&input.repo)
        } else {
            &input.repo
        };
        sqlx::query!("SELECT id FROM users WHERE handle = $1", short_handle)
            .fetch_optional(&state.db)
            .await
            .map(|opt| opt.map(|r| r.id))
    };
    let user_id: uuid::Uuid = match user_id_opt {
        Ok(Some(id)) => id,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "RepoNotFound", "message": "Repo not found"})),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let limit = input.limit.unwrap_or(50).clamp(1, 100);
    let reverse = input.reverse.unwrap_or(false);
    let limit_i64 = limit as i64;
    let order = if reverse { "ASC" } else { "DESC" };
    let rows_res: Result<Vec<(String, String)>, sqlx::Error> = if let Some(cursor) = &input.cursor {
        let comparator = if reverse { ">" } else { "<" };
        let query = format!(
            "SELECT rkey, record_cid FROM records WHERE repo_id = $1 AND collection = $2 AND rkey {} $3 ORDER BY rkey {} LIMIT $4",
            comparator, order
        );
        sqlx::query_as(&query)
            .bind(user_id)
            .bind(&input.collection)
            .bind(cursor)
            .bind(limit_i64)
            .fetch_all(&state.db)
            .await
    } else {
        let mut conditions = vec!["repo_id = $1", "collection = $2"];
        let mut param_idx = 3;
        if input.rkey_start.is_some() {
            conditions.push("rkey > $3");
            param_idx += 1;
        }
        if input.rkey_end.is_some() {
            conditions.push(if param_idx == 3 {
                "rkey < $3"
            } else {
                "rkey < $4"
            });
            param_idx += 1;
        }
        let limit_idx = param_idx;
        let query = format!(
            "SELECT rkey, record_cid FROM records WHERE {} ORDER BY rkey {} LIMIT ${}",
            conditions.join(" AND "),
            order,
            limit_idx
        );
        let mut query_builder = sqlx::query_as::<_, (String, String)>(&query)
            .bind(user_id)
            .bind(&input.collection);
        if let Some(start) = &input.rkey_start {
            query_builder = query_builder.bind(start);
        }
        if let Some(end) = &input.rkey_end {
            query_builder = query_builder.bind(end);
        }
        query_builder.bind(limit_i64).fetch_all(&state.db).await
    };
    let rows = match rows_res {
        Ok(r) => r,
        Err(e) => {
            error!("Error listing records: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let last_rkey = rows.last().map(|(rkey, _)| rkey.clone());
    let mut cid_to_rkey: HashMap<Cid, (String, String)> = HashMap::new();
    let mut cids: Vec<Cid> = Vec::with_capacity(rows.len());
    for (rkey, cid_str) in &rows {
        if let Ok(cid) = Cid::from_str(cid_str) {
            cid_to_rkey.insert(cid, (rkey.clone(), cid_str.clone()));
            cids.push(cid);
        }
    }
    let blocks = match state.block_store.get_many(&cids).await {
        Ok(b) => b,
        Err(e) => {
            error!("Error fetching blocks: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "InternalError"})),
            )
                .into_response();
        }
    };
    let mut records = Vec::new();
    for (cid, block_opt) in cids.iter().zip(blocks.into_iter()) {
        if let Some(block) = block_opt
            && let Some((rkey, cid_str)) = cid_to_rkey.get(cid)
                && let Ok(value) = serde_ipld_dagcbor::from_slice::<serde_json::Value>(&block) {
                    records.push(json!({
                        "uri": format!("at://{}/{}/{}", input.repo, input.collection, rkey),
                        "cid": cid_str,
                        "value": value
                    }));
                }
    }
    Json(ListRecordsOutput {
        cursor: last_rkey,
        records,
    })
    .into_response()
}
