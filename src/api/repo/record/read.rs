use crate::state::AppState;
use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use base64::Engine;
use cid::Cid;
use ipld_core::ipld::Ipld;
use jacquard_repo::storage::BlockStore;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
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
        let handle = if !input.repo.contains('.') {
            format!("{}.{}", input.repo, hostname)
        } else {
            input.repo.clone()
        };
        sqlx::query!("SELECT id FROM users WHERE handle = $1", handle)
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
                Json(json!({"error": "RecordNotFound", "message": "Record not found"})),
            )
                .into_response();
        }
    };
    if let Some(expected_cid) = &input.cid
        && &record_cid_str != expected_cid
    {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "RecordNotFound", "message": "Record CID mismatch"})),
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
    let ipld: Ipld = match serde_ipld_dagcbor::from_slice(&block) {
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
        let handle = if !input.repo.contains('.') {
            format!("{}.{}", input.repo, hostname)
        } else {
            input.repo.clone()
        };
        sqlx::query!("SELECT id FROM users WHERE handle = $1", handle)
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
            && let Ok(ipld) = serde_ipld_dagcbor::from_slice::<Ipld>(&block)
        {
            let value = ipld_to_json(ipld);
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
