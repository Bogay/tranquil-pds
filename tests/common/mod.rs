use aws_config::BehaviorVersion;
use aws_sdk_s3::Client as S3Client;
use aws_sdk_s3::config::Credentials;
use chrono::Utc;
use reqwest::{Client, StatusCode, header};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
#[allow(unused_imports)]
use std::collections::HashMap;
use std::sync::OnceLock;
#[allow(unused_imports)]
use std::time::Duration;
use tokio::net::TcpListener;
use tranquil_pds::state::AppState;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

static SERVER_URL: OnceLock<String> = OnceLock::new();
static APP_PORT: OnceLock<u16> = OnceLock::new();
static MOCK_APPVIEW: OnceLock<MockServer> = OnceLock::new();
static TEST_DB_POOL: OnceLock<sqlx::PgPool> = OnceLock::new();

#[cfg(not(feature = "external-infra"))]
use testcontainers::core::ContainerPort;
#[cfg(not(feature = "external-infra"))]
use testcontainers::{ContainerAsync, GenericImage, ImageExt, runners::AsyncRunner};
#[cfg(not(feature = "external-infra"))]
use testcontainers_modules::postgres::Postgres;
#[cfg(not(feature = "external-infra"))]
static DB_CONTAINER: OnceLock<ContainerAsync<Postgres>> = OnceLock::new();
#[cfg(not(feature = "external-infra"))]
static S3_CONTAINER: OnceLock<ContainerAsync<GenericImage>> = OnceLock::new();

#[allow(dead_code)]
pub const AUTH_TOKEN: &str = "test-token";
#[allow(dead_code)]
pub const BAD_AUTH_TOKEN: &str = "bad-token";
#[allow(dead_code)]
pub const AUTH_DID: &str = "did:plc:fake";
#[allow(dead_code)]
pub const TARGET_DID: &str = "did:plc:target";

fn has_external_infra() -> bool {
    std::env::var("TRANQUIL_PDS_TEST_INFRA_READY").is_ok()
        || (std::env::var("DATABASE_URL").is_ok() && std::env::var("S3_ENDPOINT").is_ok())
}
#[cfg(test)]
#[ctor::dtor]
fn cleanup() {
    if has_external_infra() {
        return;
    }
    if std::env::var("XDG_RUNTIME_DIR").is_ok() {
        let _ = std::process::Command::new("podman")
            .args(&["rm", "-f", "--filter", "label=tranquil_pds_test=true"])
            .output();
    }
    let _ = std::process::Command::new("docker")
        .args(&[
            "container",
            "prune",
            "-f",
            "--filter",
            "label=tranquil_pds_test=true",
        ])
        .output();
}

#[allow(dead_code)]
pub fn client() -> Client {
    Client::new()
}

#[allow(dead_code)]
pub fn app_port() -> u16 {
    *APP_PORT.get().expect("APP_PORT not initialized")
}

pub async fn base_url() -> &'static str {
    SERVER_URL.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            unsafe {
                std::env::set_var("TRANQUIL_PDS_ALLOW_INSECURE_SECRETS", "1");
            }
            if std::env::var("DOCKER_HOST").is_err() {
                if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
                    let podman_sock = std::path::Path::new(&runtime_dir).join("podman/podman.sock");
                    if podman_sock.exists() {
                        unsafe {
                            std::env::set_var(
                                "DOCKER_HOST",
                                format!("unix://{}", podman_sock.display()),
                            );
                        }
                    }
                }
            }
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                if has_external_infra() {
                    let url = setup_with_external_infra().await;
                    tx.send(url).unwrap();
                } else {
                    let url = setup_with_testcontainers().await;
                    tx.send(url).unwrap();
                }
                std::future::pending::<()>().await;
            });
        });
        rx.recv().expect("Failed to start test server")
    })
}

async fn setup_with_external_infra() -> String {
    let database_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL must be set when using external infra");
    let s3_endpoint =
        std::env::var("S3_ENDPOINT").expect("S3_ENDPOINT must be set when using external infra");
    unsafe {
        std::env::set_var(
            "S3_BUCKET",
            std::env::var("S3_BUCKET").unwrap_or_else(|_| "test-bucket".to_string()),
        );
        std::env::set_var(
            "AWS_ACCESS_KEY_ID",
            std::env::var("AWS_ACCESS_KEY_ID").unwrap_or_else(|_| "minioadmin".to_string()),
        );
        std::env::set_var(
            "AWS_SECRET_ACCESS_KEY",
            std::env::var("AWS_SECRET_ACCESS_KEY").unwrap_or_else(|_| "minioadmin".to_string()),
        );
        std::env::set_var(
            "AWS_REGION",
            std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string()),
        );
        std::env::set_var("S3_ENDPOINT", &s3_endpoint);
    }
    let mock_server = MockServer::start().await;
    setup_mock_appview(&mock_server).await;
    let mock_uri = mock_server.uri();
    let mock_host = mock_uri.strip_prefix("http://").unwrap_or(&mock_uri);
    let mock_did = format!("did:web:{}", mock_host.replace(':', "%3A"));
    setup_mock_did_document(&mock_server, &mock_did, &mock_uri).await;
    MOCK_APPVIEW.set(mock_server).ok();
    spawn_app(database_url).await
}

#[cfg(not(feature = "external-infra"))]
async fn setup_with_testcontainers() -> String {
    let s3_container = GenericImage::new("minio/minio", "latest")
        .with_exposed_port(ContainerPort::Tcp(9000))
        .with_env_var("MINIO_ROOT_USER", "minioadmin")
        .with_env_var("MINIO_ROOT_PASSWORD", "minioadmin")
        .with_cmd(vec!["server".to_string(), "/data".to_string()])
        .with_label("tranquil_pds_test", "true")
        .start()
        .await
        .expect("Failed to start MinIO");
    let s3_port = s3_container
        .get_host_port_ipv4(9000)
        .await
        .expect("Failed to get S3 port");
    let s3_endpoint = format!("http://127.0.0.1:{}", s3_port);
    unsafe {
        std::env::set_var("S3_BUCKET", "test-bucket");
        std::env::set_var("AWS_ACCESS_KEY_ID", "minioadmin");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "minioadmin");
        std::env::set_var("AWS_REGION", "us-east-1");
        std::env::set_var("S3_ENDPOINT", &s3_endpoint);
    }
    let sdk_config = aws_config::defaults(BehaviorVersion::latest())
        .region("us-east-1")
        .endpoint_url(&s3_endpoint)
        .credentials_provider(Credentials::new(
            "minioadmin",
            "minioadmin",
            None,
            None,
            "test",
        ))
        .load()
        .await;
    let s3_config = aws_sdk_s3::config::Builder::from(&sdk_config)
        .force_path_style(true)
        .build();
    let s3_client = S3Client::from_conf(s3_config);
    let _ = s3_client.create_bucket().bucket("test-bucket").send().await;
    let mock_server = MockServer::start().await;
    setup_mock_appview(&mock_server).await;
    let mock_uri = mock_server.uri();
    let mock_host = mock_uri.strip_prefix("http://").unwrap_or(&mock_uri);
    let mock_did = format!("did:web:{}", mock_host.replace(':', "%3A"));
    setup_mock_did_document(&mock_server, &mock_did, &mock_uri).await;
    MOCK_APPVIEW.set(mock_server).ok();
    S3_CONTAINER.set(s3_container).ok();
    let container = Postgres::default()
        .with_tag("18-alpine")
        .with_label("tranquil_pds_test", "true")
        .start()
        .await
        .expect("Failed to start Postgres");
    let connection_string = format!(
        "postgres://postgres:postgres@127.0.0.1:{}",
        container
            .get_host_port_ipv4(5432)
            .await
            .expect("Failed to get port")
    );
    DB_CONTAINER.set(container).ok();
    spawn_app(connection_string).await
}

#[cfg(feature = "external-infra")]
async fn setup_with_testcontainers() -> String {
    panic!(
        "Testcontainers disabled with external-infra feature. Set DATABASE_URL and S3_ENDPOINT."
    );
}

async fn setup_mock_did_document(mock_server: &MockServer, did: &str, service_endpoint: &str) {
    Mock::given(method("GET"))
        .and(path("/.well-known/did.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": did,
            "service": [{
                "id": "#atproto_appview",
                "type": "AtprotoAppView",
                "serviceEndpoint": service_endpoint
            }]
        })))
        .mount(mock_server)
        .await;
}

async fn setup_mock_appview(_mock_server: &MockServer) {}

async fn spawn_app(database_url: String) -> String {
    use tranquil_pds::rate_limit::RateLimiters;
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .acquire_timeout(std::time::Duration::from_secs(30))
        .connect(&database_url)
        .await
        .expect("Failed to connect to Postgres. Make sure the database is running.");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");
    let test_pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(std::time::Duration::from_secs(30))
        .connect(&database_url)
        .await
        .expect("Failed to create test pool");
    TEST_DB_POOL.set(test_pool).ok();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    APP_PORT.set(addr.port()).ok();
    unsafe {
        std::env::set_var("PDS_HOSTNAME", addr.to_string());
    }
    let rate_limiters = RateLimiters::new()
        .with_login_limit(10000)
        .with_account_creation_limit(10000)
        .with_password_reset_limit(10000)
        .with_email_update_limit(10000)
        .with_oauth_authorize_limit(10000)
        .with_oauth_token_limit(10000);
    let state = AppState::from_db(pool)
        .await
        .with_rate_limiters(rate_limiters);
    tranquil_pds::sync::listener::start_sequencer_listener(state.clone()).await;
    let app = tranquil_pds::app(state);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{}", addr)
}

#[allow(dead_code)]
pub async fn get_db_connection_string() -> String {
    base_url().await;
    if has_external_infra() {
        std::env::var("DATABASE_URL").expect("DATABASE_URL not set")
    } else {
        #[cfg(not(feature = "external-infra"))]
        {
            let container = DB_CONTAINER.get().expect("DB container not initialized");
            let port = container
                .get_host_port_ipv4(5432)
                .await
                .expect("Failed to get port");
            format!("postgres://postgres:postgres@127.0.0.1:{}/postgres", port)
        }
        #[cfg(feature = "external-infra")]
        {
            panic!("DATABASE_URL must be set with external-infra feature");
        }
    }
}

#[allow(dead_code)]
pub async fn get_test_db_pool() -> &'static sqlx::PgPool {
    base_url().await;
    TEST_DB_POOL.get().expect("TEST_DB_POOL not initialized")
}

#[allow(dead_code)]
pub async fn verify_new_account(client: &Client, did: &str) -> String {
    let pool = get_test_db_pool().await;
    let body_text: String = sqlx::query_scalar!(
        "SELECT body FROM comms_queue WHERE user_id = (SELECT id FROM users WHERE did = $1) AND comms_type = 'email_verification' ORDER BY created_at DESC LIMIT 1",
        did
    )
    .fetch_one(pool)
    .await
    .expect("Failed to get verification code");

    let lines: Vec<&str> = body_text.lines().collect();
    let verification_code = lines
        .iter()
        .enumerate()
        .find(|(_, line)| line.contains("verification code is:") || line.contains("code is:"))
        .and_then(|(i, _)| lines.get(i + 1).map(|s| s.trim().to_string()))
        .or_else(|| {
            body_text
                .split_whitespace()
                .find(|word| word.contains('-') && word.chars().filter(|c| *c == '-').count() >= 3)
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| body_text.clone());

    let confirm_payload = json!({
        "did": did,
        "verificationCode": verification_code
    });
    let confirm_res = client
        .post(format!(
            "{}/xrpc/com.atproto.server.confirmSignup",
            base_url().await
        ))
        .json(&confirm_payload)
        .send()
        .await
        .expect("confirmSignup request failed");
    assert_eq!(confirm_res.status(), StatusCode::OK, "confirmSignup failed");
    let confirm_body: Value = confirm_res
        .json()
        .await
        .expect("Invalid JSON from confirmSignup");
    confirm_body["accessJwt"]
        .as_str()
        .expect("No accessJwt in confirmSignup response")
        .to_string()
}

#[allow(dead_code)]
pub async fn upload_test_blob(client: &Client, data: &'static str, mime: &'static str) -> Value {
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.uploadBlob",
            base_url().await
        ))
        .header(header::CONTENT_TYPE, mime)
        .bearer_auth(AUTH_TOKEN)
        .body(data)
        .send()
        .await
        .expect("Failed to send uploadBlob request");
    assert_eq!(res.status(), StatusCode::OK, "Failed to upload blob");
    let body: Value = res.json().await.expect("Blob upload response was not JSON");
    body["blob"].clone()
}

#[allow(dead_code)]
pub async fn create_test_post(
    client: &Client,
    text: &str,
    reply_to: Option<Value>,
) -> (String, String, String) {
    let collection = "app.bsky.feed.post";
    let mut record = json!({
        "$type": collection,
        "text": text,
        "createdAt": Utc::now().to_rfc3339()
    });
    if let Some(reply_obj) = reply_to {
        record["reply"] = reply_obj;
    }
    let payload = json!({
        "repo": AUTH_DID,
        "collection": collection,
        "record": record
    });
    let res = client
        .post(format!(
            "{}/xrpc/com.atproto.repo.createRecord",
            base_url().await
        ))
        .bearer_auth(AUTH_TOKEN)
        .json(&payload)
        .send()
        .await
        .expect("Failed to send createRecord");
    assert_eq!(res.status(), StatusCode::OK, "Failed to create post record");
    let body: Value = res
        .json()
        .await
        .expect("createRecord response was not JSON");
    let uri = body["uri"]
        .as_str()
        .expect("Response had no URI")
        .to_string();
    let cid = body["cid"]
        .as_str()
        .expect("Response had no CID")
        .to_string();
    let rkey = uri
        .split('/')
        .last()
        .expect("URI was malformed")
        .to_string();
    (uri, cid, rkey)
}

#[allow(dead_code)]
pub async fn create_account_and_login(client: &Client) -> (String, String) {
    create_account_and_login_internal(client, false).await
}

#[allow(dead_code)]
pub async fn create_admin_account_and_login(client: &Client) -> (String, String) {
    create_account_and_login_internal(client, true).await
}

async fn create_account_and_login_internal(client: &Client, make_admin: bool) -> (String, String) {
    let mut last_error = String::new();
    for attempt in 0..3 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(100 * (attempt as u64 + 1))).await;
        }
        let handle = format!("u{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
        let payload = json!({
            "handle": handle,
            "email": format!("{}@example.com", handle),
            "password": "Testpass123!"
        });
        let res = match client
            .post(format!(
                "{}/xrpc/com.atproto.server.createAccount",
                base_url().await
            ))
            .json(&payload)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                last_error = format!("Request failed: {}", e);
                continue;
            }
        };
        if res.status() == StatusCode::OK {
            let body: Value = res.json().await.expect("Invalid JSON");
            let did = body["did"].as_str().expect("No did").to_string();
            let pool = get_test_db_pool().await;
            if make_admin {
                sqlx::query!("UPDATE users SET is_admin = TRUE WHERE did = $1", &did)
                    .execute(pool)
                    .await
                    .expect("Failed to mark user as admin");
            }
            let verification_required = body["verificationRequired"].as_bool().unwrap_or(true);
            if let Some(access_jwt) = body["accessJwt"].as_str() {
                if !verification_required {
                    return (access_jwt.to_string(), did);
                }
            }
            let body_text: String = sqlx::query_scalar!(
                "SELECT body FROM comms_queue WHERE user_id = (SELECT id FROM users WHERE did = $1) AND comms_type = 'email_verification' ORDER BY created_at DESC LIMIT 1",
                &did
            )
            .fetch_one(pool)
            .await
            .expect("Failed to get verification from comms_queue");
            let lines: Vec<&str> = body_text.lines().collect();
            let verification_code = lines
                .iter()
                .enumerate()
                .find(|(_, line)| {
                    line.contains("verification code is:") || line.contains("code is:")
                })
                .and_then(|(i, _)| lines.get(i + 1).map(|s| s.trim().to_string()))
                .or_else(|| {
                    body_text
                        .split_whitespace()
                        .find(|word| {
                            word.contains('-') && word.chars().filter(|c| *c == '-').count() >= 3
                        })
                        .map(|s| s.to_string())
                })
                .unwrap_or_else(|| body_text.clone());

            let confirm_payload = json!({
                "did": did,
                "verificationCode": verification_code
            });
            let confirm_res = client
                .post(format!(
                    "{}/xrpc/com.atproto.server.confirmSignup",
                    base_url().await
                ))
                .json(&confirm_payload)
                .send()
                .await
                .expect("confirmSignup request failed");
            if confirm_res.status() == StatusCode::OK {
                let confirm_body: Value = confirm_res
                    .json()
                    .await
                    .expect("Invalid JSON from confirmSignup");
                let access_jwt = confirm_body["accessJwt"]
                    .as_str()
                    .expect("No accessJwt in confirmSignup response")
                    .to_string();
                return (access_jwt, did);
            }
            last_error = format!("confirmSignup failed: {:?}", confirm_res.text().await);
            continue;
        }
        last_error = format!("Status {}: {:?}", res.status(), res.text().await);
    }
    panic!("Failed to create account after 3 attempts: {}", last_error);
}
