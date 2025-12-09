use aws_config::BehaviorVersion;
use aws_sdk_s3::Client as S3Client;
use aws_sdk_s3::config::Credentials;
use bspds::state::AppState;
use chrono::Utc;
use reqwest::{Client, StatusCode, header};
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
#[allow(unused_imports)]
use std::collections::HashMap;
use std::sync::OnceLock;
#[allow(unused_imports)]
use std::time::Duration;
use testcontainers::core::ContainerPort;
use testcontainers::{ContainerAsync, GenericImage, ImageExt, runners::AsyncRunner};
use testcontainers_modules::postgres::Postgres;
use tokio::net::TcpListener;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

static SERVER_URL: OnceLock<String> = OnceLock::new();
static DB_CONTAINER: OnceLock<ContainerAsync<Postgres>> = OnceLock::new();
static S3_CONTAINER: OnceLock<ContainerAsync<GenericImage>> = OnceLock::new();
static MOCK_APPVIEW: OnceLock<MockServer> = OnceLock::new();

#[allow(dead_code)]
pub const AUTH_TOKEN: &str = "test-token";
#[allow(dead_code)]
pub const BAD_AUTH_TOKEN: &str = "bad-token";
#[allow(dead_code)]
pub const AUTH_DID: &str = "did:plc:fake";
#[allow(dead_code)]
pub const TARGET_DID: &str = "did:plc:target";

#[cfg(test)]
#[ctor::dtor]
fn cleanup() {
    // my attempt to force clean up containers created by this test binary.
    // this is a fallback in case ryuk fails or is not supported
    if std::env::var("XDG_RUNTIME_DIR").is_ok() {
         let _ = std::process::Command::new("podman")
            .args(&["rm", "-f", "--filter", "label=bspds_test=true"])
            .output();
    }

    let _ = std::process::Command::new("docker")
        .args(&["container", "prune", "-f", "--filter", "label=bspds_test=true"])
        .output();
}

#[allow(dead_code)]
pub fn client() -> Client {
    Client::new()
}

pub async fn base_url() -> &'static str {
    SERVER_URL.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel();

        std::thread::spawn(move || {
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
                let s3_container = GenericImage::new("minio/minio", "latest")
                    .with_exposed_port(ContainerPort::Tcp(9000))
                    .with_env_var("MINIO_ROOT_USER", "minioadmin")
                    .with_env_var("MINIO_ROOT_PASSWORD", "minioadmin")
                    .with_cmd(vec!["server".to_string(), "/data".to_string()])
                    .with_label("bspds_test", "true")
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

                Mock::given(method("GET"))
                    .and(path("/xrpc/app.bsky.actor.getProfile"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                        "handle": "mock.handle",
                        "did": "did:plc:mock",
                        "displayName": "Mock User"
                    })))
                    .mount(&mock_server)
                    .await;

                Mock::given(method("GET"))
                    .and(path("/xrpc/app.bsky.actor.searchActors"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                        "actors": [],
                        "cursor": null
                    })))
                    .mount(&mock_server)
                    .await;

                unsafe {
                    std::env::set_var("APPVIEW_URL", mock_server.uri());
                }
                MOCK_APPVIEW.set(mock_server).ok();

                S3_CONTAINER.set(s3_container).ok();

                let container = Postgres::default()
                    .with_tag("18-alpine")
                    .with_label("bspds_test", "true")
                    .start()
                    .await
                    .expect("Failed to start Postgres");
                let connection_string = format!(
                    "postgres://postgres:postgres@127.0.0.1:{}/postgres",
                    container
                        .get_host_port_ipv4(5432)
                        .await
                        .expect("Failed to get port")
                );

                DB_CONTAINER.set(container).ok();

                let url = spawn_app(connection_string).await;
                tx.send(url).unwrap();
                std::future::pending::<()>().await;
            });
        });

        rx.recv().expect("Failed to start test server")
    })
}

async fn spawn_app(database_url: String) -> String {
    let pool = PgPoolOptions::new()
        .max_connections(50)
        .connect(&database_url)
        .await
        .expect("Failed to connect to Postgres. Make sure the database is running.");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    unsafe {
        std::env::set_var("PDS_HOSTNAME", addr.to_string());
    }

    let state = AppState::new(pool).await;
    let app = bspds::app(state);

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    format!("http://{}", addr)
}

#[allow(dead_code)]
pub async fn get_db_connection_string() -> String {
    base_url().await;
    let container = DB_CONTAINER.get().expect("DB container not initialized");
    let port = container.get_host_port_ipv4(5432).await.expect("Failed to get port");
    format!("postgres://postgres:postgres@127.0.0.1:{}/postgres", port)
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
    let mut last_error = String::new();

    for attempt in 0..3 {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(100 * (attempt as u64 + 1))).await;
        }

        let handle = format!("user_{}", uuid::Uuid::new_v4());
        let payload = json!({
            "handle": handle,
            "email": format!("{}@example.com", handle),
            "password": "password"
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
            let access_jwt = body["accessJwt"]
                .as_str()
                .expect("No accessJwt")
                .to_string();
            let did = body["did"].as_str().expect("No did").to_string();
            return (access_jwt, did);
        }

        last_error = format!("Status {}: {:?}", res.status(), res.text().await);
    }

    panic!("Failed to create account after 3 attempts: {}", last_error);
}
