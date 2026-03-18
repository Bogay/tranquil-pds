pub mod blob;
pub mod commit;
pub mod crawl;
pub mod deprecated;
pub mod listener;
pub mod repo;
pub mod subscribe_repos;

pub use blob::{get_blob, list_blobs};
pub use commit::{get_latest_commit, get_repo_status, list_repos};
pub use crawl::{notify_of_update, request_crawl};
pub use deprecated::{get_checkout, get_head};
pub use repo::{get_blocks, get_record, get_repo};
pub use subscribe_repos::subscribe_repos;

use tranquil_pds::state::AppState;

pub fn sync_routes() -> axum::Router<AppState> {
    use axum::routing::{get, post};

    axum::Router::new()
        .route("/com.atproto.sync.getLatestCommit", get(get_latest_commit))
        .route("/com.atproto.sync.listRepos", get(list_repos))
        .route("/com.atproto.sync.getBlob", get(get_blob))
        .route("/com.atproto.sync.listBlobs", get(list_blobs))
        .route("/com.atproto.sync.getRepoStatus", get(get_repo_status))
        .route("/com.atproto.sync.notifyOfUpdate", post(notify_of_update))
        .route("/com.atproto.sync.requestCrawl", post(request_crawl))
        .route("/com.atproto.sync.getBlocks", get(get_blocks))
        .route("/com.atproto.sync.getRepo", get(get_repo))
        .route("/com.atproto.sync.getRecord", get(get_record))
        .route("/com.atproto.sync.subscribeRepos", get(subscribe_repos))
        .route("/com.atproto.sync.getHead", get(get_head))
        .route("/com.atproto.sync.getCheckout", get(get_checkout))
}
