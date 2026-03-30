mod common;
mod helpers;

use std::sync::Arc;
use tranquil_db::PostgresRepositories;
use tranquil_db_traits::{Backlink, BacklinkPath, CommsChannel, CommsType};
use tranquil_types::{AtUri, CidLink, Did, Handle, Nsid, Rkey};
use uuid::Uuid;

async fn create_store_repos() -> Arc<PostgresRepositories> {
    let temp_dir = std::env::temp_dir().join(format!("tranquil-parity-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).expect("failed to create parity temp dir");

    let metastore_dir = temp_dir.join("metastore");
    let segments_dir = temp_dir.join("eventlog/segments");
    let bs_data = temp_dir.join("blockstore/data");
    let bs_index = temp_dir.join("blockstore/index");
    std::fs::create_dir_all(&metastore_dir).unwrap();
    std::fs::create_dir_all(&segments_dir).unwrap();
    std::fs::create_dir_all(&bs_data).unwrap();
    std::fs::create_dir_all(&bs_index).unwrap();

    use tranquil_store::RealIO;
    use tranquil_store::blockstore::{BlockStoreConfig, TranquilBlockStore};
    use tranquil_store::eventlog::{EventLog, EventLogBridge, EventLogConfig};
    use tranquil_store::metastore::client::MetastoreClient;
    use tranquil_store::metastore::handler::HandlerPool;
    use tranquil_store::metastore::partitions::Partition;
    use tranquil_store::metastore::{Metastore, MetastoreConfig};

    let metastore =
        Metastore::open(&metastore_dir, MetastoreConfig::default()).expect("metastore open");

    let blockstore = TranquilBlockStore::open(BlockStoreConfig {
        data_dir: bs_data,
        index_dir: bs_index,
        max_file_size: tranquil_store::blockstore::DEFAULT_MAX_FILE_SIZE,
        group_commit: Default::default(),
        shard_count: 1,
    })
    .expect("blockstore open");

    let event_log = Arc::new(
        EventLog::open(
            EventLogConfig {
                segments_dir,
                ..EventLogConfig::default()
            },
            RealIO::new(),
        )
        .expect("eventlog open"),
    );

    let bridge = Arc::new(EventLogBridge::new(Arc::clone(&event_log)));
    let indexes = metastore.partition(Partition::Indexes).clone();
    let event_ops = metastore.event_ops(Arc::clone(&bridge));
    event_ops
        .recover_metastore_mutations(&indexes)
        .expect("metastore mutation recovery failed");

    let notifier = bridge.notifier();

    let pool = Arc::new(HandlerPool::spawn::<RealIO>(
        metastore,
        bridge,
        Some(blockstore),
        Some(2),
    ));

    let client = MetastoreClient::<RealIO>::new(pool, Arc::clone(&event_log));

    Arc::new(PostgresRepositories {
        pool: None,
        repo: Arc::new(client.clone()),
        backlink: Arc::new(client.clone()),
        blob: Arc::new(client.clone()),
        user: Arc::new(client.clone()),
        session: Arc::new(client.clone()),
        oauth: Arc::new(client.clone()),
        infra: Arc::new(client.clone()),
        delegation: Arc::new(client.clone()),
        sso: Arc::new(client),
        event_notifier: Arc::new(notifier),
    })
}

async fn create_pg_repos() -> Arc<PostgresRepositories> {
    let db_url = common::get_db_connection_string().await;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .expect("failed to connect for parity test");
    Arc::new(PostgresRepositories::new(pool))
}

struct ParityFixture {
    pg: Arc<PostgresRepositories>,
    store: Arc<PostgresRepositories>,
}

impl ParityFixture {
    async fn new() -> Self {
        Self {
            pg: create_pg_repos().await,
            store: create_store_repos().await,
        }
    }
}

fn test_did(suffix: &str) -> Did {
    Did::new(format!("did:plc:parity{suffix}")).unwrap()
}

fn test_handle(suffix: &str) -> Handle {
    Handle::new(format!("parity-{suffix}.test")).unwrap()
}

fn test_cid(seed: u8) -> CidLink {
    CidLink::from(helpers::make_cid(&[seed]))
}

fn test_nsid(name: &str) -> Nsid {
    Nsid::new(format!("app.bsky.feed.{name}")).unwrap()
}

fn test_rkey(s: &str) -> Rkey {
    Rkey::new(s).unwrap()
}

fn test_at_uri(did: &Did, collection: &Nsid, rkey: &Rkey) -> AtUri {
    AtUri::new(format!(
        "at://{}/{}/{}",
        did.as_str(),
        collection.as_str(),
        rkey.as_str()
    ))
    .unwrap()
}

async fn seed_user(repos: &PostgresRepositories, did: &Did, handle: &Handle) -> Uuid {
    let commit_cid = helpers::make_cid(did.as_str().as_bytes()).to_string();
    let input = tranquil_db_traits::CreatePasswordAccountInput {
        handle: handle.clone(),
        email: None,
        did: did.clone(),
        password_hash: "parity-test-hash".to_string(),
        preferred_comms_channel: CommsChannel::Email,
        discord_username: None,
        telegram_username: None,
        signal_username: None,
        deactivated_at: None,
        encrypted_key_bytes: vec![0u8; 32],
        encryption_version: 0,
        reserved_key_id: None,
        commit_cid,
        repo_rev: "rev0".to_string(),
        genesis_block_cids: vec![],
        invite_code: None,
        birthdate_pref: None,
    };
    repos
        .user
        .create_password_account(&input)
        .await
        .unwrap()
        .user_id
}

async fn seed_repos(f: &ParityFixture, did: &Did, handle: &Handle) -> (Uuid, Uuid) {
    let pg_uid = seed_user(&f.pg, did, handle).await;
    let store_uid = seed_user(&f.store, did, handle).await;
    (pg_uid, store_uid)
}

async fn seed_records(
    repos: &PostgresRepositories,
    repo_id: Uuid,
    collection: &Nsid,
    records: &[(Rkey, CidLink)],
) {
    let collections: Vec<Nsid> = records.iter().map(|_| collection.clone()).collect();
    let rkeys: Vec<Rkey> = records.iter().map(|(r, _)| r.clone()).collect();
    let cids: Vec<CidLink> = records.iter().map(|(_, c)| c.clone()).collect();
    repos
        .repo
        .upsert_records(repo_id, &collections, &rkeys, &cids, "rev1")
        .await
        .unwrap();
}

#[tokio::test]
async fn parity_server_config() {
    let f = ParityFixture::new().await;

    f.pg.infra
        .upsert_server_config("parity_key", "parity_value")
        .await
        .unwrap();
    f.store
        .infra
        .upsert_server_config("parity_key", "parity_value")
        .await
        .unwrap();

    let pg_val = f.pg.infra.get_server_config("parity_key").await.unwrap();
    let store_val = f.store.infra.get_server_config("parity_key").await.unwrap();
    assert_eq!(pg_val, store_val);

    f.pg.infra.delete_server_config("parity_key").await.unwrap();
    f.store
        .infra
        .delete_server_config("parity_key")
        .await
        .unwrap();

    let pg_gone = f.pg.infra.get_server_config("parity_key").await.unwrap();
    let store_gone = f.store.infra.get_server_config("parity_key").await.unwrap();
    assert_eq!(pg_gone, None);
    assert_eq!(store_gone, None);
}

#[tokio::test]
async fn parity_health_check() {
    let f = ParityFixture::new().await;

    let pg_health = f.pg.infra.health_check().await.unwrap();
    let store_health = f.store.infra.health_check().await.unwrap();
    assert!(pg_health);
    assert!(store_health);
}

#[tokio::test]
async fn parity_rkey_sort_order() {
    let f = ParityFixture::new().await;
    let did = test_did("rkey");
    let handle = test_handle("rkey");
    let collection = test_nsid("post");

    let (pg_uid, store_uid) = seed_repos(&f, &did, &handle).await;

    let records: Vec<(Rkey, CidLink)> = (0u8..10)
        .map(|i| {
            let rkey = test_rkey(&format!("3l{i}aaaaaaaa{i}"));
            let cid = test_cid(i + 1);
            (rkey, cid)
        })
        .collect();

    seed_records(&f.pg, pg_uid, &collection, &records).await;
    seed_records(&f.store, store_uid, &collection, &records).await;

    let pg_fwd =
        f.pg.repo
            .list_records(pg_uid, &collection, None, 100, false, None, None)
            .await
            .unwrap();
    let store_fwd = f
        .store
        .repo
        .list_records(store_uid, &collection, None, 100, false, None, None)
        .await
        .unwrap();

    let pg_rkeys: Vec<&str> = pg_fwd.iter().map(|r| r.rkey.as_str()).collect();
    let store_rkeys: Vec<&str> = store_fwd.iter().map(|r| r.rkey.as_str()).collect();
    assert_eq!(pg_rkeys, store_rkeys, "forward rkey order mismatch");

    let pg_rev =
        f.pg.repo
            .list_records(pg_uid, &collection, None, 100, true, None, None)
            .await
            .unwrap();
    let store_rev = f
        .store
        .repo
        .list_records(store_uid, &collection, None, 100, true, None, None)
        .await
        .unwrap();

    let pg_rkeys_rev: Vec<&str> = pg_rev.iter().map(|r| r.rkey.as_str()).collect();
    let store_rkeys_rev: Vec<&str> = store_rev.iter().map(|r| r.rkey.as_str()).collect();
    assert_eq!(pg_rkeys_rev, store_rkeys_rev, "reverse rkey order mismatch");

    let pg_cids: Vec<&str> = pg_fwd.iter().map(|r| r.record_cid.as_str()).collect();
    let store_cids: Vec<&str> = store_fwd.iter().map(|r| r.record_cid.as_str()).collect();
    assert_eq!(pg_cids, store_cids, "cid mapping mismatch");
}

#[tokio::test]
async fn parity_cursor_pagination() {
    let f = ParityFixture::new().await;
    let did = test_did("cursor");
    let handle = test_handle("cursor");
    let collection = test_nsid("post");

    let (pg_uid, store_uid) = seed_repos(&f, &did, &handle).await;

    let records: Vec<(Rkey, CidLink)> = (0u8..20)
        .map(|i| {
            let rkey = test_rkey(&format!("3l{:02}aaaaaaaaa", i));
            let cid = test_cid(i + 1);
            (rkey, cid)
        })
        .collect();

    seed_records(&f.pg, pg_uid, &collection, &records).await;
    seed_records(&f.store, store_uid, &collection, &records).await;

    let mut pg_all = Vec::new();
    let mut store_all = Vec::new();
    let mut pg_cursor: Option<Rkey> = None;
    let mut store_cursor: Option<Rkey> = None;
    let limit = 5i64;
    let mut pages = 0;

    loop {
        let pg_page =
            f.pg.repo
                .list_records(
                    pg_uid,
                    &collection,
                    pg_cursor.as_ref(),
                    limit,
                    false,
                    None,
                    None,
                )
                .await
                .unwrap();
        let store_page = f
            .store
            .repo
            .list_records(
                store_uid,
                &collection,
                store_cursor.as_ref(),
                limit,
                false,
                None,
                None,
            )
            .await
            .unwrap();

        assert_eq!(
            pg_page.len(),
            store_page.len(),
            "page size mismatch at page {pages}"
        );

        let pg_rkeys: Vec<&str> = pg_page.iter().map(|r| r.rkey.as_str()).collect();
        let store_rkeys: Vec<&str> = store_page.iter().map(|r| r.rkey.as_str()).collect();
        assert_eq!(
            pg_rkeys, store_rkeys,
            "page content mismatch at page {pages}"
        );

        pg_all.extend(pg_page.iter().map(|r| r.rkey.clone()));
        store_all.extend(store_page.iter().map(|r| r.rkey.clone()));

        if pg_page.len() < limit as usize {
            break;
        }

        pg_cursor = pg_page.last().map(|r| r.rkey.clone());
        store_cursor = store_page.last().map(|r| r.rkey.clone());
        pages += 1;
    }

    assert_eq!(pg_all.len(), 20);
    assert_eq!(store_all.len(), 20);
}

#[tokio::test]
async fn parity_cursor_pagination_reverse() {
    let f = ParityFixture::new().await;
    let did = test_did("currev");
    let handle = test_handle("currev");
    let collection = test_nsid("post");

    let (pg_uid, store_uid) = seed_repos(&f, &did, &handle).await;

    let records: Vec<(Rkey, CidLink)> = (0u8..15)
        .map(|i| {
            let rkey = test_rkey(&format!("3l{:02}aaaaaaaaa", i));
            let cid = test_cid(i + 1);
            (rkey, cid)
        })
        .collect();

    seed_records(&f.pg, pg_uid, &collection, &records).await;
    seed_records(&f.store, store_uid, &collection, &records).await;

    let mut pg_all = Vec::new();
    let mut store_all = Vec::new();
    let mut pg_cursor: Option<Rkey> = None;
    let mut store_cursor: Option<Rkey> = None;
    let limit = 4i64;

    loop {
        let pg_page =
            f.pg.repo
                .list_records(
                    pg_uid,
                    &collection,
                    pg_cursor.as_ref(),
                    limit,
                    true,
                    None,
                    None,
                )
                .await
                .unwrap();
        let store_page = f
            .store
            .repo
            .list_records(
                store_uid,
                &collection,
                store_cursor.as_ref(),
                limit,
                true,
                None,
                None,
            )
            .await
            .unwrap();

        let pg_rkeys: Vec<&str> = pg_page.iter().map(|r| r.rkey.as_str()).collect();
        let store_rkeys: Vec<&str> = store_page.iter().map(|r| r.rkey.as_str()).collect();
        assert_eq!(pg_rkeys, store_rkeys, "reverse page mismatch");

        pg_all.extend(pg_page.iter().map(|r| r.rkey.clone()));
        store_all.extend(store_page.iter().map(|r| r.rkey.clone()));

        if pg_page.len() < limit as usize {
            break;
        }

        pg_cursor = pg_page.last().map(|r| r.rkey.clone());
        store_cursor = store_page.last().map(|r| r.rkey.clone());
    }

    assert_eq!(pg_all.len(), 15);
    assert_eq!(store_all.len(), 15);
}

#[tokio::test]
async fn parity_rkey_range_query() {
    let f = ParityFixture::new().await;
    let did = test_did("range");
    let handle = test_handle("range");
    let collection = test_nsid("post");

    let (pg_uid, store_uid) = seed_repos(&f, &did, &handle).await;

    let records: Vec<(Rkey, CidLink)> = (0u8..10)
        .map(|i| {
            let rkey = test_rkey(&format!("3l{:02}aaaaaaaaa", i));
            let cid = test_cid(i + 1);
            (rkey, cid)
        })
        .collect();

    seed_records(&f.pg, pg_uid, &collection, &records).await;
    seed_records(&f.store, store_uid, &collection, &records).await;

    let start = test_rkey("3l03aaaaaaaaa");
    let end = test_rkey("3l07aaaaaaaaa");

    let pg_range =
        f.pg.repo
            .list_records(
                pg_uid,
                &collection,
                None,
                100,
                false,
                Some(&start),
                Some(&end),
            )
            .await
            .unwrap();
    let store_range = f
        .store
        .repo
        .list_records(
            store_uid,
            &collection,
            None,
            100,
            false,
            Some(&start),
            Some(&end),
        )
        .await
        .unwrap();

    let pg_rkeys: Vec<&str> = pg_range.iter().map(|r| r.rkey.as_str()).collect();
    let store_rkeys: Vec<&str> = store_range.iter().map(|r| r.rkey.as_str()).collect();
    assert_eq!(pg_rkeys, store_rkeys, "range query mismatch");
}

#[tokio::test]
async fn parity_collection_listing() {
    let f = ParityFixture::new().await;
    let did = test_did("colls");
    let handle = test_handle("colls");

    let (pg_uid, store_uid) = seed_repos(&f, &did, &handle).await;

    let post_ns = test_nsid("post");
    let like_ns = Nsid::new("app.bsky.feed.like").unwrap();
    let repost_ns = Nsid::new("app.bsky.feed.repost").unwrap();
    let follow_ns = Nsid::new("app.bsky.graph.follow").unwrap();

    let post_records = vec![(test_rkey("3laaaaaaaaa01"), test_cid(1))];
    let like_records = vec![(test_rkey("3laaaaaaaaa02"), test_cid(2))];
    let repost_records = vec![(test_rkey("3laaaaaaaaa03"), test_cid(3))];
    let follow_records = vec![(test_rkey("3laaaaaaaaa04"), test_cid(4))];

    seed_records(&f.pg, pg_uid, &post_ns, &post_records).await;
    seed_records(&f.pg, pg_uid, &like_ns, &like_records).await;
    seed_records(&f.pg, pg_uid, &repost_ns, &repost_records).await;
    seed_records(&f.pg, pg_uid, &follow_ns, &follow_records).await;

    seed_records(&f.store, store_uid, &post_ns, &post_records).await;
    seed_records(&f.store, store_uid, &like_ns, &like_records).await;
    seed_records(&f.store, store_uid, &repost_ns, &repost_records).await;
    seed_records(&f.store, store_uid, &follow_ns, &follow_records).await;

    let mut pg_colls: Vec<String> =
        f.pg.repo
            .list_collections(pg_uid)
            .await
            .unwrap()
            .into_iter()
            .map(|n| n.as_str().to_owned())
            .collect();
    pg_colls.sort();

    let mut store_colls: Vec<String> = f
        .store
        .repo
        .list_collections(store_uid)
        .await
        .unwrap()
        .into_iter()
        .map(|n| n.as_str().to_owned())
        .collect();
    store_colls.sort();

    assert_eq!(pg_colls, store_colls, "collection listing mismatch");
    assert_eq!(pg_colls.len(), 4);

    let pg_count = f.pg.repo.count_records(pg_uid).await.unwrap();
    let store_count = f.store.repo.count_records(store_uid).await.unwrap();
    assert_eq!(pg_count, store_count, "record count mismatch");
    assert_eq!(pg_count, 4);
}

#[tokio::test]
async fn parity_record_get_and_delete() {
    let f = ParityFixture::new().await;
    let did = test_did("getdel");
    let handle = test_handle("getdel");
    let collection = test_nsid("post");
    let rkey = test_rkey("3laaaaaaaaa01");
    let cid = test_cid(1);

    let (pg_uid, store_uid) = seed_repos(&f, &did, &handle).await;

    seed_records(&f.pg, pg_uid, &collection, &[(rkey.clone(), cid.clone())]).await;
    seed_records(
        &f.store,
        store_uid,
        &collection,
        &[(rkey.clone(), cid.clone())],
    )
    .await;

    let pg_cid =
        f.pg.repo
            .get_record_cid(pg_uid, &collection, &rkey)
            .await
            .unwrap();
    let store_cid = f
        .store
        .repo
        .get_record_cid(store_uid, &collection, &rkey)
        .await
        .unwrap();
    assert_eq!(pg_cid, store_cid, "get_record_cid mismatch");
    assert!(pg_cid.is_some());

    f.pg.repo
        .delete_records(
            pg_uid,
            std::slice::from_ref(&collection),
            std::slice::from_ref(&rkey),
        )
        .await
        .unwrap();
    f.store
        .repo
        .delete_records(
            store_uid,
            std::slice::from_ref(&collection),
            std::slice::from_ref(&rkey),
        )
        .await
        .unwrap();

    let pg_gone =
        f.pg.repo
            .get_record_cid(pg_uid, &collection, &rkey)
            .await
            .unwrap();
    let store_gone = f
        .store
        .repo
        .get_record_cid(store_uid, &collection, &rkey)
        .await
        .unwrap();
    assert_eq!(pg_gone, None);
    assert_eq!(store_gone, None);
}

#[tokio::test]
async fn parity_backlink_queries() {
    let f = ParityFixture::new().await;
    let did = test_did("blink");
    let handle = test_handle("blink");
    let like_ns = Nsid::new("app.bsky.feed.like").unwrap();
    let target_did = test_did("target");

    let (pg_uid, store_uid) = seed_repos(&f, &did, &handle).await;

    let rkey1 = test_rkey("3laaaaaaaaa01");
    let rkey2 = test_rkey("3laaaaaaaaa02");
    let uri1 = test_at_uri(&did, &like_ns, &rkey1);
    let uri2 = test_at_uri(&did, &like_ns, &rkey2);
    let target_uri = format!(
        "at://{}/app.bsky.feed.post/3laaaaaaaaa99",
        target_did.as_str()
    );

    let backlinks = vec![
        Backlink {
            uri: uri1.clone(),
            path: BacklinkPath::Subject,
            link_to: target_uri.clone(),
        },
        Backlink {
            uri: uri2.clone(),
            path: BacklinkPath::Subject,
            link_to: target_uri.clone(),
        },
    ];

    f.pg.backlink
        .add_backlinks(pg_uid, &backlinks)
        .await
        .unwrap();
    f.store
        .backlink
        .add_backlinks(store_uid, &backlinks)
        .await
        .unwrap();

    let conflict_backlink = Backlink {
        uri: uri1.clone(),
        path: BacklinkPath::Subject,
        link_to: target_uri.clone(),
    };

    let pg_conflicts =
        f.pg.backlink
            .get_backlink_conflicts(pg_uid, &like_ns, std::slice::from_ref(&conflict_backlink))
            .await
            .unwrap();
    let store_conflicts = f
        .store
        .backlink
        .get_backlink_conflicts(store_uid, &like_ns, &[conflict_backlink])
        .await
        .unwrap();

    assert_eq!(
        pg_conflicts.len(),
        store_conflicts.len(),
        "backlink conflict count mismatch"
    );

    f.pg.backlink.remove_backlinks_by_uri(&uri1).await.unwrap();
    f.store
        .backlink
        .remove_backlinks_by_uri(&uri1)
        .await
        .unwrap();

    let post_removal = Backlink {
        uri: uri1.clone(),
        path: BacklinkPath::Subject,
        link_to: target_uri.clone(),
    };

    let pg_after =
        f.pg.backlink
            .get_backlink_conflicts(pg_uid, &like_ns, std::slice::from_ref(&post_removal))
            .await
            .unwrap();
    let store_after = f
        .store
        .backlink
        .get_backlink_conflicts(store_uid, &like_ns, &[post_removal])
        .await
        .unwrap();

    assert_eq!(
        pg_after.len(),
        store_after.len(),
        "backlink conflicts after removal mismatch"
    );
}

#[tokio::test]
async fn parity_backlink_remove_by_repo() {
    let f = ParityFixture::new().await;
    let did = test_did("blrep");
    let handle = test_handle("blrep");
    let like_ns = Nsid::new("app.bsky.feed.like").unwrap();

    let (pg_uid, store_uid) = seed_repos(&f, &did, &handle).await;

    let rkey = test_rkey("3laaaaaaaaa01");
    let uri = test_at_uri(&did, &like_ns, &rkey);
    let backlinks = vec![Backlink {
        uri: uri.clone(),
        path: BacklinkPath::Subject,
        link_to: "at://did:plc:sometarget/app.bsky.feed.post/abc".to_owned(),
    }];

    f.pg.backlink
        .add_backlinks(pg_uid, &backlinks)
        .await
        .unwrap();
    f.store
        .backlink
        .add_backlinks(store_uid, &backlinks)
        .await
        .unwrap();

    f.pg.backlink
        .remove_backlinks_by_repo(pg_uid)
        .await
        .unwrap();
    f.store
        .backlink
        .remove_backlinks_by_repo(store_uid)
        .await
        .unwrap();

    let probe = Backlink {
        uri,
        path: BacklinkPath::Subject,
        link_to: "at://did:plc:sometarget/app.bsky.feed.post/abc".to_owned(),
    };
    let pg_after =
        f.pg.backlink
            .get_backlink_conflicts(pg_uid, &like_ns, std::slice::from_ref(&probe))
            .await
            .unwrap();
    let store_after = f
        .store
        .backlink
        .get_backlink_conflicts(store_uid, &like_ns, &[probe])
        .await
        .unwrap();
    assert_eq!(pg_after.len(), 0);
    assert_eq!(store_after.len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn parity_blob_metadata() {
    let f = ParityFixture::new().await;
    let did = test_did("blob");
    let handle = test_handle("blob");

    let (pg_uid, store_uid) = seed_repos(&f, &did, &handle).await;

    let blob_cid1 = test_cid(101);
    let blob_cid2 = test_cid(102);
    let blob_cid3 = test_cid(103);

    let blobs = [
        (&blob_cid1, "image/png", 1024i64, "blobs/a.png"),
        (&blob_cid2, "image/jpeg", 2048, "blobs/b.jpg"),
        (&blob_cid3, "application/pdf", 4096, "blobs/c.pdf"),
    ];

    blobs.iter().for_each(|(cid, mime, size, key)| {
        let pg = Arc::clone(&f.pg);
        let store = Arc::clone(&f.store);
        let cid = (*cid).clone();
        let size = *size;
        let mime = mime.to_string();
        let key = key.to_string();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                pg.blob
                    .insert_blob(&cid, &mime, size, pg_uid, &key)
                    .await
                    .unwrap();
                store
                    .blob
                    .insert_blob(&cid, &mime, size, store_uid, &key)
                    .await
                    .unwrap();
            });
        });
    });

    let pg_meta =
        f.pg.blob
            .get_blob_metadata(&blob_cid1)
            .await
            .unwrap()
            .unwrap();
    let store_meta = f
        .store
        .blob
        .get_blob_metadata(&blob_cid1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pg_meta.mime_type, store_meta.mime_type);
    assert_eq!(pg_meta.size_bytes, store_meta.size_bytes);
    assert_eq!(pg_meta.storage_key, store_meta.storage_key);

    let pg_key = f.pg.blob.get_blob_storage_key(&blob_cid2).await.unwrap();
    let store_key = f.store.blob.get_blob_storage_key(&blob_cid2).await.unwrap();
    assert_eq!(pg_key, store_key);

    let pg_count = f.pg.blob.count_blobs_by_user(pg_uid).await.unwrap();
    let store_count = f.store.blob.count_blobs_by_user(store_uid).await.unwrap();
    assert_eq!(pg_count, store_count);
    assert_eq!(pg_count, 3);

    let pg_list =
        f.pg.blob
            .list_blobs_by_user(pg_uid, None, 100)
            .await
            .unwrap();
    let store_list = f
        .store
        .blob
        .list_blobs_by_user(store_uid, None, 100)
        .await
        .unwrap();
    assert_eq!(pg_list.len(), store_list.len());
}

#[tokio::test(flavor = "multi_thread")]
async fn parity_blob_pagination() {
    let f = ParityFixture::new().await;
    let did = test_did("blobpg");
    let handle = test_handle("blobpg");

    let (pg_uid, store_uid) = seed_repos(&f, &did, &handle).await;

    (0u8..8).for_each(|i| {
        let cid = test_cid(200 + i);
        let key = format!("blobs/pg_{i}.bin");
        let pg = Arc::clone(&f.pg);
        let store = Arc::clone(&f.store);
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                pg.blob
                    .insert_blob(
                        &cid,
                        "application/octet-stream",
                        512 * (i as i64 + 1),
                        pg_uid,
                        &key,
                    )
                    .await
                    .unwrap();
                store
                    .blob
                    .insert_blob(
                        &cid,
                        "application/octet-stream",
                        512 * (i as i64 + 1),
                        store_uid,
                        &key,
                    )
                    .await
                    .unwrap();
            });
        });
    });

    let mut pg_all = Vec::new();
    let mut store_all = Vec::new();
    let mut pg_cursor: Option<String> = None;
    let mut store_cursor: Option<String> = None;
    let limit = 3i64;

    loop {
        let pg_page =
            f.pg.blob
                .list_blobs_by_user(pg_uid, pg_cursor.as_deref(), limit)
                .await
                .unwrap();
        let store_page = f
            .store
            .blob
            .list_blobs_by_user(store_uid, store_cursor.as_deref(), limit)
            .await
            .unwrap();

        assert_eq!(pg_page.len(), store_page.len(), "blob page size mismatch");

        let pg_cids: Vec<&str> = pg_page.iter().map(|c| c.as_str()).collect();
        let store_cids: Vec<&str> = store_page.iter().map(|c| c.as_str()).collect();
        assert_eq!(pg_cids, store_cids, "blob page content mismatch");

        pg_all.extend(pg_page.iter().map(|c| c.as_str().to_owned()));
        store_all.extend(store_page.iter().map(|c| c.as_str().to_owned()));

        if pg_page.len() < limit as usize {
            break;
        }

        pg_cursor = pg_page.last().map(|c| c.as_str().to_owned());
        store_cursor = store_page.last().map(|c| c.as_str().to_owned());
    }

    assert_eq!(pg_all.len(), 8);
    assert_eq!(store_all.len(), 8);
}

#[tokio::test]
async fn parity_blob_duplicate_insert() {
    let f = ParityFixture::new().await;
    let did = test_did("blobdup");
    let handle = test_handle("blobdup");

    let (pg_uid, store_uid) = seed_repos(&f, &did, &handle).await;

    let cid = test_cid(150);

    let pg_first =
        f.pg.blob
            .insert_blob(&cid, "image/png", 1024, pg_uid, "blobs/dup.png")
            .await
            .unwrap();
    let store_first = f
        .store
        .blob
        .insert_blob(&cid, "image/png", 1024, store_uid, "blobs/dup.png")
        .await
        .unwrap();
    assert_eq!(pg_first, store_first);

    let pg_dup =
        f.pg.blob
            .insert_blob(&cid, "image/png", 1024, pg_uid, "blobs/dup.png")
            .await
            .unwrap();
    let store_dup = f
        .store
        .blob
        .insert_blob(&cid, "image/png", 1024, store_uid, "blobs/dup.png")
        .await
        .unwrap();
    assert_eq!(pg_dup, store_dup);
}

#[tokio::test]
async fn parity_get_all_records() {
    let f = ParityFixture::new().await;
    let did = test_did("allrec");
    let handle = test_handle("allrec");

    let (pg_uid, store_uid) = seed_repos(&f, &did, &handle).await;

    let post_ns = test_nsid("post");
    let like_ns = Nsid::new("app.bsky.feed.like").unwrap();

    let posts = vec![
        (test_rkey("3laaaaaaaaa01"), test_cid(1)),
        (test_rkey("3laaaaaaaaa02"), test_cid(2)),
    ];
    let likes = vec![(test_rkey("3laaaaaaaaa03"), test_cid(3))];

    seed_records(&f.pg, pg_uid, &post_ns, &posts).await;
    seed_records(&f.pg, pg_uid, &like_ns, &likes).await;
    seed_records(&f.store, store_uid, &post_ns, &posts).await;
    seed_records(&f.store, store_uid, &like_ns, &likes).await;

    let mut pg_all = f.pg.repo.get_all_records(pg_uid).await.unwrap();
    let mut store_all = f.store.repo.get_all_records(store_uid).await.unwrap();

    pg_all.sort_by(|a, b| {
        a.collection
            .as_str()
            .cmp(b.collection.as_str())
            .then(a.rkey.as_str().cmp(b.rkey.as_str()))
    });
    store_all.sort_by(|a, b| {
        a.collection
            .as_str()
            .cmp(b.collection.as_str())
            .then(a.rkey.as_str().cmp(b.rkey.as_str()))
    });

    assert_eq!(pg_all.len(), store_all.len());
    pg_all.iter().zip(store_all.iter()).for_each(|(p, s)| {
        assert_eq!(p.collection.as_str(), s.collection.as_str());
        assert_eq!(p.rkey.as_str(), s.rkey.as_str());
        assert_eq!(p.record_cid.as_str(), s.record_cid.as_str());
    });
}

#[tokio::test]
async fn parity_comms_queue() {
    let f = ParityFixture::new().await;
    let did = test_did("comms");
    let handle = test_handle("comms");
    let (pg_uid, store_uid) = seed_repos(&f, &did, &handle).await;

    let pg_id =
        f.pg.infra
            .enqueue_comms(
                Some(pg_uid),
                CommsChannel::Email,
                CommsType::Welcome,
                "test@example.com",
                Some("Welcome"),
                "Welcome body",
                None,
            )
            .await
            .unwrap();

    let store_id = f
        .store
        .infra
        .enqueue_comms(
            Some(store_uid),
            CommsChannel::Email,
            CommsType::Welcome,
            "test@example.com",
            Some("Welcome"),
            "Welcome body",
            None,
        )
        .await
        .unwrap();

    assert_ne!(pg_id, Uuid::nil());
    assert_ne!(store_id, Uuid::nil());

    let pg_latest =
        f.pg.infra
            .get_latest_comms_for_user(pg_uid, CommsType::Welcome, 10)
            .await
            .unwrap();
    let store_latest = f
        .store
        .infra
        .get_latest_comms_for_user(store_uid, CommsType::Welcome, 10)
        .await
        .unwrap();

    assert_eq!(pg_latest.len(), store_latest.len());
    assert_eq!(pg_latest[0].body, store_latest[0].body);

    let pg_count =
        f.pg.infra
            .count_comms_by_type(pg_uid, CommsType::Welcome)
            .await
            .unwrap();
    let store_count = f
        .store
        .infra
        .count_comms_by_type(store_uid, CommsType::Welcome)
        .await
        .unwrap();
    assert_eq!(pg_count, store_count);
    assert_eq!(pg_count, 1);
}

#[tokio::test]
async fn parity_invite_codes() {
    let f = ParityFixture::new().await;
    let did = test_did("invite");
    let handle = test_handle("invite");
    let _ = seed_repos(&f, &did, &handle).await;
    let code = format!("parity-invite-{}", Uuid::new_v4());

    let pg_created =
        f.pg.infra
            .create_invite_code(&code, 5, Some(&did))
            .await
            .unwrap();
    let store_created = f
        .store
        .infra
        .create_invite_code(&code, 5, Some(&did))
        .await
        .unwrap();
    assert_eq!(pg_created, store_created);

    let pg_uses =
        f.pg.infra
            .get_invite_code_available_uses(&code)
            .await
            .unwrap();
    let store_uses = f
        .store
        .infra
        .get_invite_code_available_uses(&code)
        .await
        .unwrap();
    assert_eq!(pg_uses, store_uses);
    assert_eq!(pg_uses, Some(5));
}

#[tokio::test]
async fn parity_account_preferences() {
    let f = ParityFixture::new().await;
    let did = test_did("prefs");
    let handle = test_handle("prefs");

    let (pg_uid, store_uid) = seed_repos(&f, &did, &handle).await;

    let pref_value = serde_json::json!({
        "$type": "app.bsky.actor.defs#adultContentPref",
        "enabled": false
    });

    f.pg.infra
        .upsert_account_preference(
            pg_uid,
            "app.bsky.actor.defs#adultContentPref/0",
            pref_value.clone(),
        )
        .await
        .unwrap();
    f.store
        .infra
        .upsert_account_preference(
            store_uid,
            "app.bsky.actor.defs#adultContentPref/0",
            pref_value,
        )
        .await
        .unwrap();

    let mut pg_prefs = f.pg.infra.get_account_preferences(pg_uid).await.unwrap();
    let mut store_prefs = f
        .store
        .infra
        .get_account_preferences(store_uid)
        .await
        .unwrap();

    pg_prefs.sort_by(|a, b| a.0.cmp(&b.0));
    store_prefs.sort_by(|a, b| a.0.cmp(&b.0));

    assert_eq!(pg_prefs.len(), store_prefs.len());
    pg_prefs.iter().zip(store_prefs.iter()).for_each(|(p, s)| {
        assert_eq!(p.0, s.0);
        assert_eq!(p.1, s.1);
    });
}

#[tokio::test]
async fn parity_record_upsert_overwrites() {
    let f = ParityFixture::new().await;
    let did = test_did("upsert");
    let handle = test_handle("upsert");
    let collection = test_nsid("post");
    let rkey = test_rkey("3laaaaaaaaa01");

    let (pg_uid, store_uid) = seed_repos(&f, &did, &handle).await;

    let cid_v1 = test_cid(1);
    seed_records(
        &f.pg,
        pg_uid,
        &collection,
        &[(rkey.clone(), cid_v1.clone())],
    )
    .await;
    seed_records(
        &f.store,
        store_uid,
        &collection,
        &[(rkey.clone(), cid_v1.clone())],
    )
    .await;

    let cid_v2 = test_cid(2);
    seed_records(
        &f.pg,
        pg_uid,
        &collection,
        &[(rkey.clone(), cid_v2.clone())],
    )
    .await;
    seed_records(
        &f.store,
        store_uid,
        &collection,
        &[(rkey.clone(), cid_v2.clone())],
    )
    .await;

    let pg_cid =
        f.pg.repo
            .get_record_cid(pg_uid, &collection, &rkey)
            .await
            .unwrap();
    let store_cid = f
        .store
        .repo
        .get_record_cid(store_uid, &collection, &rkey)
        .await
        .unwrap();
    assert_eq!(pg_cid, store_cid);
    assert_eq!(pg_cid.unwrap().as_str(), cid_v2.as_str());

    let pg_count = f.pg.repo.count_records(pg_uid).await.unwrap();
    let store_count = f.store.repo.count_records(store_uid).await.unwrap();
    assert_eq!(pg_count, 1);
    assert_eq!(store_count, 1);
}

#[tokio::test]
async fn parity_empty_queries() {
    let f = ParityFixture::new().await;
    let did = test_did("empty");
    let handle = test_handle("empty");
    let collection = test_nsid("post");

    let (pg_uid, store_uid) = seed_repos(&f, &did, &handle).await;

    let pg_records =
        f.pg.repo
            .list_records(pg_uid, &collection, None, 100, false, None, None)
            .await
            .unwrap();
    let store_records = f
        .store
        .repo
        .list_records(store_uid, &collection, None, 100, false, None, None)
        .await
        .unwrap();
    assert_eq!(pg_records.len(), 0);
    assert_eq!(store_records.len(), 0);

    let pg_colls = f.pg.repo.list_collections(pg_uid).await.unwrap();
    let store_colls = f.store.repo.list_collections(store_uid).await.unwrap();
    assert_eq!(pg_colls.len(), 0);
    assert_eq!(store_colls.len(), 0);

    let pg_count = f.pg.repo.count_records(pg_uid).await.unwrap();
    let store_count = f.store.repo.count_records(store_uid).await.unwrap();
    assert_eq!(pg_count, 0);
    assert_eq!(store_count, 0);

    let pg_blobs =
        f.pg.blob
            .list_blobs_by_user(pg_uid, None, 100)
            .await
            .unwrap();
    let store_blobs = f
        .store
        .blob
        .list_blobs_by_user(store_uid, None, 100)
        .await
        .unwrap();
    assert_eq!(pg_blobs.len(), 0);
    assert_eq!(store_blobs.len(), 0);

    let nonexistent_cid = test_cid(255);
    let pg_meta = f.pg.blob.get_blob_metadata(&nonexistent_cid).await.unwrap();
    let store_meta = f
        .store
        .blob
        .get_blob_metadata(&nonexistent_cid)
        .await
        .unwrap();
    assert_eq!(pg_meta.is_none(), store_meta.is_none());
}

#[tokio::test]
async fn parity_deletion_requests() {
    let f = ParityFixture::new().await;
    let did = test_did("delreq");
    let handle = test_handle("delreq");
    let _ = seed_repos(&f, &did, &handle).await;
    let token = format!("del-token-{}", Uuid::new_v4());
    let expires = chrono::Utc::now() + chrono::Duration::hours(24);

    f.pg.infra
        .create_deletion_request(&token, &did, expires)
        .await
        .unwrap();
    f.store
        .infra
        .create_deletion_request(&token, &did, expires)
        .await
        .unwrap();

    let pg_req = f.pg.infra.get_deletion_request(&token).await.unwrap();
    let store_req = f.store.infra.get_deletion_request(&token).await.unwrap();
    assert!(pg_req.is_some());
    assert!(store_req.is_some());
    assert_eq!(
        pg_req.as_ref().unwrap().did,
        store_req.as_ref().unwrap().did
    );

    let pg_by_did = f.pg.infra.get_deletion_request_by_did(&did).await.unwrap();
    let store_by_did = f
        .store
        .infra
        .get_deletion_request_by_did(&did)
        .await
        .unwrap();
    assert!(pg_by_did.is_some());
    assert!(store_by_did.is_some());
    assert_eq!(pg_by_did.unwrap().token, store_by_did.unwrap().token);

    f.pg.infra.delete_deletion_request(&token).await.unwrap();
    f.store.infra.delete_deletion_request(&token).await.unwrap();

    let pg_gone = f.pg.infra.get_deletion_request(&token).await.unwrap();
    let store_gone = f.store.infra.get_deletion_request(&token).await.unwrap();
    assert!(pg_gone.is_none());
    assert!(store_gone.is_none());
}

#[tokio::test]
async fn parity_signing_key_reservation() {
    let f = ParityFixture::new().await;
    let did = test_did("sigkey");
    let expires = chrono::Utc::now() + chrono::Duration::hours(1);
    let pub_key = format!("did:key:z6Mk{}", Uuid::new_v4().simple());
    let priv_bytes = vec![1u8, 2, 3, 4, 5, 6, 7, 8];

    f.pg.infra
        .reserve_signing_key(Some(&did), &pub_key, &priv_bytes, expires)
        .await
        .unwrap();
    f.store
        .infra
        .reserve_signing_key(Some(&did), &pub_key, &priv_bytes, expires)
        .await
        .unwrap();

    let pg_key = f.pg.infra.get_reserved_signing_key(&pub_key).await.unwrap();
    let store_key = f
        .store
        .infra
        .get_reserved_signing_key(&pub_key)
        .await
        .unwrap();
    assert!(pg_key.is_some());
    assert!(store_key.is_some());
    assert_eq!(
        pg_key.unwrap().private_key_bytes,
        store_key.unwrap().private_key_bytes
    );

    let pg_full =
        f.pg.infra
            .get_reserved_signing_key_full(&pub_key)
            .await
            .unwrap();
    let store_full = f
        .store
        .infra
        .get_reserved_signing_key_full(&pub_key)
        .await
        .unwrap();
    assert!(pg_full.is_some());
    assert!(store_full.is_some());
    let pg_f = pg_full.unwrap();
    let store_f = store_full.unwrap();
    assert_eq!(pg_f.public_key_did_key, store_f.public_key_did_key);
    assert_eq!(pg_f.did, store_f.did);
}

#[tokio::test]
async fn parity_repo_root_operations() {
    let f = ParityFixture::new().await;
    let did = test_did("root");
    let handle = test_handle("root");

    let (pg_uid, store_uid) = seed_repos(&f, &did, &handle).await;

    let pg_root = f.pg.repo.get_repo_root_by_did(&did).await.unwrap();
    let store_root = f.store.repo.get_repo_root_by_did(&did).await.unwrap();
    assert_eq!(pg_root, store_root);

    let new_root = test_cid(99);
    f.pg.repo
        .update_repo_root(pg_uid, &new_root, "rev1")
        .await
        .unwrap();
    f.store
        .repo
        .update_repo_root(store_uid, &new_root, "rev1")
        .await
        .unwrap();

    let pg_updated = f.pg.repo.get_repo_root_by_did(&did).await.unwrap();
    let store_updated = f.store.repo.get_repo_root_by_did(&did).await.unwrap();
    assert_eq!(pg_updated, store_updated);
    assert_eq!(pg_updated.unwrap().as_str(), new_root.as_str());

    let pg_info = f.pg.repo.get_repo(pg_uid).await.unwrap().unwrap();
    let store_info = f.store.repo.get_repo(store_uid).await.unwrap().unwrap();
    assert_eq!(pg_info.repo_rev, store_info.repo_rev);
    assert_eq!(
        pg_info.repo_root_cid.as_str(),
        store_info.repo_root_cid.as_str()
    );
}

#[tokio::test]
async fn parity_delete_all_records() {
    let f = ParityFixture::new().await;
    let did = test_did("delall");
    let handle = test_handle("delall");
    let collection = test_nsid("post");

    let (pg_uid, store_uid) = seed_repos(&f, &did, &handle).await;

    let records: Vec<(Rkey, CidLink)> = (0u8..5)
        .map(|i| (test_rkey(&format!("3l{:02}aaaaaaaaa", i)), test_cid(i + 1)))
        .collect();

    seed_records(&f.pg, pg_uid, &collection, &records).await;
    seed_records(&f.store, store_uid, &collection, &records).await;

    f.pg.repo.delete_all_records(pg_uid).await.unwrap();
    f.store.repo.delete_all_records(store_uid).await.unwrap();

    let pg_count = f.pg.repo.count_records(pg_uid).await.unwrap();
    let store_count = f.store.repo.count_records(store_uid).await.unwrap();
    assert_eq!(pg_count, 0);
    assert_eq!(store_count, 0);

    let pg_colls = f.pg.repo.list_collections(pg_uid).await.unwrap();
    let store_colls = f.store.repo.list_collections(store_uid).await.unwrap();
    assert_eq!(pg_colls.len(), 0);
    assert_eq!(store_colls.len(), 0);
}

#[tokio::test]
async fn parity_plc_tokens() {
    let f = ParityFixture::new().await;
    let did = test_did("plctok");
    let handle = test_handle("plctok");

    let (pg_uid, store_uid) = seed_repos(&f, &did, &handle).await;

    let token = format!("plc-{}", Uuid::new_v4());
    let expires = chrono::Utc::now() + chrono::Duration::hours(1);

    f.pg.infra
        .insert_plc_token(pg_uid, &token, expires)
        .await
        .unwrap();
    f.store
        .infra
        .insert_plc_token(store_uid, &token, expires)
        .await
        .unwrap();

    let pg_expiry =
        f.pg.infra
            .get_plc_token_expiry(pg_uid, &token)
            .await
            .unwrap();
    let store_expiry = f
        .store
        .infra
        .get_plc_token_expiry(store_uid, &token)
        .await
        .unwrap();
    assert!(pg_expiry.is_some());
    assert!(store_expiry.is_some());

    let pg_by_did = f.pg.infra.get_plc_tokens_by_did(&did).await.unwrap();
    let store_by_did = f.store.infra.get_plc_tokens_by_did(&did).await.unwrap();
    assert_eq!(pg_by_did.len(), store_by_did.len());

    let pg_count = f.pg.infra.count_plc_tokens_by_did(&did).await.unwrap();
    let store_count = f.store.infra.count_plc_tokens_by_did(&did).await.unwrap();
    assert_eq!(pg_count, store_count);
    assert_eq!(pg_count, 1);

    f.pg.infra.delete_plc_token(pg_uid, &token).await.unwrap();
    f.store
        .infra
        .delete_plc_token(store_uid, &token)
        .await
        .unwrap();

    let pg_gone =
        f.pg.infra
            .get_plc_token_expiry(pg_uid, &token)
            .await
            .unwrap();
    let store_gone = f
        .store
        .infra
        .get_plc_token_expiry(store_uid, &token)
        .await
        .unwrap();
    assert!(pg_gone.is_none());
    assert!(store_gone.is_none());
}

#[tokio::test]
async fn parity_blob_delete_and_takedown() {
    let f = ParityFixture::new().await;
    let did = test_did("blobdel");
    let handle = test_handle("blobdel");

    let (pg_uid, store_uid) = seed_repos(&f, &did, &handle).await;

    let cid = test_cid(180);
    f.pg.blob
        .insert_blob(&cid, "image/png", 1024, pg_uid, "blobs/td.png")
        .await
        .unwrap();
    f.store
        .blob
        .insert_blob(&cid, "image/png", 1024, store_uid, "blobs/td.png")
        .await
        .unwrap();

    let pg_td =
        f.pg.blob
            .update_blob_takedown(&cid, Some("mod-action-1"))
            .await
            .unwrap();
    let store_td = f
        .store
        .blob
        .update_blob_takedown(&cid, Some("mod-action-1"))
        .await
        .unwrap();
    assert_eq!(pg_td, store_td);

    let pg_with_td = f.pg.blob.get_blob_with_takedown(&cid).await.unwrap();
    let store_with_td = f.store.blob.get_blob_with_takedown(&cid).await.unwrap();
    assert_eq!(
        pg_with_td.as_ref().map(|b| b.takedown_ref.as_deref()),
        store_with_td.as_ref().map(|b| b.takedown_ref.as_deref())
    );

    f.pg.blob.delete_blob_by_cid(&cid).await.unwrap();
    f.store.blob.delete_blob_by_cid(&cid).await.unwrap();

    let pg_meta = f.pg.blob.get_blob_metadata(&cid).await.unwrap();
    let store_meta = f.store.blob.get_blob_metadata(&cid).await.unwrap();
    assert!(pg_meta.is_none());
    assert!(store_meta.is_none());
}

#[tokio::test]
async fn parity_prune_events_older_than() {
    let f = ParityFixture::new().await;
    let did = test_did("prune");

    let event = tranquil_db_traits::CommitEventData {
        did: did.clone(),
        event_type: tranquil_db_traits::RepoEventType::Commit,
        commit_cid: Some(test_cid(1)),
        prev_cid: None,
        ops: None,
        blobs: None,
        blocks: None,
        prev_data_cid: None,
        rev: Some("rev0".to_string()),
    };

    let pg_seq = f.pg.repo.insert_commit_event(&event).await.unwrap();
    let store_seq = f.store.repo.insert_commit_event(&event).await.unwrap();
    assert!(pg_seq.as_i64() > 0);
    assert!(store_seq.as_i64() > 0);

    let past_cutoff = chrono::Utc::now() - chrono::Duration::hours(24);
    let pg_pruned_past =
        f.pg.repo
            .prune_events_older_than(past_cutoff)
            .await
            .unwrap();
    let store_pruned_past = f
        .store
        .repo
        .prune_events_older_than(past_cutoff)
        .await
        .unwrap();
    assert!(
        pg_pruned_past.is_zero(),
        "past cutoff should not prune fresh events on pg, got {pg_pruned_past:?}"
    );
    assert!(
        store_pruned_past.is_zero(),
        "past cutoff should not prune fresh events on store, got {store_pruned_past:?}"
    );
    assert!(
        matches!(pg_pruned_past, tranquil_db_traits::PruneCount::Rows(_)),
        "pg backend must report row counts"
    );
    assert!(
        matches!(
            store_pruned_past,
            tranquil_db_traits::PruneCount::Segments(_)
        ),
        "store backend must report segment counts"
    );

    let future_cutoff = chrono::Utc::now() + chrono::Duration::hours(24);
    let pg_pruned_future =
        f.pg.repo
            .prune_events_older_than(future_cutoff)
            .await
            .unwrap();
    assert!(
        pg_pruned_future.count() > 0,
        "future cutoff should prune at least one row on pg, got {pg_pruned_future:?}"
    );

    let pg_after = f.pg.repo.get_event_by_seq(pg_seq).await.unwrap();
    assert!(
        pg_after.is_none(),
        "pruned pg event must no longer be readable"
    );

    let store_max_before = f.store.repo.get_max_seq().await.unwrap();
    let _ = f
        .store
        .repo
        .prune_events_older_than(future_cutoff)
        .await
        .unwrap();
    let store_max_after = f.store.repo.get_max_seq().await.unwrap();
    assert_eq!(
        store_max_after, store_max_before,
        "store retention must not regress max_seq"
    );
}
