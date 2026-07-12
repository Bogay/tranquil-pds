pub mod backlink_ops;
pub mod backlinks;
pub mod blob_ops;
pub mod blobs;
pub mod commit_ops;
pub mod delegation_ops;
pub mod delegations;
pub mod encoding;
pub mod event_keys;
pub mod event_ops;
pub mod infra_ops;
pub mod infra_schema;
pub mod keys;
pub mod oauth_ops;
pub mod oauth_schema;
pub mod partitions;
pub mod record_ops;
pub mod records;
pub mod recovery;
pub mod repo_meta;
pub mod repo_ops;
pub mod scan;
pub mod session_ops;
pub mod sessions;
pub mod sso_ops;
pub mod sso_schema;
pub mod user_block_ops;
pub mod user_blocks;
pub mod user_hash;
pub mod user_ops;
pub mod users;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use fjall::{Database, Keyspace};

use self::keys::KeyTag;
use self::partitions::Partition;
use self::user_hash::UserHashMap;

const CURRENT_FORMAT_VERSION: u64 = 1;

#[derive(Debug, Clone)]
pub struct MetastoreConfig {
    pub cache_size_bytes: u64,
}

impl Default for MetastoreConfig {
    fn default() -> Self {
        let total_ram = total_system_ram_bytes();
        let twenty_percent = total_ram / 5;
        let max_cache: u64 = 4 * 1024 * 1024 * 1024;

        Self {
            cache_size_bytes: twenty_percent.min(max_cache),
        }
    }
}

fn total_system_ram_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|contents| {
                contents
                    .lines()
                    .find(|line| line.starts_with("MemTotal:"))
                    .and_then(|line| {
                        line.split_whitespace()
                            .nth(1)
                            .and_then(|kb| kb.parse::<u64>().ok())
                            .map(|kb| kb.saturating_mul(1024))
                    })
            })
            .unwrap_or(4 * 1024 * 1024 * 1024)
    }
    #[cfg(not(target_os = "linux"))]
    {
        tracing::warn!("cannot detect system RAM on this platform, defaulting to 4GB");
        4 * 1024 * 1024 * 1024
    }
}

#[derive(Debug)]
pub enum MetastoreError {
    Fjall(fjall::Error),
    Lsm(lsm_tree::Error),
    VersionMismatch {
        expected: u64,
        found: u64,
    },
    CorruptData(&'static str),
    InvalidInput(&'static str),
    UserHashCollision {
        hash: keys::UserHash,
        existing_uuid: uuid::Uuid,
        new_uuid: uuid::Uuid,
    },
    UniqueViolation(&'static str),
}

impl std::fmt::Display for MetastoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fjall(e) => write!(f, "fjall: {e}"),
            Self::Lsm(e) => write!(f, "lsm: {e}"),
            Self::VersionMismatch { expected, found } => {
                write!(
                    f,
                    "format version mismatch: expected {expected}, found {found}"
                )
            }
            Self::CorruptData(msg) => write!(f, "corrupt data: {msg}"),
            Self::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
            Self::UserHashCollision {
                hash,
                existing_uuid,
                new_uuid,
            } => write!(
                f,
                "user hash collision: hash {hash} maps to both {existing_uuid} and {new_uuid}"
            ),
            Self::UniqueViolation(constraint) => {
                write!(f, "unique constraint violated: {constraint}")
            }
        }
    }
}

impl std::error::Error for MetastoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Fjall(e) => Some(e),
            Self::Lsm(e) => Some(e),
            _ => None,
        }
    }
}

impl From<fjall::Error> for MetastoreError {
    fn from(e: fjall::Error) -> Self {
        Self::Fjall(e)
    }
}

impl From<lsm_tree::Error> for MetastoreError {
    fn from(e: lsm_tree::Error) -> Self {
        Self::Lsm(e)
    }
}

type CompactionFilterFn =
    Arc<dyn Fn(&str) -> Option<Arc<dyn fjall::compaction::filter::Factory>> + Send + Sync>;

pub mod client;
pub mod handler;

#[derive(Clone)]
pub struct Metastore {
    db: Database,
    partitions: [Keyspace; Partition::ALL.len()],
    user_hashes: Arc<UserHashMap>,
    counter_lock: Arc<parking_lot::Mutex<()>>,
    comms_seq: Arc<std::sync::atomic::AtomicU32>,
    path: PathBuf,
}

impl Metastore {
    pub fn open(path: &Path, config: MetastoreConfig) -> Result<Self, MetastoreError> {
        let auth_name = Partition::Auth.name();
        let filter_factory: CompactionFilterFn =
            Arc::new(move |name: &str| match name == auth_name {
                true => Some(Arc::new(partitions::TtlFilterFactory)),
                false => None,
            });

        let db = Database::builder(path)
            .cache_size(config.cache_size_bytes)
            .with_compaction_filter_factories(filter_factory)
            .open()?;

        let opened: Vec<Keyspace> = Partition::ALL
            .iter()
            .map(|&p| {
                let opts = p.create_options();
                db.keyspace(p.name(), || opts)
            })
            .collect::<Result<_, fjall::Error>>()?;

        let partitions: [Keyspace; Partition::ALL.len()] = opened
            .try_into()
            .ok()
            .expect("opened exactly Partition::ALL.len() keyspaces");

        let repo_data = partitions[Partition::RepoData.index()].clone();
        Self::check_or_write_version(&db, &repo_data)?;

        let user_hashes = Arc::new(UserHashMap::new(repo_data));
        let loaded = user_hashes.load_all()?;
        tracing::info!(count = loaded, "loaded user hash mappings");

        Ok(Self {
            db,
            partitions,
            user_hashes,
            counter_lock: Arc::new(parking_lot::Mutex::new(())),
            comms_seq: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            path: path.to_path_buf(),
        })
    }

    fn check_or_write_version(db: &Database, repo_data: &Keyspace) -> Result<(), MetastoreError> {
        let version_key = [KeyTag::FORMAT_VERSION.raw()];
        let version_bytes = CURRENT_FORMAT_VERSION.to_be_bytes();

        match repo_data.get(version_key)? {
            Some(existing) => {
                let found_bytes: [u8; 8] = existing
                    .as_ref()
                    .try_into()
                    .map_err(|_| MetastoreError::CorruptData("format version not 8 bytes"))?;
                let found = u64::from_be_bytes(found_bytes);
                match found == CURRENT_FORMAT_VERSION {
                    true => Ok(()),
                    false => Err(MetastoreError::VersionMismatch {
                        expected: CURRENT_FORMAT_VERSION,
                        found,
                    }),
                }
            }
            None => {
                repo_data.insert(version_key, version_bytes)?;
                db.persist(fjall::PersistMode::SyncData)?;
                Ok(())
            }
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn partition(&self, p: Partition) -> &Keyspace {
        &self.partitions[p.index()]
    }

    pub fn signal_keyspace(&self) -> Keyspace {
        self.partitions[Partition::Signal.index()].clone()
    }

    pub fn user_hashes(&self) -> &Arc<UserHashMap> {
        &self.user_hashes
    }

    pub fn database(&self) -> &Database {
        &self.db
    }

    pub fn repo_ops(&self) -> repo_ops::RepoOps {
        repo_ops::RepoOps::new(
            self.partitions[Partition::RepoData.index()].clone(),
            Arc::clone(&self.user_hashes),
        )
    }

    pub fn record_ops(&self) -> record_ops::RecordOps {
        record_ops::RecordOps::new(
            self.partitions[Partition::RepoData.index()].clone(),
            Arc::clone(&self.user_hashes),
        )
    }

    pub fn user_block_ops(&self) -> user_block_ops::UserBlockOps {
        user_block_ops::UserBlockOps::new(
            self.partitions[Partition::RepoData.index()].clone(),
            Arc::clone(&self.user_hashes),
        )
    }

    pub fn event_ops<S: crate::io::StorageIO + 'static>(
        &self,
        bridge: Arc<crate::eventlog::EventLogBridge<S>>,
    ) -> event_ops::EventOps<S> {
        event_ops::EventOps::new(
            self.db.clone(),
            self.partitions[Partition::RepoData.index()].clone(),
            bridge,
        )
    }

    pub fn blob_ops(&self) -> blob_ops::BlobOps {
        blob_ops::BlobOps::new(
            self.db.clone(),
            self.partitions[Partition::RepoData.index()].clone(),
            Arc::clone(&self.user_hashes),
        )
    }

    pub fn backlink_ops(&self) -> backlink_ops::BacklinkOps {
        backlink_ops::BacklinkOps::new(
            self.partitions[Partition::Indexes.index()].clone(),
            Arc::clone(&self.user_hashes),
        )
    }

    pub fn delegation_ops(&self) -> delegation_ops::DelegationOps {
        delegation_ops::DelegationOps::new(
            self.db.clone(),
            self.partitions[Partition::Indexes.index()].clone(),
            self.partitions[Partition::Users.index()].clone(),
            Arc::clone(&self.user_hashes),
        )
    }

    pub fn sso_ops(&self) -> sso_ops::SsoOps {
        sso_ops::SsoOps::new(
            self.db.clone(),
            self.partitions[Partition::Indexes.index()].clone(),
        )
    }

    pub fn session_ops(&self) -> session_ops::SessionOps {
        session_ops::SessionOps::new(
            self.db.clone(),
            self.partitions[Partition::Auth.index()].clone(),
            self.partitions[Partition::Users.index()].clone(),
            Arc::clone(&self.user_hashes),
            Arc::clone(&self.counter_lock),
        )
    }

    pub fn infra_ops(&self) -> infra_ops::InfraOps {
        infra_ops::InfraOps::new(
            self.db.clone(),
            self.partitions[Partition::Infra.index()].clone(),
            self.partitions[Partition::RepoData.index()].clone(),
            self.partitions[Partition::Users.index()].clone(),
            Arc::clone(&self.user_hashes),
            Arc::clone(&self.comms_seq),
            Arc::clone(&self.counter_lock),
        )
    }

    pub fn oauth_ops(&self) -> oauth_ops::OAuthOps {
        oauth_ops::OAuthOps::new(
            self.db.clone(),
            self.partitions[Partition::Auth.index()].clone(),
            self.partitions[Partition::Users.index()].clone(),
            Arc::clone(&self.counter_lock),
        )
    }

    pub fn user_ops(&self) -> user_ops::UserOps {
        user_ops::UserOps::new(
            self.db.clone(),
            self.partitions[Partition::Users.index()].clone(),
            self.partitions[Partition::RepoData.index()].clone(),
            self.partitions[Partition::Auth.index()].clone(),
            Arc::clone(&self.user_hashes),
        )
    }

    pub fn commit_ops<S: crate::io::StorageIO + 'static>(
        &self,
        bridge: Arc<crate::eventlog::EventLogBridge<S>>,
    ) -> commit_ops::CommitOps<S> {
        commit_ops::CommitOps::new(
            self.db.clone(),
            self.partitions[Partition::RepoData.index()].clone(),
            self.partitions[Partition::Indexes.index()].clone(),
            Arc::clone(&self.user_hashes),
            bridge,
        )
    }

    pub fn persist(&self) -> Result<(), MetastoreError> {
        self.db
            .persist(fjall::PersistMode::SyncData)
            .map_err(MetastoreError::Fjall)
    }

    pub fn major_compact(&self) -> Result<(), MetastoreError> {
        Partition::ALL.iter().try_for_each(|&p| {
            tracing::info!(partition = p.name(), "starting major compaction");
            self.partitions[p.index()]
                .major_compact()
                .map_err(MetastoreError::Fjall)?;
            tracing::info!(partition = p.name(), "major compaction complete");
            Ok::<(), MetastoreError>(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tranquil_types::Did;

    fn open_fresh() -> (tempfile::TempDir, Metastore) {
        let dir = tempfile::TempDir::new().unwrap();
        let ms = Metastore::open(
            dir.path(),
            MetastoreConfig {
                cache_size_bytes: 64 * 1024 * 1024,
            },
        )
        .unwrap();
        (dir, ms)
    }

    fn test_config() -> MetastoreConfig {
        MetastoreConfig {
            cache_size_bytes: 64 * 1024 * 1024,
        }
    }

    #[test]
    fn open_fresh_directory_succeeds() {
        let (_dir, ms) = open_fresh();
        assert_eq!(ms.user_hashes().len(), 0);
    }

    #[test]
    fn all_partitions_accessible() {
        let (_dir, ms) = open_fresh();
        Partition::ALL.iter().for_each(|&p| {
            let _ = ms.partition(p);
        });
    }

    fn legacy_session_create(
        did: &str,
        access_jti: &str,
        refresh_jti: &str,
    ) -> tranquil_db_traits::SessionTokenCreate {
        let now = chrono::Utc::now();
        tranquil_db_traits::SessionTokenCreate {
            did: tranquil_types::Did::new(did.to_string()).unwrap(),
            access_jti: tranquil_types::Jti::new(access_jti),
            refresh_jti: tranquil_types::Jti::new(refresh_jti),
            access_expires_at: now + chrono::Duration::minutes(120),
            refresh_expires_at: now + chrono::Duration::days(90),
            login_type: tranquil_db_traits::LoginType::Legacy,
            mfa_verified: false,
            scope: None,
            controller_did: None,
            app_password_name: None,
        }
    }

    fn create_test_user(ms: &Metastore, did: &str, handle: &str) {
        let input = tranquil_db_traits::CreatePasswordAccountInput {
            handle: tranquil_types::Handle::new(handle.to_string()).unwrap(),
            email: None,
            did: tranquil_types::Did::new(did.to_string()).unwrap(),
            password_hash: "test-hash".to_string(),
            preferred_comms_channel: tranquil_db_traits::CommsChannel::Email,
            discord_username: None,
            telegram_username: None,
            signal_username: None,
            deactivated_at: None,
            inbound_migration: false,
            encrypted_key_bytes: vec![7u8; 32],
            encryption_version: 0,
            reserved_key_id: None,
            commit_cid: "bafyreib2rxk3ryblouj3fxza5jvx6psmwewwessc4m6g6e7pqhhkwqomfi".to_string(),
            repo_rev: "rev0".to_string(),
            genesis_block_cids: vec![],
            invite_code: None,
            birthdate_pref: None,
        };
        ms.user_ops().create_password_account(&input).unwrap();
    }

    fn legacy_refresh_data(
        did: &Did,
        session_id: tranquil_db_traits::SessionId,
        old_refresh_jti: &str,
        new_access_jti: &str,
        new_refresh_jti: &str,
    ) -> tranquil_db_traits::SessionRefreshData {
        let now = chrono::Utc::now();
        tranquil_db_traits::SessionRefreshData {
            did: did.clone(),
            old_refresh_jti: tranquil_types::Jti::new(old_refresh_jti),
            session_id,
            new_access_jti: tranquil_types::Jti::new(new_access_jti),
            new_refresh_jti: tranquil_types::Jti::new(new_refresh_jti),
            new_access_expires_at: now + chrono::Duration::minutes(120),
            new_refresh_expires_at: now + chrono::Duration::days(90),
        }
    }

    #[test]
    fn legacy_refresh_grace_replays_within_window() {
        use tranquil_db_traits::{RefreshGraceLookup, RefreshSessionResult};
        let (_dir, ms) = open_fresh();
        let did = Did::new("did:plc:grace".to_string()).unwrap();
        create_test_user(&ms, did.as_str(), "grace.test");
        let ops = ms.session_ops();

        let session_id = ops
            .create_session(&legacy_session_create(did.as_str(), "acc0", "ref0"))
            .unwrap();

        // The winning request rotates ref0 -> ref1.
        let win = legacy_refresh_data(&did, session_id, "ref0", "acc1", "ref1");
        assert!(matches!(
            ops.refresh_session_atomic(&win).unwrap(),
            RefreshSessionResult::Success
        ));

        // A racing client re-presents ref0; the up-front grace lookup points at
        // the session's current tokens for re-minting (jtis, not signed JWTs),
        // carrying the signing key so the caller can verify the presented token.
        match ops.lookup_refresh_grace("ref0").unwrap() {
            RefreshGraceLookup::Replay(replay) => {
                assert_eq!(replay.did.as_str(), "did:plc:grace");
                assert_eq!(replay.access_jti, "acc1");
                assert_eq!(replay.refresh_jti, "ref1");
                assert_eq!(replay.key_bytes, vec![7u8; 32]);
            }
            other => panic!("expected Replay, got {other:?}"),
        }

        // The atomic path (two requests both past the used-check) also yields
        // the winner's current tokens rather than revoking.
        let lose = legacy_refresh_data(&did, session_id, "ref0", "accX", "refX");
        match ops.refresh_session_atomic(&lose).unwrap() {
            RefreshSessionResult::GraceReplay(replay) => {
                assert_eq!(replay.access_jti, "acc1");
                assert_eq!(replay.refresh_jti, "ref1");
            }
            other => panic!("expected GraceReplay, got {other:?}"),
        }

        // Crucially, the session is still alive on the winner's tokens — nobody
        // got logged out.
        let alive = ops.get_session_by_access_jti("acc1").unwrap();
        assert!(
            alive.is_some(),
            "session must survive a benign concurrent refresh"
        );
        assert_eq!(alive.unwrap().refresh_jti, "ref1");
    }

    // Per-token grace: a token two rotations stale but rotated moments ago is
    // still within its own grace window, so it must replay the session's CURRENT
    // tokens (acc2/ref2) rather than revoking. Regression for the defect where
    // only the immediate predecessor was replayable.
    #[test]
    fn legacy_refresh_superseded_token_within_grace_replays() {
        use tranquil_db_traits::{RefreshGraceLookup, RefreshSessionResult};
        let (_dir, ms) = open_fresh();
        let did = Did::new("did:plc:reuse".to_string()).unwrap();
        create_test_user(&ms, did.as_str(), "reuse.test");
        let ops = ms.session_ops();

        let session_id = ops
            .create_session(&legacy_session_create(did.as_str(), "acc0", "ref0"))
            .unwrap();
        ops.refresh_session_atomic(&legacy_refresh_data(
            &did, session_id, "ref0", "acc1", "ref1",
        ))
        .unwrap();
        ops.refresh_session_atomic(&legacy_refresh_data(
            &did, session_id, "ref1", "acc2", "ref2",
        ))
        .unwrap();

        // ref0 is two rotations back but was rotated just now: still in window.
        match ops.lookup_refresh_grace("ref0").unwrap() {
            RefreshGraceLookup::Replay(replay) => {
                assert_eq!(replay.access_jti, "acc2");
                assert_eq!(replay.refresh_jti, "ref2");
            }
            other => panic!("expected Replay, got {other:?}"),
        }
        match ops
            .refresh_session_atomic(&legacy_refresh_data(&did, session_id, "ref0", "z", "z"))
            .unwrap()
        {
            RefreshSessionResult::GraceReplay(replay) => {
                assert_eq!(replay.access_jti, "acc2");
                assert_eq!(replay.refresh_jti, "ref2");
            }
            other => panic!("expected GraceReplay, got {other:?}"),
        }
        // The session is still alive on the current tokens — nobody logged out.
        assert!(ops.get_session_by_access_jti("acc2").unwrap().is_some());
    }

    #[test]
    fn rotated_refresh_jti_is_none_from_fetch_but_replay_from_grace() {
        use tranquil_db_traits::RefreshGraceLookup;
        let (_dir, ms) = open_fresh();
        let did = Did::new("did:plc:whelk".to_string()).unwrap();
        create_test_user(&ms, did.as_str(), "whelk.test");
        let ops = ms.session_ops();

        let session_id = ops
            .create_session(&legacy_session_create(did.as_str(), "acc0", "ref0"))
            .unwrap();
        ops.refresh_session_atomic(&legacy_refresh_data(
            &did, session_id, "ref0", "acc1", "ref1",
        ))
        .unwrap();

        assert!(ops.get_session_for_refresh("ref0").unwrap().is_none());
        match ops.lookup_refresh_grace("ref0").unwrap() {
            RefreshGraceLookup::Replay(replay) => assert_eq!(replay.refresh_jti, "ref1"),
            other => panic!("expected Replay, got {other:?}"),
        }
    }

    #[test]
    fn delete_session_is_scoped_to_did() {
        let (_dir, ms) = open_fresh();
        let owner = Did::new("did:plc:limpet".to_string()).unwrap();
        let other = Did::new("did:plc:scallop".to_string()).unwrap();
        create_test_user(&ms, owner.as_str(), "limpet.test");
        let ops = ms.session_ops();

        let session_id = ops
            .create_session(&legacy_session_create(owner.as_str(), "acc0", "ref0"))
            .unwrap();

        assert_eq!(ops.delete_session_by_id(session_id, &other).unwrap(), 0);
        assert_eq!(ops.delete_session_by_access_jti("acc0", &other).unwrap(), 0);
        assert!(ops.get_session_by_access_jti("acc0").unwrap().is_some());

        assert_eq!(ops.delete_session_by_access_jti("acc0", &owner).unwrap(), 1);
        assert!(ops.get_session_by_access_jti("acc0").unwrap().is_none());
    }

    // An old-format (12-byte, no rotated_at) used marker has unknown rotation
    // time and must classify as Compromised, never Replay.
    #[test]
    fn legacy_old_format_marker_is_compromise() {
        use tranquil_db_traits::RefreshGraceLookup;
        let (_dir, ms) = open_fresh();
        create_test_user(&ms, "did:plc:oldfmt", "oldfmt.test");
        let ops = ms.session_ops();

        let session_id = ops
            .create_session(&legacy_session_create("did:plc:oldfmt", "acc0", "ref0"))
            .unwrap();

        // Write a pre-upgrade 12-byte marker (TTL prefix + session_id) directly.
        let mut marker = 0u64.to_be_bytes().to_vec();
        marker.extend_from_slice(&session_id.as_i32().to_be_bytes());
        assert_eq!(marker.len(), 12);
        ms.partition(Partition::Auth)
            .insert(
                super::sessions::session_used_refresh_key("ref0").as_slice(),
                marker,
            )
            .unwrap();

        assert!(matches!(
            ops.lookup_refresh_grace("ref0").unwrap(),
            RefreshGraceLookup::Compromised { .. }
        ));
    }

    // A current-format marker whose rotation predates the grace window is genuine
    // reuse: lookup classifies Compromised, the atomic path returns Compromise and
    // revokes, and the session is gone afterwards.
    #[test]
    fn legacy_refresh_stale_rotation_outside_grace_is_compromise() {
        use tranquil_db_traits::{
            REFRESH_GRACE_PERIOD_SECS, RefreshGraceLookup, RefreshSessionResult,
        };
        let (_dir, ms) = open_fresh();
        let did = Did::new("did:plc:stale".to_string()).unwrap();
        create_test_user(&ms, did.as_str(), "stale.test");
        let ops = ms.session_ops();

        let session_id = ops
            .create_session(&legacy_session_create(did.as_str(), "acc0", "ref0"))
            .unwrap();

        // Overwrite ref0's used marker with a current 20-byte marker rotated 3h ago,
        // well outside the 2h grace window.
        let stale_rotated_at_ms =
            (chrono::Utc::now() - chrono::Duration::hours(3)).timestamp_millis();
        let refresh_expires_at_ms =
            (chrono::Utc::now() + chrono::Duration::days(90)).timestamp_millis();
        assert!(
            stale_rotated_at_ms
                < (chrono::Utc::now() - chrono::Duration::seconds(REFRESH_GRACE_PERIOD_SECS))
                    .timestamp_millis()
        );
        ms.partition(Partition::Auth)
            .insert(
                super::sessions::session_used_refresh_key("ref0").as_slice(),
                super::sessions::serialize_used_refresh_value(
                    refresh_expires_at_ms,
                    session_id.as_i32(),
                    stale_rotated_at_ms,
                ),
            )
            .unwrap();

        match ops.lookup_refresh_grace("ref0").unwrap() {
            RefreshGraceLookup::Compromised { key_bytes, .. } => {
                assert_eq!(key_bytes, vec![7u8; 32]);
            }
            other => panic!("expected Compromised, got {other:?}"),
        }

        assert!(matches!(
            ops.refresh_session_atomic(&legacy_refresh_data(&did, session_id, "ref0", "z", "z"))
                .unwrap(),
            RefreshSessionResult::Compromise
        ));

        // The session was actually revoked.
        assert!(ops.get_session_by_access_jti("acc0").unwrap().is_none());
    }

    #[test]
    fn reopen_preserves_partitions() {
        let dir = tempfile::TempDir::new().unwrap();

        {
            let ms = Metastore::open(dir.path(), test_config()).unwrap();
            let repo_data = ms.partition(Partition::RepoData);
            repo_data.insert(b"test_key", b"test_value").unwrap();
            ms.persist().unwrap();
        }

        {
            let ms = Metastore::open(dir.path(), test_config()).unwrap();
            let repo_data = ms.partition(Partition::RepoData);
            let val = repo_data.get(b"test_key").unwrap().unwrap();
            assert_eq!(val.as_ref(), b"test_value");
        }
    }

    #[test]
    fn version_mismatch_returns_error() {
        let dir = tempfile::TempDir::new().unwrap();

        {
            let ms = Metastore::open(dir.path(), test_config()).unwrap();
            let repo_data = ms.partition(Partition::RepoData);
            let version_key = [KeyTag::FORMAT_VERSION.raw()];
            repo_data.insert(version_key, 999u64.to_be_bytes()).unwrap();
            ms.persist().unwrap();
        }

        {
            let result = Metastore::open(dir.path(), test_config());
            assert!(matches!(
                result,
                Err(MetastoreError::VersionMismatch {
                    expected: 1,
                    found: 999
                })
            ));
        }
    }

    #[test]
    fn user_hash_mappings_survive_reopen() {
        let dir = tempfile::TempDir::new().unwrap();
        let uuid = uuid::Uuid::new_v4();
        let hash = keys::UserHash::from_did("did:plc:survivor");

        {
            let ms = Metastore::open(dir.path(), test_config()).unwrap();
            let mut batch = ms.database().batch();
            ms.user_hashes()
                .stage_insert(&mut batch, uuid, hash)
                .unwrap();
            batch.commit().unwrap();
            ms.persist().unwrap();
        }

        {
            let ms = Metastore::open(dir.path(), test_config()).unwrap();
            assert_eq!(ms.user_hashes().len(), 1);
            assert_eq!(ms.user_hashes().get(&uuid), Some(hash));
            assert_eq!(ms.user_hashes().get_uuid(&hash), Some(uuid));
        }
    }

    #[test]
    fn default_config_has_reasonable_cache_size() {
        let config = MetastoreConfig::default();
        assert!(config.cache_size_bytes > 0);
        assert!(config.cache_size_bytes <= 4 * 1024 * 1024 * 1024);
    }
}
