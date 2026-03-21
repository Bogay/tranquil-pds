use presage::libsignal_service::{
    pre_keys::{KyberPreKeyStoreExt, PreKeysStore},
    prelude::{ProfileKey, SessionStoreExt},
    protocol::{
        DeviceId, Direction, GenericSignedPreKey, IdentityKeyPair, IdentityKeyStore, KeyPair,
        KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore,
        ProtocolAddress, SenderKeyStore, ServiceId, SessionRecord, SessionStore, SignedPreKeyId,
        SignedPreKeyRecord, SignedPreKeyStore, Timestamp,
    },
};
use presage::store::{ContentsStore, StateStore, Store};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use crate::store::{IdentityType, PgProtocolStore, PgSignalStore};

async fn test_store() -> PgSignalStore {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:5432/postgres".into());

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .unwrap();

    sqlx::query("DELETE FROM signal_kv")
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM signal_base_keys_seen")
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM signal_sender_keys")
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM signal_sessions")
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM signal_identities")
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM signal_kyber_pre_keys")
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM signal_signed_pre_keys")
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM signal_pre_keys")
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM signal_profile_keys")
        .execute(&pool)
        .await
        .ok();

    PgSignalStore::new(pool)
}

fn protocol_store(store: &PgSignalStore, identity: IdentityType) -> PgProtocolStore {
    PgProtocolStore::new(store.clone(), identity)
}

#[tokio::test]
async fn state_store_registration_empty() {
    let store = test_store().await;

    assert!(store.load_registration_data().await.unwrap().is_none());
    assert!(!store.is_registered().await);
}

#[tokio::test]
async fn state_store_kv_roundtrip() {
    let store = test_store().await;

    let value = b"test-data".to_vec();
    sqlx::query("INSERT INTO signal_kv (key, value) VALUES ('test_key', $1)")
        .bind(&value)
        .execute(&store.db)
        .await
        .unwrap();

    let loaded: Vec<u8> = sqlx::query_scalar("SELECT value FROM signal_kv WHERE key = 'test_key'")
        .fetch_one(&store.db)
        .await
        .unwrap();
    assert_eq!(loaded, value);
}

#[tokio::test]
async fn state_store_identity_keypairs() {
    let store = test_store().await;

    let aci_pair = IdentityKeyPair::generate(&mut rand::rng());
    let pni_pair = IdentityKeyPair::generate(&mut rand::rng());

    store.set_aci_identity_key_pair(aci_pair).await.unwrap();
    store.set_pni_identity_key_pair(pni_pair).await.unwrap();

    let aci_store = protocol_store(&store, IdentityType::Aci);
    let pni_store = protocol_store(&store, IdentityType::Pni);

    let loaded_aci = aci_store.get_identity_key_pair().await.unwrap();
    let loaded_pni = pni_store.get_identity_key_pair().await.unwrap();

    assert_eq!(loaded_aci.serialize(), aci_pair.serialize());
    assert_eq!(loaded_pni.serialize(), pni_pair.serialize());
}

#[tokio::test]
async fn state_store_sender_certificate_roundtrip() {
    let store = test_store().await;
    assert!(store.sender_certificate().await.unwrap().is_none());
}

#[tokio::test]
async fn state_store_clear_registration() {
    let mut store = test_store().await;

    sqlx::query("INSERT INTO signal_kv (key, value) VALUES ('registration', $1)")
        .bind(b"dummy-data".as_slice())
        .execute(&store.db)
        .await
        .unwrap();

    let mut ps = protocol_store(&store, IdentityType::Aci);
    let keypair = KeyPair::generate(&mut rand::rng());
    let record = PreKeyRecord::new(PreKeyId::from(1u32), &keypair);
    ps.save_pre_key(PreKeyId::from(1u32), &record)
        .await
        .unwrap();

    store.clear_registration().await.unwrap();

    let remaining: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT value FROM signal_kv WHERE key = 'registration'")
            .fetch_optional(&store.db)
            .await
            .unwrap();
    assert!(remaining.is_none());

    assert!(ps.get_pre_key(PreKeyId::from(1u32)).await.is_err());
}

#[tokio::test]
async fn session_store_crud() {
    let store = test_store().await;
    let mut ps = protocol_store(&store, IdentityType::Aci);

    let addr = ProtocolAddress::new("test-uuid".into(), DeviceId::new(1).unwrap());
    assert!(ps.load_session(&addr).await.unwrap().is_none());

    let record = SessionRecord::new_fresh();
    ps.store_session(&addr, &record).await.unwrap();

    let loaded = ps.load_session(&addr).await.unwrap();
    assert!(loaded.is_some());

    ps.store_session(&addr, &record).await.unwrap();
    let loaded2 = ps.load_session(&addr).await.unwrap();
    assert!(loaded2.is_some());
}

#[tokio::test]
async fn session_store_sub_devices() {
    let store = test_store().await;
    let mut ps = protocol_store(&store, IdentityType::Aci);

    let uuid = Uuid::new_v4();
    let service_id: ServiceId = presage::libsignal_service::protocol::Aci::from(uuid).into();
    let addr1 = ProtocolAddress::new(uuid.to_string(), DeviceId::new(1).unwrap());
    let addr2 = ProtocolAddress::new(uuid.to_string(), DeviceId::new(2).unwrap());
    let addr3 = ProtocolAddress::new(uuid.to_string(), DeviceId::new(3).unwrap());

    let record = SessionRecord::new_fresh();
    ps.store_session(&addr1, &record).await.unwrap();
    ps.store_session(&addr2, &record).await.unwrap();
    ps.store_session(&addr3, &record).await.unwrap();

    let sub_devices = ps.get_sub_device_sessions(&service_id).await.unwrap();
    assert_eq!(sub_devices.len(), 2);

    let deleted = ps.delete_all_sessions(&service_id).await.unwrap();
    assert_eq!(deleted, 3);

    let sub_devices = ps.get_sub_device_sessions(&service_id).await.unwrap();
    assert!(sub_devices.is_empty());
}

#[tokio::test]
async fn pre_key_store_crud() {
    let store = test_store().await;
    let mut ps = protocol_store(&store, IdentityType::Aci);

    let keypair = KeyPair::generate(&mut rand::rng());
    let id = PreKeyId::from(42u32);
    let record = PreKeyRecord::new(id, &keypair);

    ps.save_pre_key(id, &record).await.unwrap();
    let loaded = ps.get_pre_key(id).await.unwrap();
    assert_eq!(loaded.serialize().unwrap(), record.serialize().unwrap());

    ps.remove_pre_key(id).await.unwrap();
    assert!(ps.get_pre_key(id).await.is_err());
}

#[tokio::test]
async fn pre_key_store_next_ids() {
    let store = test_store().await;
    let mut ps = protocol_store(&store, IdentityType::Aci);

    assert_eq!(ps.next_pre_key_id().await.unwrap(), 1);

    let keypair = KeyPair::generate(&mut rand::rng());
    let record = PreKeyRecord::new(PreKeyId::from(5u32), &keypair);
    ps.save_pre_key(PreKeyId::from(5u32), &record)
        .await
        .unwrap();

    assert_eq!(ps.next_pre_key_id().await.unwrap(), 6);
}

#[tokio::test]
async fn signed_pre_key_store_crud() {
    let store = test_store().await;
    let mut ps = protocol_store(&store, IdentityType::Aci);

    let keypair = KeyPair::generate(&mut rand::rng());
    let id = SignedPreKeyId::from(1u32);
    let signature = keypair
        .private_key
        .calculate_signature(&keypair.public_key.serialize(), &mut rand::rng())
        .unwrap();
    let record =
        SignedPreKeyRecord::new(id, Timestamp::from_epoch_millis(1000), &keypair, &signature);

    ps.save_signed_pre_key(id, &record).await.unwrap();
    let loaded = ps.get_signed_pre_key(id).await.unwrap();
    assert_eq!(loaded.serialize().unwrap(), record.serialize().unwrap());

    assert_eq!(ps.signed_pre_keys_count().await.unwrap(), 1);
    assert_eq!(ps.next_signed_pre_key_id().await.unwrap(), 2);
}

#[tokio::test]
async fn kyber_pre_key_one_time_mark_used_deletes() {
    let store = test_store().await;
    let mut ps = protocol_store(&store, IdentityType::Aci);

    let keypair = KeyPair::generate(&mut rand::rng());
    let id = KyberPreKeyId::from(1u32);
    let record = KyberPreKeyRecord::generate(
        presage::libsignal_service::protocol::kem::KeyType::Kyber1024,
        id,
        &keypair.private_key,
    )
    .unwrap();

    ps.save_kyber_pre_key(id, &record).await.unwrap();
    assert!(ps.get_kyber_pre_key(id).await.is_ok());

    let ec_prekey_id = SignedPreKeyId::from(1u32);
    ps.mark_kyber_pre_key_used(id, ec_prekey_id, &keypair.public_key)
        .await
        .unwrap();

    assert!(ps.get_kyber_pre_key(id).await.is_err());
}

#[tokio::test]
async fn kyber_pre_key_last_resort_survives_mark_used() {
    let store = test_store().await;
    let mut ps = protocol_store(&store, IdentityType::Aci);

    let keypair = KeyPair::generate(&mut rand::rng());
    let id = KyberPreKeyId::from(1u32);
    let record = KyberPreKeyRecord::generate(
        presage::libsignal_service::protocol::kem::KeyType::Kyber1024,
        id,
        &keypair.private_key,
    )
    .unwrap();

    ps.store_last_resort_kyber_pre_key(id, &record)
        .await
        .unwrap();
    assert!(ps.get_kyber_pre_key(id).await.is_ok());

    let ec_prekey_id = SignedPreKeyId::from(1u32);
    ps.mark_kyber_pre_key_used(id, ec_prekey_id, &keypair.public_key)
        .await
        .unwrap();

    assert!(ps.get_kyber_pre_key(id).await.is_ok());
}

#[tokio::test]
async fn kyber_pre_key_last_resort_rejects_replayed_base_key() {
    let store = test_store().await;
    let mut ps = protocol_store(&store, IdentityType::Aci);

    let keypair = KeyPair::generate(&mut rand::rng());
    let id = KyberPreKeyId::from(1u32);
    let record = KyberPreKeyRecord::generate(
        presage::libsignal_service::protocol::kem::KeyType::Kyber1024,
        id,
        &keypair.private_key,
    )
    .unwrap();

    ps.store_last_resort_kyber_pre_key(id, &record)
        .await
        .unwrap();

    let ec_prekey_id = SignedPreKeyId::from(1u32);
    ps.mark_kyber_pre_key_used(id, ec_prekey_id, &keypair.public_key)
        .await
        .unwrap();

    let replay_result = ps
        .mark_kyber_pre_key_used(id, ec_prekey_id, &keypair.public_key)
        .await;
    assert!(replay_result.is_err());
}

#[tokio::test]
async fn kyber_pre_key_last_resort_list() {
    let store = test_store().await;
    let mut ps = protocol_store(&store, IdentityType::Aci);

    let keypair = KeyPair::generate(&mut rand::rng());
    let id = KyberPreKeyId::from(1u32);
    let record = KyberPreKeyRecord::generate(
        presage::libsignal_service::protocol::kem::KeyType::Kyber1024,
        id,
        &keypair.private_key,
    )
    .unwrap();

    assert!(
        ps.load_last_resort_kyber_pre_keys()
            .await
            .unwrap()
            .is_empty()
    );

    ps.store_last_resort_kyber_pre_key(id, &record)
        .await
        .unwrap();

    let last_resorts = ps.load_last_resort_kyber_pre_keys().await.unwrap();
    assert_eq!(last_resorts.len(), 1);
}

#[tokio::test]
async fn identity_store_crud() {
    let store = test_store().await;
    let mut ps = protocol_store(&store, IdentityType::Aci);

    let addr = ProtocolAddress::new("test-addr".into(), DeviceId::new(1).unwrap());
    let keypair = IdentityKeyPair::generate(&mut rand::rng());
    let identity_key = keypair.identity_key();

    assert!(ps.get_identity(&addr).await.unwrap().is_none());

    ps.save_identity(&addr, identity_key).await.unwrap();
    let loaded = ps.get_identity(&addr).await.unwrap().unwrap();
    assert_eq!(loaded.serialize(), identity_key.serialize());

    assert!(
        ps.is_trusted_identity(&addr, identity_key, Direction::Receiving)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn identity_store_aci_pni_isolation() {
    let store = test_store().await;
    let mut aci_store = protocol_store(&store, IdentityType::Aci);
    let pni_store = protocol_store(&store, IdentityType::Pni);

    let addr = ProtocolAddress::new("same-addr".into(), DeviceId::new(1).unwrap());
    let keypair = IdentityKeyPair::generate(&mut rand::rng());

    aci_store
        .save_identity(&addr, keypair.identity_key())
        .await
        .unwrap();

    assert!(aci_store.get_identity(&addr).await.unwrap().is_some());
    assert!(pni_store.get_identity(&addr).await.unwrap().is_none());
}

#[tokio::test]
async fn sender_key_store_load_missing() {
    let store = test_store().await;
    let mut ps = protocol_store(&store, IdentityType::Aci);

    let sender = ProtocolAddress::new("sender-uuid".into(), DeviceId::new(1).unwrap());
    let dist_id = Uuid::new_v4();

    assert!(
        ps.load_sender_key(&sender, dist_id)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn profile_key_store_roundtrip() {
    let mut store = test_store().await;

    let uuid = Uuid::new_v4();
    let service_id: ServiceId = presage::libsignal_service::protocol::Aci::from(uuid).into();
    let key = ProfileKey { bytes: [42u8; 32] };

    assert!(store.profile_key(&service_id).await.unwrap().is_none());

    store.upsert_profile_key(&uuid, key).await.unwrap();

    let loaded = store.profile_key(&service_id).await.unwrap().unwrap();
    assert_eq!(loaded.bytes, key.bytes);
}

#[tokio::test]
async fn client_from_pool_returns_none_without_registration() {
    let store = test_store().await;
    let pool = store.db.clone();

    let client =
        crate::SignalClient::from_pool(&pool, tokio_util::sync::CancellationToken::new()).await;
    assert!(client.is_none());
}

#[tokio::test]
async fn store_clear_removes_kv() {
    let mut store = test_store().await;

    store
        .set_aci_identity_key_pair(IdentityKeyPair::generate(&mut rand::rng()))
        .await
        .unwrap();

    sqlx::query("INSERT INTO signal_kv (key, value) VALUES ('registration', $1)")
        .bind(b"dummy".as_slice())
        .execute(&store.db)
        .await
        .unwrap();

    store.clear().await.unwrap();

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM signal_kv")
        .fetch_one(&store.db)
        .await
        .unwrap();
    assert_eq!(count, 0);
}
