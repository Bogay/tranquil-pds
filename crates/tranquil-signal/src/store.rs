use std::ops::RangeBounds;

use async_trait::async_trait;
use presage::{
    AvatarBytes,
    libsignal_service::{
        Profile,
        pre_keys::{KyberPreKeyStoreExt, PreKeysStore},
        prelude::{Content, MasterKey, ProfileKey, SessionStoreExt, Uuid},
        protocol::{
            CiphertextMessageType, DeviceId, Direction, GenericSignedPreKey, IdentityChange,
            IdentityKey, IdentityKeyPair, IdentityKeyStore, KyberPreKeyId, KyberPreKeyRecord,
            KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore, ProtocolAddress, ProtocolStore,
            PublicKey, SenderCertificate, SenderKeyRecord, SenderKeyStore, ServiceId,
            SessionRecord, SessionStore, SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord,
            SignedPreKeyStore,
        },
        push_service::DEFAULT_DEVICE_ID,
        zkgroup::GroupMasterKeyBytes,
    },
    manager::RegistrationData,
    model::{contacts::Contact, groups::Group},
    store::{ContentsStore, StateStore, StickerPack, Store, Thread},
};
use sqlx::PgPool;
use tracing::warn;

#[derive(Debug, Clone)]
pub struct PgSignalStore {
    pub db: PgPool,
}

impl PgSignalStore {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    pub async fn is_linked(&self) -> Result<bool, PgStoreError> {
        let row = sqlx::query!("SELECT value FROM signal_kv WHERE key = 'registration'")
            .fetch_optional(&self.db)
            .await?;
        Ok(row.is_some())
    }

    async fn set_identity_key_pair(
        &self,
        identity: IdentityType,
        key_pair: IdentityKeyPair,
    ) -> Result<(), PgStoreError> {
        let key = identity.identity_key_pair_key();
        let value = key_pair.serialize().to_vec();
        sqlx::query!(
            "INSERT INTO signal_kv (key, value) VALUES ($1, $2)
             ON CONFLICT (key) DO UPDATE SET value = $2",
            key,
            &value,
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn clear_protocol_tables(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> Result<(), PgStoreError> {
        sqlx::query!("DELETE FROM signal_base_keys_seen")
            .execute(&mut **tx)
            .await?;
        sqlx::query!("DELETE FROM signal_sender_keys")
            .execute(&mut **tx)
            .await?;
        sqlx::query!("DELETE FROM signal_kyber_pre_keys")
            .execute(&mut **tx)
            .await?;
        sqlx::query!("DELETE FROM signal_signed_pre_keys")
            .execute(&mut **tx)
            .await?;
        sqlx::query!("DELETE FROM signal_pre_keys")
            .execute(&mut **tx)
            .await?;
        sqlx::query!("DELETE FROM signal_identities")
            .execute(&mut **tx)
            .await?;
        sqlx::query!("DELETE FROM signal_sessions")
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    pub async fn clear_all(&self) -> Result<(), PgStoreError> {
        let mut tx = self.db.begin().await?;
        Self::clear_protocol_tables(&mut tx).await?;
        sqlx::query!("DELETE FROM signal_profile_keys")
            .execute(&mut *tx)
            .await?;
        sqlx::query!("DELETE FROM signal_kv")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct PgProtocolStore {
    store: PgSignalStore,
    identity: IdentityType,
}

impl PgProtocolStore {
    pub(crate) fn new(store: PgSignalStore, identity: IdentityType) -> Self {
        Self { store, identity }
    }
}

fn next_id_from_max(max_id: Option<i32>) -> Result<u32, SignalProtocolError> {
    match max_id {
        None => Ok(1),
        Some(id) => {
            let current = i32_to_u32(id)?;
            current.checked_add(1).ok_or_else(|| {
                SignalProtocolError::InvalidState(
                    "pre key id space exhausted",
                    format!("max id {current} has no successor"),
                )
            })
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum IdentityType {
    Aci,
    Pni,
}

impl IdentityType {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Aci => "aci",
            Self::Pni => "pni",
        }
    }

    fn identity_key_pair_key(&self) -> &'static str {
        match self {
            Self::Aci => "identity_keypair_aci",
            Self::Pni => "identity_keypair_pni",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PgStoreError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("protocol: {0}")]
    Protocol(#[from] SignalProtocolError),
    #[error("invalid format")]
    InvalidFormat,
}

impl presage::store::StoreError for PgStoreError {}

fn u32_to_i32(val: u32) -> Result<i32, SignalProtocolError> {
    i32::try_from(val).map_err(|_| {
        SignalProtocolError::InvalidState("id overflow", format!("{val} exceeds i32::MAX"))
    })
}

fn i32_to_u32(val: i32) -> Result<u32, SignalProtocolError> {
    u32::try_from(val)
        .map_err(|_| SignalProtocolError::InvalidState("negative id", format!("{val} is negative")))
}

trait IntoProtocolError<T> {
    fn into_protocol_error(self) -> Result<T, SignalProtocolError>;
}

impl<T> IntoProtocolError<T> for Result<T, sqlx::Error> {
    fn into_protocol_error(self) -> Result<T, SignalProtocolError> {
        self.map_err(|e| SignalProtocolError::InvalidState("sqlx", e.to_string()))
    }
}

impl<T> IntoProtocolError<T> for Result<T, PgStoreError> {
    fn into_protocol_error(self) -> Result<T, SignalProtocolError> {
        self.map_err(|e| SignalProtocolError::InvalidState("store", e.to_string()))
    }
}

impl Store for PgSignalStore {
    type Error = PgStoreError;
    type AciStore = PgProtocolStore;
    type PniStore = PgProtocolStore;

    async fn clear(&mut self) -> Result<(), PgStoreError> {
        self.clear_all().await
    }

    fn aci_protocol_store(&self) -> Self::AciStore {
        PgProtocolStore::new(self.clone(), IdentityType::Aci)
    }

    fn pni_protocol_store(&self) -> Self::PniStore {
        PgProtocolStore::new(self.clone(), IdentityType::Pni)
    }
}

impl StateStore for PgSignalStore {
    type StateStoreError = PgStoreError;

    async fn load_registration_data(&self) -> Result<Option<RegistrationData>, PgStoreError> {
        sqlx::query_scalar!("SELECT value FROM signal_kv WHERE key = 'registration'")
            .fetch_optional(&self.db)
            .await?
            .map(|value| serde_json::from_slice(&value))
            .transpose()
            .map_err(From::from)
    }

    async fn save_registration_data(
        &mut self,
        state: &RegistrationData,
    ) -> Result<(), PgStoreError> {
        let value = serde_json::to_vec(state)?;
        sqlx::query!(
            "INSERT INTO signal_kv (key, value) VALUES ('registration', $1)
             ON CONFLICT (key) DO UPDATE SET value = $1",
            &value,
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn is_registered(&self) -> bool {
        self.load_registration_data().await.ok().flatten().is_some()
    }

    async fn clear_registration(&mut self) -> Result<(), PgStoreError> {
        let mut tx = self.db.begin().await?;
        sqlx::query!("DELETE FROM signal_kv WHERE key = 'registration'")
            .execute(&mut *tx)
            .await?;
        Self::clear_protocol_tables(&mut tx).await?;
        tx.commit().await?;
        Ok(())
    }

    async fn set_aci_identity_key_pair(
        &self,
        key_pair: IdentityKeyPair,
    ) -> Result<(), PgStoreError> {
        self.set_identity_key_pair(IdentityType::Aci, key_pair)
            .await
    }

    async fn set_pni_identity_key_pair(
        &self,
        key_pair: IdentityKeyPair,
    ) -> Result<(), PgStoreError> {
        self.set_identity_key_pair(IdentityType::Pni, key_pair)
            .await
    }

    async fn sender_certificate(&self) -> Result<Option<SenderCertificate>, PgStoreError> {
        sqlx::query_scalar!("SELECT value FROM signal_kv WHERE key = 'sender_certificate' LIMIT 1")
            .fetch_optional(&self.db)
            .await?
            .map(|value| SenderCertificate::deserialize(&value))
            .transpose()
            .map_err(From::from)
    }

    async fn save_sender_certificate(
        &self,
        certificate: &SenderCertificate,
    ) -> Result<(), PgStoreError> {
        let value = certificate.serialized()?.to_vec();
        sqlx::query!(
            "INSERT INTO signal_kv (key, value) VALUES ('sender_certificate', $1)
             ON CONFLICT (key) DO UPDATE SET value = $1",
            &value,
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn fetch_master_key(&self) -> Result<Option<MasterKey>, PgStoreError> {
        sqlx::query_scalar!("SELECT value FROM signal_kv WHERE key = 'master_key' LIMIT 1")
            .fetch_optional(&self.db)
            .await?
            .map(|value| MasterKey::from_slice(&value))
            .transpose()
            .map_err(|_| PgStoreError::InvalidFormat)
    }

    async fn store_master_key(&self, master_key: Option<&MasterKey>) -> Result<(), PgStoreError> {
        match master_key {
            Some(k) => {
                let value = k.inner.to_vec();
                sqlx::query!(
                    "INSERT INTO signal_kv (key, value) VALUES ('master_key', $1)
                     ON CONFLICT (key) DO UPDATE SET value = $1",
                    &value,
                )
                .execute(&self.db)
                .await?;
            }
            None => {
                sqlx::query!("DELETE FROM signal_kv WHERE key = 'master_key'")
                    .execute(&self.db)
                    .await?;
            }
        }
        Ok(())
    }
}

impl ProtocolStore for PgProtocolStore {}

#[async_trait(?Send)]
impl SessionStore for PgProtocolStore {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        let device_id: i32 = u32_to_i32(u32::from(address.device_id()))?;
        let identity = self.identity.as_str();
        let addr = address.name();
        sqlx::query_scalar!(
            "SELECT record FROM signal_sessions
             WHERE address = $1 AND device_id = $2 AND identity = $3",
            addr,
            device_id,
            identity,
        )
        .fetch_optional(&self.store.db)
        .await
        .into_protocol_error()?
        .map(|record| SessionRecord::deserialize(&record))
        .transpose()
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        let device_id: i32 = u32_to_i32(u32::from(address.device_id()))?;
        let identity = self.identity.as_str();
        let addr = address.name();
        let record = record.serialize()?;
        sqlx::query!(
            "INSERT INTO signal_sessions (address, device_id, identity, record)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (address, device_id, identity) DO UPDATE SET record = $4",
            addr,
            device_id,
            identity,
            &record,
        )
        .execute(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl SessionStoreExt for PgProtocolStore {
    async fn get_sub_device_sessions(
        &self,
        name: &ServiceId,
    ) -> Result<Vec<DeviceId>, SignalProtocolError> {
        let address = name.raw_uuid().to_string();
        let default_device: i32 = u32_to_i32(u32::from(*DEFAULT_DEVICE_ID))?;
        let identity = self.identity.as_str();
        sqlx::query_scalar!(
            "SELECT device_id FROM signal_sessions
             WHERE address = $1 AND device_id != $2 AND identity = $3",
            &address,
            default_device,
            identity,
        )
        .fetch_all(&self.store.db)
        .await
        .into_protocol_error()?
        .into_iter()
        .map(|id| {
            let v = i32_to_u32(id)?;
            let byte = u8::try_from(v).map_err(|_| {
                SignalProtocolError::InvalidState("device id", format!("{id} exceeds u8::MAX"))
            })?;
            DeviceId::new(byte).map_err(|_| {
                SignalProtocolError::InvalidState("device id", format!("invalid device id {id}"))
            })
        })
        .collect()
    }

    async fn delete_session(&self, address: &ProtocolAddress) -> Result<(), SignalProtocolError> {
        let device_id: i32 = u32_to_i32(u32::from(address.device_id()))?;
        let identity = self.identity.as_str();
        let addr = address.name();
        sqlx::query!(
            "DELETE FROM signal_sessions WHERE address = $1 AND device_id = $2 AND identity = $3",
            addr,
            device_id,
            identity,
        )
        .execute(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(())
    }

    async fn delete_all_sessions(&self, name: &ServiceId) -> Result<usize, SignalProtocolError> {
        let address = name.raw_uuid().to_string();
        let identity = self.identity.as_str();
        let res = sqlx::query!(
            "DELETE FROM signal_sessions WHERE address = $1 AND identity = $2",
            &address,
            identity,
        )
        .execute(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(usize::try_from(res.rows_affected()).unwrap_or(usize::MAX))
    }
}

#[async_trait(?Send)]
impl PreKeyStore for PgProtocolStore {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord, SignalProtocolError> {
        let id: i32 = u32_to_i32(u32::from(prekey_id))?;
        let identity = self.identity.as_str();
        let record = sqlx::query_scalar!(
            "SELECT record FROM signal_pre_keys WHERE id = $1 AND identity = $2",
            id,
            identity,
        )
        .fetch_one(&self.store.db)
        .await
        .into_protocol_error()?;
        PreKeyRecord::deserialize(&record)
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let id: i32 = u32_to_i32(u32::from(prekey_id))?;
        let identity = self.identity.as_str();
        let record = record.serialize()?;
        sqlx::query!(
            "INSERT INTO signal_pre_keys (id, identity, record)
             VALUES ($1, $2, $3)
             ON CONFLICT (id, identity) DO UPDATE SET record = $3",
            id,
            identity,
            &record,
        )
        .execute(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(())
    }

    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<(), SignalProtocolError> {
        let id: i32 = u32_to_i32(u32::from(prekey_id))?;
        let identity = self.identity.as_str();
        sqlx::query!(
            "DELETE FROM signal_pre_keys WHERE id = $1 AND identity = $2",
            id,
            identity,
        )
        .execute(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl PreKeysStore for PgProtocolStore {
    async fn next_pre_key_id(&self) -> Result<u32, SignalProtocolError> {
        let identity = self.identity.as_str();
        let max_id = sqlx::query_scalar!(
            "SELECT MAX(id) FROM signal_pre_keys WHERE identity = $1",
            identity,
        )
        .fetch_one(&self.store.db)
        .await
        .into_protocol_error()?;
        next_id_from_max(max_id)
    }

    async fn next_signed_pre_key_id(&self) -> Result<u32, SignalProtocolError> {
        let identity = self.identity.as_str();
        let max_id = sqlx::query_scalar!(
            "SELECT MAX(id) FROM signal_signed_pre_keys WHERE identity = $1",
            identity,
        )
        .fetch_one(&self.store.db)
        .await
        .into_protocol_error()?;
        next_id_from_max(max_id)
    }

    async fn next_pq_pre_key_id(&self) -> Result<u32, SignalProtocolError> {
        let identity = self.identity.as_str();
        let max_id = sqlx::query_scalar!(
            "SELECT MAX(id) FROM signal_kyber_pre_keys WHERE identity = $1",
            identity,
        )
        .fetch_one(&self.store.db)
        .await
        .into_protocol_error()?;
        next_id_from_max(max_id)
    }

    async fn signed_pre_keys_count(&self) -> Result<usize, SignalProtocolError> {
        let identity = self.identity.as_str();
        let count = sqlx::query_scalar!(
            "SELECT COUNT(*) AS \"count!\" FROM signal_signed_pre_keys WHERE identity = $1",
            identity,
        )
        .fetch_one(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(usize::try_from(count).unwrap_or(usize::MAX))
    }

    async fn kyber_pre_keys_count(&self, last_resort: bool) -> Result<usize, SignalProtocolError> {
        let identity = self.identity.as_str();
        let count = sqlx::query_scalar!(
            "SELECT COUNT(*) AS \"count!\" FROM signal_kyber_pre_keys
             WHERE identity = $1 AND is_last_resort = $2",
            identity,
            last_resort,
        )
        .fetch_one(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(usize::try_from(count).unwrap_or(usize::MAX))
    }

    async fn signed_prekey_id(&self) -> Result<Option<SignedPreKeyId>, SignalProtocolError> {
        let identity = self.identity.as_str();
        let max_id = sqlx::query_scalar!(
            "SELECT MAX(id) FROM signal_signed_pre_keys WHERE identity = $1",
            identity,
        )
        .fetch_one(&self.store.db)
        .await
        .into_protocol_error()?;
        max_id
            .map(|id| i32_to_u32(id).map(SignedPreKeyId::from))
            .transpose()
    }

    async fn last_resort_kyber_prekey_id(
        &self,
    ) -> Result<Option<KyberPreKeyId>, SignalProtocolError> {
        let identity = self.identity.as_str();
        let max_id = sqlx::query_scalar!(
            "SELECT MAX(id) FROM signal_kyber_pre_keys
             WHERE identity = $1 AND is_last_resort = TRUE",
            identity,
        )
        .fetch_one(&self.store.db)
        .await
        .into_protocol_error()?;
        max_id
            .map(|id| i32_to_u32(id).map(KyberPreKeyId::from))
            .transpose()
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for PgProtocolStore {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        let id: i32 = u32_to_i32(u32::from(signed_prekey_id))?;
        let identity = self.identity.as_str();
        let bytes = sqlx::query_scalar!(
            "SELECT record FROM signal_signed_pre_keys WHERE id = $1 AND identity = $2",
            id,
            identity,
        )
        .fetch_one(&self.store.db)
        .await
        .into_protocol_error()?;
        SignedPreKeyRecord::deserialize(&bytes)
    }

    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let id: i32 = u32_to_i32(u32::from(signed_prekey_id))?;
        let identity = self.identity.as_str();
        let bytes = record.serialize()?;
        sqlx::query!(
            "INSERT INTO signal_signed_pre_keys (id, identity, record)
             VALUES ($1, $2, $3)
             ON CONFLICT (id, identity) DO UPDATE SET record = $3",
            id,
            identity,
            &bytes,
        )
        .execute(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStore for PgProtocolStore {
    async fn get_kyber_pre_key(
        &self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        let id: i32 = u32_to_i32(u32::from(kyber_prekey_id))?;
        let identity = self.identity.as_str();
        let bytes = sqlx::query_scalar!(
            "SELECT record FROM signal_kyber_pre_keys WHERE id = $1 AND identity = $2",
            id,
            identity,
        )
        .fetch_one(&self.store.db)
        .await
        .into_protocol_error()?;
        KyberPreKeyRecord::deserialize(&bytes)
    }

    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let id: i32 = u32_to_i32(u32::from(kyber_prekey_id))?;
        let identity = self.identity.as_str();
        let record = record.serialize()?;
        sqlx::query!(
            "INSERT INTO signal_kyber_pre_keys (id, identity, record, is_last_resort)
             VALUES ($1, $2, $3, FALSE)
             ON CONFLICT (id, identity) DO UPDATE SET record = $3, is_last_resort = FALSE",
            id,
            identity,
            &record,
        )
        .execute(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(())
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        ec_prekey_id: SignedPreKeyId,
        base_key: &PublicKey,
    ) -> Result<(), SignalProtocolError> {
        let mut tx = self.store.db.begin().await.into_protocol_error()?;
        let kyber_id: i32 = u32_to_i32(u32::from(kyber_prekey_id))?;
        let identity = self.identity.as_str();

        let is_last_resort = sqlx::query_scalar!(
            "SELECT is_last_resort FROM signal_kyber_pre_keys WHERE id = $1 AND identity = $2",
            kyber_id,
            identity,
        )
        .fetch_one(&mut *tx)
        .await
        .into_protocol_error()?;

        if is_last_resort {
            let ec_id: i32 = u32_to_i32(u32::from(ec_prekey_id))?;
            let base_key_bytes = base_key.serialize().to_vec();

            let result = sqlx::query!(
                "INSERT INTO signal_base_keys_seen
                 (kyber_pre_key_id, signed_pre_key_id, identity, base_key)
                 VALUES ($1, $2, $3, $4)",
                kyber_id,
                ec_id,
                identity,
                &base_key_bytes,
            )
            .execute(&mut *tx)
            .await;

            match result {
                Err(sqlx::Error::Database(ref e)) if e.is_unique_violation() => {
                    return Err(SignalProtocolError::InvalidMessage(
                        CiphertextMessageType::PreKey,
                        "reused base key",
                    ));
                }
                other => {
                    other.into_protocol_error()?;
                }
            }
        } else {
            sqlx::query!(
                "DELETE FROM signal_kyber_pre_keys
                 WHERE id = $1 AND identity = $2 AND is_last_resort = FALSE",
                kyber_id,
                identity,
            )
            .execute(&mut *tx)
            .await
            .into_protocol_error()?;
        }

        tx.commit().await.into_protocol_error()?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStoreExt for PgProtocolStore {
    async fn store_last_resort_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let id: i32 = u32_to_i32(u32::from(kyber_prekey_id))?;
        let identity = self.identity.as_str();
        let record = record.serialize()?;
        sqlx::query!(
            "INSERT INTO signal_kyber_pre_keys (id, identity, record, is_last_resort)
             VALUES ($1, $2, $3, TRUE)
             ON CONFLICT (id, identity) DO UPDATE SET is_last_resort = TRUE, record = $3",
            id,
            identity,
            &record,
        )
        .execute(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(())
    }

    async fn load_last_resort_kyber_pre_keys(
        &self,
    ) -> Result<Vec<KyberPreKeyRecord>, SignalProtocolError> {
        let identity = self.identity.as_str();
        sqlx::query_scalar!(
            "SELECT record FROM signal_kyber_pre_keys
             WHERE identity = $1 AND is_last_resort = TRUE",
            identity,
        )
        .fetch_all(&self.store.db)
        .await
        .into_protocol_error()?
        .into_iter()
        .map(|record| KyberPreKeyRecord::deserialize(&record))
        .collect()
    }

    async fn remove_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<(), SignalProtocolError> {
        let id: i32 = u32_to_i32(u32::from(kyber_prekey_id))?;
        let identity = self.identity.as_str();
        sqlx::query!(
            "DELETE FROM signal_kyber_pre_keys WHERE id = $1 AND identity = $2",
            id,
            identity,
        )
        .execute(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(())
    }

    async fn mark_all_one_time_kyber_pre_keys_stale_if_necessary(
        &mut self,
        stale_time: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), SignalProtocolError> {
        let identity = self.identity.as_str();
        sqlx::query!(
            "UPDATE signal_kyber_pre_keys
             SET stale_at = $1
             WHERE identity = $2 AND is_last_resort = FALSE AND stale_at IS NULL",
            stale_time,
            identity,
        )
        .execute(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(())
    }

    async fn delete_all_stale_one_time_kyber_pre_keys(
        &mut self,
        threshold: chrono::DateTime<chrono::Utc>,
        min_count: usize,
    ) -> Result<(), SignalProtocolError> {
        let identity = self.identity.as_str();
        let min_count = i64::try_from(min_count).unwrap_or(i64::MAX);
        sqlx::query!(
            "WITH total AS (
                SELECT COUNT(*) AS cnt FROM signal_kyber_pre_keys
                WHERE identity = $1 AND is_last_resort = FALSE
            )
            DELETE FROM signal_kyber_pre_keys
            WHERE identity = $1 AND is_last_resort = FALSE
              AND stale_at IS NOT NULL AND stale_at < $2
              AND (SELECT cnt FROM total) > $3",
            identity,
            threshold,
            min_count,
        )
        .execute(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl IdentityKeyStore for PgProtocolStore {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        let key = self.identity.identity_key_pair_key();
        let bytes = sqlx::query_scalar!("SELECT value FROM signal_kv WHERE key = $1", key,)
            .fetch_one(&self.store.db)
            .await
            .into_protocol_error()?;
        IdentityKeyPair::try_from(&*bytes)
    }

    async fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        let data = self
            .store
            .load_registration_data()
            .await
            .into_protocol_error()?
            .ok_or_else(|| {
                SignalProtocolError::InvalidState(
                    "failed to load registration ID",
                    "no registration data".into(),
                )
            })?;
        Ok(data.registration_id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity_key: &IdentityKey,
    ) -> Result<IdentityChange, SignalProtocolError> {
        let existing = self.get_identity(address).await?;

        let addr = address.name();
        let identity = self.identity.as_str();
        let bytes = identity_key.serialize().to_vec();

        sqlx::query!(
            "INSERT INTO signal_identities (address, identity, record)
             VALUES ($1, $2, $3)
             ON CONFLICT (address, identity) DO UPDATE SET record = $3",
            addr,
            identity,
            &bytes,
        )
        .execute(&self.store.db)
        .await
        .into_protocol_error()?;

        Ok(match existing {
            Some(k) if k == *identity_key => IdentityChange::NewOrUnchanged,
            Some(_) => IdentityChange::ReplacedExisting,
            None => IdentityChange::NewOrUnchanged,
        })
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity_key: &IdentityKey,
        _direction: Direction,
    ) -> Result<bool, SignalProtocolError> {
        match self.get_identity(address).await? {
            Some(trusted_key) if identity_key == &trusted_key => Ok(true),
            Some(_) => {
                warn!(%address, "trusting changed identity");
                Ok(true)
            }
            None => {
                warn!(%address, "trusting new identity");
                Ok(true)
            }
        }
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        let addr = address.name();
        let identity = self.identity.as_str();
        sqlx::query_scalar!(
            "SELECT record FROM signal_identities WHERE address = $1 AND identity = $2",
            addr,
            identity,
        )
        .fetch_optional(&self.store.db)
        .await
        .into_protocol_error()?
        .map(|bytes| IdentityKey::decode(&bytes))
        .transpose()
    }
}

#[async_trait(?Send)]
impl SenderKeyStore for PgProtocolStore {
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let device_id: i32 = u32_to_i32(u32::from(sender.device_id()))?;
        let identity = self.identity.as_str();
        let addr = sender.name();
        let record = record.serialize()?;
        sqlx::query!(
            "INSERT INTO signal_sender_keys
             (address, device_id, identity, distribution_id, record)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (address, device_id, identity, distribution_id) DO UPDATE SET record = $5",
            addr,
            device_id,
            identity,
            distribution_id,
            &record,
        )
        .execute(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(())
    }

    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        let device_id: i32 = u32_to_i32(u32::from(sender.device_id()))?;
        let identity = self.identity.as_str();
        let addr = sender.name();
        sqlx::query_scalar!(
            "SELECT record FROM signal_sender_keys
             WHERE address = $1 AND device_id = $2 AND identity = $3 AND distribution_id = $4",
            addr,
            device_id,
            identity,
            distribution_id,
        )
        .fetch_optional(&self.store.db)
        .await
        .into_protocol_error()?
        .map(|record| SenderKeyRecord::deserialize(&record))
        .transpose()
    }
}

type EmptyIter<T> = std::iter::Empty<Result<T, PgStoreError>>;

impl ContentsStore for PgSignalStore {
    type ContentsStoreError = PgStoreError;
    type ContactsIter = EmptyIter<Contact>;
    type GroupsIter = EmptyIter<(GroupMasterKeyBytes, Group)>;
    type MessagesIter = EmptyIter<Content>;
    type StickerPacksIter = EmptyIter<StickerPack>;

    async fn clear_profiles(&mut self) -> Result<(), PgStoreError> {
        sqlx::query!("DELETE FROM signal_profile_keys")
            .execute(&self.db)
            .await?;
        Ok(())
    }

    async fn clear_contents(&mut self) -> Result<(), PgStoreError> {
        Ok(())
    }

    async fn clear_messages(&mut self) -> Result<(), PgStoreError> {
        Ok(())
    }

    async fn clear_thread(&mut self, _thread: &Thread) -> Result<(), PgStoreError> {
        Ok(())
    }

    async fn save_message(&self, _thread: &Thread, _message: Content) -> Result<(), PgStoreError> {
        Ok(())
    }

    async fn delete_message(
        &mut self,
        _thread: &Thread,
        _timestamp: u64,
    ) -> Result<bool, PgStoreError> {
        Ok(false)
    }

    async fn message(
        &self,
        _thread: &Thread,
        _timestamp: u64,
    ) -> Result<Option<Content>, PgStoreError> {
        Ok(None)
    }

    async fn messages(
        &self,
        _thread: &Thread,
        _range: impl RangeBounds<u64>,
    ) -> Result<Self::MessagesIter, PgStoreError> {
        Ok(std::iter::empty())
    }

    async fn clear_contacts(&mut self) -> Result<(), PgStoreError> {
        Ok(())
    }

    async fn save_contact(&mut self, _contact: &Contact) -> Result<(), PgStoreError> {
        Ok(())
    }

    async fn contacts(&self) -> Result<Self::ContactsIter, PgStoreError> {
        Ok(std::iter::empty())
    }

    async fn contact_by_id(&self, _id: &ServiceId) -> Result<Option<Contact>, PgStoreError> {
        Ok(None)
    }

    async fn clear_groups(&mut self) -> Result<(), PgStoreError> {
        Ok(())
    }

    async fn save_group(
        &self,
        _master_key: GroupMasterKeyBytes,
        _group: impl Into<Group>,
    ) -> Result<(), PgStoreError> {
        Ok(())
    }

    async fn groups(&self) -> Result<Self::GroupsIter, PgStoreError> {
        Ok(std::iter::empty())
    }

    async fn group(&self, _master_key: GroupMasterKeyBytes) -> Result<Option<Group>, PgStoreError> {
        Ok(None)
    }

    async fn save_group_avatar(
        &self,
        _master_key: GroupMasterKeyBytes,
        _avatar: &AvatarBytes,
    ) -> Result<(), PgStoreError> {
        Ok(())
    }

    async fn group_avatar(
        &self,
        _master_key: GroupMasterKeyBytes,
    ) -> Result<Option<AvatarBytes>, PgStoreError> {
        Ok(None)
    }

    async fn upsert_profile_key(
        &mut self,
        uuid: &Uuid,
        key: ProfileKey,
    ) -> Result<bool, PgStoreError> {
        let key_bytes = key.bytes.to_vec();
        let inserted = sqlx::query_scalar!(
            "INSERT INTO signal_profile_keys (uuid, key) VALUES ($1, $2)
             ON CONFLICT (uuid) DO UPDATE SET key = $2
             RETURNING (xmax = 0) AS \"inserted!\"",
            uuid,
            &key_bytes,
        )
        .fetch_one(&self.db)
        .await?;
        Ok(inserted)
    }

    async fn profile_key(
        &self,
        service_id: &ServiceId,
    ) -> Result<Option<ProfileKey>, PgStoreError> {
        let uuid: Uuid = service_id.raw_uuid();
        let row = sqlx::query!("SELECT key FROM signal_profile_keys WHERE uuid = $1", uuid,)
            .fetch_optional(&self.db)
            .await?;

        Ok(match row {
            Some(r) => match <[u8; 32]>::try_from(r.key.as_slice()) {
                Ok(arr) => Some(ProfileKey { bytes: arr }),
                Err(_) => {
                    warn!(%uuid, len = r.key.len(), "corrupted profile key, expected 32 bytes");
                    None
                }
            },
            None => None,
        })
    }

    async fn save_profile(
        &mut self,
        _uuid: Uuid,
        _key: ProfileKey,
        _profile: Profile,
    ) -> Result<(), PgStoreError> {
        Ok(())
    }

    async fn profile(
        &self,
        _uuid: Uuid,
        _key: ProfileKey,
    ) -> Result<Option<Profile>, PgStoreError> {
        Ok(None)
    }

    async fn save_profile_avatar(
        &mut self,
        _uuid: Uuid,
        _key: ProfileKey,
        _profile: &AvatarBytes,
    ) -> Result<(), PgStoreError> {
        Ok(())
    }

    async fn profile_avatar(
        &self,
        _uuid: Uuid,
        _key: ProfileKey,
    ) -> Result<Option<AvatarBytes>, PgStoreError> {
        Ok(None)
    }

    async fn add_sticker_pack(&mut self, _pack: &StickerPack) -> Result<(), PgStoreError> {
        Ok(())
    }

    async fn sticker_pack(&self, _id: &[u8]) -> Result<Option<StickerPack>, PgStoreError> {
        Ok(None)
    }

    async fn remove_sticker_pack(&mut self, _id: &[u8]) -> Result<bool, PgStoreError> {
        Ok(false)
    }

    async fn sticker_packs(&self) -> Result<Self::StickerPacksIter, PgStoreError> {
        Ok(std::iter::empty())
    }
}
