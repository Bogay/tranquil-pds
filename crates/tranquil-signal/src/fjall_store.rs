use std::ops::RangeBounds;
use std::sync::Arc;

use async_trait::async_trait;
use fjall::{Database, Keyspace};
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
use tracing::warn;

use crate::{DeviceName, LinkResult, SignalClient, SignalError};

#[derive(Debug, thiserror::Error)]
pub enum FjallStoreError {
    #[error("fjall: {0}")]
    Fjall(#[from] fjall::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("protocol: {0}")]
    Protocol(#[from] SignalProtocolError),
    #[error("not found: {0}")]
    NotFound(String),
}

impl presage::store::StoreError for FjallStoreError {}

#[derive(Clone)]
pub struct FjallSignalStore {
    db: Database,
    ks: Keyspace,
}

#[derive(Clone)]
pub struct FjallProtocolStore {
    store: FjallSignalStore,
    identity: IdentityType,
}

#[derive(Debug, Clone, Copy)]
enum IdentityType {
    Aci,
    Pni,
}

impl IdentityType {
    fn tag(self) -> u8 {
        match self {
            Self::Aci => b'a',
            Self::Pni => b'p',
        }
    }
}

fn kv_key(name: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + name.len());
    k.push(b'K');
    k.extend_from_slice(name);
    k
}

fn session_key(identity: IdentityType, address: &str, device_id: u32) -> Vec<u8> {
    let mut k = Vec::with_capacity(2 + address.len() + 1 + 4);
    k.push(b'S');
    k.push(identity.tag());
    k.extend_from_slice(address.as_bytes());
    k.push(0);
    k.extend_from_slice(&device_id.to_be_bytes());
    k
}

fn session_prefix(identity: IdentityType, address: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(2 + address.len() + 1);
    k.push(b'S');
    k.push(identity.tag());
    k.extend_from_slice(address.as_bytes());
    k.push(0);
    k
}

fn identity_rec_key(identity: IdentityType, address: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(2 + address.len());
    k.push(b'I');
    k.push(identity.tag());
    k.extend_from_slice(address.as_bytes());
    k
}

fn pre_key_key(identity: IdentityType, id: u32) -> Vec<u8> {
    let mut k = vec![b'P', identity.tag()];
    k.extend_from_slice(&id.to_be_bytes());
    k
}

fn pre_key_prefix(identity: IdentityType) -> Vec<u8> {
    vec![b'P', identity.tag()]
}

fn signed_pre_key_key(identity: IdentityType, id: u32) -> Vec<u8> {
    let mut k = vec![b'G', identity.tag()];
    k.extend_from_slice(&id.to_be_bytes());
    k
}

fn signed_pre_key_prefix(identity: IdentityType) -> Vec<u8> {
    vec![b'G', identity.tag()]
}

fn kyber_key(identity: IdentityType, id: u32) -> Vec<u8> {
    let mut k = vec![b'Q', identity.tag()];
    k.extend_from_slice(&id.to_be_bytes());
    k
}

fn kyber_prefix(identity: IdentityType) -> Vec<u8> {
    vec![b'Q', identity.tag()]
}

fn sender_key_key(
    identity: IdentityType,
    address: &str,
    device_id: u32,
    distribution_id: Uuid,
) -> Vec<u8> {
    let mut k = Vec::with_capacity(2 + address.len() + 1 + 4 + 16);
    k.push(b'N');
    k.push(identity.tag());
    k.extend_from_slice(address.as_bytes());
    k.push(0);
    k.extend_from_slice(&device_id.to_be_bytes());
    k.extend_from_slice(distribution_id.as_bytes());
    k
}

fn base_key_seen_key(
    identity: IdentityType,
    kyber_id: u32,
    signed_id: u32,
    base_key: &[u8],
) -> Vec<u8> {
    let mut k = Vec::with_capacity(2 + 4 + 4 + base_key.len());
    k.push(b'B');
    k.push(identity.tag());
    k.extend_from_slice(&kyber_id.to_be_bytes());
    k.extend_from_slice(&signed_id.to_be_bytes());
    k.extend_from_slice(base_key);
    k
}

fn profile_key_key(uuid: &Uuid) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 16);
    k.push(b'R');
    k.extend_from_slice(uuid.as_bytes());
    k
}

const KYBER_META_SIZE: usize = 1 + 8;

fn encode_kyber_value(record: &[u8], is_last_resort: bool, stale_at_ms: Option<i64>) -> Vec<u8> {
    let mut v = Vec::with_capacity(KYBER_META_SIZE + record.len());
    v.push(u8::from(is_last_resort));
    v.extend_from_slice(&stale_at_ms.unwrap_or(0).to_be_bytes());
    v.extend_from_slice(record);
    v
}

fn decode_kyber_value(data: &[u8]) -> Option<(bool, Option<i64>, &[u8])> {
    (data.len() >= KYBER_META_SIZE).then_some(())?;
    let is_last_resort = data[0] != 0;
    let stale_ms = i64::from_be_bytes(data[1..9].try_into().ok()?);
    let stale_at = (stale_ms != 0).then_some(stale_ms);
    Some((is_last_resort, stale_at, &data[KYBER_META_SIZE..]))
}

fn into_protocol_err<E: std::fmt::Display>(e: E) -> SignalProtocolError {
    SignalProtocolError::InvalidState("fjall", e.to_string())
}

fn guard_to_kv(guard: fjall::Guard) -> Result<fjall::KvPair, fjall::Error> {
    guard.into_inner()
}

fn max_id_in_prefix(ks: &Keyspace, prefix: &[u8]) -> Result<Option<u32>, SignalProtocolError> {
    let mut max: Option<u32> = None;
    ks.prefix(prefix).try_for_each(|guard| {
        let (key_bytes, _) = guard_to_kv(guard).map_err(into_protocol_err)?;
        let id_offset = prefix.len();
        if key_bytes.len() >= id_offset + 4 {
            let id = u32::from_be_bytes(
                key_bytes[id_offset..id_offset + 4]
                    .try_into()
                    .map_err(into_protocol_err)?,
            );
            max = Some(max.map_or(id, |m| m.max(id)));
        }
        Ok::<(), SignalProtocolError>(())
    })?;
    Ok(max)
}

fn next_id_from_max(max_id: Option<u32>) -> Result<u32, SignalProtocolError> {
    match max_id {
        None => Ok(1),
        Some(id) => id.checked_add(1).ok_or_else(|| {
            SignalProtocolError::InvalidState(
                "pre key id space exhausted",
                format!("max id {id} has no successor"),
            )
        }),
    }
}

impl FjallSignalStore {
    pub fn new(db: Database, ks: Keyspace) -> Self {
        Self { db, ks }
    }

    pub fn is_linked(&self) -> Result<bool, FjallStoreError> {
        Ok(self.ks.get(kv_key(b"registration"))?.is_some())
    }

    pub fn clear_all(&self) -> Result<(), FjallStoreError> {
        let mut batch = self.db.batch();
        self.ks.prefix([]).try_for_each(|guard| {
            let (key, _) = guard.into_inner()?;
            batch.remove(&self.ks, key.as_ref());
            Ok::<(), fjall::Error>(())
        })?;
        batch.commit()?;
        Ok(())
    }

    fn set_identity_key_pair(
        &self,
        identity: IdentityType,
        key_pair: IdentityKeyPair,
    ) -> Result<(), FjallStoreError> {
        let key_name = match identity {
            IdentityType::Aci => b"identity_keypair_aci".as_slice(),
            IdentityType::Pni => b"identity_keypair_pni".as_slice(),
        };
        let serialized = key_pair.serialize();
        self.ks.insert(kv_key(key_name), &*serialized)?;
        Ok(())
    }
}

impl Store for FjallSignalStore {
    type Error = FjallStoreError;
    type AciStore = FjallProtocolStore;
    type PniStore = FjallProtocolStore;

    async fn clear(&mut self) -> Result<(), FjallStoreError> {
        self.clear_all()
    }

    fn aci_protocol_store(&self) -> Self::AciStore {
        FjallProtocolStore {
            store: self.clone(),
            identity: IdentityType::Aci,
        }
    }

    fn pni_protocol_store(&self) -> Self::PniStore {
        FjallProtocolStore {
            store: self.clone(),
            identity: IdentityType::Pni,
        }
    }
}

impl StateStore for FjallSignalStore {
    type StateStoreError = FjallStoreError;

    async fn load_registration_data(&self) -> Result<Option<RegistrationData>, FjallStoreError> {
        self.ks
            .get(kv_key(b"registration"))?
            .map(|v| serde_json::from_slice(&v))
            .transpose()
            .map_err(From::from)
    }

    async fn save_registration_data(
        &mut self,
        state: &RegistrationData,
    ) -> Result<(), FjallStoreError> {
        let value = serde_json::to_vec(state)?;
        self.ks.insert(kv_key(b"registration"), &value)?;
        Ok(())
    }

    async fn is_registered(&self) -> bool {
        self.ks
            .get(kv_key(b"registration"))
            .ok()
            .flatten()
            .is_some()
    }

    async fn clear_registration(&mut self) -> Result<(), FjallStoreError> {
        let protocol_tags: &[u8] = b"SIPGQNB";
        let mut batch = self.db.batch();
        batch.remove(&self.ks, kv_key(b"registration"));
        self.ks.prefix([]).try_for_each(|guard| {
            let (key, _) = guard.into_inner()?;
            if key.first().is_some_and(|b| protocol_tags.contains(b)) {
                batch.remove(&self.ks, key.as_ref());
            }
            Ok::<(), fjall::Error>(())
        })?;
        batch.commit()?;
        Ok(())
    }

    async fn set_aci_identity_key_pair(
        &self,
        key_pair: IdentityKeyPair,
    ) -> Result<(), FjallStoreError> {
        self.set_identity_key_pair(IdentityType::Aci, key_pair)
    }

    async fn set_pni_identity_key_pair(
        &self,
        key_pair: IdentityKeyPair,
    ) -> Result<(), FjallStoreError> {
        self.set_identity_key_pair(IdentityType::Pni, key_pair)
    }

    async fn sender_certificate(&self) -> Result<Option<SenderCertificate>, FjallStoreError> {
        self.ks
            .get(kv_key(b"sender_certificate"))?
            .map(|v| SenderCertificate::deserialize(&v))
            .transpose()
            .map_err(From::from)
    }

    async fn save_sender_certificate(
        &self,
        certificate: &SenderCertificate,
    ) -> Result<(), FjallStoreError> {
        let serialized = certificate.serialized()?;
        self.ks.insert(kv_key(b"sender_certificate"), serialized)?;
        Ok(())
    }

    async fn fetch_master_key(&self) -> Result<Option<MasterKey>, FjallStoreError> {
        self.ks
            .get(kv_key(b"master_key"))?
            .map(|v| MasterKey::from_slice(&v))
            .transpose()
            .map_err(|_| FjallStoreError::NotFound("master key has wrong length".into()))
    }

    async fn store_master_key(
        &self,
        master_key: Option<&MasterKey>,
    ) -> Result<(), FjallStoreError> {
        match master_key {
            Some(k) => self.ks.insert(kv_key(b"master_key"), k.inner)?,
            None => self.ks.remove(kv_key(b"master_key"))?,
        }
        Ok(())
    }
}

impl ProtocolStore for FjallProtocolStore {}

#[async_trait(?Send)]
impl SessionStore for FjallProtocolStore {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        let key = session_key(
            self.identity,
            address.name(),
            u32::from(address.device_id()),
        );
        self.store
            .ks
            .get(key)
            .map_err(into_protocol_err)?
            .map(|v| SessionRecord::deserialize(&v))
            .transpose()
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        let key = session_key(
            self.identity,
            address.name(),
            u32::from(address.device_id()),
        );
        let serialized = record.serialize()?;
        self.store
            .ks
            .insert(key, serialized.as_slice())
            .map_err(into_protocol_err)
    }
}

#[async_trait(?Send)]
impl SessionStoreExt for FjallProtocolStore {
    async fn get_sub_device_sessions(
        &self,
        name: &ServiceId,
    ) -> Result<Vec<DeviceId>, SignalProtocolError> {
        let address = name.raw_uuid().to_string();
        let default_device = u32::from(*DEFAULT_DEVICE_ID);
        let prefix = session_prefix(self.identity, &address);
        let prefix_len = prefix.len();

        let mut devices = Vec::new();
        self.store.ks.prefix(prefix).try_for_each(|guard| {
            let (key, _) = guard_to_kv(guard).map_err(into_protocol_err)?;
            if key.len() >= prefix_len + 4 {
                let id = u32::from_be_bytes(
                    key[prefix_len..prefix_len + 4]
                        .try_into()
                        .map_err(into_protocol_err)?,
                );
                if id != default_device
                    && let Ok(byte) = u8::try_from(id)
                    && let Ok(device_id) = DeviceId::new(byte)
                {
                    devices.push(device_id);
                }
            }
            Ok::<(), SignalProtocolError>(())
        })?;
        Ok(devices)
    }

    async fn delete_session(&self, address: &ProtocolAddress) -> Result<(), SignalProtocolError> {
        let key = session_key(
            self.identity,
            address.name(),
            u32::from(address.device_id()),
        );
        self.store.ks.remove(key).map_err(into_protocol_err)
    }

    async fn delete_all_sessions(&self, name: &ServiceId) -> Result<usize, SignalProtocolError> {
        let address = name.raw_uuid().to_string();
        let prefix = session_prefix(self.identity, &address);
        let mut batch = self.store.db.batch();
        let mut count = 0usize;
        self.store.ks.prefix(prefix).try_for_each(|guard| {
            let (key, _) = guard_to_kv(guard).map_err(into_protocol_err)?;
            batch.remove(&self.store.ks, key.as_ref());
            count = count.saturating_add(1);
            Ok::<(), SignalProtocolError>(())
        })?;
        batch.commit().map_err(into_protocol_err)?;
        Ok(count)
    }
}

#[async_trait(?Send)]
impl PreKeyStore for FjallProtocolStore {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord, SignalProtocolError> {
        let key = pre_key_key(self.identity, u32::from(prekey_id));
        let data = self
            .store
            .ks
            .get(key)
            .map_err(into_protocol_err)?
            .ok_or(SignalProtocolError::InvalidPreKeyId)?;
        PreKeyRecord::deserialize(&data)
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let key = pre_key_key(self.identity, u32::from(prekey_id));
        let serialized = record.serialize()?;
        self.store
            .ks
            .insert(key, serialized.as_slice())
            .map_err(into_protocol_err)
    }

    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<(), SignalProtocolError> {
        let key = pre_key_key(self.identity, u32::from(prekey_id));
        self.store.ks.remove(key).map_err(into_protocol_err)
    }
}

#[async_trait(?Send)]
impl PreKeysStore for FjallProtocolStore {
    async fn next_pre_key_id(&self) -> Result<u32, SignalProtocolError> {
        next_id_from_max(max_id_in_prefix(
            &self.store.ks,
            &pre_key_prefix(self.identity),
        )?)
    }

    async fn next_signed_pre_key_id(&self) -> Result<u32, SignalProtocolError> {
        next_id_from_max(max_id_in_prefix(
            &self.store.ks,
            &signed_pre_key_prefix(self.identity),
        )?)
    }

    async fn next_pq_pre_key_id(&self) -> Result<u32, SignalProtocolError> {
        next_id_from_max(max_id_in_prefix(
            &self.store.ks,
            &kyber_prefix(self.identity),
        )?)
    }

    async fn signed_pre_keys_count(&self) -> Result<usize, SignalProtocolError> {
        let prefix = signed_pre_key_prefix(self.identity);
        let mut count = 0usize;
        self.store.ks.prefix(prefix).try_for_each(|guard| {
            guard_to_kv(guard).map_err(into_protocol_err)?;
            count = count.saturating_add(1);
            Ok::<(), SignalProtocolError>(())
        })?;
        Ok(count)
    }

    async fn kyber_pre_keys_count(&self, last_resort: bool) -> Result<usize, SignalProtocolError> {
        let prefix = kyber_prefix(self.identity);
        let mut count = 0usize;
        self.store.ks.prefix(prefix).try_for_each(|guard| {
            let (_, val) = guard_to_kv(guard).map_err(into_protocol_err)?;
            if decode_kyber_value(&val).is_some_and(|(is_lr, _, _)| is_lr == last_resort) {
                count = count.saturating_add(1);
            }
            Ok::<(), SignalProtocolError>(())
        })?;
        Ok(count)
    }

    async fn signed_prekey_id(&self) -> Result<Option<SignedPreKeyId>, SignalProtocolError> {
        max_id_in_prefix(&self.store.ks, &signed_pre_key_prefix(self.identity))
            .map(|opt| opt.map(SignedPreKeyId::from))
    }

    async fn last_resort_kyber_prekey_id(
        &self,
    ) -> Result<Option<KyberPreKeyId>, SignalProtocolError> {
        let prefix = kyber_prefix(self.identity);
        let prefix_len = prefix.len();
        let mut max: Option<u32> = None;
        self.store.ks.prefix(prefix).try_for_each(|guard| {
            let (key, val) = guard_to_kv(guard).map_err(into_protocol_err)?;
            if let Some((true, _, _)) = decode_kyber_value(&val)
                && key.len() >= prefix_len + 4
            {
                let id = u32::from_be_bytes(
                    key[prefix_len..prefix_len + 4]
                        .try_into()
                        .map_err(into_protocol_err)?,
                );
                max = Some(max.map_or(id, |m| m.max(id)));
            }
            Ok::<(), SignalProtocolError>(())
        })?;
        Ok(max.map(KyberPreKeyId::from))
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for FjallProtocolStore {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        let key = signed_pre_key_key(self.identity, u32::from(signed_prekey_id));
        let data = self
            .store
            .ks
            .get(key)
            .map_err(into_protocol_err)?
            .ok_or(SignalProtocolError::InvalidSignedPreKeyId)?;
        SignedPreKeyRecord::deserialize(&data)
    }

    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let key = signed_pre_key_key(self.identity, u32::from(signed_prekey_id));
        let serialized = record.serialize()?;
        self.store
            .ks
            .insert(key, serialized.as_slice())
            .map_err(into_protocol_err)
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStore for FjallProtocolStore {
    async fn get_kyber_pre_key(
        &self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        let key = kyber_key(self.identity, u32::from(kyber_prekey_id));
        let data = self
            .store
            .ks
            .get(key)
            .map_err(into_protocol_err)?
            .ok_or(SignalProtocolError::InvalidKyberPreKeyId)?;
        let (_, _, record) = decode_kyber_value(&data).ok_or_else(|| {
            SignalProtocolError::InvalidState("kyber", "corrupted kyber pre key record".into())
        })?;
        KyberPreKeyRecord::deserialize(record)
    }

    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let key = kyber_key(self.identity, u32::from(kyber_prekey_id));
        let serialized = record.serialize()?;
        let value = encode_kyber_value(&serialized, false, None);
        self.store.ks.insert(key, &value).map_err(into_protocol_err)
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        ec_prekey_id: SignedPreKeyId,
        base_key: &PublicKey,
    ) -> Result<(), SignalProtocolError> {
        let key = kyber_key(self.identity, u32::from(kyber_prekey_id));
        let data = self
            .store
            .ks
            .get(&key)
            .map_err(into_protocol_err)?
            .ok_or(SignalProtocolError::InvalidKyberPreKeyId)?;
        let (is_last_resort, _, _) = decode_kyber_value(&data).ok_or_else(|| {
            SignalProtocolError::InvalidState("kyber", "corrupted kyber pre key record".into())
        })?;

        if is_last_resort {
            let base_key_bytes = base_key.serialize();
            let seen_key = base_key_seen_key(
                self.identity,
                u32::from(kyber_prekey_id),
                u32::from(ec_prekey_id),
                base_key_bytes.as_ref(),
            );
            if self
                .store
                .ks
                .get(&seen_key)
                .map_err(into_protocol_err)?
                .is_some()
            {
                return Err(SignalProtocolError::InvalidMessage(
                    CiphertextMessageType::PreKey,
                    "reused base key",
                ));
            }
            self.store
                .ks
                .insert(seen_key, [])
                .map_err(into_protocol_err)?;
        } else {
            self.store.ks.remove(key).map_err(into_protocol_err)?;
        }
        Ok(())
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStoreExt for FjallProtocolStore {
    async fn store_last_resort_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let key = kyber_key(self.identity, u32::from(kyber_prekey_id));
        let serialized = record.serialize()?;
        let value = encode_kyber_value(&serialized, true, None);
        self.store.ks.insert(key, &value).map_err(into_protocol_err)
    }

    async fn load_last_resort_kyber_pre_keys(
        &self,
    ) -> Result<Vec<KyberPreKeyRecord>, SignalProtocolError> {
        let prefix = kyber_prefix(self.identity);
        let mut result = Vec::new();
        self.store.ks.prefix(prefix).try_for_each(|guard| {
            let (_, val) = guard_to_kv(guard).map_err(into_protocol_err)?;
            if let Some((true, _, record)) = decode_kyber_value(&val) {
                result.push(KyberPreKeyRecord::deserialize(record)?);
            }
            Ok::<(), SignalProtocolError>(())
        })?;
        Ok(result)
    }

    async fn remove_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<(), SignalProtocolError> {
        let key = kyber_key(self.identity, u32::from(kyber_prekey_id));
        self.store.ks.remove(key).map_err(into_protocol_err)
    }

    async fn mark_all_one_time_kyber_pre_keys_stale_if_necessary(
        &mut self,
        stale_time: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), SignalProtocolError> {
        let stale_ms = stale_time.timestamp_millis();
        let prefix = kyber_prefix(self.identity);
        let mut batch = self.store.db.batch();
        self.store.ks.prefix(&prefix).try_for_each(|guard| {
            let (key, val) = guard_to_kv(guard).map_err(into_protocol_err)?;
            if let Some((false, None, record)) = decode_kyber_value(&val) {
                let new_val = encode_kyber_value(record, false, Some(stale_ms));
                batch.insert(&self.store.ks, key.as_ref(), &new_val);
            }
            Ok::<(), SignalProtocolError>(())
        })?;
        batch.commit().map_err(into_protocol_err)
    }

    async fn delete_all_stale_one_time_kyber_pre_keys(
        &mut self,
        threshold: chrono::DateTime<chrono::Utc>,
        min_count: usize,
    ) -> Result<(), SignalProtocolError> {
        let threshold_ms = threshold.timestamp_millis();
        let prefix = kyber_prefix(self.identity);

        let mut total_one_time = 0usize;
        self.store.ks.prefix(&prefix).try_for_each(|guard| {
            let (_, val) = guard_to_kv(guard).map_err(into_protocol_err)?;
            if decode_kyber_value(&val).is_some_and(|(is_lr, _, _)| !is_lr) {
                total_one_time = total_one_time.saturating_add(1);
            }
            Ok::<(), SignalProtocolError>(())
        })?;

        if total_one_time <= min_count {
            return Ok(());
        }

        let mut batch = self.store.db.batch();
        self.store.ks.prefix(&prefix).try_for_each(|guard| {
            let (key, val) = guard_to_kv(guard).map_err(into_protocol_err)?;
            if let Some((false, Some(stale_at), _)) = decode_kyber_value(&val)
                && stale_at < threshold_ms
            {
                batch.remove(&self.store.ks, key.as_ref());
            }
            Ok::<(), SignalProtocolError>(())
        })?;
        batch.commit().map_err(into_protocol_err)
    }
}

#[async_trait(?Send)]
impl IdentityKeyStore for FjallProtocolStore {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        let key_name = match self.identity {
            IdentityType::Aci => b"identity_keypair_aci".as_slice(),
            IdentityType::Pni => b"identity_keypair_pni".as_slice(),
        };
        let bytes = self
            .store
            .ks
            .get(kv_key(key_name))
            .map_err(into_protocol_err)?
            .ok_or_else(|| {
                SignalProtocolError::InvalidState("identity key pair", "not found in store".into())
            })?;
        IdentityKeyPair::try_from(&*bytes)
    }

    async fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        let data = self
            .store
            .load_registration_data()
            .await
            .map_err(into_protocol_err)?
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
        identity_key_val: &IdentityKey,
    ) -> Result<IdentityChange, SignalProtocolError> {
        let existing = self.get_identity(address).await?;

        let key = identity_rec_key(self.identity, address.name());
        let serialized = identity_key_val.serialize();
        self.store
            .ks
            .insert(key, &*serialized)
            .map_err(into_protocol_err)?;

        Ok(match existing {
            Some(k) if k == *identity_key_val => IdentityChange::NewOrUnchanged,
            Some(_) => IdentityChange::ReplacedExisting,
            None => IdentityChange::NewOrUnchanged,
        })
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity_key_val: &IdentityKey,
        _direction: Direction,
    ) -> Result<bool, SignalProtocolError> {
        match self.get_identity(address).await? {
            Some(trusted_key) if identity_key_val == &trusted_key => Ok(true),
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
        let key = identity_rec_key(self.identity, address.name());
        self.store
            .ks
            .get(key)
            .map_err(into_protocol_err)?
            .map(|bytes| IdentityKey::decode(&bytes))
            .transpose()
    }
}

#[async_trait(?Send)]
impl SenderKeyStore for FjallProtocolStore {
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let key = sender_key_key(
            self.identity,
            sender.name(),
            u32::from(sender.device_id()),
            distribution_id,
        );
        let serialized = record.serialize()?;
        self.store
            .ks
            .insert(key, serialized.as_slice())
            .map_err(into_protocol_err)
    }

    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        let key = sender_key_key(
            self.identity,
            sender.name(),
            u32::from(sender.device_id()),
            distribution_id,
        );
        self.store
            .ks
            .get(key)
            .map_err(into_protocol_err)?
            .map(|record| SenderKeyRecord::deserialize(&record))
            .transpose()
    }
}

type EmptyIter<T> = std::iter::Empty<Result<T, FjallStoreError>>;

impl ContentsStore for FjallSignalStore {
    type ContentsStoreError = FjallStoreError;
    type ContactsIter = EmptyIter<Contact>;
    type GroupsIter = EmptyIter<(GroupMasterKeyBytes, Group)>;
    type MessagesIter = EmptyIter<Content>;
    type StickerPacksIter = EmptyIter<StickerPack>;

    async fn clear_profiles(&mut self) -> Result<(), FjallStoreError> {
        let mut batch = self.db.batch();
        self.ks.prefix([b'R']).try_for_each(|guard| {
            let (key, _) = guard.into_inner()?;
            batch.remove(&self.ks, key.as_ref());
            Ok::<(), fjall::Error>(())
        })?;
        batch.commit()?;
        Ok(())
    }

    async fn clear_contents(&mut self) -> Result<(), FjallStoreError> {
        Ok(())
    }

    async fn clear_messages(&mut self) -> Result<(), FjallStoreError> {
        Ok(())
    }

    async fn clear_thread(&mut self, _thread: &Thread) -> Result<(), FjallStoreError> {
        Ok(())
    }

    async fn save_message(
        &self,
        _thread: &Thread,
        _message: Content,
    ) -> Result<(), FjallStoreError> {
        Ok(())
    }

    async fn delete_message(
        &mut self,
        _thread: &Thread,
        _timestamp: u64,
    ) -> Result<bool, FjallStoreError> {
        Ok(false)
    }

    async fn message(
        &self,
        _thread: &Thread,
        _timestamp: u64,
    ) -> Result<Option<Content>, FjallStoreError> {
        Ok(None)
    }

    async fn messages(
        &self,
        _thread: &Thread,
        _range: impl RangeBounds<u64>,
    ) -> Result<Self::MessagesIter, FjallStoreError> {
        Ok(std::iter::empty())
    }

    async fn clear_contacts(&mut self) -> Result<(), FjallStoreError> {
        Ok(())
    }

    async fn save_contact(&mut self, _contact: &Contact) -> Result<(), FjallStoreError> {
        Ok(())
    }

    async fn contacts(&self) -> Result<Self::ContactsIter, FjallStoreError> {
        Ok(std::iter::empty())
    }

    async fn contact_by_id(&self, _id: &ServiceId) -> Result<Option<Contact>, FjallStoreError> {
        Ok(None)
    }

    async fn clear_groups(&mut self) -> Result<(), FjallStoreError> {
        Ok(())
    }

    async fn save_group(
        &self,
        _master_key: GroupMasterKeyBytes,
        _group: impl Into<Group>,
    ) -> Result<(), FjallStoreError> {
        Ok(())
    }

    async fn groups(&self) -> Result<Self::GroupsIter, FjallStoreError> {
        Ok(std::iter::empty())
    }

    async fn group(
        &self,
        _master_key: GroupMasterKeyBytes,
    ) -> Result<Option<Group>, FjallStoreError> {
        Ok(None)
    }

    async fn save_group_avatar(
        &self,
        _master_key: GroupMasterKeyBytes,
        _avatar: &AvatarBytes,
    ) -> Result<(), FjallStoreError> {
        Ok(())
    }

    async fn group_avatar(
        &self,
        _master_key: GroupMasterKeyBytes,
    ) -> Result<Option<AvatarBytes>, FjallStoreError> {
        Ok(None)
    }

    async fn upsert_profile_key(
        &mut self,
        uuid: &Uuid,
        key: ProfileKey,
    ) -> Result<bool, FjallStoreError> {
        let k = profile_key_key(uuid);
        let existed = self.ks.get(&k)?.is_some();
        self.ks.insert(k, key.bytes)?;
        Ok(!existed)
    }

    async fn profile_key(
        &self,
        service_id: &ServiceId,
    ) -> Result<Option<ProfileKey>, FjallStoreError> {
        let uuid = service_id.raw_uuid();
        let k = profile_key_key(&uuid);
        Ok(self
            .ks
            .get(k)?
            .and_then(|v| match <[u8; 32]>::try_from(v.as_ref()) {
                Ok(arr) => Some(ProfileKey { bytes: arr }),
                Err(_) => {
                    warn!(%uuid, len = v.len(), "corrupted profile key, expected 32 bytes");
                    None
                }
            }))
    }

    async fn save_profile(
        &mut self,
        _uuid: Uuid,
        _key: ProfileKey,
        _profile: Profile,
    ) -> Result<(), FjallStoreError> {
        Ok(())
    }

    async fn profile(
        &self,
        _uuid: Uuid,
        _key: ProfileKey,
    ) -> Result<Option<Profile>, FjallStoreError> {
        Ok(None)
    }

    async fn save_profile_avatar(
        &mut self,
        _uuid: Uuid,
        _key: ProfileKey,
        _profile: &AvatarBytes,
    ) -> Result<(), FjallStoreError> {
        Ok(())
    }

    async fn profile_avatar(
        &self,
        _uuid: Uuid,
        _key: ProfileKey,
    ) -> Result<Option<AvatarBytes>, FjallStoreError> {
        Ok(None)
    }

    async fn add_sticker_pack(&mut self, _pack: &StickerPack) -> Result<(), FjallStoreError> {
        Ok(())
    }

    async fn sticker_pack(&self, _id: &[u8]) -> Result<Option<StickerPack>, FjallStoreError> {
        Ok(None)
    }

    async fn remove_sticker_pack(&mut self, _id: &[u8]) -> Result<bool, FjallStoreError> {
        Ok(false)
    }

    async fn sticker_packs(&self) -> Result<Self::StickerPacksIter, FjallStoreError> {
        Ok(std::iter::empty())
    }
}

pub struct FjallSignalStoreProvider {
    store: FjallSignalStore,
}

impl FjallSignalStoreProvider {
    pub fn new(db: Database, ks: Keyspace) -> Self {
        Self {
            store: FjallSignalStore::new(db, ks),
        }
    }
}

#[async_trait::async_trait]
impl crate::SignalStoreProvider for FjallSignalStoreProvider {
    async fn is_signal_linked(&self) -> bool {
        self.store.is_linked().unwrap_or(false)
    }

    async fn clear_signal_data(&self) -> Result<(), SignalError> {
        self.store
            .clear_all()
            .map_err(|e| SignalError::Store(e.to_string()))
    }

    async fn link_signal_device(
        &self,
        device_name: DeviceName,
        shutdown: tokio_util::sync::CancellationToken,
        link_cancel: tokio_util::sync::CancellationToken,
        linking_flag: Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<LinkResult, SignalError> {
        SignalClient::link_device_with_store(
            self.store.clone(),
            device_name,
            shutdown,
            link_cancel,
            linking_flag,
        )
        .await
    }

    async fn load_signal_client(
        &self,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> Option<SignalClient> {
        SignalClient::from_store(self.store.clone(), shutdown).await
    }
}
