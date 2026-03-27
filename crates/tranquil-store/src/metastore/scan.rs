use fjall::Keyspace;

use super::MetastoreError;

pub fn count_prefix(keyspace: &Keyspace, prefix: &[u8]) -> Result<i64, MetastoreError> {
    keyspace.prefix(prefix).try_fold(0i64, |acc, guard| {
        guard.into_inner().map_err(MetastoreError::Fjall)?;
        Ok::<_, MetastoreError>(acc.saturating_add(1))
    })
}

pub fn delete_all_by_prefix(
    keyspace: &Keyspace,
    batch: &mut fjall::OwnedWriteBatch,
    prefix: &[u8],
) -> Result<(), MetastoreError> {
    keyspace.prefix(prefix).try_for_each(|guard| {
        let (key_bytes, _) = guard.into_inner().map_err(MetastoreError::Fjall)?;
        batch.remove(keyspace, key_bytes.as_ref());
        Ok::<(), MetastoreError>(())
    })
}

pub fn point_lookup<T>(
    keyspace: &Keyspace,
    key: &[u8],
    deserialize: impl FnOnce(&[u8]) -> Option<T>,
    corrupt_msg: &'static str,
) -> Result<Option<T>, MetastoreError> {
    match keyspace.get(key).map_err(MetastoreError::Fjall)? {
        Some(raw) => deserialize(&raw)
            .ok_or(MetastoreError::CorruptData(corrupt_msg))
            .map(Some),
        None => Ok(None),
    }
}
