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

pub fn stage_in_chunks<T>(
    db: &fjall::Database,
    mut items: impl Iterator<Item = Result<T, MetastoreError>>,
    commit_every: usize,
    mut stage: impl FnMut(&mut fjall::OwnedWriteBatch, T) -> Result<(), MetastoreError>,
) -> Result<usize, MetastoreError> {
    let (batch, staged) = items.try_fold((db.batch(), 0usize), |(mut batch, staged), item| {
        stage(&mut batch, item?)?;
        match (staged + 1).is_multiple_of(commit_every) {
            true => {
                batch.commit()?;
                Ok::<_, MetastoreError>((db.batch(), staged + 1))
            }
            false => Ok((batch, staged + 1)),
        }
    })?;
    batch.commit()?;
    Ok(staged)
}

pub fn prefix_entries<'a>(
    keyspace: &'a Keyspace,
    prefix: &[u8],
) -> impl Iterator<Item = Result<(fjall::Slice, fjall::Slice), MetastoreError>> + 'a {
    keyspace
        .prefix(prefix)
        .map(|guard| guard.into_inner().map_err(MetastoreError::Fjall))
}

pub fn delete_all_by_prefix_chunked(
    db: &fjall::Database,
    keyspace: &Keyspace,
    prefix: &[u8],
    commit_every: usize,
) -> Result<usize, MetastoreError> {
    stage_in_chunks(
        db,
        prefix_entries(keyspace, prefix),
        commit_every,
        |batch, (key_bytes, _)| {
            batch.remove(keyspace, key_bytes.as_ref());
            Ok(())
        },
    )
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metastore::{Metastore, MetastoreConfig, Partition};

    const PREFIX: &[u8] = &[0xE0];
    const NEIGHBOR: &[u8] = &[0xE1];

    fn open_fresh() -> (tempfile::TempDir, Metastore) {
        let dir = tempfile::TempDir::new().unwrap();
        let ms = Metastore::open(dir.path(), MetastoreConfig::default()).unwrap();
        (dir, ms)
    }

    fn seed(ms: &Metastore, keyspace: &Keyspace, prefix: &[u8], count: usize) {
        let mut batch = ms.database().batch();
        (0..count).for_each(|i| {
            let key: Vec<u8> = prefix
                .iter()
                .copied()
                .chain((i as u32).to_be_bytes())
                .collect();
            batch.insert(keyspace, key.as_slice(), []);
        });
        batch.commit().unwrap();
    }

    fn count(keyspace: &Keyspace, prefix: &[u8]) -> usize {
        keyspace.prefix(prefix).count()
    }

    #[test]
    fn chunked_delete_removes_every_key_across_many_mid_iteration_commits() {
        let (_dir, ms) = open_fresh();
        let keyspace = ms.partition(Partition::RepoData).clone();
        let total = 1_000usize;

        seed(&ms, &keyspace, PREFIX, total);
        seed(&ms, &keyspace, NEIGHBOR, 8);

        assert_eq!(
            delete_all_by_prefix_chunked(ms.database(), &keyspace, PREFIX, 100).unwrap(),
            total,
            "every key under the prefix must be visited despite committing mid-iteration"
        );
        assert_eq!(
            count(&keyspace, PREFIX),
            0,
            "deleting from the prefix being iterated must not skip keys"
        );
        assert_eq!(
            count(&keyspace, NEIGHBOR),
            8,
            "chunked delete must not reach past its prefix"
        );
    }

    #[test]
    fn chunked_delete_commits_a_remainder_smaller_than_one_chunk() {
        let (_dir, ms) = open_fresh();
        let keyspace = ms.partition(Partition::RepoData).clone();

        seed(&ms, &keyspace, PREFIX, 101);

        assert_eq!(
            delete_all_by_prefix_chunked(ms.database(), &keyspace, PREFIX, 100).unwrap(),
            101
        );
        assert_eq!(count(&keyspace, PREFIX), 0);
    }

    #[test]
    fn stage_in_chunks_propagates_a_failing_item() {
        let (_dir, ms) = open_fresh();
        let keyspace = ms.partition(Partition::RepoData).clone();

        let items = (0..10usize).map(|i| match i {
            7 => Err(MetastoreError::CorruptData("bad item")),
            _ => Ok(i),
        });
        let result = stage_in_chunks(ms.database(), items, 4, |batch, i| {
            batch.insert(&keyspace, [0xE2, i as u8].as_slice(), []);
            Ok(())
        });

        assert!(matches!(result, Err(MetastoreError::CorruptData(_))));
        assert_eq!(
            count(&keyspace, &[0xE2]),
            4,
            "chunks committed before the failure stay committed"
        );
    }
}
