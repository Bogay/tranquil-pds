use smallvec::SmallVec;
use tranquil_types::Tid;

use super::encoding::KeyBuilder;
use super::keys::{KeyTag, UserHash};

pub fn user_block_key(user_hash: UserHash, rev: &Tid, cid_bytes: &[u8]) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::USER_BLOCKS)
        .u64(user_hash.raw())
        .string(rev)
        .raw(cid_bytes)
        .build()
}

pub fn user_block_user_prefix(user_hash: UserHash) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::USER_BLOCKS)
        .u64(user_hash.raw())
        .build()
}

pub fn user_block_rev_prefix(user_hash: UserHash, rev: &Tid) -> SmallVec<[u8; 128]> {
    KeyBuilder::new()
        .tag(KeyTag::USER_BLOCKS)
        .u64(user_hash.raw())
        .string(rev)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metastore::encoding::KeyReader;

    fn test_rev(seq: u64) -> Tid {
        const ALPHABET: &[u8] = b"234567abcdefghijklmnopqrstuvwxyz";
        let s: String = (0..13)
            .rev()
            .map(|i| ALPHABET[((seq >> (i * 5)) & 0x1F) as usize] as char)
            .collect();
        Tid::new(s).expect("generated TID is valid")
    }

    #[test]
    fn user_block_key_roundtrip() {
        let hash = UserHash::from_raw(0xDEAD_BEEF_CAFE_BABE);
        let cid = [0x01, 0x71, 0x12, 0x20, 0xAB];
        let rev = test_rev(10);
        let key = user_block_key(hash, &rev, &cid);

        let mut reader = KeyReader::new(&key);
        assert_eq!(reader.tag(), Some(KeyTag::USER_BLOCKS.raw()));
        assert_eq!(reader.u64(), Some(0xDEAD_BEEF_CAFE_BABE));
        assert_eq!(reader.string(), Some(rev.as_str().to_owned()));
        assert_eq!(reader.remaining(), &cid);
    }

    #[test]
    fn keys_sort_by_user_then_rev_then_cid() {
        let h1 = UserHash::from_raw(1);
        let h2 = UserHash::from_raw(2);
        let rev_low = test_rev(10);
        let rev_high = test_rev(20);

        let k1 = user_block_key(h1, &rev_low, &[0x01]);
        let k2 = user_block_key(h1, &rev_low, &[0x02]);
        let k3 = user_block_key(h1, &rev_high, &[0x01]);
        let k4 = user_block_key(h2, &rev_low, &[0x01]);

        assert!(k1.as_slice() < k2.as_slice());
        assert!(k2.as_slice() < k3.as_slice());
        assert!(k3.as_slice() < k4.as_slice());
    }

    #[test]
    fn user_prefix_is_prefix_of_rev_prefix() {
        let hash = UserHash::from_raw(42);
        let user_pfx = user_block_user_prefix(hash);
        let rev_pfx = user_block_rev_prefix(hash, &test_rev(10));
        assert!(rev_pfx.as_slice().starts_with(user_pfx.as_slice()));
    }

    #[test]
    fn rev_prefix_is_prefix_of_full_key() {
        let hash = UserHash::from_raw(42);
        let rev = test_rev(10);
        let rev_pfx = user_block_rev_prefix(hash, &rev);
        let full = user_block_key(hash, &rev, &[0x01, 0x02]);
        assert!(full.as_slice().starts_with(rev_pfx.as_slice()));
    }

    #[test]
    fn cid_with_null_bytes_roundtrips() {
        let hash = UserHash::from_raw(99);
        let cid = [0x00, 0x01, 0x00, 0xFF];
        let rev = test_rev(10);
        let key = user_block_key(hash, &rev, &cid);

        let mut reader = KeyReader::new(&key);
        assert_eq!(reader.tag(), Some(KeyTag::USER_BLOCKS.raw()));
        assert_eq!(reader.u64(), Some(99));
        assert_eq!(reader.string(), Some(rev.as_str().to_owned()));
        assert_eq!(reader.remaining(), &cid);
    }

    #[test]
    fn cid_with_double_null_bytes_roundtrips() {
        let hash = UserHash::from_raw(99);
        let cid = [0x00, 0x00, 0x01, 0x00, 0x00];
        let rev = test_rev(10);
        let key = user_block_key(hash, &rev, &cid);

        let mut reader = KeyReader::new(&key);
        assert_eq!(reader.tag(), Some(KeyTag::USER_BLOCKS.raw()));
        assert_eq!(reader.u64(), Some(99));
        assert_eq!(reader.string(), Some(rev.as_str().to_owned()));
        assert_eq!(reader.remaining(), &cid);
    }

    #[test]
    fn empty_cid_produces_key_equal_to_rev_prefix() {
        let hash = UserHash::from_raw(42);
        let rev = test_rev(10);
        let rev_pfx = user_block_rev_prefix(hash, &rev);
        let full = user_block_key(hash, &rev, &[]);
        assert_eq!(full.as_slice(), rev_pfx.as_slice());
    }
}
