use cid::Cid;
use multihash::Multihash;
use sha2::{Digest, Sha256};

use super::data_file::CID_SIZE;

pub const DAG_CBOR_CODEC: u64 = 0x71;
pub const SHA2_256_CODE: u64 = 0x12;

pub fn hash_to_cid(data: &[u8]) -> Cid {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mh = Multihash::wrap(SHA2_256_CODE, &digest)
        .expect("SHA-256 digest is 32 bytes, well within multihash capacity");
    Cid::new_v1(DAG_CBOR_CODEC, mh)
}

pub fn hash_to_cid_bytes(data: &[u8]) -> [u8; CID_SIZE] {
    let raw = hash_to_cid(data).to_bytes();
    raw.try_into()
        .expect("CIDv1 + DAG-CBOR + SHA-256 always encodes to CID_SIZE bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_to_cid_bytes_is_deterministic() {
        let a = hash_to_cid_bytes(b"hello");
        let b = hash_to_cid_bytes(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn hash_to_cid_bytes_diverges_on_single_byte_change() {
        assert_ne!(hash_to_cid_bytes(b"abc"), hash_to_cid_bytes(b"abd"));
    }

    #[test]
    fn hash_to_cid_and_bytes_agree() {
        let cid = hash_to_cid(b"payload");
        let raw: [u8; CID_SIZE] = cid.to_bytes().try_into().expect("36 bytes");
        assert_eq!(raw, hash_to_cid_bytes(b"payload"));
    }
}
