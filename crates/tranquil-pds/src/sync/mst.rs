use cid::Cid;
use ipld_core::ipld::Ipld;

pub struct MstEntry {
    pub prefix_len: usize,
    pub key_suffix: Option<Vec<u8>>,
    pub subtree: Option<Cid>,
    pub value: Option<Cid>,
}

pub fn parse_mst_entry(entry: &Ipld) -> Option<MstEntry> {
    let obj = match entry {
        Ipld::Map(m) => m,
        _ => return None,
    };
    let prefix_len = obj
        .get("p")
        .and_then(|p| match p {
            Ipld::Integer(n) => usize::try_from(*n).ok(),
            _ => None,
        })
        .unwrap_or(0);
    let key_suffix = obj.get("k").and_then(|k| match k {
        Ipld::Bytes(b) => Some(b.clone()),
        Ipld::String(s) => Some(s.as_bytes().to_vec()),
        _ => None,
    });
    let subtree = obj.get("t").and_then(|t| match t {
        Ipld::Link(cid) => Some(*cid),
        _ => None,
    });
    let value = obj.get("v").and_then(|v| match v {
        Ipld::Link(cid) => Some(*cid),
        _ => None,
    });
    Some(MstEntry {
        prefix_len,
        key_suffix,
        subtree,
        value,
    })
}

pub fn left_child(node: &Ipld) -> Option<Cid> {
    match node {
        Ipld::Map(obj) => match obj.get("l") {
            Some(Ipld::Link(cid)) => Some(*cid),
            _ => None,
        },
        _ => None,
    }
}

pub fn entries(node: &Ipld) -> Option<&Vec<Ipld>> {
    match node {
        Ipld::Map(obj) => match obj.get("e") {
            Some(Ipld::List(entries)) => Some(entries),
            _ => None,
        },
        _ => None,
    }
}

pub fn reconstruct_key(prev_key: &mut Vec<u8>, prefix_len: usize, suffix: &[u8]) {
    prev_key.truncate(prefix_len);
    prev_key.extend_from_slice(suffix);
}
