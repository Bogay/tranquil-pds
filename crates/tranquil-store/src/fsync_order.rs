use std::io;

use crate::blockstore::BlocksSynced;

pub trait PostBlockstoreHook: Send + Sync {
    fn on_blocks_synced(&self, proof: &BlocksSynced) -> io::Result<()>;
}
