pub use tranquil_types::*;

use std::sync::LazyLock;

pub static PROFILE_COLLECTION: LazyLock<Nsid> =
    LazyLock::new(|| "app.bsky.actor.profile".parse().unwrap());
pub static PROFILE_RKEY: LazyLock<Rkey> = LazyLock::new(|| "self".parse().unwrap());
