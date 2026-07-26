pub use tranquil_types::*;

#[cfg(feature = "bsky")]
use std::sync::LazyLock;

#[cfg(feature = "bsky")]
pub static PROFILE_COLLECTION: LazyLock<Nsid> =
    LazyLock::new(|| "app.bsky.actor.profile".parse().unwrap());
#[cfg(feature = "bsky")]
pub static PROFILE_RKEY: LazyLock<Rkey> = LazyLock::new(|| "self".parse().unwrap());
