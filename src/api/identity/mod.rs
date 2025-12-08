pub mod account;
pub mod did;

pub use account::create_account;
pub use did::{resolve_handle, user_did_doc, well_known_did};
