pub mod account;
pub mod did;

pub use account::create_account;
pub use did::{
    get_recommended_did_credentials, resolve_handle, update_handle, user_did_doc, well_known_did,
};
