mod formats;
mod registry;
mod schema;
mod validate;

#[cfg(feature = "resolve")]
mod dynamic;
#[cfg(feature = "resolve")]
mod resolve;

#[cfg(test)]
mod test_schemas;

pub use formats::{
    is_valid_at_identifier, is_valid_at_uri, is_valid_cid, is_valid_datetime, is_valid_did,
    is_valid_handle, is_valid_language, is_valid_nsid, is_valid_record_key, is_valid_tid,
    is_valid_uri,
};
pub use registry::LexiconRegistry;
pub use schema::{LexiconDoc, ParsedRef, parse_ref};
pub use validate::{LexValidationError, validate_record};

#[cfg(feature = "resolve")]
pub use resolve::{
    ResolveError, fetch_schema_from_pds, resolve_did_from_dns, resolve_lexicon,
    resolve_lexicon_from_did, resolve_lexicon_with_config, resolve_pds_endpoint,
};
