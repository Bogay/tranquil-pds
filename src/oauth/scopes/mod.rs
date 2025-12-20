mod definitions;
mod error;
mod parser;
mod permissions;

pub use definitions::{SCOPE_DEFINITIONS, ScopeCategory, ScopeDefinition};
pub use error::ScopeError;
pub use parser::{
    AccountAction, AccountAttr, AccountScope, BlobScope, IdentityAttr, IdentityScope, IncludeScope,
    ParsedScope, RepoAction, RepoScope, RpcScope, parse_scope, parse_scope_string,
};
pub use permissions::ScopePermissions;
