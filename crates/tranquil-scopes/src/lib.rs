mod definitions;
mod error;
mod parser;
mod permission_set;
mod permissions;

pub use definitions::{
    SCOPE_DEFINITIONS, ScopeCategory, ScopeDefinition, format_scope_for_display,
    get_required_scopes, get_scope_definition, is_valid_scope,
};
pub use error::ScopeError;
pub use parser::{
    AccountAction, AccountAttr, AccountScope, BlobScope, IdentityAttr, IdentityScope, IncludeScope,
    ParsedScope, RepoAction, RepoScope, RpcScope, parse_scope, parse_scope_string,
};
pub use permission_set::{ScopeExpansionError, expand_include_scopes};
pub use permissions::ScopePermissions;
