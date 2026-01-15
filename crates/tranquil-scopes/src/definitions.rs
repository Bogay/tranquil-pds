use std::collections::HashMap;
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScopeCategory {
    Core,
    Transition,
    Repo,
    Blob,
    Rpc,
    Account,
}

impl ScopeCategory {
    pub fn display_name(&self) -> &'static str {
        match self {
            ScopeCategory::Core => "Core Access",
            ScopeCategory::Transition => "Transition",
            ScopeCategory::Repo => "Repository",
            ScopeCategory::Blob => "Media",
            ScopeCategory::Rpc => "API Access",
            ScopeCategory::Account => "Account",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScopeDefinition {
    pub scope: &'static str,
    pub category: ScopeCategory,
    pub required: bool,
    pub description: &'static str,
    pub display_name: &'static str,
}

pub static SCOPE_DEFINITIONS: LazyLock<HashMap<&'static str, ScopeDefinition>> = LazyLock::new(
    || {
        let definitions = vec![
            ScopeDefinition {
                scope: "atproto",
                category: ScopeCategory::Core,
                required: true,
                description: "Full access to read, write, and manage this account (when no granular permissions are specified)",
                display_name: "Full Account Access",
            },
            ScopeDefinition {
                scope: "transition:generic",
                category: ScopeCategory::Transition,
                required: false,
                description: "Generic transition scope for compatibility",
                display_name: "Transition Access",
            },
            ScopeDefinition {
                scope: "transition:chat.bsky",
                category: ScopeCategory::Transition,
                required: false,
                description: "Access to Bluesky chat features",
                display_name: "Chat Access",
            },
            ScopeDefinition {
                scope: "transition:email",
                category: ScopeCategory::Account,
                required: false,
                description: "Read your account email address",
                display_name: "Email Access",
            },
            ScopeDefinition {
                scope: "repo:*?action=create",
                category: ScopeCategory::Repo,
                required: false,
                description: "Create new records in your repository",
                display_name: "Create Records",
            },
            ScopeDefinition {
                scope: "repo:*?action=update",
                category: ScopeCategory::Repo,
                required: false,
                description: "Update existing records in your repository",
                display_name: "Update Records",
            },
            ScopeDefinition {
                scope: "repo:*?action=delete",
                category: ScopeCategory::Repo,
                required: false,
                description: "Delete records from your repository",
                display_name: "Delete Records",
            },
            ScopeDefinition {
                scope: "blob:*/*",
                category: ScopeCategory::Blob,
                required: false,
                description: "Upload images, videos, and other media files",
                display_name: "Upload Media",
            },
            ScopeDefinition {
                scope: "repo:*",
                category: ScopeCategory::Repo,
                required: false,
                description: "Full read and write access to all repository records",
                display_name: "Full Repository Access",
            },
            ScopeDefinition {
                scope: "account:*?action=manage",
                category: ScopeCategory::Account,
                required: false,
                description: "Manage account settings and preferences",
                display_name: "Manage Account",
            },
        ];

        definitions.into_iter().map(|d| (d.scope, d)).collect()
    },
);

#[allow(dead_code)]
pub fn get_scope_definition(scope: &str) -> Option<&'static ScopeDefinition> {
    SCOPE_DEFINITIONS.get(scope)
}

#[allow(dead_code)]
pub fn is_valid_scope(scope: &str) -> bool {
    if SCOPE_DEFINITIONS.contains_key(scope) {
        return true;
    }
    if scope.starts_with("ref:") {
        return true;
    }
    false
}

#[allow(dead_code)]
pub fn get_required_scopes() -> Vec<&'static str> {
    SCOPE_DEFINITIONS
        .values()
        .filter(|d| d.required)
        .map(|d| d.scope)
        .collect()
}

#[allow(dead_code)]
pub fn format_scope_for_display(scope: &str) -> String {
    if let Some(def) = get_scope_definition(scope) {
        def.description.to_string()
    } else if scope.starts_with("ref:") {
        "Referenced scope".to_string()
    } else {
        format!("Access to {}", scope)
    }
}
