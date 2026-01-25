use std::marker::PhantomData;
use std::ops::Deref;

use axum::response::{IntoResponse, Response};

use crate::api::error::ApiError;
use crate::oauth::scopes::{
    AccountAction, AccountAttr, IdentityAttr, RepoAction, ScopePermissions,
};
use crate::types::Did;

use super::AuthenticatedUser;

#[derive(Debug, Clone)]
pub struct PrincipalDid(Did);

impl PrincipalDid {
    pub fn as_did(&self) -> &Did {
        &self.0
    }

    pub fn into_did(self) -> Did {
        self.0
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Deref for PrincipalDid {
    type Target = Did;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<Did> for PrincipalDid {
    fn as_ref(&self) -> &Did {
        &self.0
    }
}

impl std::fmt::Display for PrincipalDid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone)]
pub struct ControllerDid(Did);

impl ControllerDid {
    pub fn as_did(&self) -> &Did {
        &self.0
    }

    pub fn into_did(self) -> Did {
        self.0
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Deref for ControllerDid {
    type Target = Did;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<Did> for ControllerDid {
    fn as_ref(&self) -> &Did {
        &self.0
    }
}

impl std::fmt::Display for ControllerDid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug)]
pub struct ScopeVerificationError {
    message: String,
}

impl ScopeVerificationError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for ScopeVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ScopeVerificationError {}

impl IntoResponse for ScopeVerificationError {
    fn into_response(self) -> Response {
        ApiError::InsufficientScope(Some(self.message)).into_response()
    }
}

mod private {
    pub trait Sealed {}
    pub trait RepoScopeSealed {}
    pub trait BlobScopeSealed {}
}

pub trait ScopeAction: private::Sealed {}

pub trait RepoScopeAction: ScopeAction + private::RepoScopeSealed {}

pub trait BlobScopeAction: ScopeAction + private::BlobScopeSealed {}

pub struct RepoCreate;
pub struct RepoUpdate;
pub struct RepoDelete;
pub struct RepoUpsert;
pub struct BlobUpload;
pub struct RpcCall;
pub struct AccountRead;
pub struct AccountManage;
pub struct IdentityAccess;

impl private::Sealed for RepoCreate {}
impl private::Sealed for RepoUpdate {}
impl private::Sealed for RepoDelete {}
impl private::Sealed for RepoUpsert {}
impl private::Sealed for BlobUpload {}
impl private::Sealed for RpcCall {}
impl private::Sealed for AccountRead {}
impl private::Sealed for AccountManage {}
impl private::Sealed for IdentityAccess {}

impl private::RepoScopeSealed for RepoCreate {}
impl private::RepoScopeSealed for RepoUpdate {}
impl private::RepoScopeSealed for RepoDelete {}
impl private::RepoScopeSealed for RepoUpsert {}

impl private::BlobScopeSealed for BlobUpload {}

impl ScopeAction for RepoCreate {}
impl ScopeAction for RepoUpdate {}
impl ScopeAction for RepoDelete {}
impl ScopeAction for RepoUpsert {}
impl ScopeAction for BlobUpload {}
impl ScopeAction for RpcCall {}
impl ScopeAction for AccountRead {}
impl ScopeAction for AccountManage {}
impl ScopeAction for IdentityAccess {}

impl RepoScopeAction for RepoCreate {}
impl RepoScopeAction for RepoUpdate {}
impl RepoScopeAction for RepoDelete {}
impl RepoScopeAction for RepoUpsert {}

impl BlobScopeAction for BlobUpload {}

pub struct ScopeVerified<'a, A: ScopeAction> {
    user: &'a AuthenticatedUser,
    _action: PhantomData<A>,
}

impl<'a, A: ScopeAction> ScopeVerified<'a, A> {
    pub fn user(&self) -> &AuthenticatedUser {
        self.user
    }

    pub fn principal_did(&self) -> PrincipalDid {
        PrincipalDid(self.user.did.clone())
    }

    pub fn controller_did(&self) -> Option<ControllerDid> {
        self.user.controller_did.clone().map(ControllerDid)
    }

    pub fn is_admin(&self) -> bool {
        self.user.is_admin
    }
}

pub struct BatchWriteScopes<'a> {
    user: &'a AuthenticatedUser,
    has_creates: bool,
    has_updates: bool,
    has_deletes: bool,
}

impl<'a> BatchWriteScopes<'a> {
    pub fn principal_did(&self) -> PrincipalDid {
        PrincipalDid(self.user.did.clone())
    }

    pub fn controller_did(&self) -> Option<ControllerDid> {
        self.user.controller_did.clone().map(ControllerDid)
    }

    pub fn user(&self) -> &AuthenticatedUser {
        self.user
    }

    pub fn has_creates(&self) -> bool {
        self.has_creates
    }

    pub fn has_updates(&self) -> bool {
        self.has_updates
    }

    pub fn has_deletes(&self) -> bool {
        self.has_deletes
    }
}

pub fn verify_batch_write_scopes<'a, T, C, F>(
    auth: &'a impl VerifyScope,
    user: &'a AuthenticatedUser,
    writes: &[T],
    get_collection: F,
    classify: C,
) -> Result<BatchWriteScopes<'a>, ScopeVerificationError>
where
    F: Fn(&T) -> &str,
    C: Fn(&T) -> WriteOpKind,
{
    use std::collections::HashSet;

    let create_collections: HashSet<&str> = writes
        .iter()
        .filter(|w| matches!(classify(w), WriteOpKind::Create))
        .map(&get_collection)
        .collect();

    let update_collections: HashSet<&str> = writes
        .iter()
        .filter(|w| matches!(classify(w), WriteOpKind::Update))
        .map(&get_collection)
        .collect();

    let delete_collections: HashSet<&str> = writes
        .iter()
        .filter(|w| matches!(classify(w), WriteOpKind::Delete))
        .map(&get_collection)
        .collect();

    if auth.needs_scope_check() {
        create_collections.iter().try_for_each(|c| {
            auth.permissions()
                .assert_repo(RepoAction::Create, c)
                .map_err(|e| ScopeVerificationError::new(e.to_string()))
        })?;

        update_collections.iter().try_for_each(|c| {
            auth.permissions()
                .assert_repo(RepoAction::Update, c)
                .map_err(|e| ScopeVerificationError::new(e.to_string()))
        })?;

        delete_collections.iter().try_for_each(|c| {
            auth.permissions()
                .assert_repo(RepoAction::Delete, c)
                .map_err(|e| ScopeVerificationError::new(e.to_string()))
        })?;
    }

    Ok(BatchWriteScopes {
        user,
        has_creates: !create_collections.is_empty(),
        has_updates: !update_collections.is_empty(),
        has_deletes: !delete_collections.is_empty(),
    })
}

#[derive(Clone, Copy)]
pub enum WriteOpKind {
    Create,
    Update,
    Delete,
}

pub trait VerifyScope {
    fn needs_scope_check(&self) -> bool;
    fn permissions(&self) -> ScopePermissions;

    fn verify_repo_create<'a>(
        &'a self,
        collection: &str,
    ) -> Result<ScopeVerified<'a, RepoCreate>, ScopeVerificationError>
    where
        Self: AsRef<AuthenticatedUser>,
    {
        if !self.needs_scope_check() {
            return Ok(ScopeVerified {
                user: self.as_ref(),
                _action: PhantomData,
            });
        }
        self.permissions()
            .assert_repo(RepoAction::Create, collection)
            .map_err(|e| ScopeVerificationError::new(e.to_string()))?;
        Ok(ScopeVerified {
            user: self.as_ref(),
            _action: PhantomData,
        })
    }

    fn verify_repo_update<'a>(
        &'a self,
        collection: &str,
    ) -> Result<ScopeVerified<'a, RepoUpdate>, ScopeVerificationError>
    where
        Self: AsRef<AuthenticatedUser>,
    {
        if !self.needs_scope_check() {
            return Ok(ScopeVerified {
                user: self.as_ref(),
                _action: PhantomData,
            });
        }
        self.permissions()
            .assert_repo(RepoAction::Update, collection)
            .map_err(|e| ScopeVerificationError::new(e.to_string()))?;
        Ok(ScopeVerified {
            user: self.as_ref(),
            _action: PhantomData,
        })
    }

    fn verify_repo_delete<'a>(
        &'a self,
        collection: &str,
    ) -> Result<ScopeVerified<'a, RepoDelete>, ScopeVerificationError>
    where
        Self: AsRef<AuthenticatedUser>,
    {
        if !self.needs_scope_check() {
            return Ok(ScopeVerified {
                user: self.as_ref(),
                _action: PhantomData,
            });
        }
        self.permissions()
            .assert_repo(RepoAction::Delete, collection)
            .map_err(|e| ScopeVerificationError::new(e.to_string()))?;
        Ok(ScopeVerified {
            user: self.as_ref(),
            _action: PhantomData,
        })
    }

    fn verify_repo_upsert<'a>(
        &'a self,
        collection: &str,
    ) -> Result<ScopeVerified<'a, RepoUpsert>, ScopeVerificationError>
    where
        Self: AsRef<AuthenticatedUser>,
    {
        if !self.needs_scope_check() {
            return Ok(ScopeVerified {
                user: self.as_ref(),
                _action: PhantomData,
            });
        }
        self.permissions()
            .assert_repo(RepoAction::Create, collection)
            .map_err(|e| ScopeVerificationError::new(e.to_string()))?;
        self.permissions()
            .assert_repo(RepoAction::Update, collection)
            .map_err(|e| ScopeVerificationError::new(e.to_string()))?;
        Ok(ScopeVerified {
            user: self.as_ref(),
            _action: PhantomData,
        })
    }

    fn verify_blob_upload<'a>(
        &'a self,
        mime_type: &str,
    ) -> Result<ScopeVerified<'a, BlobUpload>, ScopeVerificationError>
    where
        Self: AsRef<AuthenticatedUser>,
    {
        if !self.needs_scope_check() {
            return Ok(ScopeVerified {
                user: self.as_ref(),
                _action: PhantomData,
            });
        }
        self.permissions()
            .assert_blob(mime_type)
            .map_err(|e| ScopeVerificationError::new(e.to_string()))?;
        Ok(ScopeVerified {
            user: self.as_ref(),
            _action: PhantomData,
        })
    }

    fn verify_rpc<'a>(
        &'a self,
        aud: &str,
        lxm: &str,
    ) -> Result<ScopeVerified<'a, RpcCall>, ScopeVerificationError>
    where
        Self: AsRef<AuthenticatedUser>,
    {
        if !self.needs_scope_check() {
            return Ok(ScopeVerified {
                user: self.as_ref(),
                _action: PhantomData,
            });
        }
        self.permissions()
            .assert_rpc(aud, lxm)
            .map_err(|e| ScopeVerificationError::new(e.to_string()))?;
        Ok(ScopeVerified {
            user: self.as_ref(),
            _action: PhantomData,
        })
    }

    fn verify_account_read<'a>(
        &'a self,
        attr: AccountAttr,
    ) -> Result<ScopeVerified<'a, AccountRead>, ScopeVerificationError>
    where
        Self: AsRef<AuthenticatedUser>,
    {
        if !self.needs_scope_check() {
            return Ok(ScopeVerified {
                user: self.as_ref(),
                _action: PhantomData,
            });
        }
        self.permissions()
            .assert_account(attr, AccountAction::Read)
            .map_err(|e| ScopeVerificationError::new(e.to_string()))?;
        Ok(ScopeVerified {
            user: self.as_ref(),
            _action: PhantomData,
        })
    }

    fn verify_account_manage<'a>(
        &'a self,
        attr: AccountAttr,
    ) -> Result<ScopeVerified<'a, AccountManage>, ScopeVerificationError>
    where
        Self: AsRef<AuthenticatedUser>,
    {
        if !self.needs_scope_check() {
            return Ok(ScopeVerified {
                user: self.as_ref(),
                _action: PhantomData,
            });
        }
        self.permissions()
            .assert_account(attr, AccountAction::Manage)
            .map_err(|e| ScopeVerificationError::new(e.to_string()))?;
        Ok(ScopeVerified {
            user: self.as_ref(),
            _action: PhantomData,
        })
    }

    fn verify_identity<'a>(
        &'a self,
        attr: IdentityAttr,
    ) -> Result<ScopeVerified<'a, IdentityAccess>, ScopeVerificationError>
    where
        Self: AsRef<AuthenticatedUser>,
    {
        if !self.needs_scope_check() {
            return Ok(ScopeVerified {
                user: self.as_ref(),
                _action: PhantomData,
            });
        }
        self.permissions()
            .assert_identity(attr)
            .map_err(|e| ScopeVerificationError::new(e.to_string()))?;
        Ok(ScopeVerified {
            user: self.as_ref(),
            _action: PhantomData,
        })
    }
}
