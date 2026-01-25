use std::marker::PhantomData;

use crate::DbError;

#[derive(Debug)]
pub struct ValidatedInviteCode<'a> {
    code: &'a str,
    _marker: PhantomData<&'a ()>,
}

impl<'a> ValidatedInviteCode<'a> {
    pub fn new_validated(code: &'a str) -> Self {
        Self {
            code,
            _marker: PhantomData,
        }
    }

    pub fn code(&self) -> &str {
        self.code
    }
}

#[derive(Debug)]
pub enum InviteCodeError {
    NotFound,
    ExhaustedUses,
    Disabled,
    DatabaseError(DbError),
}

impl std::fmt::Display for InviteCodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "Invite code not found"),
            Self::ExhaustedUses => write!(f, "Invite code has no remaining uses"),
            Self::Disabled => write!(f, "Invite code is disabled"),
            Self::DatabaseError(e) => write!(f, "Database error: {}", e),
        }
    }
}

impl std::error::Error for InviteCodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DatabaseError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<DbError> for InviteCodeError {
    fn from(e: DbError) -> Self {
        Self::DatabaseError(e)
    }
}
