use thiserror::Error;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("Database query error: {0}")]
    Query(String),

    #[error("Record not found")]
    NotFound,

    #[error("Constraint violation: {0}")]
    Constraint(String),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Transaction error: {0}")]
    Transaction(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Ambiguous: {0}")]
    Ambiguous(String),

    #[error("Resource busy, try again")]
    LockContention,

    #[error("Other database error: {0}")]
    Other(String),
}

impl DbError {
    pub fn from_query_error(msg: impl Into<String>) -> Self {
        DbError::Query(msg.into())
    }

    pub fn from_constraint_error(msg: impl Into<String>) -> Self {
        DbError::Constraint(msg.into())
    }

    pub fn from_connection_error(msg: impl Into<String>) -> Self {
        DbError::Connection(msg.into())
    }
}
