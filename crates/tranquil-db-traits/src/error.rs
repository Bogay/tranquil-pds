use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ColumnRef {
    table: &'static str,
    column: &'static str,
}

impl ColumnRef {
    pub const fn new(table: &'static str, column: &'static str) -> Self {
        Self { table, column }
    }

    pub const fn table(&self) -> &'static str {
        self.table
    }

    pub const fn column(&self) -> &'static str {
        self.column
    }
}

impl std::fmt::Display for ColumnRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.table, self.column)
    }
}

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

    #[error("Corrupt data in column: {0}")]
    CorruptData(&'static str),

    #[error("Column {0} has a value that isn't valid for its type")]
    InvalidColumn(ColumnRef),

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
