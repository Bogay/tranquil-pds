use rand::Rng;
use sqlx::PgPool;
use uuid::Uuid;
const BASE32_ALPHABET: &str = "abcdefghijklmnopqrstuvwxyz234567";
pub fn generate_token_code() -> String {
    generate_token_code_parts(2, 5)
}
pub fn generate_token_code_parts(parts: usize, part_len: usize) -> String {
    let mut rng = rand::thread_rng();
    let chars: Vec<char> = BASE32_ALPHABET.chars().collect();
    (0..parts)
        .map(|_| {
            (0..part_len)
                .map(|_| chars[rng.gen_range(0..chars.len())])
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("-")
}
#[derive(Debug)]
pub enum DbLookupError {
    NotFound,
    DatabaseError(sqlx::Error),
}
impl From<sqlx::Error> for DbLookupError {
    fn from(e: sqlx::Error) -> Self {
        DbLookupError::DatabaseError(e)
    }
}
pub async fn get_user_id_by_did(db: &PgPool, did: &str) -> Result<Uuid, DbLookupError> {
    sqlx::query_scalar!("SELECT id FROM users WHERE did = $1", did)
        .fetch_optional(db)
        .await?
        .ok_or(DbLookupError::NotFound)
}
pub struct UserInfo {
    pub id: Uuid,
    pub did: String,
    pub handle: String,
}
pub async fn get_user_by_did(db: &PgPool, did: &str) -> Result<UserInfo, DbLookupError> {
    sqlx::query_as!(
        UserInfo,
        "SELECT id, did, handle FROM users WHERE did = $1",
        did
    )
    .fetch_optional(db)
    .await?
    .ok_or(DbLookupError::NotFound)
}
pub async fn get_user_by_identifier(db: &PgPool, identifier: &str) -> Result<UserInfo, DbLookupError> {
    sqlx::query_as!(
        UserInfo,
        "SELECT id, did, handle FROM users WHERE did = $1 OR handle = $1",
        identifier
    )
    .fetch_optional(db)
    .await?
    .ok_or(DbLookupError::NotFound)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_generate_token_code() {
        let code = generate_token_code();
        assert_eq!(code.len(), 11);
        assert!(code.contains('-'));
        let parts: Vec<&str> = code.split('-').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].len(), 5);
        assert_eq!(parts[1].len(), 5);
        for c in code.chars() {
            if c != '-' {
                assert!(BASE32_ALPHABET.contains(c));
            }
        }
    }
    #[test]
    fn test_generate_token_code_parts() {
        let code = generate_token_code_parts(3, 4);
        let parts: Vec<&str> = code.split('-').collect();
        assert_eq!(parts.len(), 3);
        for part in parts {
            assert_eq!(part.len(), 4);
        }
    }
}
