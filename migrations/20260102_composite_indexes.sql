CREATE INDEX IF NOT EXISTS idx_session_tokens_did_created_at
ON session_tokens(did, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_oauth_token_did_expires_at
ON oauth_token(did, expires_at DESC);

CREATE INDEX IF NOT EXISTS idx_oauth_token_did_created_at
ON oauth_token(did, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_session_tokens_did_refresh_expires
ON session_tokens(did, refresh_expires_at DESC);

CREATE INDEX IF NOT EXISTS idx_app_passwords_user_created
ON app_passwords(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_records_repo_collection_rkey
ON records(repo_id, collection, rkey);

CREATE INDEX IF NOT EXISTS idx_passkeys_did_created
ON passkeys(did, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_backup_codes_did_unused
ON backup_codes(did) WHERE used_at IS NULL;
