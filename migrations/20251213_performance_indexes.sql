CREATE INDEX IF NOT EXISTS idx_records_repo_collection
    ON records(repo_id, collection);
CREATE INDEX IF NOT EXISTS idx_records_repo_collection_created
    ON records(repo_id, collection, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_users_email
    ON users(email)
    WHERE email IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_blobs_created_by_user
    ON blobs(created_by_user, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_repo_seq_did_seq
    ON repo_seq(did, seq DESC);
CREATE INDEX IF NOT EXISTS idx_app_passwords_user_id
    ON app_passwords(user_id);
CREATE INDEX IF NOT EXISTS idx_invite_codes_created_by
    ON invite_codes(created_by_user);
