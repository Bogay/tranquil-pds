ALTER TABLE users ADD COLUMN backup_enabled BOOLEAN NOT NULL DEFAULT TRUE;

CREATE TABLE account_backups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    storage_key TEXT NOT NULL,
    repo_root_cid TEXT NOT NULL,
    repo_rev TEXT NOT NULL,
    block_count INT NOT NULL,
    size_bytes BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_account_backups_user_id ON account_backups(user_id);
CREATE INDEX idx_account_backups_created_at ON account_backups(created_at);
