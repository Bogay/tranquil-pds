CREATE TABLE IF NOT EXISTS account_deletion_requests (
    token TEXT PRIMARY KEY,
    did TEXT NOT NULL REFERENCES users(did) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
