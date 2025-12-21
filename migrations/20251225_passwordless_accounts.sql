ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;
ALTER TABLE users ADD COLUMN password_required BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE users ADD COLUMN recovery_token TEXT;
ALTER TABLE users ADD COLUMN recovery_token_expires_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_users_recovery_token ON users(recovery_token) WHERE recovery_token IS NOT NULL;
