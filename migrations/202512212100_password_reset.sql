ALTER TABLE users ADD COLUMN IF NOT EXISTS password_reset_code TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_reset_code_expires_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_users_password_reset_code ON users(password_reset_code) WHERE password_reset_code IS NOT NULL;
