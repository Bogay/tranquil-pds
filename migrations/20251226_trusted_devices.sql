ALTER TABLE oauth_device ADD COLUMN trusted_at TIMESTAMPTZ;
ALTER TABLE oauth_device ADD COLUMN trusted_until TIMESTAMPTZ;
ALTER TABLE oauth_device ADD COLUMN friendly_name TEXT;
CREATE INDEX IF NOT EXISTS idx_oauth_device_trusted ON oauth_device(trusted_until) WHERE trusted_until IS NOT NULL;
