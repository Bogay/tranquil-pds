ALTER TYPE notification_type ADD VALUE IF NOT EXISTS 'channel_verification';

CREATE TABLE IF NOT EXISTS channel_verifications (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    channel notification_channel NOT NULL,
    code TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, channel)
);

CREATE INDEX IF NOT EXISTS idx_channel_verifications_expires ON channel_verifications(expires_at);
