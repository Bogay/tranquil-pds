CREATE TYPE notification_channel AS ENUM ('email', 'discord', 'telegram', 'signal');
CREATE TYPE notification_status AS ENUM ('pending', 'processing', 'sent', 'failed');
CREATE TYPE notification_type AS ENUM (
    'welcome',
    'email_verification',
    'password_reset',
    'email_update',
    'account_deletion'
);

CREATE TABLE IF NOT EXISTS notification_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    channel notification_channel NOT NULL DEFAULT 'email',
    notification_type notification_type NOT NULL,
    status notification_status NOT NULL DEFAULT 'pending',
    recipient TEXT NOT NULL,
    subject TEXT,
    body TEXT NOT NULL,
    metadata JSONB,
    attempts INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 3,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    scheduled_for TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ
);

CREATE INDEX idx_notification_queue_status_scheduled
    ON notification_queue(status, scheduled_for)
    WHERE status = 'pending';

CREATE INDEX idx_notification_queue_user_id ON notification_queue(user_id);

ALTER TABLE users ADD COLUMN IF NOT EXISTS preferred_notification_channel notification_channel NOT NULL DEFAULT 'email';
