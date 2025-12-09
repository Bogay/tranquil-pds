CREATE TYPE notification_channel AS ENUM ('email', 'discord', 'telegram', 'signal');
CREATE TYPE notification_status AS ENUM ('pending', 'processing', 'sent', 'failed');
CREATE TYPE notification_type AS ENUM (
    'welcome',
    'email_verification',
    'password_reset',
    'email_update',
    'account_deletion',
    'admin_email'
);

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    handle TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    did TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- status & moderation
    deactivated_at TIMESTAMPTZ,
    invites_disabled BOOLEAN DEFAULT FALSE,
    takedown_ref TEXT,

    -- notifs
    preferred_notification_channel notification_channel NOT NULL DEFAULT 'email',

    -- auth & verification
    password_reset_code TEXT,
    password_reset_code_expires_at TIMESTAMPTZ,

    email_pending_verification TEXT,
    email_confirmation_code TEXT,
    email_confirmation_code_expires_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_users_password_reset_code ON users(password_reset_code) WHERE password_reset_code IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_email_confirmation_code ON users(email_confirmation_code) WHERE email_confirmation_code IS NOT NULL;

CREATE TABLE IF NOT EXISTS invite_codes (
    code TEXT PRIMARY KEY,
    available_uses INT NOT NULL DEFAULT 1,
    created_by_user UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    disabled BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS invite_code_uses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code TEXT NOT NULL REFERENCES invite_codes(code),
    used_by_user UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(code, used_by_user)
);

-- TODO: encrypt at rest!
CREATE TABLE IF NOT EXISTS user_keys (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    key_bytes BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS repos (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    repo_root_cid TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- content addressable storage
CREATE TABLE IF NOT EXISTS blocks (
    cid BYTEA PRIMARY KEY,
    data BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- denormalized index for fast queries
CREATE TABLE IF NOT EXISTS records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_id UUID NOT NULL REFERENCES repos(user_id) ON DELETE CASCADE,
    collection TEXT NOT NULL,
    rkey TEXT NOT NULL,
    record_cid TEXT NOT NULL,
    takedown_ref TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(repo_id, collection, rkey)
);

CREATE TABLE IF NOT EXISTS blobs (
    cid TEXT PRIMARY KEY,
    mime_type TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    created_by_user UUID NOT NULL REFERENCES users(id),
    storage_key TEXT NOT NULL,
    takedown_ref TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sessions (
    access_jwt TEXT PRIMARY KEY,
    refresh_jwt TEXT NOT NULL UNIQUE,
    did TEXT NOT NULL REFERENCES users(did) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS app_passwords (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    privileged BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE(user_id, name)
);

-- naughty list
CREATE TABLE reports (
    id BIGINT PRIMARY KEY,
    reason_type TEXT NOT NULL,
    reason TEXT,
    subject_json JSONB NOT NULL,
    reported_by_did TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS account_deletion_requests (
    token TEXT PRIMARY KEY,
    did TEXT NOT NULL REFERENCES users(did) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
