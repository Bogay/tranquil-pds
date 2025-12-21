CREATE TYPE comms_channel AS ENUM ('email', 'discord', 'telegram', 'signal');
CREATE TYPE comms_status AS ENUM ('pending', 'processing', 'sent', 'failed');
CREATE TYPE comms_type AS ENUM (
    'welcome',
    'email_verification',
    'password_reset',
    'email_update',
    'account_deletion',
    'admin_email',
    'plc_operation',
    'two_factor_code',
    'channel_verification'
);
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    handle TEXT NOT NULL UNIQUE,
    email TEXT UNIQUE,
    did TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deactivated_at TIMESTAMPTZ,
    invites_disabled BOOLEAN DEFAULT FALSE,
    takedown_ref TEXT,
    preferred_comms_channel comms_channel NOT NULL DEFAULT 'email',
    password_reset_code TEXT,
    password_reset_code_expires_at TIMESTAMPTZ,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    two_factor_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    discord_id TEXT,
    discord_verified BOOLEAN NOT NULL DEFAULT FALSE,
    telegram_username TEXT,
    telegram_verified BOOLEAN NOT NULL DEFAULT FALSE,
    signal_number TEXT,
    signal_verified BOOLEAN NOT NULL DEFAULT FALSE,
    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    migrated_to_pds TEXT,
    migrated_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_users_password_reset_code ON users(password_reset_code) WHERE password_reset_code IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_discord_id ON users(discord_id) WHERE discord_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_telegram_username ON users(telegram_username) WHERE telegram_username IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_signal_number ON users(signal_number) WHERE signal_number IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE email IS NOT NULL;
CREATE TABLE IF NOT EXISTS invite_codes (
    code TEXT PRIMARY KEY,
    available_uses INT NOT NULL DEFAULT 1,
    created_by_user UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    disabled BOOLEAN DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_invite_codes_created_by ON invite_codes(created_by_user);
CREATE TABLE IF NOT EXISTS invite_code_uses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code TEXT NOT NULL REFERENCES invite_codes(code),
    used_by_user UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(code, used_by_user)
);
CREATE TABLE IF NOT EXISTS user_keys (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    key_bytes BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    encrypted_at TIMESTAMPTZ,
    encryption_version INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS repos (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    repo_root_cid TEXT NOT NULL,
    repo_rev TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS blocks (
    cid BYTEA PRIMARY KEY,
    data BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_id UUID NOT NULL REFERENCES repos(user_id) ON DELETE CASCADE,
    collection TEXT NOT NULL,
    rkey TEXT NOT NULL,
    record_cid TEXT NOT NULL,
    takedown_ref TEXT,
    repo_rev TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(repo_id, collection, rkey)
);
CREATE INDEX idx_records_repo_rev ON records(repo_rev);
CREATE INDEX IF NOT EXISTS idx_records_repo_collection ON records(repo_id, collection);
CREATE INDEX IF NOT EXISTS idx_records_repo_collection_created ON records(repo_id, collection, created_at DESC);
CREATE TABLE IF NOT EXISTS blobs (
    cid TEXT PRIMARY KEY,
    mime_type TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    created_by_user UUID NOT NULL REFERENCES users(id),
    storage_key TEXT NOT NULL,
    takedown_ref TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_blobs_created_by_user ON blobs(created_by_user, created_at DESC);
CREATE TABLE IF NOT EXISTS app_passwords (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    privileged BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE(user_id, name)
);
CREATE INDEX IF NOT EXISTS idx_app_passwords_user_id ON app_passwords(user_id);
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
CREATE TABLE IF NOT EXISTS comms_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    channel comms_channel NOT NULL DEFAULT 'email',
    comms_type comms_type NOT NULL,
    status comms_status NOT NULL DEFAULT 'pending',
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
CREATE INDEX idx_comms_queue_status_scheduled
    ON comms_queue(status, scheduled_for)
    WHERE status = 'pending';
CREATE INDEX idx_comms_queue_user_id ON comms_queue(user_id);
CREATE TABLE IF NOT EXISTS reserved_signing_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    did TEXT,
    public_key_did_key TEXT NOT NULL,
    private_key_bytes BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '24 hours',
    used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_reserved_signing_keys_did ON reserved_signing_keys(did) WHERE did IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_reserved_signing_keys_expires ON reserved_signing_keys(expires_at) WHERE used_at IS NULL;
CREATE TABLE repo_seq (
    seq BIGSERIAL PRIMARY KEY,
    did TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type TEXT NOT NULL,
    commit_cid TEXT,
    prev_cid TEXT,
    ops JSONB,
    blobs TEXT[],
    blocks_cids TEXT[],
    prev_data_cid TEXT,
    handle TEXT,
    active BOOLEAN,
    status TEXT
);
CREATE INDEX idx_repo_seq_seq ON repo_seq(seq);
CREATE INDEX idx_repo_seq_did ON repo_seq(did);
CREATE INDEX IF NOT EXISTS idx_repo_seq_did_seq ON repo_seq(did, seq DESC);
CREATE TABLE IF NOT EXISTS session_tokens (
    id SERIAL PRIMARY KEY,
    did TEXT NOT NULL REFERENCES users(did) ON DELETE CASCADE,
    access_jti TEXT NOT NULL UNIQUE,
    refresh_jti TEXT NOT NULL UNIQUE,
    access_expires_at TIMESTAMPTZ NOT NULL,
    refresh_expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_session_tokens_did ON session_tokens(did);
CREATE INDEX idx_session_tokens_access_jti ON session_tokens(access_jti);
CREATE INDEX idx_session_tokens_refresh_jti ON session_tokens(refresh_jti);
CREATE TABLE IF NOT EXISTS used_refresh_tokens (
    refresh_jti TEXT PRIMARY KEY,
    session_id INTEGER NOT NULL REFERENCES session_tokens(id) ON DELETE CASCADE,
    used_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_used_refresh_tokens_session_id ON used_refresh_tokens(session_id);
CREATE TABLE IF NOT EXISTS oauth_device (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL UNIQUE,
    user_agent TEXT,
    ip_address TEXT NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS oauth_authorization_request (
    id TEXT PRIMARY KEY,
    did TEXT REFERENCES users(did) ON DELETE CASCADE,
    device_id TEXT REFERENCES oauth_device(id) ON DELETE SET NULL,
    client_id TEXT NOT NULL,
    client_auth JSONB,
    parameters JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    code TEXT UNIQUE
);
CREATE INDEX idx_oauth_auth_request_expires ON oauth_authorization_request(expires_at);
CREATE INDEX idx_oauth_auth_request_code ON oauth_authorization_request(code) WHERE code IS NOT NULL;
CREATE TABLE IF NOT EXISTS oauth_token (
    id SERIAL PRIMARY KEY,
    did TEXT NOT NULL REFERENCES users(did) ON DELETE CASCADE,
    token_id TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    client_id TEXT NOT NULL,
    client_auth JSONB NOT NULL,
    device_id TEXT REFERENCES oauth_device(id) ON DELETE SET NULL,
    parameters JSONB NOT NULL,
    details JSONB,
    code TEXT UNIQUE,
    current_refresh_token TEXT UNIQUE,
    scope TEXT
);
CREATE INDEX idx_oauth_token_did ON oauth_token(did);
CREATE INDEX idx_oauth_token_code ON oauth_token(code) WHERE code IS NOT NULL;
CREATE TABLE IF NOT EXISTS oauth_account_device (
    did TEXT NOT NULL REFERENCES users(did) ON DELETE CASCADE,
    device_id TEXT NOT NULL REFERENCES oauth_device(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (did, device_id)
);
CREATE TABLE IF NOT EXISTS oauth_authorized_client (
    did TEXT NOT NULL REFERENCES users(did) ON DELETE CASCADE,
    client_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    data JSONB NOT NULL,
    PRIMARY KEY (did, client_id)
);
CREATE TABLE IF NOT EXISTS oauth_used_refresh_token (
    refresh_token TEXT PRIMARY KEY,
    token_id INTEGER NOT NULL REFERENCES oauth_token(id) ON DELETE CASCADE
);
CREATE TABLE oauth_dpop_jti (
    jti TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_oauth_dpop_jti_created_at ON oauth_dpop_jti(created_at);
CREATE TABLE plc_operation_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_plc_op_tokens_user ON plc_operation_tokens(user_id);
CREATE INDEX idx_plc_op_tokens_expires ON plc_operation_tokens(expires_at);
CREATE TABLE IF NOT EXISTS account_preferences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    value_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, name)
);
CREATE INDEX IF NOT EXISTS idx_account_preferences_user_id ON account_preferences(user_id);
CREATE INDEX IF NOT EXISTS idx_account_preferences_name ON account_preferences(name);
CREATE TABLE oauth_2fa_challenge (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    did TEXT NOT NULL REFERENCES users(did) ON DELETE CASCADE,
    request_uri TEXT NOT NULL,
    code TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '10 minutes'
);
CREATE INDEX idx_oauth_2fa_challenge_request_uri ON oauth_2fa_challenge(request_uri);
CREATE INDEX idx_oauth_2fa_challenge_expires ON oauth_2fa_challenge(expires_at);
CREATE TABLE IF NOT EXISTS channel_verifications (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    channel comms_channel NOT NULL,
    code TEXT NOT NULL,
    pending_identifier TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, channel)
);
CREATE INDEX IF NOT EXISTS idx_channel_verifications_expires ON channel_verifications(expires_at);
CREATE TABLE oauth_scope_preference (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    did TEXT NOT NULL REFERENCES users(did) ON DELETE CASCADE,
    client_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    granted BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(did, client_id, scope)
);
CREATE INDEX idx_oauth_scope_pref_lookup ON oauth_scope_preference(did, client_id);
CREATE TABLE user_totp (
    did TEXT PRIMARY KEY REFERENCES users(did) ON DELETE CASCADE,
    secret_encrypted BYTEA NOT NULL,
    encryption_version INTEGER NOT NULL DEFAULT 1,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used TIMESTAMPTZ
);
CREATE TABLE backup_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    did TEXT NOT NULL REFERENCES users(did) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_backup_codes_did ON backup_codes(did);
CREATE TABLE passkeys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    did TEXT NOT NULL REFERENCES users(did) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE,
    public_key BYTEA NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used TIMESTAMPTZ,
    friendly_name TEXT,
    aaguid BYTEA,
    transports TEXT[]
);
CREATE INDEX idx_passkeys_did ON passkeys(did);
CREATE TABLE webauthn_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    did TEXT NOT NULL,
    challenge BYTEA NOT NULL,
    challenge_type TEXT NOT NULL,
    state_json TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_webauthn_challenges_did ON webauthn_challenges(did);
