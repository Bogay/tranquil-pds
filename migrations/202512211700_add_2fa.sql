ALTER TABLE users ADD COLUMN two_factor_enabled BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TYPE notification_type ADD VALUE 'two_factor_code';

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
