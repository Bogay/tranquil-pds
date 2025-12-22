ALTER TABLE users ADD COLUMN allow_legacy_login BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE session_tokens ADD COLUMN mfa_verified BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE session_tokens ADD COLUMN legacy_login BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX idx_session_tokens_legacy ON session_tokens(did, legacy_login) WHERE legacy_login = TRUE;

ALTER TYPE comms_type ADD VALUE IF NOT EXISTS 'legacy_login_alert';
