ALTER TABLE session_tokens ADD COLUMN app_password_name TEXT;
CREATE INDEX idx_session_tokens_app_password ON session_tokens(did, app_password_name) WHERE app_password_name IS NOT NULL;
