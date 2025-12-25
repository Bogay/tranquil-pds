ALTER TABLE oauth_token ADD COLUMN previous_refresh_token TEXT;
ALTER TABLE oauth_token ADD COLUMN rotated_at TIMESTAMPTZ;
