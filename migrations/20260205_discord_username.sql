ALTER TABLE users ADD COLUMN discord_username TEXT;

UPDATE users SET discord_id = NULL, discord_verified = FALSE WHERE discord_id IS NOT NULL;
