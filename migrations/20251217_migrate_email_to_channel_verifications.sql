ALTER TABLE channel_verifications ADD COLUMN pending_identifier TEXT;

INSERT INTO channel_verifications (user_id, channel, code, pending_identifier, expires_at)
SELECT id, 'email', email_confirmation_code, email_pending_verification, email_confirmation_code_expires_at
FROM users
WHERE email_confirmation_code IS NOT NULL AND email_confirmation_code_expires_at IS NOT NULL;

ALTER TABLE users
DROP COLUMN email_confirmation_code,
DROP COLUMN email_confirmation_code_expires_at,
DROP COLUMN email_pending_verification;
