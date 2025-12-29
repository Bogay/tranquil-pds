ALTER TABLE invite_codes ADD COLUMN IF NOT EXISTS for_account TEXT NOT NULL DEFAULT 'admin';
CREATE INDEX IF NOT EXISTS idx_invite_codes_for_account ON invite_codes(for_account);
