ALTER TABLE user_blocks ADD COLUMN IF NOT EXISTS repo_rev TEXT;

UPDATE user_blocks ub
SET repo_rev = r.repo_rev
FROM repos r
WHERE ub.user_id = r.user_id AND ub.repo_rev IS NULL;

CREATE INDEX IF NOT EXISTS idx_user_blocks_repo_rev ON user_blocks(user_id, repo_rev);
