CREATE TABLE IF NOT EXISTS user_blocks (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    block_cid BYTEA NOT NULL,
    PRIMARY KEY (user_id, block_cid)
);

CREATE INDEX IF NOT EXISTS idx_user_blocks_user_id ON user_blocks(user_id);
