CREATE TABLE repo_seq (
    seq BIGSERIAL PRIMARY KEY,
    did TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type TEXT NOT NULL,
    commit_cid TEXT,
    prev_cid TEXT,
    ops JSONB,
    blobs TEXT[]
);

CREATE INDEX idx_repo_seq_seq ON repo_seq(seq);
CREATE INDEX idx_repo_seq_did ON repo_seq(did);
