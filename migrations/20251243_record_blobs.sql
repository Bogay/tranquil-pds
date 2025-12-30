CREATE TABLE record_blobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    record_uri TEXT NOT NULL,
    blob_cid TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(repo_id, record_uri, blob_cid)
);

CREATE INDEX idx_record_blobs_repo_id ON record_blobs(repo_id);
CREATE INDEX idx_record_blobs_blob_cid ON record_blobs(blob_cid);
