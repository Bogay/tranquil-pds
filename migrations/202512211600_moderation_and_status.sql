ALTER TABLE users ADD COLUMN deactivated_at TIMESTAMPTZ;

-- * reports u *
CREATE TABLE reports (
    id BIGINT PRIMARY KEY,
    reason_type TEXT NOT NULL,
    reason TEXT,
    subject_json JSONB NOT NULL,
    reported_by_did TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
