ALTER TABLE records ADD COLUMN repo_rev TEXT;
CREATE INDEX idx_records_repo_rev ON records(repo_rev);
