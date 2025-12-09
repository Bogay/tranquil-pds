ALTER TABLE users ADD COLUMN takedown_ref TEXT;

ALTER TABLE records ADD COLUMN takedown_ref TEXT;

ALTER TABLE blobs ADD COLUMN takedown_ref TEXT;
