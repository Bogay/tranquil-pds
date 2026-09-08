ALTER TABLE blobs DROP CONSTRAINT IF EXISTS blobs_pkey;
ALTER TABLE blobs ADD PRIMARY KEY (cid, created_by_user);
