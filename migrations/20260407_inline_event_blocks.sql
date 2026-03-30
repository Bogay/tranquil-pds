ALTER TABLE repo_seq
    ADD COLUMN block_cids BYTEA[],
    ADD COLUMN block_data BYTEA[];
