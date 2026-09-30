ALTER TABLE comms_queue ADD COLUMN html_body TEXT;
UPDATE comms_queue SET html_body = metadata->>'html_body' WHERE metadata IS NOT NULL;
ALTER TABLE comms_queue DROP COLUMN IF EXISTS metadata;
