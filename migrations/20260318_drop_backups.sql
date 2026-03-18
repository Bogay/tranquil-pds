DROP TABLE IF EXISTS account_backups;
ALTER TABLE users DROP COLUMN IF EXISTS backup_enabled;
