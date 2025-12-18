DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'notification_channel') THEN
        ALTER TYPE notification_channel RENAME TO comms_channel;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'notification_status') THEN
        ALTER TYPE notification_status RENAME TO comms_status;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'notification_type') THEN
        ALTER TYPE notification_type RENAME TO comms_type;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'notification_queue') THEN
        ALTER TABLE notification_queue RENAME TO comms_queue;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'comms_queue' AND column_name = 'notification_type') THEN
        ALTER TABLE comms_queue RENAME COLUMN notification_type TO comms_type;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_notification_queue_status_scheduled') THEN
        ALTER INDEX idx_notification_queue_status_scheduled RENAME TO idx_comms_queue_status_scheduled;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_notification_queue_user_id') THEN
        ALTER INDEX idx_notification_queue_user_id RENAME TO idx_comms_queue_user_id;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'preferred_notification_channel') THEN
        ALTER TABLE users RENAME COLUMN preferred_notification_channel TO preferred_comms_channel;
    END IF;
END $$;
