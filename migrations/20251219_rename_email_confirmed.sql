DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'email_confirmed') THEN
        ALTER TABLE users RENAME COLUMN email_confirmed TO email_verified;
    END IF;
END $$;
