-- Admin console support: track when each user last established a session
-- so the admin user list can surface activity at a glance.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS last_login TIMESTAMPTZ NULL;
