-- Track when each user last opened the notifications panel. Rows in
-- rule_audit (assignee_id=$user) newer than this timestamp count as
-- "unread" in the TopNav bell badge. NULL means the user has never
-- opened the panel — everything is unread.
ALTER TABLE users
    ADD COLUMN notifications_last_seen TIMESTAMPTZ NULL;
