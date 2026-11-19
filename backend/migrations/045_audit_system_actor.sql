-- System-originated audit events (for example a scheduled DISA download that
-- hit its size cap) have no acting user. A NULL user_id means "system", and is
-- permitted only together with user_role = 'system'; every user-originated row
-- keeps its user_id (and its foreign key to users).
ALTER TABLE audit_events ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE audit_events
    ADD CONSTRAINT audit_events_system_actor
    CHECK (user_id IS NOT NULL OR COALESCE(user_role, '') = 'system');
COMMENT ON COLUMN audit_events.user_id IS
    'Acting user; NULL = system-originated event (user_role = ''system'').';
