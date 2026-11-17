-- Request context on durable audit events: where the request came from
-- (X-Forwarded-For / X-Real-IP, as asserted by the client or the trusted
-- proxy in front of the app), a server-generated request id, and the role the
-- user held at the time. All nullable: rows written before this migration
-- (and events written outside a request) have no context.
ALTER TABLE audit_events
    ADD COLUMN source_ip  TEXT NULL,
    ADD COLUMN request_id TEXT NULL,
    ADD COLUMN user_role  TEXT NULL;
