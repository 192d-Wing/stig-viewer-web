CREATE TABLE IF NOT EXISTS audit_log (
    id           BIGSERIAL    PRIMARY KEY,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    actor_sub    TEXT         NOT NULL,
    actor_email  TEXT,
    actor_role   TEXT         NOT NULL,
    action       TEXT         NOT NULL,
    resource     TEXT,
    remote_ip    TEXT,
    status_code  INTEGER      NOT NULL,
    metadata     JSONB
);

CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor      ON audit_log (actor_sub);
CREATE INDEX IF NOT EXISTS idx_audit_log_action     ON audit_log (action);
