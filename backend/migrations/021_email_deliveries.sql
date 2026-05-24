-- Audit log for every outbound email the app sends. mode='dryrun'
-- when SMTP wasn't configured (we skip the send but keep the row so
-- ops can see what would have happened).
CREATE TABLE email_deliveries (
    id            BIGSERIAL PRIMARY KEY,
    kind          TEXT NOT NULL,
    to_addresses  TEXT NOT NULL,           -- comma-joined
    subject       TEXT NOT NULL,
    body_snippet  TEXT NOT NULL,
    attached      TEXT,                    -- relative path inside data_dir, if any
    mode          TEXT NOT NULL,           -- 'sent' | 'dryrun'
    error         TEXT,
    attempted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX email_deliveries_attempted_idx
    ON email_deliveries(attempted_at DESC);
