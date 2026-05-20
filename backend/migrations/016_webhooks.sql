-- Outbound webhooks for assignment (and future) events. The `kinds`
-- array gates which event types a given webhook receives; today only
-- 'assigned' fires, but the column is open-ended so we can add more
-- kinds (overdue, status_change, etc.) without another migration.
CREATE TABLE webhooks (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    url         TEXT NOT NULL,
    secret      TEXT NOT NULL DEFAULT '',
    kinds       TEXT[] NOT NULL DEFAULT ARRAY['assigned'],
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_by  TEXT NOT NULL REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Per-attempt delivery log: one row per outbound HTTP call. Either
-- (http_status, response) is populated on a real reply, or `error` is
-- populated when the request itself failed (connection refused, DNS,
-- timeout, etc.). The frontend "recent deliveries" panel reads this.
CREATE TABLE webhook_deliveries (
    id          BIGSERIAL PRIMARY KEY,
    webhook_id  TEXT NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,
    payload     TEXT NOT NULL,
    http_status INT,
    response    TEXT,
    error       TEXT,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX webhook_deliveries_webhook_idx
    ON webhook_deliveries(webhook_id, attempted_at DESC);
