-- Persistent record of every background scheduler tick.
--
-- Five `tokio::spawn` loops drive periodic work in `main.rs` (DISA sync,
-- dashboard snapshot, overdue-digest webhook fan-out, audit retention,
-- and the weekly compliance report). Each currently only emits tracing
-- output, which means ops have no way to confirm "did the 24h prune run
-- last night?" without scraping logs. This table records every tick:
-- a `running` row is inserted at the start and then flipped to `ok` or
-- `error` (with a message) when the tick finishes.
--
-- The `name` column is a free-text discriminator the application owns —
-- we deliberately do not enforce a CHECK so adding a new scheduler in
-- code is a one-line change. Today the known values are:
--   sync | snapshot | overdue_digest | audit_retention | compliance_report

CREATE TABLE scheduler_runs (
    id           BIGSERIAL PRIMARY KEY,
    name         TEXT NOT NULL,
    started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at  TIMESTAMPTZ,
    status       TEXT NOT NULL DEFAULT 'running',
    message      TEXT
);

CREATE INDEX scheduler_runs_name_started_idx
    ON scheduler_runs(name, started_at DESC);
