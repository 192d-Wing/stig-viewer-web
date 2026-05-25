-- Per-asset scheduled compliance-report email.
--
-- The on-demand per-asset email path landed in 029_asset_email_cc.sql /
-- PR #63. This migration adds the knobs that turn that same send into a
-- recurring background job: pick a cadence on the asset and a new
-- scheduler loop fires `send_asset_report` whenever enough time has
-- elapsed since the last send.
--
-- Cadence is a small enum encoded as TEXT to match how the rest of the
-- codebase stores its small enums (`assets.classification`,
-- `checklist_rules.status`, etc). The four legal values are
-- 'off' | 'daily' | 'weekly' | 'monthly'; validation is enforced in the
-- HTTP handler.
--
-- `email_last_sent_at` is stamped by the scheduler after each attempt
-- (whether it actually mailed via SMTP or fell into dryrun mode) so the
-- cadence interval check is monotonic and a no-op tick stays a no-op
-- until enough wall-clock time has passed. NULL means "never sent" and
-- always fires on the first eligible tick.
--
-- The partial index keeps the scheduler's per-tick scan cheap: only
-- rows where the owner opted in to a non-`off` cadence matter, and that
-- is expected to be a small fraction of the total asset set.
ALTER TABLE assets
    ADD COLUMN email_cadence       TEXT NOT NULL DEFAULT 'off',
                                              -- 'off' | 'daily' | 'weekly' | 'monthly'
    ADD COLUMN email_last_sent_at  TIMESTAMPTZ NULL;

CREATE INDEX assets_email_cadence_idx ON assets(email_cadence)
    WHERE email_cadence <> 'off';
