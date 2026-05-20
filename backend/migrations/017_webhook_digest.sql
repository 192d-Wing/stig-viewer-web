-- Track when an overdue digest was last fired per webhook so the
-- background sweep doesn't spam on every interval tick when the
-- digest cadence is lower than the loop frequency.
ALTER TABLE webhooks
    ADD COLUMN last_digest_at TIMESTAMPTZ NULL;
