-- Collapsing of repeated denied/rejected events: an identical event within the
-- collapse window increments repeat_count and sets last_occurred_at instead of
-- adding a row. The row keeps the first occurrence's occurred_at, request_id
-- and source_ip.
ALTER TABLE audit_events
    ADD COLUMN repeat_count     INT NOT NULL DEFAULT 1,
    ADD COLUMN last_occurred_at TIMESTAMPTZ NULL;
