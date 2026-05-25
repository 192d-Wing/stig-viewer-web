-- Per-user notification preferences.
--
-- One row per (user, event_type) pair. The notifications bell modal
-- surfaces a fixed set of event types ("assigned", "overdue",
-- "mentions", "approvals", "decisions", "assigned_drafts"); when a
-- pref row exists with `enabled = false`, the corresponding bucket is
-- empty for that user AND its contribution to `unread_count` is
-- dropped.
--
-- Missing rows are intentionally treated as `enabled = true` by the
-- HTTP layer. This keeps existing users (zero rows in this table)
-- seeing every event type by default — matching pre-migration
-- behavior — and lets the PUT handler upsert only the fields the
-- client cares about without us pre-seeding rows for every user at
-- registration time.
--
-- `event_type` is a free-form TEXT column rather than a CHECK
-- constraint because the set of event types is owned by the HTTP
-- layer and is expected to grow. Unknown event_type rows are simply
-- ignored when computing the response shape.
--
-- ON DELETE CASCADE on the user FK keeps this table clean when an
-- account is removed.
CREATE TABLE notification_prefs (
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    enabled    BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (user_id, event_type)
);
