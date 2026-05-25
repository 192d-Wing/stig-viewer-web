-- Per-webhook payload "flavor" — which wire schema the dispatcher
-- formats outbound events into. Up until now every webhook received a
-- Slack-incoming-webhook-compatible body (`{ text, attachments }`).
-- That works fine for Slack itself, but Microsoft Teams expects a
-- "MessageCard" JSON object and custom integrations often prefer a
-- flatter, format-agnostic shape they can re-render however they like.
--
-- The column is plain TEXT (not a Postgres enum) to keep schema churn
-- low when we inevitably add more flavors. Validation is done in the
-- HTTP layer against an allow-list, mirroring the `kinds` column.
--
-- Default 'slack' preserves the wire format every existing webhook is
-- already receiving — operators do not need to touch their config to
-- stay on the legacy schema.
ALTER TABLE webhooks
    ADD COLUMN flavor TEXT NOT NULL DEFAULT 'slack';
