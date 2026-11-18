-- AC-8 login binding: the protocol values for an in-flight login are stored on
-- the acknowledgement row. The columns are set at login start (when the ack is
-- consumed); the row is deleted at login completion (callback / ACS claim) or by
-- the 10-minute prune. The table stays excluded from backup.
ALTER TABLE login_notice_acks
    ADD COLUMN oidc_state         TEXT NULL,
    ADD COLUMN oidc_nonce         TEXT NULL,
    ADD COLUMN oidc_pkce_verifier TEXT NULL;

CREATE INDEX login_notice_acks_consumed_idx
    ON login_notice_acks(consumed_at) WHERE consumed_at IS NOT NULL;
