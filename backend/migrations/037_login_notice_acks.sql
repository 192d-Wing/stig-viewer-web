-- AC-8 system use notification acknowledgements. One row per "I Agree" click;
-- the login-start endpoints atomically consume it. Transient runtime table like
-- `sessions` (pruned on insert), so it is excluded from backup. No foreign keys:
-- the acknowledgement happens before any user is known.
CREATE TABLE login_notice_acks (
    id              TEXT PRIMARY KEY,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    consumed_at     TIMESTAMPTZ NULL,
    notice_version  TEXT        NOT NULL,
    ip              TEXT        NOT NULL DEFAULT '' CHECK (length(ip) <= 45),
    user_agent      TEXT        NOT NULL DEFAULT '',
    method          TEXT        NULL,  -- 'oidc' | 'saml'
    saml_request_id TEXT        NULL
);
CREATE INDEX login_notice_acks_created_idx ON login_notice_acks(created_at);
CREATE INDEX login_notice_acks_expiry_idx
    ON login_notice_acks(expires_at) WHERE consumed_at IS NULL;
CREATE UNIQUE INDEX login_notice_acks_saml_req_idx
    ON login_notice_acks(saml_request_id) WHERE saml_request_id IS NOT NULL;
