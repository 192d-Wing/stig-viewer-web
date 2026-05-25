-- Per-asset email CC list for on-demand compliance report sends.
--
-- The asset owner (and any user with write/admin ACL) can curate a small
-- list of additional recipients here. When they click "Email report now"
-- on the asset detail page, the per-asset compliance PDF is generated
-- and mailed to (owner.email if non-empty) UNION asset_email_cc.email.
--
-- We model the table as a composite PK of (asset_id, email) so duplicate
-- POSTs are a no-op via ON CONFLICT DO NOTHING — the UI is free to
-- re-submit without worrying about a 409.
CREATE TABLE asset_email_cc (
    asset_id    TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    email       TEXT NOT NULL,
    added_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    added_by    TEXT NOT NULL REFERENCES users(id),
    PRIMARY KEY (asset_id, email)
);
