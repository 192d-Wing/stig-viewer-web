-- AC-8 follow-up (#78): protect the in-flight OIDC login secrets held on
-- `login_notice_acks`. (045 is taken by an open PR; keep this number.)
--  * `oidc_state` is only ever compared for equality, so store its SHA-256
--    (lowercase hex, identical to `db_notice::state_digest`) instead.
--  * The table is UNLOGGED: the remaining plaintext nonce and PKCE verifier
--    (live for at most 10 minutes) stay out of the WAL, replicas and PITR.
--    UNLOGGED tables are truncated after a crash and empty on a promoted
--    standby, so in-flight users must re-acknowledge (fails closed). The table
--    has no foreign keys in either direction, so this is allowed.
-- Existing rows are hashed in place (they expire within minutes anyway).
UPDATE login_notice_acks
   SET oidc_state = encode(sha256(convert_to(oidc_state, 'UTF8')), 'hex')
 WHERE oidc_state IS NOT NULL;
ALTER TABLE login_notice_acks RENAME COLUMN oidc_state TO oidc_state_sha256;
ALTER TABLE login_notice_acks SET UNLOGGED;
COMMENT ON TABLE login_notice_acks IS
    'Transient AC-8 acknowledgements and in-flight login bindings. UNLOGGED: not in WAL/replicas/PITR, truncated on crash, excluded from app backup. oidc_state is stored only as a SHA-256 hash.';
