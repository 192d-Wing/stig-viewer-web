-- SAML replay cache (#62): SHA-256 of each verified Assertion/Response ID, kept until the
-- assertion can no longer be accepted. Transient (excluded from app backup); logged (not
-- UNLOGGED) so a crash does not forget still-valid assertions. Holds no secrets.
CREATE TABLE saml_seen_ids (
    id_sha256     TEXT PRIMARY KEY CHECK (id_sha256 ~ '^[0-9a-f]{64}$'),
    kind          TEXT NOT NULL CHECK (kind IN ('assertion','response')),
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ NOT NULL
);
CREATE INDEX saml_seen_ids_expiry_idx ON saml_seen_ids(expires_at);
