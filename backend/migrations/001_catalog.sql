CREATE TABLE IF NOT EXISTS stigs_catalog (
    id           TEXT PRIMARY KEY,
    title        TEXT        NOT NULL,
    category     TEXT        NOT NULL,
    version      TEXT        NOT NULL DEFAULT '',
    release_info TEXT        NOT NULL DEFAULT '',
    rule_count   INTEGER     NOT NULL DEFAULT 0,
    json_path    TEXT        NOT NULL,
    last_updated TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_stigs_catalog_category ON stigs_catalog (category);
