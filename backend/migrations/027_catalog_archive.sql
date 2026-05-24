-- Catalog archive — stores a per-version JSON snapshot of each STIG so
-- ops can diff the current live catalog row against the previous one
-- after a DISA sync replaces the file in place. Today the sync path
-- overwrites `${data_dir}/stigs/{id}.json` and there's no record of
-- what changed; this table is the first half of fixing that (the other
-- half is the copy-then-insert in `sync::disa`).
--
-- One row per (stig_id, version, release_info). Idempotent — if the
-- sync runs twice without DISA actually shipping a new revision the
-- second insert is a no-op via the UNIQUE constraint.
CREATE TABLE catalog_archive (
    id            BIGSERIAL PRIMARY KEY,
    stig_id       TEXT NOT NULL,
    version       TEXT NOT NULL,
    release_info  TEXT NOT NULL,
    archived_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    json_path     TEXT NOT NULL,         -- relative path under data_dir
    UNIQUE (stig_id, version, release_info)
);

CREATE INDEX catalog_archive_stig_archived_idx
    ON catalog_archive(stig_id, archived_at DESC);
