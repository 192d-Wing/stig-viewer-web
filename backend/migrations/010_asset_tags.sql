-- Free-form tags on assets. Many-to-many without a separate tag table —
-- tag values are just strings, and an asset's tag set is replaced
-- wholesale on each PUT (no diff-and-patch tracking).
CREATE TABLE asset_tags (
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    tag      TEXT NOT NULL,
    PRIMARY KEY (asset_id, tag)
);

CREATE INDEX asset_tags_tag_idx ON asset_tags(tag);
