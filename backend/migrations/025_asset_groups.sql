-- Asset groups: first-class, named collections of assets.
--
-- Distinct from `asset_tags` (which are free-form string labels). A group
-- has a single owner and an explicit, mutable membership list. An asset
-- can belong to any number of groups (many-to-many via
-- `asset_group_members`).
--
-- v1 intentionally has no per-group ACL — the group owner (or a global
-- admin) is the only one who can edit name/description/membership. Every
-- authenticated user can list groups and view their members. If we need
-- finer-grained sharing later we can mirror the asset_acl pattern.
CREATE TABLE asset_groups (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    owner_id    TEXT NOT NULL REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE asset_group_members (
    group_id  TEXT NOT NULL REFERENCES asset_groups(id) ON DELETE CASCADE,
    asset_id  TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    added_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    added_by  TEXT NOT NULL REFERENCES users(id),
    PRIMARY KEY (group_id, asset_id)
);

CREATE INDEX asset_group_members_asset_idx ON asset_group_members(asset_id);
