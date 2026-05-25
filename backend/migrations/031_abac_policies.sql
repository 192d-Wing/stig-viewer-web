-- Attribute-based access control (ABAC) policies.
--
-- Layered on top of the existing owner/ACL/admin checks in
-- `asset_acl::user_can`. When none of those three paths grant access,
-- we evaluate every enabled policy whose `level` equals the requested
-- access level AND whose role/classification/tag predicates (each NULL
-- meaning "any") match the requesting user + target asset.
--
-- Deny wins over Allow when multiple rows match — a single deny pulls
-- the answer to FORBIDDEN even if other rows would allow. With zero
-- rows in the table the helper returns `NoOpinion` and callers fall
-- back to today's behaviour exactly.
CREATE TABLE abac_policies (
    id                    TEXT PRIMARY KEY,
    name                  TEXT NOT NULL UNIQUE,
    effect                TEXT NOT NULL,          -- 'allow' | 'deny'
    level                 TEXT NOT NULL,          -- 'read' | 'write' | 'admin'
    role_match            TEXT,                   -- NULL = match any role
    classification_match  TEXT,                   -- NULL = any
    tag_match             TEXT,                   -- NULL = any; matched against asset.tags
    enabled               BOOLEAN NOT NULL DEFAULT TRUE,
    created_by            TEXT NOT NULL REFERENCES users(id),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX abac_policies_enabled_idx ON abac_policies(enabled);
