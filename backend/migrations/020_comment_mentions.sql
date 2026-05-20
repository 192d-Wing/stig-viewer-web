-- @-mention records derived from rule_comments bodies.
--
-- Each row links a comment to one user that was mentioned in its body.
-- `read_at` is stamped when the mentioned user calls
-- POST /api/notifications/mark-read, mirroring the assignment watermark.
CREATE TABLE comment_mentions (
    id                TEXT PRIMARY KEY,
    comment_id        TEXT NOT NULL REFERENCES rule_comments(id) ON DELETE CASCADE,
    mentioned_user_id TEXT NOT NULL REFERENCES users(id),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    read_at           TIMESTAMPTZ NULL
);

CREATE INDEX comment_mentions_user_unread_idx
    ON comment_mentions(mentioned_user_id, read_at);
