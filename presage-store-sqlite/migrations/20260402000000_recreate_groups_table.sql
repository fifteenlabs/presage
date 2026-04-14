CREATE TABLE groups_new (
  master_key                        BLOB NOT NULL PRIMARY KEY,
  title                             TEXT,
  revision                          INTEGER NOT NULL DEFAULT 0,
  invite_link_password              BLOB,
  access_control                    BLOB,
  avatar                            TEXT,
  description                       TEXT,
  members                           BLOB NOT NULL,
  pending_members                   BLOB NOT NULL,
  requesting_members                BLOB NOT NULL,
  needs_hydration                   BOOLEAN NOT NULL DEFAULT 0,
  blocked                           BOOLEAN NOT NULL DEFAULT 0,
  whitelisted                       BOOLEAN NOT NULL DEFAULT 0,
  archived                          BOOLEAN NOT NULL DEFAULT 0,
  marked_unread                     BOOLEAN NOT NULL DEFAULT 0,
  muted_until_timestamp             INTEGER NOT NULL DEFAULT 0,
  dont_notify_for_mentions_if_muted BOOLEAN NOT NULL DEFAULT 0,
  hide_story                        BOOLEAN NOT NULL DEFAULT 0,
  story_send_mode                   INTEGER NOT NULL DEFAULT 0
);

INSERT INTO groups_new (
  master_key, title, revision, invite_link_password,
  access_control, avatar, description,
  members, pending_members, requesting_members
)
SELECT
  master_key, title, revision, invite_link_password,
  access_control, avatar, description,
  members, pending_members, requesting_members
FROM groups;

DROP TABLE groups;
ALTER TABLE groups_new RENAME TO groups;
