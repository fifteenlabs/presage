-- Indexed `group_id` column for O(log N) call_event peer resolution.
--
-- Sync `call_event.conversation_id` for group calls carries the 32-byte
-- derived group_id (one-way SHO of master_key). Without this column the
-- resolver iterates all groups and re-derives each one's group_id on every
-- event. Mirrors Signal Desktop's `conversation.groupId` column.
--
-- Column is nullable so the migration is non-destructive on existing rows;
-- a partial UNIQUE INDEX enforces uniqueness only on populated rows.
-- Pre-existing rows get backfilled the next time `save_group` runs for
-- them (storage sync / group update / avatar refresh); until then the
-- resolver's default fallback iterates as before.
ALTER TABLE groups ADD COLUMN group_id BLOB;

CREATE UNIQUE INDEX groups_by_group_id
  ON groups (group_id) WHERE group_id IS NOT NULL;
