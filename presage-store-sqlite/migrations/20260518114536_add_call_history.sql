-- Canonical merged call log. One row per (call_id, peer_id) — the state
-- machine in `presage::model::calls::transition_call_history` collapses
-- per-event sync records into a single entry, and writes here via
-- `ContentsStore::save_call_history`.
--
-- Column naming follows Signal Desktop's `callsHistory` (migrations 89 and
-- 1210) so cross-tool reasoning matches:
--   ringer_id           — ACI of who rang the call (optional)
--   started_by_id       — ACI of the call initiator (optional)
--   ended_timestamp_ms  — wall-clock end of the call (optional)
--
-- All three are nullable today: wire `call_event` doesn't carry them and
-- backup import doesn't yet populate them. Reserved for live-call lifecycle
-- code paths.
--
-- Status strings overlap between Direct and Group modes ("Accepted",
-- "Missed", "Deleted", …) — readers disambiguate via the `mode` column,
-- matching Desktop's convention.
CREATE TABLE IF NOT EXISTS call_history (
  call_id            INTEGER NOT NULL, -- RingRTC u64, bit-preserved as i64
  peer_id            TEXT NOT NULL,    -- UUID (direct) / hex(master_key) (group) / room_id (adhoc)
  ringer_id          TEXT,
  mode               TEXT NOT NULL,    -- "Direct" | "Group" | "Adhoc"
  call_type          TEXT NOT NULL,    -- "Audio" | "Video" | "Group" | "Adhoc"
  direction          TEXT NOT NULL,    -- "Incoming" | "Outgoing"
  status             TEXT NOT NULL,    -- mode-dependent; see CallStatus::parse
  timestamp_ms       INTEGER NOT NULL,
  started_by_id      TEXT,
  ended_timestamp_ms INTEGER,
  PRIMARY KEY (call_id, peer_id)
);

-- Chronological listing for the "calls" tab. Includes call_id/peer_id to
-- keep the index covering for ORDER BY timestamp_ms DESC queries that only
-- need to surface row identity.
CREATE INDEX IF NOT EXISTS call_history_order
  ON call_history (timestamp_ms DESC, call_id, peer_id);
