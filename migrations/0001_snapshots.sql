-- ISC-14: Snapshots table (append-only) — every scan writes one row per control
CREATE TABLE IF NOT EXISTS snapshots (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL,
  scan_timestamp INTEGER NOT NULL,
  control_id TEXT NOT NULL,
  observed TEXT NOT NULL,
  expected TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pass', 'drift', 'error')),
  detail TEXT,
  created_at INTEGER NOT NULL DEFAULT (cast(unixepoch() * 1000 as integer))
);

-- Index for queries: scans by time (ISC-19: ?asof= queries)
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON snapshots(scan_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_scan_id ON snapshots(scan_id);
