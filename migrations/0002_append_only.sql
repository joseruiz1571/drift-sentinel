-- Enforce append-only at the database: abort any UPDATE or DELETE on snapshots.
-- A D1 admin can still DROP these triggers; the guarantee is not a substitute
-- for access control on the database itself.
CREATE TRIGGER IF NOT EXISTS snapshots_block_update
BEFORE UPDATE ON snapshots
BEGIN
  SELECT RAISE(ABORT, 'snapshots is append-only: UPDATE is not permitted');
END;

CREATE TRIGGER IF NOT EXISTS snapshots_block_delete
BEFORE DELETE ON snapshots
BEGIN
  SELECT RAISE(ABORT, 'snapshots is append-only: DELETE is not permitted');
END;
