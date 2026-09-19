-- INSERT OR REPLACE / REPLACE INTO overwrite a row without firing UPDATE or
-- DELETE triggers in this SQLite/D1 runtime. Abort any INSERT whose primary
-- key already exists so evidence rows cannot be silently rewritten.
CREATE TRIGGER IF NOT EXISTS snapshots_block_replace
BEFORE INSERT ON snapshots
WHEN EXISTS (SELECT 1 FROM snapshots WHERE id = NEW.id)
BEGIN
  SELECT RAISE(ABORT, 'snapshots is append-only: REPLACE is not permitted');
END;
