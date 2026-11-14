-- Legacy observations retain NULL for metadata that was never captured.
ALTER TABLE snapshots ADD COLUMN baseline_version TEXT;
ALTER TABLE snapshots ADD COLUMN control_name TEXT;
ALTER TABLE snapshots ADD COLUMN severity TEXT;
ALTER TABLE snapshots ADD COLUMN citation TEXT;
