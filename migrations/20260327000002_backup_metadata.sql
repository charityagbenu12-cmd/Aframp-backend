-- Backup metadata table (Issue #119)
-- Tracks every daily snapshot and its automated verification result.

CREATE TABLE IF NOT EXISTS backup_metadata (
    id                   BIGSERIAL PRIMARY KEY,
    snapshot_filename    TEXT        NOT NULL UNIQUE,
    file_size_bytes      BIGINT      NOT NULL,
    storage_location     TEXT        NOT NULL,
    snapshot_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    verification_status  TEXT        NOT NULL DEFAULT 'pending'
                             CHECK (verification_status IN ('pending', 'verified', 'failed')),
    verified_at          TIMESTAMPTZ,
    notes                TEXT
);

CREATE INDEX IF NOT EXISTS idx_backup_metadata_snapshot_at
    ON backup_metadata (snapshot_at DESC);

COMMENT ON TABLE backup_metadata IS
    'Audit record for every automated database snapshot and its integrity verification result.';
