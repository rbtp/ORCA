-- Migration: add_package_tokens
-- Run: docker exec -i orca-postgres psql -U postgres -d orca_db < add_package_tokens.sql

CREATE TABLE IF NOT EXISTS package_tokens (
    token           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id        INTEGER NOT NULL,
    case_name       VARCHAR(255) NOT NULL,
    created_by      INTEGER,                        -- analyst user id
    created_at      TIMESTAMP DEFAULT NOW(),
    expires_at      TIMESTAMP NOT NULL,
    revoked         BOOLEAN DEFAULT FALSE,
    revoked_at      TIMESTAMP,
    technique_count INTEGER DEFAULT 0,              -- how many techniques were packaged
    techniques_received INTEGER DEFAULT 0,          -- incremented on each ingest POST
    completed_at    TIMESTAMP                       -- set when techniques_received = technique_count
);

CREATE INDEX IF NOT EXISTS idx_package_tokens_asset_id ON package_tokens(asset_id);
CREATE INDEX IF NOT EXISTS idx_package_tokens_expires_at ON package_tokens(expires_at);

-- Served package files are written to DATA_ROOT/packages/{token}/
-- The package_tokens row is the authority — file may be deleted after expiry
