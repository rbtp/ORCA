-- Behavioral Analysis Migration
-- Run: docker exec orca-postgres psql -U postgres -d orca_db -f /tmp/behavioral_analysis_migration.sql

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS behavioral_jobs (
    job_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id            INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    submitted_file      TEXT NOT NULL,
    file_path           TEXT NOT NULL,
    file_md5            TEXT,
    file_sha256         TEXT,
    file_type           TEXT,
    file_size_bytes     BIGINT,
    submitted_by        TEXT,
    submitted_at        TIMESTAMPTZ DEFAULT NOW(),

    capa_status         TEXT DEFAULT 'pending',
    floss_status        TEXT DEFAULT 'pending',
    speakeasy_status    TEXT DEFAULT 'pending',

    capa_started_at         TIMESTAMPTZ,
    capa_completed_at       TIMESTAMPTZ,
    floss_started_at        TIMESTAMPTZ,
    floss_completed_at      TIMESTAMPTZ,
    speakeasy_started_at    TIMESTAMPTZ,
    speakeasy_completed_at  TIMESTAMPTZ,

    capa_error          TEXT,
    floss_error         TEXT,
    speakeasy_error     TEXT,

    overall_status      TEXT DEFAULT 'running'
);

CREATE TABLE IF NOT EXISTS capa_results (
    id              SERIAL PRIMARY KEY,
    job_id          UUID NOT NULL REFERENCES behavioral_jobs(job_id) ON DELETE CASCADE,
    asset_id        INTEGER NOT NULL,
    technique_id    TEXT NOT NULL,
    technique_name  TEXT NOT NULL,
    tactic_name     TEXT NOT NULL,
    namespace       TEXT,
    severity        TEXT,
    raw_result      JSONB
);

CREATE INDEX IF NOT EXISTS idx_capa_results_job       ON capa_results(job_id);
CREATE INDEX IF NOT EXISTS idx_capa_results_asset     ON capa_results(asset_id);
CREATE INDEX IF NOT EXISTS idx_capa_results_technique ON capa_results(technique_id);

CREATE TABLE IF NOT EXISTS floss_results (
    id              SERIAL PRIMARY KEY,
    job_id          UUID NOT NULL REFERENCES behavioral_jobs(job_id) ON DELETE CASCADE,
    asset_id        INTEGER NOT NULL,
    string_value    TEXT NOT NULL,
    string_type     TEXT NOT NULL,
    is_ioc          BOOLEAN DEFAULT FALSE,
    ioc_type        TEXT,
    string_offset   BIGINT
);

CREATE INDEX IF NOT EXISTS idx_floss_results_job   ON floss_results(job_id);
CREATE INDEX IF NOT EXISTS idx_floss_results_asset ON floss_results(asset_id);
CREATE INDEX IF NOT EXISTS idx_floss_results_ioc   ON floss_results(job_id, is_ioc) WHERE is_ioc = TRUE;

CREATE TABLE IF NOT EXISTS speakeasy_results (
    id              SERIAL PRIMARY KEY,
    job_id          UUID NOT NULL REFERENCES behavioral_jobs(job_id) ON DELETE CASCADE,
    asset_id        INTEGER NOT NULL,
    result_type     TEXT NOT NULL,
    entry_point     INTEGER DEFAULT 0,
    func_name       TEXT,
    args            JSONB,
    ret_val         TEXT,
    pc              TEXT,
    protocol        TEXT,
    host            TEXT,
    port            INTEGER,
    url             TEXT,
    raw_entry       JSONB
);

CREATE INDEX IF NOT EXISTS idx_speakeasy_results_job  ON speakeasy_results(job_id);
CREATE INDEX IF NOT EXISTS idx_speakeasy_results_asset ON speakeasy_results(asset_id);
CREATE INDEX IF NOT EXISTS idx_speakeasy_results_type  ON speakeasy_results(job_id, result_type);
