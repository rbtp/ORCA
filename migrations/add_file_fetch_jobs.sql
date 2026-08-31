-- Migration: add_file_fetch_jobs
-- Run: docker exec -i orca-postgres psql -U postgres -d orca_db < add_file_fetch_jobs.sql
--
-- Tracks one-off "pull this exact file" jobs triggered from the MFT file
-- browser -- deliberately its own table, not artifact_results/evidence,
-- so a one-off fetch never shows up in the MITRE technique checklist or
-- any technique-workflow UI. token is a single-use secret the pushed
-- launcher presents when POSTing the file back, checked the same way
-- package_tokens gates collection ingest.

CREATE TABLE IF NOT EXISTS public.file_fetch_jobs (
    job_id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id     integer NOT NULL,
    token        uuid NOT NULL DEFAULT gen_random_uuid(),
    file_path    text NOT NULL,
    status       text NOT NULL DEFAULT 'pending',  -- pending | staged | triggered | received | failed | timeout
    error        text,
    local_path   text,
    file_size    bigint,
    sha256       text,
    created_by   integer,
    created_at   timestamp with time zone NOT NULL DEFAULT NOW(),
    completed_at timestamp with time zone
);

CREATE INDEX IF NOT EXISTS idx_file_fetch_jobs_asset ON public.file_fetch_jobs (asset_id);
CREATE INDEX IF NOT EXISTS idx_file_fetch_jobs_token ON public.file_fetch_jobs (token);
