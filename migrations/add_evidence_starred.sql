-- Migration: add_evidence_starred
-- Run: docker exec -i orca-postgres psql -U postgres -d orca_db < add_evidence_starred.sql
--
-- Lets an analyst star individual evidence rows while reviewing a technique,
-- then filter the evidence view down to only starred rows -- separate from
-- the existing keyword filter. Defaults to false for all existing rows, so
-- this is fully backward compatible.

ALTER TABLE evidence ADD COLUMN IF NOT EXISTS starred boolean NOT NULL DEFAULT false;

CREATE INDEX IF NOT EXISTS idx_evidence_starred ON evidence (asset_id, t_code, starred) WHERE starred = true;
