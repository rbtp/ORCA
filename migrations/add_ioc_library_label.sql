-- Migration: add_ioc_library_label
-- Run: docker exec -i orca-postgres psql -U postgres -d orca_db < add_ioc_library_label.sql
--
-- Lets an analyst tag a library IOC with a short free-text label (e.g.
-- "Confirmed Malicious", "False Positive", a case reference) separate from
-- the existing threat_actor/severity/description fields. NULL for all
-- existing rows, so this is fully backward compatible.

ALTER TABLE ref_ioc_library ADD COLUMN IF NOT EXISTS label character varying(100);
