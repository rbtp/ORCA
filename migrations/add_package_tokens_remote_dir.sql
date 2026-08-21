-- Migration: add_package_tokens_remote_dir
-- Run: docker exec -i orca-postgres psql -U postgres -d orca_db < add_package_tokens_remote_dir.sql
--
-- Lets an analyst choose an alternate staging directory on the remote
-- target for a deploy/triage collection, instead of always landing in
-- $env:TEMP (which resolves to C:\Windows\Temp for the SYSTEM-context
-- scheduled task the bootstrap runs under). Some environments block
-- execution from C:\Windows\Temp entirely (AppLocker/SRP/EDR policy), which
-- silently fails the collection with no clear error -- this is how an
-- operator works around that without editing any code.
-- NULL/empty means "use the existing $env:TEMP default", so this is fully
-- backward compatible with every already-issued token and every existing
-- deploy flow that doesn't set it.

ALTER TABLE package_tokens ADD COLUMN IF NOT EXISTS remote_dir VARCHAR(255);
