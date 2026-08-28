-- Migration: add_vt_lookups
-- Run: docker exec -i orca-postgres psql -U postgres -d orca_db < add_vt_lookups.sql
--
-- Backs the background VirusTotal lookup worker. Keyed globally by hash (not
-- per-asset/case) -- the same hash means the same verdict regardless of which
-- machine it came from, so this also means the same hash is never looked up
-- twice even if it shows up on multiple assets. Only ever holds hashes that
-- have actually been queried (found/not_found/error) -- a hash with no row
-- here yet is simply "not looked up yet", discovered by the worker scanning
-- AMCACHE/SUSPICIOUS_LOCATIONS_HASH evidence for hashes missing from this
-- table, so there's no separate queue table to keep in sync.

CREATE TABLE IF NOT EXISTS public.vt_lookups (
    hash              text PRIMARY KEY,
    status            text NOT NULL,   -- found | not_found | error
    malicious_count   integer,
    suspicious_count  integer,
    total_engines     integer,
    checked_at        timestamp with time zone NOT NULL DEFAULT NOW()
);
