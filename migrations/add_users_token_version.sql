-- Migration: add_users_token_version
-- Run: docker exec -i orca-postgres psql -U postgres -d orca_db < add_users_token_version.sql
--
-- Server-side session revocation. Every login JWT carries the user's
-- token_version as its "tv" claim, and get_current_user (auth_utils.py)
-- rejects any token whose tv no longer matches the users row. Bumping the
-- column therefore logs that user out everywhere at once. Bumped on:
-- password change, password reset, and deactivation. Tokens issued before
-- this migration have no tv claim and are treated as version 0, so existing
-- sessions stay valid when this is first applied.
ALTER TABLE public.users
    ADD COLUMN IF NOT EXISTS token_version integer NOT NULL DEFAULT 0;
