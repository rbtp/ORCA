-- Migration: add_user_account_management
-- Run: docker exec -i orca-postgres psql -U postgres -d orca_db < add_user_account_management.sql
--
-- Backs the expanded user account features: email-based enrollment
-- (replacing admin-sets-the-password-directly with a one-time link the
-- new user completes themselves), admin- and self-service password
-- reset, real account activation status (soft-disable instead of a hard
-- DELETE, so audit_log/case_assignments rows referencing a deactivated
-- user's id don't need to be touched or lose context), and last-login
-- tracking. The UI's "ACTIVE_LINK" badge was previously hardcoded, not
-- backed by any real column -- is_active is what makes that real.

ALTER TABLE public.users
    ADD COLUMN IF NOT EXISTS email text,
    ADD COLUMN IF NOT EXISTS is_active boolean NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS last_login timestamp with time zone;

-- Single-use tokens for both admin-initiated and self-service ("forgot
-- password") resets -- created_by is NULL for a self-service request, set
-- to the admin's user id for an admin-initiated one, purely informational
-- (doesn't gate anything, just useful in the audit trail).
CREATE TABLE IF NOT EXISTS public.password_reset_tokens (
    token       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     integer NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    created_by  integer REFERENCES public.users(id),
    expires_at  timestamp with time zone NOT NULL,
    used_at     timestamp with time zone,
    created_at  timestamp with time zone NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user ON public.password_reset_tokens (user_id);

-- A pending invite -- the real `users` row doesn't exist until the
-- invitee completes enrollment and sets their own password, so the
-- account details an admin chose at invite time (username/initials/role/
-- email) live here until then.
CREATE TABLE IF NOT EXISTS public.enrollment_tokens (
    token       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username    character varying(50) NOT NULL,
    initials    character varying(5) NOT NULL,
    role        character varying(20) NOT NULL DEFAULT 'analyst',
    email       text,
    created_by  integer REFERENCES public.users(id),
    expires_at  timestamp with time zone NOT NULL,
    used_at     timestamp with time zone,
    created_at  timestamp with time zone NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_username ON public.enrollment_tokens (username);
