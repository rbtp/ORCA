-- Migration: add_mount_sessions_agent_id
-- Run: docker exec -i orca-postgres psql -U postgres -d orca_db < add_mount_sessions_agent_id.sql
--
-- Disk mounting now dispatches to an ORCA agent (Arsenal Image Mounter has
-- no Linux equivalent, so the backend container can never do this itself).
-- Records which agent performed each mount so dismount can automatically
-- target the same one -- device_number is only meaningful on the specific
-- Windows host that created it, so this isn't optional metadata.

ALTER TABLE mount_sessions ADD COLUMN IF NOT EXISTS agent_id character varying(64);
