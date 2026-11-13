-- Live vs dead-disk query variants, keyed off the asset's analysis_mode.
-- Each technique keeps its existing query as the LIVE/default; an optional dead
-- variant (custom_vql_dead / surgical_yaml_dead) is used only for a dead-disk
-- asset when present, otherwise the agent's dead-disk remap handles the default.
-- applies_live / applies_dead say where a technique can produce evidence at all:
-- a live-only technique (running-process memory, live network state) is N/A on a
-- dead disk; a dead-disk-only forensic collection (MFT, USN, Prefetch, ...) is
-- absent on a live host.
ALTER TABLE ref_artifact_library ADD COLUMN IF NOT EXISTS applies_live       boolean NOT NULL DEFAULT true;
ALTER TABLE ref_artifact_library ADD COLUMN IF NOT EXISTS applies_dead       boolean NOT NULL DEFAULT true;
ALTER TABLE ref_artifact_library ADD COLUMN IF NOT EXISTS custom_vql_dead    text;
ALTER TABLE ref_artifact_library ADD COLUMN IF NOT EXISTS surgical_yaml_dead text;

-- Techniques whose only query source is live-system state (no on-disk artifact):
-- N/A on a dead-disk image. Only the techniques whose every source is a live-only
-- plugin are marked; a technique also caught via command-line / event-log evidence
-- stays applies_dead = true (those logs survive on an image). The agent already
-- reports these "na" at run time; this makes it explicit in the UI up front.
UPDATE ref_artifact_library SET applies_dead = false
WHERE t_code IN ('T1036.011')
  AND applies_dead = true
  AND COALESCE(surgical_yaml_dead, '') = '' AND COALESCE(custom_vql_dead, '') = '';
