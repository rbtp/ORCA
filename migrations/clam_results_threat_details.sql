-- ClamAV detections: hashes and file facts per flagged file (MD5/SHA-1/SHA-256,
-- size, modified/created), keyed by the threat line ("<path>: <signature> FOUND").
ALTER TABLE clam_results ADD COLUMN IF NOT EXISTS threat_details jsonb DEFAULT '{}'::jsonb;
