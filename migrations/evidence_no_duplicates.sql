-- Re-running a collection (or re-ingesting a file) must not store the same
-- evidence row twice (2026-11-12). A row is a duplicate when the same asset
-- and technique already hold identical raw_data. The check lives in the
-- database so every ingest path (agent, server, uploads, parsers) gets it.

-- 1. Remove the duplicates already stored: keep one copy of each (a starred
--    copy if there is one, otherwise the oldest), log what was removed.
CREATE TEMP TABLE _evidence_dups ON COMMIT DROP AS
SELECT id, asset_id, t_code
FROM (
    SELECT id, asset_id, t_code,
           row_number() OVER (
               PARTITION BY asset_id, t_code, md5(raw_data::text)
               ORDER BY starred DESC, id
           ) AS n
    FROM evidence
    WHERE raw_data IS NOT NULL AND asset_id IS NOT NULL AND t_code IS NOT NULL
) x
WHERE n > 1;

INSERT INTO audit_log (username, action, case_name, asset_id, asset_hostname, t_code, details)
SELECT 'system', 'DELETE_EVIDENCE', a.case_name, d.asset_id, a.hostname, d.t_code,
       'Removed ' || count(*) || ' duplicate evidence rows (identical copies from re-run collections); one copy of each kept'
FROM _evidence_dups d
LEFT JOIN assets a ON a.id = d.asset_id
GROUP BY d.asset_id, a.hostname, a.case_name, d.t_code;

DELETE FROM evidence e USING _evidence_dups d WHERE e.id = d.id;

-- 2. Fast lookup for the duplicate check.
CREATE INDEX IF NOT EXISTS idx_evidence_dedup
    ON evidence (asset_id, t_code, md5(raw_data::text));

-- 3. Skip an insert whose row is already stored. Inserts for the same asset +
--    technique are serialized (one lock per technique per transaction, not per
--    row), so two parallel runs can't both insert the same row.
CREATE OR REPLACE FUNCTION evidence_skip_duplicate() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.raw_data IS NULL OR NEW.asset_id IS NULL OR NEW.t_code IS NULL THEN
        RETURN NEW;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('orca_evidence'),
                                  hashtext(NEW.asset_id::text || '|' || NEW.t_code));
    IF EXISTS (
        SELECT 1 FROM evidence
        WHERE asset_id = NEW.asset_id
          AND t_code = NEW.t_code
          AND md5(raw_data::text) = md5(NEW.raw_data::text)
          AND raw_data = NEW.raw_data
    ) THEN
        RETURN NULL;  -- already stored: skip silently
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS evidence_skip_duplicate ON evidence;
CREATE TRIGGER evidence_skip_duplicate
    BEFORE INSERT ON evidence
    FOR EACH ROW EXECUTE FUNCTION evidence_skip_duplicate();
