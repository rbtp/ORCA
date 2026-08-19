-- Audit trail for sensitive admin actions (e.g. evidence deletion).
-- action is free text so future admin-gated actions can log into the same
-- table without another migration.
CREATE TABLE IF NOT EXISTS audit_log (
    id             SERIAL PRIMARY KEY,
    ts             TIMESTAMPTZ NOT NULL DEFAULT now(),
    username       TEXT NOT NULL,
    user_initials  TEXT,
    action         TEXT NOT NULL,
    case_name      TEXT,
    asset_id       INTEGER,
    asset_hostname TEXT,
    t_code         TEXT,
    details        TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_log_case  ON audit_log(case_name);
CREATE INDEX IF NOT EXISTS idx_audit_log_asset ON audit_log(asset_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_ts    ON audit_log(ts);
