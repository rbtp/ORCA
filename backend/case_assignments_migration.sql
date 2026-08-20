-- Lightweight case->analyst assignment. A case with zero rows here is
-- unrestricted (open to every analyst, same as today) -- it only becomes
-- access-restricted once someone actually assigns people to it, so this
-- can't retroactively lock anyone out of an existing, unmanaged case.
CREATE TABLE IF NOT EXISTS case_assignments (
    id          SERIAL PRIMARY KEY,
    case_name   TEXT NOT NULL REFERENCES cases(name) ON DELETE CASCADE,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (case_name, user_id)
);

CREATE INDEX IF NOT EXISTS idx_case_assignments_case ON case_assignments(case_name);
CREATE INDEX IF NOT EXISTS idx_case_assignments_user ON case_assignments(user_id);
