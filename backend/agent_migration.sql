CREATE TABLE IF NOT EXISTS agent_registrations (
    id           SERIAL PRIMARY KEY,
    agent_id     VARCHAR(64) UNIQUE NOT NULL,
    hostname     VARCHAR(255),
    analyst_id   INTEGER REFERENCES users(id),
    capabilities JSONB DEFAULT '[]',
    last_seen    TIMESTAMP DEFAULT NOW(),
    registered_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS agent_jobs (
    id          SERIAL PRIMARY KEY,
    job_id      VARCHAR(64) UNIQUE NOT NULL,
    agent_id    VARCHAR(64) REFERENCES agent_registrations(agent_id),
    job_type    VARCHAR(50) NOT NULL,
    params      JSONB NOT NULL,
    status      VARCHAR(20) DEFAULT 'PENDING',
    created_at  TIMESTAMP DEFAULT NOW(),
    started_at  TIMESTAMP,
    completed_at TIMESTAMP,
    summary     JSONB
);
