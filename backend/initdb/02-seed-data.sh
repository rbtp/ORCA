#!/bin/sh
# Runs once, only when Postgres initialises a brand-new data volume (after
# 01-schema.sql). Loads the reference-data dumps in /seed_data (MITRE
# analytics/actors/log sources, artifact library, VQL mappings, threat
# attribution). No users, cases or evidence are in these files.
set -e
for f in /seed_data/*.sql; do
    echo "[ORCA] Loading seed data: $(basename "$f")"
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -q -f "$f"
done
