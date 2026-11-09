"""
migrate.py -- applies pending database migrations before the backend starts.

Run by entrypoint.sh before main.py, so the app never runs against a schema
older than its code. (Before this, upgrades relied on someone remembering to
psql each new migration file by hand; when that was missed, login failed
with a 500 because users.is_active / users.token_version didn't exist.)

Sources, applied in this order, each sorted by file name:
  1. /app/*_migration.sql          (backend/, baked into the image)
  2. /app/migrations/*.sql         (repo-root migrations/, bind-mounted by
                                    docker-compose.yml)

Each file runs exactly once: applied files are recorded in
public.schema_migrations, each file runs in its own transaction together
with its bookkeeping row, and a Postgres advisory lock keeps two backends
from migrating at the same time. On a brand-new database (built from
schema.sql) every file still runs once; they're all idempotent
(IF NOT EXISTS / guarded upserts), so that's a no-op.

A failing migration stops startup (exit 1) with the file name and error,
rather than letting the app start half-upgraded.
"""

import glob
import os
import sys
import time

from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError

from config import cfg

_LOCK_ID = 727274001  # arbitrary, constant: pg_advisory_lock key for ORCA migrations
_CONNECT_RETRIES = 20
_CONNECT_DELAY = 3.0

APP_DIR = os.path.dirname(os.path.abspath(__file__))


def _log(msg: str) -> None:
    print(f"[ORCA] {msg}", flush=True)


def migration_files():
    """(key, path) pairs in apply order. The key is what's recorded in
    schema_migrations, prefixed by source so names can't collide."""
    files = [("backend/" + os.path.basename(p), p)
             for p in sorted(glob.glob(os.path.join(APP_DIR, "*_migration.sql")))]
    files += [("migrations/" + os.path.basename(p), p)
              for p in sorted(glob.glob(os.path.join(APP_DIR, "migrations", "*.sql")))]
    return files


def _connect(engine):
    for attempt in range(1, _CONNECT_RETRIES + 1):
        try:
            return engine.raw_connection()
        except OperationalError:
            if attempt == _CONNECT_RETRIES:
                raise
            _log(f"Database not reachable yet (attempt {attempt}/{_CONNECT_RETRIES}), retrying...")
            time.sleep(_CONNECT_DELAY)


def main() -> int:
    if not os.path.isdir(os.path.join(APP_DIR, "migrations")):
        _log("WARN: migrations/ directory not mounted -- only backend/*_migration.sql will be applied. "
             "Check the ./migrations volume in docker-compose.yml.")

    engine = create_engine(cfg.DB_URL)
    conn = _connect(engine)
    try:
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute("SELECT pg_advisory_lock(%s)", (_LOCK_ID,))
        cur.execute("""
            CREATE TABLE IF NOT EXISTS public.schema_migrations (
                filename   text PRIMARY KEY,
                applied_at timestamp with time zone NOT NULL DEFAULT NOW()
            )
        """)
        cur.execute("SELECT filename FROM public.schema_migrations")
        applied = {row[0] for row in cur.fetchall()}

        pending = [(k, p) for k, p in migration_files() if k not in applied]
        if not pending:
            _log("Database schema up to date.")
            return 0

        conn.autocommit = False
        for key, path in pending:
            with open(path, encoding="utf-8") as fh:
                sql = fh.read()
            try:
                # Raw DB-API execute with no parameters: psycopg2 sends the
                # file as-is (multiple statements, $$-quoting, '%' and '::'
                # all fine), unlike SQLAlchemy text() which parses ':name'.
                cur.execute(sql)
                cur.execute("INSERT INTO public.schema_migrations (filename) VALUES (%s)", (key,))
                conn.commit()
                _log(f"Applied migration {key}")
            except Exception as e:
                conn.rollback()
                _log(f"FATAL: migration {key} failed: {e}")
                return 1
        return 0
    finally:
        try:
            conn.rollback()
            conn.autocommit = True
            conn.cursor().execute("SELECT pg_advisory_unlock(%s)", (_LOCK_ID,))
        except Exception:
            pass
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
