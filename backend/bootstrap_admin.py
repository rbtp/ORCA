"""
bootstrap_admin.py — creates a first admin account on a genuinely fresh
install.

The users table has no seed data (see schema.sql -- pure DDL, no INSERTs)
and the only endpoint that creates a user (admin.py's create_user) requires
an *existing* admin to call it. Without this, a fresh database has zero
users and no way to log in at all -- confirmed live the hard way while
standing up a new instance, via a one-off `docker exec` + Python REPL.

Runs as a main.py startup hook: if public.users is empty, creates one admin
account, either from ORCA_BOOTSTRAP_ADMIN_USERNAME/PASSWORD/INITIALS (for
scripted/non-interactive deploys) or -- if those aren't set -- a randomly
generated password that's logged once, at WARNING level so it's actually
visible in `docker logs`, and never stored anywhere in plaintext (only its
bcrypt hash goes to the DB, same as any normal user creation).

Also runnable standalone if you'd rather do this by hand:
    python bootstrap_admin.py [username] [initials]
(prompts for the password interactively via getpass, same as the
docker-exec workaround this replaces.)
"""

import logging
import os
import secrets
import string
import sys

from sqlalchemy import text

logger = logging.getLogger(__name__)


def users_table_is_empty(conn) -> bool:
    row = conn.execute(text("SELECT COUNT(*) FROM public.users")).fetchone()
    return not row or row[0] == 0


def _generate_password(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def create_first_admin(conn, username: str, password: str, initials: str = "ADM") -> None:
    from auth_utils import hash_password  # deferred: keeps this module importable without the full app context

    # Table columns are varchar(50)/varchar(5) -- truncate defensively rather
    # than let an oversized custom value from an env var crash the insert.
    username = (username or "admin").strip()[:50] or "admin"
    initials = (initials or "ADM").strip()[:5] or "ADM"

    conn.execute(text("""
        INSERT INTO public.users (username, password_hash, initials, role)
        VALUES (:u, :p, :i, 'admin')
    """), {"u": username, "p": hash_password(password), "i": initials})


def auto_bootstrap_if_empty(engine) -> None:
    """Startup-hook entry point. Never raises -- a failure here is logged
    and the app keeps booting rather than crashing the whole backend over
    it (an operator can still fall back to the manual docker-exec route)."""
    try:
        with engine.connect() as conn:
            if not users_table_is_empty(conn):
                return  # normal case on every restart after the first

            username = os.environ.get("ORCA_BOOTSTRAP_ADMIN_USERNAME", "admin")
            initials = os.environ.get("ORCA_BOOTSTRAP_ADMIN_INITIALS", "ADM")
            password = os.environ.get("ORCA_BOOTSTRAP_ADMIN_PASSWORD", "").strip()
            generated = not password
            if generated:
                password = _generate_password()

            create_first_admin(conn, username, password, initials)
            conn.commit()

            if generated:
                # WARNING, not INFO -- this codebase has no root logging
                # config, so INFO is silently swallowed (see mitre_import.py
                # for the same fix). This is a one-time, must-not-miss
                # message: it's the only place this password is ever shown.
                logger.warning(
                    "\n" + "=" * 70 +
                    "\nFIRST-BOOT ADMIN ACCOUNT CREATED -- shown here once, save it now:\n"
                    "  username: %s\n  password: %s\n"
                    "Only its bcrypt hash is stored in the database. Log in and change\n"
                    "this password immediately." + "\n" + "=" * 70,
                    username, password,
                )
            else:
                logger.warning(
                    "First-boot admin account '%s' created from ORCA_BOOTSTRAP_ADMIN_* env vars.",
                    username,
                )
    except Exception as e:
        logger.error("admin bootstrap failed: %s", e, exc_info=True)


if __name__ == "__main__":
    import getpass

    logging.basicConfig(level=logging.INFO)
    from core.database_manager import db

    username = sys.argv[1] if len(sys.argv) > 1 else "admin"
    initials = sys.argv[2] if len(sys.argv) > 2 else "ADM"

    with db.engine.connect() as conn:
        if not users_table_is_empty(conn):
            print("users table is not empty -- refusing to run (this script is for first-boot only).")
            print("Use the admin panel, or POST /api/admin/users/create as an existing admin, instead.")
            sys.exit(1)
        password = getpass.getpass(f"Password for first admin '{username}': ")
        create_first_admin(conn, username, password, initials)
        conn.commit()
    print(f"Admin user '{username}' created.")
