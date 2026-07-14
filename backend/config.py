"""
config.py — ORCA centralized configuration.
All hardcoded paths and connection strings live here.
Import with: from config import cfg
"""

import os
import platform

_BASE = os.path.dirname(os.path.abspath(__file__))
_EXE = ".exe" if platform.system() == "Windows" else ""


class _Config:

    # ── TLS ───────────────────────────────────────────────────────────────────
    SSL_CERTFILE: str = (
        os.getenv("TLS_CERT_PATH") or
        os.getenv("ORCA_SSL_CERT") or
        os.path.join(_BASE, "orca.crt")
    )
    SSL_KEYFILE: str = (
        os.getenv("TLS_KEY_PATH") or
        os.getenv("ORCA_SSL_KEY") or
        os.path.join(_BASE, "orca.key")
    )

    # ── Database ──────────────────────────────────────────────────────────────
    DB_URL: str = (
        os.environ.get("DATABASE_URL") or
        os.environ.get("ORCA_DB_URL") or
        "postgresql://postgres:password@localhost:5432/orca_db"
    )

    # ── Data root ─────────────────────────────────────────────────────────────
    DATA_ROOT: str = os.environ.get(
        "ORCA_DATA_ROOT",
        os.path.abspath(os.path.join(_BASE, "..", "data", "results"))
    )

    # ── Binaries ──────────────────────────────────────────────────────────────
    # VR_EXE_WINDOWS: the binary shipped to / executed on remote Windows targets
    # (package_builder.py, vr_remote.py). Always the Windows build regardless of
    # the container's own OS.
    VR_EXE_WINDOWS: str = os.environ.get(
        "ORCA_VR_EXE_WINDOWS",
        os.path.join(_BASE, "bin", "velociraptor.exe")
    )
    # VR_EXE_LOCAL: the binary executed directly inside this process's own OS
    # (velociraptor_manager.py's in-container GUI). Must match the container's
    # actual platform — empty extension on Linux.
    VR_EXE_LOCAL: str = os.environ.get(
        "ORCA_VR_EXE_LOCAL",
        os.path.join(_BASE, "bin", f"velociraptor{_EXE}")
    )
    SYFT_EXE: str = os.environ.get(
        "ORCA_SYFT_EXE",
        os.path.join(_BASE, "bin", "syftgrype", f"syft{_EXE}")
    )
    GRYPE_EXE: str = os.environ.get(
        "ORCA_GRYPE_EXE",
        os.path.join(_BASE, "bin", "syftgrype", f"grype{_EXE}")
    )
    AIM_CLI: str = os.environ.get(
        "ORCA_AIM_CLI",
        os.path.join(_BASE, "bin", "arsenal", f"aim_cli{_EXE}")
    )

    # ── Parallel collection ───────────────────────────────────────────────────
    VR_MAX_WORKERS: int = int(os.environ.get("ORCA_VR_MAX_WORKERS", "5"))


cfg = _Config()


def _validate_required_env():
    missing = [v for v in ("DATABASE_URL", "TLS_CERT_PATH", "TLS_KEY_PATH") if not os.environ.get(v)]
    if missing:
        raise RuntimeError(f"FATAL: Missing required environment variables: {', '.join(missing)}")

_validate_required_env()