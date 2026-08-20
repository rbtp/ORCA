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
        ""
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

    # ── Memory / forensics binaries ───────────────────────────────────────────
    VOL3_BASE: str = os.environ.get(
        "ORCA_VOL3_BASE",
        os.path.join(_BASE, "bin", "remora", "volatility3")
    )
    WINPMEM_BASE: str = os.environ.get(
        "ORCA_WINPMEM_BASE",
        os.path.join(_BASE, "bin", "remora", "volatility3")
    )
    CLAM_BASE: str = os.environ.get(
        "ORCA_CLAM_BASE",
        os.path.join(_BASE, "bin", "clamav")
    )

    # ── Parallel collection ───────────────────────────────────────────────────
    VR_MAX_WORKERS: int = int(os.environ.get("ORCA_VR_MAX_WORKERS", "5"))


cfg = _Config()


def _validate_required_env():
    # SSL_CERTFILE/SSL_KEYFILE always resolve to something (TLS_CERT_PATH ->
    # ORCA_SSL_CERT -> a bundled default path, auto-generated on first boot)
    # so they were never actually "required" env vars -- hard-requiring
    # TLS_CERT_PATH/TLS_KEY_PATH here rejected a fully working, documented
    # configuration (using ORCA_SSL_CERT/ORCA_SSL_KEY, or the default path)
    # with a fatal startup error for no real reason. DB_URL is the only
    # setting with no working default, and it's already checked correctly.
    if not cfg.DB_URL:
        raise RuntimeError("FATAL: DATABASE_URL or ORCA_DB_URL must be set")

_validate_required_env()