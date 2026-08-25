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
    # Arsenal Image Mounter (aim_cli) has no Linux build and is never executed
    # in this process -- disk mounting is dispatched to a Windows ORCA agent
    # instead (main.py's /api/assets/mount), so there's no local-path config here.

    # ── Memory / forensics binaries ───────────────────────────────────────────
    VOL3_BASE: str = os.environ.get(
        "ORCA_VOL3_BASE",
        os.path.join(_BASE, "bin", "remora", "volatility3")
    )
    WINPMEM_BASE: str = os.environ.get(
        "ORCA_WINPMEM_BASE",
        os.path.join(_BASE, "bin", "remora", "volatility3")
    )
    # CLAM_BASE: the vendored Windows ClamAV bundle -- only ever served for
    # download to remote targets via /api/agent/download/bin/clamscan.exe
    # (agent_routes.py's _AGENT_BIN_MAP), never executed in this process.
    CLAM_BASE: str = os.environ.get(
        "ORCA_CLAM_BASE",
        os.path.join(_BASE, "bin", "clamav")
    )
    # CLAM_EXE / CLAM_FRESHCLAM_EXE / CLAM_DB_DIR: for scanning directly inside
    # this process's own OS (mitre_routes.py's /scan/clam -- e.g. a dead-disk
    # image mounted locally). Must match the container's actual platform: the
    # Windows vendored copy only runs on Windows; on Linux this points at the
    # apt-installed system clamscan/freshclam (Dockerfile installs `clamav
    # clamav-daemon` and pre-creates /var/lib/clamav for exactly this).
    CLAM_EXE: str = os.environ.get(
        "ORCA_CLAM_EXE",
        os.path.join(_BASE, "bin", "clamav", "clamscan.exe") if platform.system() == "Windows"
        else "/usr/bin/clamscan"
    )
    CLAM_FRESHCLAM_EXE: str = os.environ.get(
        "ORCA_CLAM_FRESHCLAM_EXE",
        os.path.join(_BASE, "bin", "clamav", "freshclam.exe") if platform.system() == "Windows"
        else "/usr/bin/freshclam"
    )
    CLAM_DB_DIR: str = os.environ.get(
        "ORCA_CLAM_DB_DIR",
        os.path.join(_BASE, "bin", "clamav") if platform.system() == "Windows"
        else "/var/lib/clamav"
    )
    # Linux only: Debian's default /etc/clamav/freshclam.conf sets
    # UpdateLogFile, which freshclam locks/writes to regardless of --stdout --
    # bypass it with our own minimal config instead. Windows freshclam.exe
    # already auto-discovers freshclam.conf next to itself in bin/clamav/.
    CLAM_FRESHCLAM_CONF: str = os.environ.get(
        "ORCA_CLAM_FRESHCLAM_CONF",
        os.path.join(_BASE, "clamav_freshclam_linux.conf") if platform.system() != "Windows"
        else ""
    )

    # ── Parallel collection ───────────────────────────────────────────────────
    VR_MAX_WORKERS: int = int(os.environ.get("ORCA_VR_MAX_WORKERS", "5"))

    # ── Reference data ────────────────────────────────────────────────────────
    # MITRE ATT&CK STIX 2.1 bundle (e.g. enterprise-attack.json from
    # https://github.com/mitre-attack/attack-stix-data) -- deliberately NOT
    # vendored into the repo like everything under bin/ is. The operator drops
    # it here (or points ORCA_MITRE_ATTACK_JSON elsewhere); mitre_import.py
    # loads it into mitre_groups/software/techniques/tactics/mitigations/
    # relationships automatically on first boot if those tables are empty.
    MITRE_ATTACK_JSON: str = os.environ.get(
        "ORCA_MITRE_ATTACK_JSON",
        os.path.join(_BASE, "data", "mitre-attack.json")
    )


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