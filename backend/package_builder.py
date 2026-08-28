"""
package_builder.py
Builds a self-contained ORCA collection package (ZIP) for a given asset.

Called by ingest_routes.py when analyst requests a package download.
"""

import os
import re
import json
import uuid
import base64
import shutil
import zipfile
import logging
import tempfile
from datetime import datetime, timedelta
from typing import Optional
from pathlib import Path

from sqlalchemy import text
from core.database_manager import db
from config import cfg

logger = logging.getLogger(__name__)

PACKAGE_TOKEN_TTL_HOURS = 24
PS1_TEMPLATE_PATH        = Path(__file__).parent / "run_orca_collection.ps1"
PS1_TRIAGE_TEMPLATE_PATH = Path(__file__).parent / "run_orca_triage.ps1"

# An analyst-supplied remote staging directory gets interpolated directly
# into a generated PowerShell script (see generate_bootstrap_ps1) -- this is
# NOT about trusting the analyst (they're already authenticated and this
# isn't materially more dangerous than the VQL/YAML they can already submit
# into the same script), it's about catching a typo or copy-paste mistake
# before it becomes a broken or unexpected command on someone's machine.
# Absolute Windows path, drive letter, no quotes/backticks/$/semicolons/
# pipes -- deliberately conservative rather than trying to enumerate every
# unsafe character.
_SAFE_WINDOWS_PATH = re.compile(r'^[A-Za-z]:\\[A-Za-z0-9 ._\\-]+$')


def validate_remote_dir(remote_dir: Optional[str]) -> Optional[str]:
    """Returns the trimmed path if valid/empty, raises ValueError otherwise."""
    if not remote_dir or not remote_dir.strip():
        return None
    remote_dir = remote_dir.strip().rstrip('\\')
    if not _SAFE_WINDOWS_PATH.match(remote_dir):
        raise ValueError(
            "Remote directory must be an absolute Windows path (e.g. C:\\ORCA_Staging) "
            "using only letters, numbers, spaces, dots, underscores, and hyphens."
        )
    return remote_dir


# run_orca_collection.ps1 / run_orca_triage.ps1 both make several HTTPS calls
# back to ORCA over their run (per-technique results, heartbeats, start/
# complete) and need ORCA's self-signed cert trusted for those to work. Two
# ways to get there:
#   - cert_trusted=False (default): the script disables cert validation for
#     its own process via an ICertificatePolicy override -- self-contained,
#     but that pattern (dynamically-compiled cert-bypass class) is itself a
#     heavily-signatured EDR indicator.
#   - cert_trusted=True: used by the SMB-push delivery path (vr_remote.py's
#     _run_remote_command_smb_push), which imports the real cert into the
#     target's trust store via Import-Certificate *before* this script ever
#     runs -- so normal cert validation just works, and this block is empty.
_CERT_BYPASS_BLOCK = '''# Trust ORCA self-signed cert (compatible with Windows PowerShell 5.1)
Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class OrcaTrustAll : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint s, X509Certificate c, WebRequest r, int e) {
        return true;
    }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object OrcaTrustAll'''


def _cert_bypass_block(cert_trusted: bool) -> str:
    if cert_trusted:
        return "# ORCA cert already imported into the trust store by the SMB-push delivery step"
    return _CERT_BYPASS_BLOCK


# ── Token management ──────────────────────────────────────────────────────────

def create_package_token(asset_id: int, case_name: str, user_id: int, technique_count: int,
                          remote_dir: Optional[str] = None) -> str:
    token = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(hours=PACKAGE_TOKEN_TTL_HOURS)
    remote_dir = validate_remote_dir(remote_dir)
    with db.engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO package_tokens
                (token, asset_id, case_name, created_by, expires_at, technique_count, remote_dir)
            VALUES
                (:token, :asset_id, :case_name, :user_id, :expires_at, :technique_count, :remote_dir)
        """), {
            "token": token,
            "asset_id": asset_id,
            "case_name": case_name,
            "user_id": user_id,
            "expires_at": expires_at,
            "technique_count": technique_count,
            "remote_dir": remote_dir,
        })
    return token


def validate_package_token(token: str, asset_id: int) -> Optional[dict]:
    with db.engine.connect() as conn:
        row = conn.execute(text("""
            SELECT token, asset_id, case_name, expires_at, revoked, technique_count, techniques_received
            FROM package_tokens
            WHERE token = :token
              AND asset_id = :asset_id
              AND revoked = FALSE
              AND expires_at > NOW()
        """), {"token": token, "asset_id": asset_id}).mappings().fetchone()
    return dict(row) if row else None


def increment_received(token: str):
    with db.engine.begin() as conn:
        conn.execute(text("""
            UPDATE package_tokens
            SET techniques_received = techniques_received + 1,
                completed_at = CASE
                    WHEN techniques_received + 1 >= technique_count THEN NOW()
                    ELSE completed_at
                END
            WHERE token = :token
        """), {"token": token})


def revoke_token(token: str):
    """Revoke a token — called automatically by the agent on completion."""
    with db.engine.begin() as conn:
        conn.execute(text("""
            UPDATE package_tokens
            SET revoked = TRUE, revoked_at = NOW()
            WHERE token = :token
        """), {"token": token})
    logger.info("Package token auto-revoked on collection complete: %s", token[:8])


# ── Technique query ───────────────────────────────────────────────────────────

# MFT and Amcache aren't real MITRE techniques (see _CATEGORY_TO_TCODES below --
# they're utility codes that live only in ref_artifact_library), so neither the
# geopolitical attribution chain nor a custom investigation profile ever
# surfaces them on their own. Forced into every standard collection instead:
# MFT gives a full on-disk file listing at effectively the cost of one $MFT
# read, and Amcache gives a SHA1 for everything that's ever executed, straight
# out of the registry -- both give an analyst baseline situational awareness
# before they've looked at anything, at near-zero marginal collection cost.
_ALWAYS_INCLUDED_TCODES = ["MFT", "AMCACHE", "SUSPICIOUS_LOCATIONS_HASH"]


def _always_included_techniques(conn, exclude_codes: set) -> list[dict]:
    codes = [c for c in _ALWAYS_INCLUDED_TCODES if c not in exclude_codes]
    if not codes:
        return []
    rows = conn.execute(text("""
        SELECT t_code, COALESCE(name, t_code) AS technique_name, custom_vql, surgical_yaml
        FROM ref_artifact_library
        WHERE t_code = ANY(:codes) AND (custom_vql IS NOT NULL OR surgical_yaml IS NOT NULL)
    """), {"codes": codes}).mappings().fetchall()
    return [dict(r) for r in rows]


def get_asset_techniques(asset_id: int) -> list[dict]:
    with db.engine.connect() as conn:
        # Resolve case focus to detect custom investigation profiles
        focus_row = conn.execute(text("""
            SELECT c.focus_country
            FROM assets a
            JOIN cases c ON c.name = a.case_name
            WHERE a.id = :asset_id
        """), {"asset_id": asset_id}).mappings().fetchone()

        focus = str((focus_row or {}).get("focus_country") or "")

        if focus.startswith("[PROFILE]"):
            # Custom investigation profile — bypass the MITRE attribution chain
            profile_name = focus[len("[PROFILE] "):]
            profile_row = conn.execute(text("""
                SELECT tcodes FROM investigation_profiles WHERE name = :name
            """), {"name": profile_name}).mappings().fetchone()
            t_codes = list(profile_row["tcodes"]) if profile_row else []
            rows = []
            if t_codes:
                rows = conn.execute(text("""
                    SELECT t_code,
                           COALESCE(name, t_code) AS technique_name,
                           custom_vql,
                           surgical_yaml
                    FROM ref_artifact_library
                    WHERE t_code = ANY(:codes)
                      AND (custom_vql IS NOT NULL OR surgical_yaml IS NOT NULL)
                    ORDER BY t_code
                """), {"codes": t_codes}).mappings().fetchall()
            result = [dict(r) for r in rows]
            result.extend(_always_included_techniques(conn, {r["t_code"] for r in rows}))
            return result

        # Standard path — MITRE geopolitical attribution chain
        rows = conn.execute(text("""
            SELECT DISTINCT
                mt.t_code,
                mt.name          AS technique_name,
                ral.custom_vql,
                ral.surgical_yaml
            FROM assets a
            JOIN cases c ON c.name = a.case_name
            JOIN threat_attribution ta ON ta.attribution = c.focus_country
            JOIN mitre_groups mg ON mg.name = ta.group_name
            JOIN mitre_relationships mr ON mr.source_ref = mg.stix_id
                AND mr.relationship_type = 'uses'
            JOIN mitre_techniques mt ON mt.stix_id = mr.target_ref
                AND NOT COALESCE(mt.is_deprecated, FALSE)
                AND NOT COALESCE(mt.is_revoked, FALSE)
                AND mt.platforms @> to_jsonb(ARRAY[a.os]::text[])
            JOIN ref_artifact_library ral ON ral.t_code = mt.t_code
                AND (ral.custom_vql IS NOT NULL OR ral.surgical_yaml IS NOT NULL)
            WHERE a.id = :asset_id
            ORDER BY mt.t_code
        """), {"asset_id": asset_id}).mappings().fetchall()
        result = [dict(r) for r in rows]
        result.extend(_always_included_techniques(conn, {r["t_code"] for r in rows}))
    return result

# Maps UI display names → t_codes that should be collected
_CATEGORY_TO_TCODES = {
    "Event Logs":        ["EVENT_LOGS_SECURITY","EVENT_LOGS_APPLICATION","EVENT_LOGS_SYSMON",
                          "EVENT_LOGS_POWERSHELL","EVENT_LOGS_SYSTEM","EVENT_LOGS_TASKSCHEDULER",
                          "EVENT_LOGS_WMI","EVENT_LOGS_WINRM"],
    "Prefetch":          ["PREFETCH"],
    "MFT":               ["MFT"],
    "Registry":          ["REGISTRY_SAM","REGISTRY_SYSTEM","REGISTRY_SOFTWARE","REGISTRY_SECURITY",
                          "REGISTRY_NTUSER","REGISTRY_USRCLASS","REGISTRY_CLASSES_ROOT","REGISTRY_CURRENT_CONFIG"],
    "Browser Artifacts": ["BROWSER_CHROME","BROWSER_EDGE","BROWSER_FIREFOX"],
    "LNK / Jump Lists":  ["LNK_JUMPLISTS"],
    "Scheduled Tasks":   ["SCHEDULED_TASKS"],
    "WMI Persistence":   ["WMI_PERSISTENCE"],
    "SRUM":              ["SRUM"],
    "Amcache":           ["AMCACHE"],
    "Recycle Bin":       ["RECYCLE_BIN"],
    "USB Artifacts":     ["USB_ARTIFACTS"],
}


def get_triage_techniques(categories: list) -> list[dict]:
    # Resolve display names to t_codes; fall back to all if categories is empty/unrecognized
    t_codes = []
    for cat in categories:
        t_codes.extend(_CATEGORY_TO_TCODES.get(cat, []))

    if not t_codes:
        # No recognized categories — collect everything
        t_codes = [tc for codes in _CATEGORY_TO_TCODES.values() for tc in codes]

    with db.engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT t_code, name AS technique_name, custom_vql, surgical_yaml
            FROM ref_artifact_library
            WHERE t_code = ANY(:codes)
            AND (custom_vql IS NOT NULL OR surgical_yaml IS NOT NULL)
        """), {"codes": t_codes}).mappings().fetchall()
    return [dict(r) for r in rows]


def build_triage_package(asset_id: int, user_id: int, orca_url: str, categories: list,
                          remote_dir: Optional[str] = None, cert_trusted: bool = False,
                          max_workers: int = 3) -> dict:
    asset = get_asset_info(asset_id)
    if not asset:
        raise ValueError(f"Asset {asset_id} not found")

    techniques = get_triage_techniques(categories)
    if not techniques:
        raise ValueError(f"No triage techniques found for categories: {categories}")

    token = create_package_token(
        asset_id=asset_id,
        case_name=asset["case_name"],
        user_id=user_id,
        technique_count=len(techniques),
        remote_dir=remote_dir,
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        pkg_dir = Path(tmpdir) / f"orca_triage_{asset['hostname']}"
        pkg_dir.mkdir()
        art_dir = pkg_dir / "artifacts"
        art_dir.mkdir()

        # Write one VQL file per artifact — filename IS the t_code
        for tech in techniques:
            if tech["custom_vql"]:
                (art_dir / f"{tech['t_code']}.vql").write_text(tech["custom_vql"], encoding="utf-8")

        vr_src = Path(cfg.VR_EXE_WINDOWS)
        if not vr_src.exists():
            # Used to log a warning and ship the ZIP anyway -- the generated
            # run_orca_collection.ps1 still expects velociraptor.exe to be
            # there, so a package missing it fails on the target with a
            # confusing runtime error instead of here, where it's obvious
            # and fixable.
            raise ValueError(f"velociraptor.exe not found at {cfg.VR_EXE_WINDOWS} — cannot build package")
        shutil.copy2(vr_src, pkg_dir / "velociraptor.exe")

        config = {
            "orca_url": orca_url,
            "asset_id": asset_id,
            "case_name": asset["case_name"],
            "package_token": token,
            "hostname_hint": asset["hostname"],
            "generated_at": datetime.utcnow().isoformat(),
        }
        (pkg_dir / "orca_config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")

        zip_name = f"orca_triage_{token[:8]}_{asset['hostname']}.zip"

        ps1_template = PS1_TRIAGE_TEMPLATE_PATH.read_text(encoding="utf-8")
        ps1_filled = (
            ps1_template
            .replace("{{ORCA_URL}}", orca_url)
            .replace("{{ASSET_ID}}", str(asset_id))
            .replace("{{PACKAGE_TOKEN}}", token)
            .replace("{{CASE_NAME}}", asset["case_name"])
            .replace("{{CERT_BYPASS_BLOCK}}", _cert_bypass_block(cert_trusted))
            .replace("{{MAX_WORKERS}}", str(max(1, int(max_workers))))
        )
        (pkg_dir / "run_orca_triage.ps1").write_text(ps1_filled, encoding="utf-8")

        packages_root = Path(cfg.DATA_ROOT) / "packages"
        packages_root.mkdir(parents=True, exist_ok=True)
        zip_path = packages_root / zip_name

        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for file in pkg_dir.rglob("*"):
                if file.is_file():
                    zf.write(file, file.relative_to(pkg_dir))

    bootstrap_url = f"{orca_url}/api/packages/{token}/bootstrap"
    trust_all = (
        "add-type 'using System.Net;using System.Security.Cryptography.X509Certificates;"
        "public class TrustAll:ICertificatePolicy{public bool CheckValidationResult("
        "ServicePoint s,X509Certificate c,WebRequest r,int e){return true;}}'; "
        "[System.Net.ServicePointManager]::CertificatePolicy=New-Object TrustAll; "
    )
    # Fetches the bootstrap script to a temp .ps1 and runs it with -File,
    # rather than piping it straight into iex -- avoids the "download string,
    # eval in memory" idiom that AV/EDR heavily signature, matching the
    # file-based execution style already used one step later for the real
    # collection script (the ps1.FullName invocation below).
    oneliner = (
        f"powershell -ExecutionPolicy Bypass -c \"{trust_all}"
        f"$b=[IO.Path]::Combine($env:TEMP,'orca_boot_{token[:8]}.ps1'); "
        f"(iwr '{bootstrap_url}' -UseBasicParsing).Content | Set-Content -Path $b -Encoding UTF8; "
        f"& $b; Remove-Item $b -Force\""
    )

    return {
        "token": token,
        "download_url": f"{orca_url}/api/packages/{token}/{zip_name}",
        "bootstrap_url": bootstrap_url,
        "oneliner": oneliner,
        "zip_name": zip_name,
        "zip_path": str(zip_path),
        "technique_count": len(techniques),
        "expires_at": (datetime.utcnow() + timedelta(hours=PACKAGE_TOKEN_TTL_HOURS)).isoformat(),
        "asset_hostname": asset["hostname"],
        "case_name": asset["case_name"],
    }


def get_asset_info(asset_id: int) -> Optional[dict]:
    with db.engine.connect() as conn:
        row = conn.execute(text("""
            SELECT a.id, a.hostname, a.os, a.case_name, c.focus_country
            FROM assets a
            JOIN cases c ON c.name = a.case_name
            WHERE a.id = :asset_id
        """), {"asset_id": asset_id}).mappings().fetchone()
    return dict(row) if row else None


# ── SMB-push launcher ─────────────────────────────────────────────────────────

def generate_smb_push_launcher_ps1(stage_dir: str) -> str:
    """
    Returns a small PS1 that runs entirely from files already pushed to
    `stage_dir` via SMB (vr_remote.py's _run_remote_command_smb_push) --
    no network calls of its own, since the cert, the package ZIP, and this
    script itself all arrive over the same SMB session used to trigger it.

    Imports the ORCA cert the normal way (Import-Certificate), rather than
    the ICertificatePolicy bypass class run_orca_collection.ps1 otherwise
    uses -- once genuinely trusted, that script's own HTTPS calls (results,
    heartbeats) validate normally and don't need cert_trusted=False's bypass
    either. See package_builder.py's _cert_bypass_block.
    """
    return f"""#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
$Dir = "{stage_dir}"
try {{
    $certPath = Join-Path $Dir "orca_cert.cer"
    if (Test-Path $certPath) {{
        Import-Certificate -FilePath $certPath -CertStoreLocation Cert:\\LocalMachine\\Root | Out-Null
        Remove-Item $certPath -Force -ErrorAction SilentlyContinue
    }}
    Expand-Archive -Path (Join-Path $Dir "orca_pkg.zip") -DestinationPath $Dir -Force
    Remove-Item (Join-Path $Dir "orca_pkg.zip") -Force -ErrorAction SilentlyContinue
    $ps1 = Get-ChildItem -Path $Dir -Filter "run_orca_*.ps1" -Recurse |
        Where-Object {{ $_.FullName -ne $PSCommandPath }} | Select-Object -First 1
    if (-not $ps1) {{ throw "No ORCA collection script found in pushed package" }}
    & powershell.exe -ExecutionPolicy Bypass -File $ps1.FullName
    if ($LASTEXITCODE -ne 0) {{ throw "Collection script exited with code $LASTEXITCODE" }}
}} catch {{
    Write-Host "[ORCA ERROR] $_"
    exit 1
}} finally {{
    Remove-Item $PSCommandPath -Force -ErrorAction SilentlyContinue
}}
"""


# ── Bootstrap generator ───────────────────────────────────────────────────────

def generate_bootstrap_ps1(token: str, asset_id: int, orca_url: str, zip_name: str,
                            cert_b64: Optional[str] = None, remote_dir: Optional[str] = None) -> str:
    """
    Returns a minimal bootstrap PS1 that:
      1. Imports the ORCA self-signed cert into the local machine trust store (if provided)
      2. Downloads the full package ZIP from ORCA (no JWT — token-gated URL)
      3. Expands it to a staging directory (remote_dir if given, else $env:TEMP --
         which resolves to C:\\Windows\\Temp under the SYSTEM-context scheduled
         task this normally runs under. Some environments block execution
         from C:\\Windows\\Temp via AppLocker/SRP/EDR policy, which fails the
         collection silently -- remote_dir is the escape hatch for that.)
      4. Executes run_orca_collection.ps1 (which handles collection + self-delete + revoke)

    remote_dir, if provided, is expected to already be validated by
    validate_remote_dir() (an absolute Windows path, safe character set) --
    it's interpolated directly into the generated script.
    """
    cert_block = ""
    if cert_b64:
        cert_block = f"""
# Trust ORCA self-signed cert
$certBytes = [Convert]::FromBase64String('{cert_b64}')
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$certBytes)
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','LocalMachine')
$store.Open('ReadWrite')
$store.Add($cert)
$store.Close()
Write-Host "[ORCA] Certificate trusted."
"""

    if remote_dir:
        base_dir_block = f"""$BaseDir = "{remote_dir}"
if (-not (Test-Path $BaseDir)) {{ New-Item -ItemType Directory -Path $BaseDir -Force | Out-Null }}"""
    else:
        base_dir_block = "$BaseDir = $env:TEMP"

    return f"""#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
{cert_block}
$ZipUrl  = "{orca_url}/api/packages/{token}/{zip_name}"
{base_dir_block}
$TmpDir  = Join-Path $BaseDir "orca_{token[:8]}"
$ZipPath = "$TmpDir.zip"
try {{
    Write-Host "[ORCA] Downloading collection package..."
    Invoke-WebRequest -Uri $ZipUrl -OutFile $ZipPath -UseBasicParsing
    Write-Host "[ORCA] Extracting..."
    Expand-Archive -Path $ZipPath -DestinationPath $TmpDir -Force
    Remove-Item $ZipPath -Force
    $ps1 = Get-ChildItem -Path $TmpDir -Filter "run_orca_triage.ps1" -Recurse | Select-Object -First 1
    if (-not $ps1) {{ $ps1 = Get-ChildItem -Path $TmpDir -Filter "run_orca_collection.ps1" -Recurse | Select-Object -First 1 }}
    if (-not $ps1) {{ throw "No ORCA collection script found in package" }}
    Write-Host "[ORCA] Starting collection..."
    & powershell.exe -ExecutionPolicy Bypass -File $ps1.FullName
    if ($LASTEXITCODE -ne 0) {{ throw "Collection script exited with code $LASTEXITCODE" }}
}} catch {{
    Write-Host "[ORCA ERROR] $_"
    if (Test-Path $ZipPath) {{ Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue }}
    if (Test-Path $TmpDir)  {{ Remove-Item $TmpDir  -Recurse -Force -ErrorAction SilentlyContinue }}
    exit 1
}}
"""


# ── Package builder ───────────────────────────────────────────────────────────

def build_package(asset_id: int, user_id: int, orca_url: str, remote_dir: Optional[str] = None,
                   cert_trusted: bool = False, max_workers: int = 3) -> dict:
    """
    Build the collection ZIP for asset_id.
    Returns { download_url, bootstrap_url, oneliner, token, technique_count, expires_at }

    max_workers: number of techniques run_orca_collection.ps1 processes in
    parallel on the target (each in its own child powershell.exe). 1 keeps
    the original strictly-sequential behavior; anything higher is a real
    speed/stealth trade-off -- more concurrent forensic-tool process
    creations on the target is a more conspicuous footprint to EDR than one
    at a time, so this defaults modest rather than maximal.
    """
    asset = get_asset_info(asset_id)
    if not asset:
        raise ValueError(f"Asset {asset_id} not found")

    techniques = get_asset_techniques(asset_id)
    if not techniques:
        raise ValueError(f"No techniques found for asset {asset_id} — check OS/case config")

    token = create_package_token(
        asset_id=asset_id,
        case_name=asset["case_name"],
        user_id=user_id,
        technique_count=len(techniques),
        remote_dir=remote_dir,
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        pkg_dir = Path(tmpdir) / f"orca_collection_{asset['hostname']}"
        pkg_dir.mkdir()
        tech_dir = pkg_dir / "techniques"
        tech_dir.mkdir()

        for tech in techniques:
            t_code_safe = tech["t_code"].replace(".", "_")
            meta = {"t_code": tech["t_code"], "technique_name": tech["technique_name"]}

            if tech["surgical_yaml"]:
                yaml_filename = f"{t_code_safe}.yaml"
                (tech_dir / yaml_filename).write_text(tech["surgical_yaml"], encoding="utf-8")
                meta["yaml_file"] = yaml_filename

            if tech["custom_vql"]:
                vql_filename = f"{t_code_safe}.vql"
                (tech_dir / vql_filename).write_text(tech["custom_vql"], encoding="utf-8")
                meta["vql_file"] = vql_filename

            (tech_dir / f"{t_code_safe}.json").write_text(
                json.dumps(meta, indent=2), encoding="utf-8"
            )

        vr_src = Path(cfg.VR_EXE_WINDOWS)
        if not vr_src.exists():
            # Used to log a warning and ship the ZIP anyway -- the generated
            # run_orca_collection.ps1 still expects velociraptor.exe to be
            # there, so a package missing it fails on the target with a
            # confusing runtime error instead of here, where it's obvious
            # and fixable.
            raise ValueError(f"velociraptor.exe not found at {cfg.VR_EXE_WINDOWS} — cannot build package")
        shutil.copy2(vr_src, pkg_dir / "velociraptor.exe")

        config = {
            "orca_url": orca_url,
            "asset_id": asset_id,
            "case_name": asset["case_name"],
            "package_token": token,
            "hostname_hint": asset["hostname"],
            "generated_at": datetime.utcnow().isoformat(),
        }
        (pkg_dir / "orca_config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")

        zip_name = f"orca_pkg_{token[:8]}_{asset['hostname']}.zip"

        ps1_template = PS1_TEMPLATE_PATH.read_text(encoding="utf-8")
        ps1_filled = (
            ps1_template
            .replace("{{ORCA_URL}}", orca_url)
            .replace("{{ASSET_ID}}", str(asset_id))
            .replace("{{PACKAGE_TOKEN}}", token)
            .replace("{{CASE_NAME}}", asset["case_name"])
            .replace("{{CERT_BYPASS_BLOCK}}", _cert_bypass_block(cert_trusted))
            .replace("{{MAX_WORKERS}}", str(max(1, int(max_workers))))
        )
        (pkg_dir / "run_orca_collection.ps1").write_text(ps1_filled, encoding="utf-8")

        packages_root = Path(cfg.DATA_ROOT) / "packages"
        packages_root.mkdir(parents=True, exist_ok=True)
        zip_path = packages_root / zip_name

        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for file in pkg_dir.rglob("*"):
                if file.is_file():
                    zf.write(file, file.relative_to(pkg_dir))

    logger.info("Package built: %s (%d techniques)", zip_name, len(techniques))

    bootstrap_url = f"{orca_url}/api/packages/{token}/bootstrap"

    # One-liner: bypass cert validation for the initial bootstrap fetch only.
    # ICertificatePolicy approach is reliable in a single-line context unlike the callback.
    # Once bootstrap runs, the cert is imported into the trust store and
    # all subsequent iwr calls in run_orca_collection.ps1 work natively.
    trust_all = (
        "add-type 'using System.Net;using System.Security.Cryptography.X509Certificates;"
        "public class TrustAll:ICertificatePolicy{public bool CheckValidationResult("
        "ServicePoint s,X509Certificate c,WebRequest r,int e){return true;}}'; "
        "[System.Net.ServicePointManager]::CertificatePolicy=New-Object TrustAll; "
    )
    # Fetches the bootstrap script to a temp .ps1 and runs it with -File,
    # rather than piping it straight into iex -- avoids the "download string,
    # eval in memory" idiom that AV/EDR heavily signature, matching the
    # file-based execution style already used one step later for the real
    # collection script (the ps1.FullName invocation below).
    oneliner = (
        f"powershell -ExecutionPolicy Bypass -c \"{trust_all}"
        f"$b=[IO.Path]::Combine($env:TEMP,'orca_boot_{token[:8]}.ps1'); "
        f"(iwr '{bootstrap_url}' -UseBasicParsing).Content | Set-Content -Path $b -Encoding UTF8; "
        f"& $b; Remove-Item $b -Force\""
    )

    return {
        "token": token,
        "download_url": f"{orca_url}/api/packages/{token}/{zip_name}",
        "bootstrap_url": bootstrap_url,
        "oneliner": oneliner,
        "zip_name": zip_name,
        "zip_path": str(zip_path),
        "technique_count": len(techniques),
        "expires_at": (datetime.utcnow() + timedelta(hours=PACKAGE_TOKEN_TTL_HOURS)).isoformat(),
        "asset_hostname": asset["hostname"],
        "case_name": asset["case_name"],
    }