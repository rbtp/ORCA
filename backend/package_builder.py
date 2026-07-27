"""
package_builder.py
Builds a self-contained ORCA collection package (ZIP) for a given asset.

Called by ingest_routes.py when analyst requests a package download.
"""

import os
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


# ── Token management ──────────────────────────────────────────────────────────

def create_package_token(asset_id: int, case_name: str, user_id: int, technique_count: int) -> str:
    token = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(hours=PACKAGE_TOKEN_TTL_HOURS)
    with db.engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO package_tokens
                (token, asset_id, case_name, created_by, expires_at, technique_count)
            VALUES
                (:token, :asset_id, :case_name, :user_id, :expires_at, :technique_count)
        """), {
            "token": token,
            "asset_id": asset_id,
            "case_name": case_name,
            "user_id": user_id,
            "expires_at": expires_at,
            "technique_count": technique_count,
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
            if not t_codes:
                return []
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
            return [dict(r) for r in rows]

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
    return [dict(r) for r in rows]

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


def build_triage_package(asset_id: int, user_id: int, orca_url: str, categories: list) -> dict:
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
        if vr_src.exists():
            shutil.copy2(vr_src, pkg_dir / "velociraptor.exe")
        else:
            logger.warning("velociraptor.exe not found at %s", cfg.VR_EXE_WINDOWS)

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
    oneliner = (
        f"powershell -ExecutionPolicy Bypass -c \"{trust_all}"
        f"iex (iwr '{bootstrap_url}' -UseBasicParsing).Content\""
    )

    return {
        "token": token,
        "download_url": f"{orca_url}/api/packages/{token}/{zip_name}",
        "bootstrap_url": bootstrap_url,
        "oneliner": oneliner,
        "zip_name": zip_name,
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


# ── Bootstrap generator ───────────────────────────────────────────────────────

def generate_bootstrap_ps1(token: str, asset_id: int, orca_url: str, zip_name: str, cert_b64: Optional[str] = None) -> str:
    """
    Returns a minimal bootstrap PS1 that:
      1. Imports the ORCA self-signed cert into the local machine trust store (if provided)
      2. Downloads the full package ZIP from ORCA (no JWT — token-gated URL)
      3. Expands it to a temp directory
      4. Executes run_orca_collection.ps1 (which handles collection + self-delete + revoke)
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

    return f"""#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
{cert_block}
$ZipUrl  = "{orca_url}/api/packages/{token}/{zip_name}"
$TmpDir  = Join-Path $env:TEMP "orca_{token[:8]}"
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
}} catch {{
    Write-Host "[ORCA ERROR] $_"
    if (Test-Path $ZipPath) {{ Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue }}
    if (Test-Path $TmpDir)  {{ Remove-Item $TmpDir  -Recurse -Force -ErrorAction SilentlyContinue }}
    exit 1
}}
"""


# ── Package builder ───────────────────────────────────────────────────────────

def build_package(asset_id: int, user_id: int, orca_url: str) -> dict:
    """
    Build the collection ZIP for asset_id.
    Returns { download_url, bootstrap_url, oneliner, token, technique_count, expires_at }
    """
    asset = get_asset_info(asset_id)
    if not asset:
        raise ValueError(f"Asset {asset_id} not found")

    techniques = get_asset_techniques(asset_id)
    if not techniques:
        raise ValueError(f"No techniques found for asset {asset_id} — check OS/case config")

    # Read cert for trust injection if TLS is configured
    cert_b64 = None
    if cfg.SSL_CERTFILE and os.path.exists(cfg.SSL_CERTFILE):
        with open(cfg.SSL_CERTFILE, "rb") as f:
            cert_b64 = base64.b64encode(f.read()).decode()

    token = create_package_token(
        asset_id=asset_id,
        case_name=asset["case_name"],
        user_id=user_id,
        technique_count=len(techniques),
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
        if vr_src.exists():
            shutil.copy2(vr_src, pkg_dir / "velociraptor.exe")
        else:
            logger.warning("velociraptor.exe not found at %s", cfg.VR_EXE_WINDOWS)

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
    oneliner = (
        f"powershell -ExecutionPolicy Bypass -c \"{trust_all}"
        f"iex (iwr '{bootstrap_url}' -UseBasicParsing).Content\""
    )

    return {
        "token": token,
        "download_url": f"{orca_url}/api/packages/{token}/{zip_name}",
        "bootstrap_url": bootstrap_url,
        "oneliner": oneliner,
        "zip_name": zip_name,
        "technique_count": len(techniques),
        "expires_at": (datetime.utcnow() + timedelta(hours=PACKAGE_TOKEN_TTL_HOURS)).isoformat(),
        "asset_hostname": asset["hostname"],
        "case_name": asset["case_name"],
    }