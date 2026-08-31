import os, re, uuid, json, hashlib, asyncio, time, shutil, glob, sys
from typing import Optional, Tuple
from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends, UploadFile, File, Form
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import text
from core.database_manager import db
from auth_utils import get_current_user, user_can_access_case
from config import cfg
from package_builder import build_file_fetch_package, validate_remote_dir
from deploy_routes import _get_orca_base_url
import vr_remote

router = APIRouter(prefix="/api/behavioral", tags=["behavioral"])

# Resolve CLI tool paths at startup — pip installs them alongside the Python binary
def _find_bin(name: str) -> str:
    candidate = os.path.join(os.path.dirname(sys.executable), name)
    if os.path.isfile(candidate):
        return candidate
    found = shutil.which(name)
    return found or name

_CAPA_BIN = _find_bin('capa')
_FLOSS_BIN = _find_bin('floss')
_SPEAKEASY_BIN = _find_bin('speakeasy')
SPEAKEASY_AVAILABLE = os.path.isfile(_SPEAKEASY_BIN)

# --- File type detection via magic bytes ---
_MAGIC = {b'\x4d\x5a': 'PE', b'\x7fELF': 'ELF'}

def detect_file_type(filepath: str) -> Optional[str]:
    try:
        with open(filepath, 'rb') as f:
            hdr = f.read(4)
        for magic, ftype in _MAGIC.items():
            if hdr.startswith(magic):
                return ftype
    except Exception:
        pass
    return None

def compute_hashes(filepath: str):
    md5 = hashlib.md5(usedforsecurity=False)  # nosec B324 — file identification only, not used for auth/security
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()

# --- IOC regex patterns (ordered: URL before DOMAIN to avoid false-positive DOMAIN matches on URLs) ---
# DOMAIN uses a repeating (label.)+ group so a multi-label host like
# "www.evil.com" matches in full, with "com" as the final segment -- the old
# single-label pattern stopped at the first internal dot and treated "evil"
# (the second label, not the real TLD) as if it were the TLD.
_IOC_PATTERNS = [
    ('URL',      re.compile(r'https?://[^\s"\'<>]+')),
    ('IP',       re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')),
    ('REGISTRY', re.compile(r'HKEY_[A-Z_]+\\[^\s"\n]+')),
    ('FILEPATH', re.compile(r'[A-Za-z]:\\[^"\'\n\r]+')),
    ('EMAIL',    re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,24}\b')),
    ('DOMAIN',   re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b')),
]

# Real TLDs only -- static string extraction from a PE/ELF binary otherwise
# surfaces huge numbers of "word.word" false positives (imported DLL names,
# .NET namespaces like "System.Threading", embedded filenames, PDB paths)
# that look exactly like domain.tld to a regex with no TLD constraint. A
# domain match is only kept if its final label is in this set.
_KNOWN_TLDS = {
    # Generic / new gTLDs (incl. ones commonly abused for malware infra)
    'com','net','org','info','biz','name','pro','mobi','tel','asia','xyz','top',
    'site','online','club','shop','store','tech','app','dev','icu','click','link',
    'live','vip','win','buzz','rest','cyou','monster','sbs','fun','space','website',
    'press','news','world','life','pw','cc','ws','tv','me','io','co','to','gg',
    'ai','sh','gd','im','la','li','fm','bz','nu','cx','us','edu','gov','mil','int',
    # Free/abused registrar TLDs common in phishing & malware C2
    'tk','ml','ga','cf','gq',
    # ccTLDs — broad geopolitical spread, matches this app's threat-intel scope
    'ru','su','cn','hk','tw','jp','kr','kp','ir','iq','sy','ye','af','pk',
    'in','bd','lk','np','mm','th','vn','kh','my','sg','id','ph','bn',
    'ua','by','md','ge','am','az','kz','uz','tm','kg','tj','mn',
    'uk','de','fr','it','es','pt','nl','be','lu','ch','at','pl','cz','sk',
    'hu','ro','bg','rs','hr','si','ba','mk','al','gr','tr','cy','mt',
    'se','no','dk','fi','is','ie','ee','lv','lt',
    'br','mx','ar','cl','pe','ve','ec','bo','py','uy','cr','pa','cu',
    'za','ng','ke','eg','ma','dz','tn','ly','gh','et','ug','tz','zm','zw',
    'au','nz','fj','il','sa','ae','qa','kw','bh','om','jo','lb','ca',
}

# Software namespace/package roots that are structurally identical to a
# domain (dot-separated labels ending in a real TLD -- .io/.net/.org/.com/
# .store are all both legitimate TLDs *and* common namespace terminators)
# but are near-universally compiled-in namespace references, not network
# indicators. Confirmed false positives live: "itext.io" (iText PDF
# library's actual iText.IO .NET namespace), "system.io" (.NET BCL),
# "org.bouncycastle.x509.store" (Java crypto library, reverse-domain package
# naming). Matched as (first_label, second_label) pairs rather than a bare
# prefix so a genuinely malicious domain that happens to use "system"/"org"/
# "com" as its own first label (e.g. "system.evil-c2.ru") isn't silently
# dropped -- it would also need to match a known second label to be excluded.
_KNOWN_NAMESPACE_PAIRS = {
    ('system', 'io'), ('system', 'net'), ('system', 'text'), ('system', 'data'),
    ('system', 'web'), ('system', 'xml'), ('system', 'linq'), ('system', 'security'),
    ('system', 'threading'), ('system', 'diagnostics'), ('system', 'reflection'),
    ('system', 'runtime'), ('system', 'collections'), ('system', 'configuration'),
    ('system', 'drawing'), ('system', 'componentmodel'), ('system', 'globalization'),
    ('system', 'resources'), ('system', 'windows'), ('system', 'media'),
    ('system', 'servicemodel'), ('system', 'management'),
    ('microsoft', 'win32'), ('microsoft', 'csharp'), ('microsoft', 'extensions'),
    ('microsoft', 'aspnetcore'), ('microsoft', 'entityframeworkcore'),
    ('newtonsoft', 'json'),
    ('itext', 'io'), ('itext', 'kernel'), ('itext', 'layout'),
    ('itext', 'forms'), ('itext', 'signatures'), ('itext', 'commons'),
    ('org', 'bouncycastle'), ('org', 'apache'), ('org', 'springframework'),
    ('org', 'hibernate'), ('org', 'junit'), ('org', 'slf4j'), ('org', 'w3c'),
    ('org', 'json'), ('org', 'xml'), ('org', 'ietf'),
    ('com', 'google'), ('com', 'sun'), ('com', 'fasterxml'), ('com', 'squareup'),
    ('net', 'sf'),
}


def check_ioc(s: str) -> Optional[Tuple[str, str]]:
    """Return (ioc_type, matched_substring) for the first IOC pattern found in s, else None.

    Returns the MATCHED substring, not the raw input -- static string extraction
    (FLOSS) can glue a stray leading byte onto an otherwise-clean IOC (observed
    live as e.g. "jhttp://..." / "dhttps://..."). re.search() already ignores
    that leading junk when it looks for where the pattern actually starts, so
    using match.group(0) instead of the original raw string is what strips it;
    storing the raw string (the old behavior) kept the garbage prefix in what
    got displayed and cross-referenced against the IOC library.
    """
    for ioc_type, pat in _IOC_PATTERNS:
        m = pat.search(s)
        if not m:
            continue
        if ioc_type == 'DOMAIN':
            labels = m.group(0).lower().split('.')
            if labels[-1] not in _KNOWN_TLDS:
                continue
            if len(labels) >= 2 and (labels[0], labels[1]) in _KNOWN_NAMESPACE_PAIRS:
                continue
        return ioc_type, m.group(0)
    return None

# --- In-memory queue store for SSE ↔ pipeline coordination ---
_job_queues: dict = {}

_BEHAVIORAL_TMP_DIR = "/tmp/orca_behavioral"  # nosec B108 — path pre-created and owned by orca user in Dockerfile

def cleanup_old_temp_files():
    for d in glob.glob(f'{_BEHAVIORAL_TMP_DIR}/*/'):
        try:
            if os.path.getmtime(d) < time.time() - 3600:
                shutil.rmtree(d, ignore_errors=True)
        except Exception:
            pass

# =============================================================================
# ENDPOINTS
# =============================================================================

@router.post("/submit")
async def submit_behavioral_analysis(
    background_tasks: BackgroundTasks,
    asset_id: int = Form(...),
    analyst_initials: str = Form(""),
    file_path: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    current_user: dict = Depends(get_current_user),
):
    job_id = str(uuid.uuid4())
    tmp_dir = f"{_BEHAVIORAL_TMP_DIR}/{job_id}"
    is_temp = False

    _MAX_UPLOAD = 256 * 1024 * 1024  # 256 MB application-layer limit

    if file is not None:
        os.makedirs(tmp_dir, exist_ok=True)
        safe_name = os.path.basename(file.filename or "uploaded_file")
        actual_path = os.path.join(tmp_dir, safe_name)
        # Stream to disk in bounded chunks instead of `await file.read()`-ing
        # the whole upload into memory before checking the size -- this
        # endpoint exists specifically to accept untrusted files, and reading
        # the full body first meant the 256MB check couldn't stop an
        # arbitrarily large body from being fully materialized in RAM first.
        _CHUNK = 1024 * 1024
        total = 0
        try:
            with open(actual_path, 'wb') as fout:
                while True:
                    chunk = await file.read(_CHUNK)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > _MAX_UPLOAD:
                        raise HTTPException(status_code=413, detail="File exceeds 256 MB limit")
                    fout.write(chunk)
        except HTTPException:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise
        display_name = safe_name
        is_temp = True
    elif file_path:
        # Sandbox: file_path must resolve inside the evidence root
        _allowed_roots = [
            os.path.realpath(cfg.DATA_ROOT),
            os.path.realpath("/app/evidence"),
        ]
        resolved = os.path.realpath(file_path)
        if not any(resolved.startswith(root + os.sep) or resolved == root for root in _allowed_roots):
            raise HTTPException(status_code=403, detail="file_path is outside the permitted evidence directory")
        actual_path = file_path
        display_name = os.path.basename(file_path)
    else:
        raise HTTPException(status_code=400, detail="Either file upload or file_path is required")

    if not os.path.exists(actual_path):
        if is_temp:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        raise HTTPException(status_code=404, detail=f"File not found: {actual_path}")

    ftype = detect_file_type(actual_path)
    if ftype is None:
        if is_temp:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        raise HTTPException(status_code=400, detail={
            "error": "unsupported_file_type",
            "message": "Behavioral analysis supports PE32/PE64 and ELF binaries only.",
        })

    try:
        with db.engine.connect() as conn:
            conn.execute(text("""
                INSERT INTO behavioral_jobs
                    (job_id, asset_id, submitted_file, file_path, file_type, submitted_by,
                     overall_status, capa_status, floss_status, speakeasy_status)
                VALUES
                    (:jid, :aid, :sfile, :fpath, :ftype, :by,
                     'running', 'pending', 'pending', 'pending')
            """), {
                "jid": job_id, "aid": asset_id, "sfile": display_name,
                "fpath": actual_path, "ftype": ftype,
                "by": analyst_initials or current_user.get("initials", ""),
            })
            conn.commit()
    except Exception as e:
        # Confirmed live 2026-08-18: this insert failing (behavioral_jobs
        # not existing yet, in this case) previously left the just-uploaded
        # file orphaned in tmp_dir forever -- nothing past the upload step
        # cleaned it up on this specific failure path.
        if is_temp:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        raise HTTPException(status_code=500, detail=f"Could not create analysis job: {e}")

    q: asyncio.Queue = asyncio.Queue()
    _job_queues[job_id] = q
    background_tasks.add_task(
        run_pipeline, job_id, actual_path, asset_id, q, is_temp, tmp_dir if is_temp else None
    )
    return {"job_id": job_id}


@router.get("/stream/{job_id}")
async def stream_analysis(job_id: str, current_user: dict = Depends(get_current_user)):
    q = _job_queues.get(job_id)

    async def event_gen():
        if q is None:
            with db.engine.connect() as conn:
                row = conn.execute(text(
                    "SELECT overall_status FROM behavioral_jobs WHERE job_id=:jid"
                ), {"jid": job_id}).fetchone()
            status = row[0] if row else "not_found"
            yield f"data: {json.dumps({'phase': 'PIPELINE_COMPLETE', 'overall_status': status})}\n\n"
            return

        while True:
            try:
                event = await asyncio.wait_for(q.get(), timeout=25.0)
            except asyncio.TimeoutError:
                yield f"data: {json.dumps({'phase': 'HEARTBEAT'})}\n\n"
                continue

            if event is None:
                break

            yield f"data: {json.dumps(event)}\n\n"

            if event.get('phase') in ('PIPELINE_COMPLETE', 'PIPELINE_ERROR'):
                break

    return StreamingResponse(
        event_gen(), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/job/{job_id}")
async def get_job_results(job_id: str, current_user: dict = Depends(get_current_user)):
    with db.engine.connect() as conn:
        job = conn.execute(text("""
            SELECT job_id, asset_id, submitted_file, file_path, file_md5, file_sha256,
                   file_type, file_size_bytes, submitted_by, submitted_at,
                   capa_status, floss_status, speakeasy_status,
                   capa_started_at, capa_completed_at,
                   floss_started_at, floss_completed_at,
                   speakeasy_started_at, speakeasy_completed_at,
                   capa_error, floss_error, speakeasy_error, overall_status
            FROM behavioral_jobs WHERE job_id=:jid
        """), {"jid": job_id}).mappings().first()
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

        capa = conn.execute(text("""
            SELECT technique_id, technique_name, tactic_name, namespace, severity
            FROM capa_results WHERE job_id=:jid ORDER BY tactic_name, technique_id
        """), {"jid": job_id}).mappings().fetchall()

        floss_iocs = conn.execute(text("""
            SELECT string_value, string_type, ioc_type, string_offset
            FROM floss_results WHERE job_id=:jid AND is_ioc=TRUE ORDER BY ioc_type, id
        """), {"jid": job_id}).mappings().fetchall()

        floss_all = conn.execute(text("""
            SELECT string_value, string_type, is_ioc, ioc_type, string_offset
            FROM floss_results WHERE job_id=:jid ORDER BY id LIMIT 5000
        """), {"jid": job_id}).mappings().fetchall()

        floss_count = conn.execute(text(
            "SELECT COUNT(*) FROM floss_results WHERE job_id=:jid"
        ), {"jid": job_id}).scalar() or 0

        se_apis = conn.execute(text("""
            SELECT func_name, args, ret_val, pc, entry_point
            FROM speakeasy_results WHERE job_id=:jid AND result_type='api_call'
            ORDER BY id LIMIT 2000
        """), {"jid": job_id}).mappings().fetchall()

        se_net = conn.execute(text("""
            SELECT protocol, host, port, url, entry_point
            FROM speakeasy_results WHERE job_id=:jid AND result_type='network' ORDER BY id
        """), {"jid": job_id}).mappings().fetchall()

        ioc_matches = conn.execute(text("""
            SELECT fr.string_value, fr.ioc_type, fr.string_type,
                   rl.id AS lib_id, rl.threat_actor, rl.severity,
                   rl.description, rl.indicator_type
            FROM floss_results fr
            JOIN ref_ioc_library rl ON LOWER(fr.string_value) = LOWER(rl.value)
            WHERE fr.job_id = :jid AND fr.is_ioc = TRUE
            ORDER BY rl.severity, fr.ioc_type
        """), {"jid": job_id}).mappings().fetchall()

    def _d(row):
        r = dict(row)
        for k, v in r.items():
            if hasattr(v, 'isoformat'):
                r[k] = v.isoformat()
        return r

    return {
        "job": _d(job),
        "capa": {
            "status": job["capa_status"],
            "technique_count": len(capa),
            "techniques": [dict(r) for r in capa],
        },
        "floss": {
            "status": job["floss_status"],
            "total_strings": int(floss_count),
            "ioc_count": len(floss_iocs),
            "iocs": [dict(r) for r in floss_iocs],
            "all_strings": [dict(r) for r in floss_all],
            "ioc_matches": [dict(r) for r in ioc_matches],
        },
        "speakeasy": {
            "status": job["speakeasy_status"],
            "error": job.get("speakeasy_error"),
            "api_calls": [dict(r) for r in se_apis],
            "network_events": [dict(r) for r in se_net],
        },
    }


@router.get("/asset/{asset_id}/jobs")
async def get_asset_jobs(asset_id: int, current_user: dict = Depends(get_current_user)):
    with db.engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT bj.job_id, bj.submitted_file, bj.submitted_at, bj.overall_status,
                   bj.file_sha256, bj.capa_status, bj.floss_status, bj.speakeasy_status,
                   (SELECT COUNT(*) FROM capa_results cr WHERE cr.job_id=bj.job_id)::int AS capa_technique_count,
                   (SELECT COUNT(*) FROM floss_results fr WHERE fr.job_id=bj.job_id AND fr.is_ioc=TRUE)::int AS floss_ioc_count
            FROM behavioral_jobs bj WHERE bj.asset_id=:aid
            ORDER BY bj.submitted_at DESC
        """), {"aid": asset_id}).mappings().fetchall()

    def _d(row):
        r = dict(row)
        for k, v in r.items():
            if hasattr(v, 'isoformat'):
                r[k] = v.isoformat()
        return r

    return [_d(r) for r in rows]


@router.get("/asset/{asset_id}/latest")
async def get_latest_job(asset_id: int, current_user: dict = Depends(get_current_user)):
    with db.engine.connect() as conn:
        row = conn.execute(text("""
            SELECT job_id FROM behavioral_jobs
            WHERE asset_id=:aid AND overall_status='complete'
            ORDER BY submitted_at DESC LIMIT 1
        """), {"aid": asset_id}).fetchone()
    if not row:
        return None
    return await get_job_results(row[0], current_user)


@router.get("/asset/{asset_id}/capa-techniques")
async def get_asset_capa_techniques(asset_id: int, current_user: dict = Depends(get_current_user)):
    with db.engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT DISTINCT cr.technique_id, cr.technique_name, cr.tactic_name,
                   COUNT(DISTINCT bj.job_id)::int AS job_count,
                   string_agg(DISTINCT bj.submitted_file, ', ') AS source_files
            FROM capa_results cr
            JOIN behavioral_jobs bj ON cr.job_id = bj.job_id
            WHERE bj.asset_id = :aid AND bj.overall_status = 'complete'
            GROUP BY cr.technique_id, cr.technique_name, cr.tactic_name
            ORDER BY cr.tactic_name, cr.technique_id
        """), {"aid": asset_id}).mappings().fetchall()
    return [dict(r) for r in rows]


@router.get("/asset/{asset_id}/artifact-files")
async def get_artifact_files(asset_id: int, current_user: dict = Depends(get_current_user)):
    with db.engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT DISTINCT source_file, t_code
            FROM artifact_results
            WHERE asset_id=:aid AND source_file IS NOT NULL AND source_file != ''
            ORDER BY source_file
        """), {"aid": asset_id}).fetchall()
    return [{"source_file": r[0], "t_code": r[1]} for r in rows]


# ── Live single-file pull (MFT browser "PULL FILE") ───────────────────────────
# Reuses the same push-delivery staging/trigger machinery as a full collection
# (package_builder.build_file_fetch_package + vr_remote.push_and_trigger_package)
# for a one-off "grab exactly this file" job, so an analyst mid-investigation
# doesn't need a second full evidence collection just to look at one binary
# they spotted in the MFT/Amcache-populated file browser.

class FetchFileRequest(BaseModel):
    file_path: str
    username: str
    password: str
    domain: Optional[str] = None
    transport: str = "SMB_TASK"
    remote_dir: Optional[str] = None


def _get_asset_for_fetch(asset_id: int) -> Optional[dict]:
    with db.engine.connect() as conn:
        row = conn.execute(text(
            "SELECT id, hostname, ip, case_name FROM assets WHERE id = :id"
        ), {"id": asset_id}).mappings().first()
    return dict(row) if row else None


@router.post("/asset/{asset_id}/fetch-file")
async def fetch_file(asset_id: int, req: FetchFileRequest, current_user: dict = Depends(get_current_user)):
    asset = _get_asset_for_fetch(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    if not user_can_access_case(current_user, asset.get("case_name")):
        raise HTTPException(status_code=403, detail="Not assigned to this investigation")
    ip = (asset.get("ip") or "").strip()
    if not ip:
        raise HTTPException(status_code=400, detail="No IP address configured for this asset")
    if not req.username or not req.password:
        raise HTTPException(status_code=400, detail="Credentials required")

    job_id = str(uuid.uuid4())
    token = str(uuid.uuid4())

    with db.engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO file_fetch_jobs (job_id, asset_id, token, file_path, status, created_by)
            VALUES (:job_id, :asset_id, :token, :file_path, 'pending', :created_by)
        """), {
            "job_id": job_id, "asset_id": asset_id, "token": token,
            "file_path": req.file_path, "created_by": current_user.get("id"),
        })

    orca_url = _get_orca_base_url()
    try:
        zip_path = await asyncio.to_thread(
            build_file_fetch_package, asset_id, orca_url, job_id, token, req.file_path
        )
    except ValueError as e:
        with db.engine.begin() as conn:
            conn.execute(text(
                "UPDATE file_fetch_jobs SET status='failed', error=:err WHERE job_id=:job_id"
            ), {"err": str(e), "job_id": job_id})
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        with db.engine.begin() as conn:
            conn.execute(text(
                "UPDATE file_fetch_jobs SET status='failed', error=:err WHERE job_id=:job_id"
            ), {"err": f"Package build failed: {e}", "job_id": job_id})
        raise HTTPException(status_code=500, detail=f"Package build failed: {e}")

    with db.engine.begin() as conn:
        conn.execute(text(
            "UPDATE file_fetch_jobs SET status='staged' WHERE job_id=:job_id"
        ), {"job_id": job_id})

    returncode, stdout, stderr = await vr_remote.push_and_trigger_package(
        ip, req.username, req.password, req.domain, zip_path,
        remote_dir=validate_remote_dir(req.remote_dir), transport=req.transport,
    )

    if returncode != 0:
        err_detail = (stderr or "Remote trigger failed")[:300]
        with db.engine.begin() as conn:
            conn.execute(text(
                "UPDATE file_fetch_jobs SET status='failed', error=:err, completed_at=NOW() WHERE job_id=:job_id"
            ), {"err": err_detail, "job_id": job_id})
        raise HTTPException(status_code=502, detail=f"Fetch trigger failed: {err_detail}")

    with db.engine.begin() as conn:
        conn.execute(text(
            "UPDATE file_fetch_jobs SET status='triggered' WHERE job_id=:job_id"
        ), {"job_id": job_id})

    return {"job_id": job_id, "status": "triggered"}


@router.get("/fetch-file/{job_id}")
async def get_fetch_file_status(job_id: str, current_user: dict = Depends(get_current_user)):
    with db.engine.connect() as conn:
        row = conn.execute(text("""
            SELECT ffj.job_id, ffj.asset_id, ffj.file_path, ffj.status, ffj.error,
                   ffj.local_path, ffj.file_size, ffj.sha256, ffj.created_at, ffj.completed_at,
                   a.case_name
            FROM file_fetch_jobs ffj
            JOIN assets a ON a.id = ffj.asset_id
            WHERE ffj.job_id = :job_id
        """), {"job_id": job_id}).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Fetch job not found")
    if not user_can_access_case(current_user, row["case_name"]):
        raise HTTPException(status_code=403, detail="Not assigned to this investigation")

    result = {k: v for k, v in dict(row).items() if k != "case_name"}
    for k, v in result.items():
        if hasattr(v, "isoformat"):
            result[k] = v.isoformat()
    return result


@router.delete("/job/{job_id}")
async def delete_job(job_id: str, current_user: dict = Depends(get_current_user)):
    with db.engine.connect() as conn:
        row = conn.execute(text(
            "SELECT job_id FROM behavioral_jobs WHERE job_id=:jid"
        ), {"jid": job_id}).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Job not found")
        conn.execute(text("DELETE FROM behavioral_jobs WHERE job_id=:jid"), {"jid": job_id})
        conn.commit()
    tmp_dir = f"{_BEHAVIORAL_TMP_DIR}/{job_id}"
    if os.path.exists(tmp_dir):
        shutil.rmtree(tmp_dir, ignore_errors=True)
    return {"status": "deleted"}


# =============================================================================
# PIPELINE
# =============================================================================

async def run_pipeline(
    job_id: str, filepath: str, asset_id: int,
    queue: asyncio.Queue, is_temp: bool = False, tmp_dir: Optional[str] = None,
):
    try:
        loop = asyncio.get_event_loop()
        md5, sha256 = await loop.run_in_executor(None, compute_hashes, filepath)
        file_size = os.path.getsize(filepath)
        ftype = detect_file_type(filepath)

        with db.engine.connect() as conn:
            conn.execute(text("""
                UPDATE behavioral_jobs
                SET file_md5=:md5, file_sha256=:sha256, file_size_bytes=:sz, file_type=:ft
                WHERE job_id=:jid
            """), {"md5": md5, "sha256": sha256, "sz": file_size, "ft": ftype, "jid": job_id})
            conn.commit()

        await queue.put({"phase": "FILE_INFO", "md5": md5, "sha256": sha256,
                         "file_type": ftype, "size": file_size})

        await _run_capa(job_id, asset_id, filepath, queue)
        await _run_floss(job_id, asset_id, filepath, queue, ftype=ftype)

        if ftype == 'PE':
            await _run_speakeasy(job_id, asset_id, filepath, queue)
        else:
            with db.engine.connect() as conn:
                conn.execute(text("""
                    UPDATE behavioral_jobs SET speakeasy_status='skipped',
                    speakeasy_error='ELF binaries not supported by Windows emulator'
                    WHERE job_id=:jid
                """), {"jid": job_id})
                conn.commit()
            await queue.put({"phase": "SPEAKEASY_SKIPPED",
                             "reason": "ELF binaries not supported by Windows emulator"})

        with db.engine.connect() as conn:
            conn.execute(text(
                "UPDATE behavioral_jobs SET overall_status='complete' WHERE job_id=:jid"
            ), {"jid": job_id})
            conn.commit()

        await queue.put({"phase": "PIPELINE_COMPLETE", "overall_status": "complete"})

    except Exception as e:
        try:
            with db.engine.connect() as conn:
                conn.execute(text(
                    "UPDATE behavioral_jobs SET overall_status='error' WHERE job_id=:jid"
                ), {"jid": job_id})
                conn.commit()
        except Exception:
            pass
        await queue.put({"phase": "PIPELINE_ERROR", "message": str(e)})
    finally:
        await queue.put(None)
        _job_queues.pop(job_id, None)
        if is_temp and tmp_dir and os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir, ignore_errors=True)


# --- CAPA ---

def _parse_capa_output(result: dict) -> list:
    techniques = []

    # CAPA v6+ schema: result['rules']
    if 'rules' in result:
        for rule_name, rule_data in result['rules'].items():
            meta = rule_data.get('meta', {})
            for mapping in meta.get('attack', []):
                if not isinstance(mapping, dict):
                    continue
                if 'id' in mapping:
                    # v7+ flat schema: {id, tactic, technique, subtechnique, parts}
                    tid = mapping.get('id', '')
                    sub = mapping.get('subtechnique', '')
                    tech = mapping.get('technique', '')
                    tname = sub if sub else tech
                    tactic = mapping.get('tactic', 'Unknown')
                else:
                    # v6 nested schema: {technique: {id, name}, subtechnique: {id, name}, tactic: {name}}
                    t = mapping.get('technique', {}) or {}
                    s = mapping.get('subtechnique', {}) or {}
                    tac = mapping.get('tactic', {}) or {}
                    tid = s.get('id') or t.get('id', '')
                    tname = s.get('name') or t.get('name', rule_name)
                    tactic = tac.get('name', 'Unknown')
                if not tid:
                    continue
                techniques.append({
                    "technique_id": tid,
                    "technique_name": tname,
                    "tactic_name": tactic,
                    "namespace": meta.get('namespace'),
                    "severity": None,
                    "raw": {"rule": rule_name},
                })

    # Older schema: result['attack']
    elif 'attack' in result:
        for tid, data in result['attack'].items():
            tech = data.get('technique', {})
            tac = data.get('tactic', {})
            techniques.append({
                "technique_id": tech.get('id', tid),
                "technique_name": tech.get('name', tid),
                "tactic_name": tac.get('name', 'Unknown'),
                "namespace": data.get('namespace'),
                "severity": data.get('severity'),
                "raw": data,
            })

    # Deduplicate by technique_id
    seen, deduped = set(), []
    for t in techniques:
        if t["technique_id"] not in seen:
            seen.add(t["technique_id"])
            deduped.append(t)
    return deduped


async def _run_capa(job_id: str, asset_id: int, filepath: str, queue: asyncio.Queue):
    t0 = time.time()
    with db.engine.connect() as conn:
        conn.execute(text(
            "UPDATE behavioral_jobs SET capa_status='running', capa_started_at=NOW() WHERE job_id=:jid"
        ), {"jid": job_id})
        conn.commit()

    await queue.put({"phase": "CAPA_START", "message": "Starting CAPA capability analysis..."})
    try:
        proc = await asyncio.create_subprocess_exec(
            _CAPA_BIN, '--json', filepath,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=1800.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise Exception(
                "CAPA timed out after 1800s. Vivisect disassembly of complex or packed "
                "binaries is CPU-intensive in a containerised environment. The file may "
                "require a native Windows analysis environment for reliable results."
            )

        if proc.returncode not in (0, 1) and not stdout.strip():
            raise Exception(f"CAPA exited {proc.returncode}: {stderr.decode(errors='replace')[:300]}")

        techniques = []
        if stdout.strip():
            try:
                result = json.loads(stdout.decode(errors='replace'))
                techniques = _parse_capa_output(result)
            except json.JSONDecodeError:
                raise Exception("CAPA output could not be parsed as JSON")

        technique_count = 0
        with db.engine.connect() as conn:
            for tech in techniques:
                conn.execute(text("""
                    INSERT INTO capa_results
                        (job_id, asset_id, technique_id, technique_name, tactic_name, namespace, severity, raw_result)
                    VALUES (:jid, :aid, :tid, :tn, :tac, :ns, :sev, :raw)
                """), {
                    "jid": job_id, "aid": asset_id,
                    "tid": tech["technique_id"], "tn": tech["technique_name"],
                    "tac": tech["tactic_name"], "ns": tech.get("namespace"),
                    "sev": tech.get("severity"), "raw": json.dumps(tech.get("raw", {})),
                })
                technique_count += 1
                await queue.put({
                    "phase": "CAPA_TECHNIQUE",
                    "technique_id": tech["technique_id"],
                    "technique_name": tech["technique_name"],
                    "tactic": tech["tactic_name"],
                })
            conn.execute(text(
                "UPDATE behavioral_jobs SET capa_status='complete', capa_completed_at=NOW() WHERE job_id=:jid"
            ), {"jid": job_id})
            conn.commit()

        await queue.put({"phase": "CAPA_COMPLETE", "technique_count": technique_count,
                         "elapsed_seconds": round(time.time() - t0, 1)})

    except Exception as e:
        with db.engine.connect() as conn:
            conn.execute(text("""
                UPDATE behavioral_jobs SET capa_status='error', capa_error=:err,
                capa_completed_at=NOW() WHERE job_id=:jid
            """), {"err": str(e)[:500], "jid": job_id})
            conn.commit()
        await queue.put({"phase": "ERROR", "tool": "capa", "message": str(e)})


# --- FLOSS ---

def _parse_floss_strings(result: dict) -> list:
    all_strings = []
    type_map = {
        'static_strings': 'static',
        'stack_strings': 'stack',
        'decoded_strings': 'decoded',
        'tight_strings': 'tight',
    }
    raw = result.get('strings', result)
    if isinstance(raw, dict):
        for key, stype in type_map.items():
            for item in raw.get(key, []):
                if isinstance(item, dict):
                    s = item.get('string', '')
                    off = item.get('offset') or item.get('program_counter')
                elif isinstance(item, str):
                    s, off = item, None
                else:
                    continue
                if s:
                    all_strings.append({"string": s, "type": stype, "offset": off})
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                all_strings.append({
                    "string": item.get('string', ''),
                    "type": item.get('type', 'static'),
                    "offset": item.get('offset'),
                })
            elif isinstance(item, str):
                all_strings.append({"string": item, "type": "static", "offset": None})
    return all_strings


async def _run_floss(job_id: str, asset_id: int, filepath: str, queue: asyncio.Queue, ftype: Optional[str] = None):
    t0 = time.time()
    with db.engine.connect() as conn:
        conn.execute(text(
            "UPDATE behavioral_jobs SET floss_status='running', floss_started_at=NOW() WHERE job_id=:jid"
        ), {"jid": job_id})
        conn.commit()

    await queue.put({"phase": "FLOSS_START", "message": "Starting FLOSS string extraction..."})
    try:
        # Static-only for all types: vivisect decoded/stack string extraction is too slow
        # in a containerised Linux environment (100-600s+ per binary) and produces
        # unpredictable timeouts. Static extraction still catches URLs, IPs, registry
        # keys, file paths, and other IOC-bearing strings in seconds.
        floss_cmd = [_FLOSS_BIN, '--only', 'static', '--json', filepath]
        proc = await asyncio.create_subprocess_exec(
            *floss_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise Exception("FLOSS timed out after 300s")

        if proc.returncode not in (0, 1) and not stdout.strip():
            raise Exception(f"FLOSS exited {proc.returncode}")

        try:
            result = json.loads(stdout.decode(errors='replace'))
        except json.JSONDecodeError:
            raise Exception("FLOSS output could not be parsed as JSON")

        all_strings = _parse_floss_strings(result)
        total_strings = len(all_strings)
        total_iocs = 0
        batch = []
        strings_found = 0

        with db.engine.connect() as conn:
            for item in all_strings:
                s_val = item["string"]
                if not s_val:
                    continue
                ioc_match = check_ioc(s_val)
                is_ioc = ioc_match is not None
                ioc_type = ioc_match[0] if ioc_match else None
                # Store the cleaned, matched IOC substring (not the raw string) once
                # something is flagged as an IOC -- see check_ioc's docstring. Non-IOC
                # strings are stored as-is; they're just general string content, not
                # claiming to be a specific indicator.
                stored_val = ioc_match[1] if ioc_match else s_val

                if is_ioc:
                    total_iocs += 1

                batch.append({
                    "jid": job_id, "aid": asset_id,
                    "val": stored_val[:2000], "stype": item["type"],
                    "is_ioc": is_ioc, "ioc_type": ioc_type,
                    "offset": item.get("offset"),
                })
                strings_found += 1

                if len(batch) >= 500:
                    _insert_floss_batch(conn, batch)
                    batch = []
                    await queue.put({"phase": "FLOSS_PROGRESS",
                                     "strings_found": strings_found, "iocs_found": total_iocs})

            if batch:
                _insert_floss_batch(conn, batch)

            conn.execute(text(
                "UPDATE behavioral_jobs SET floss_status='complete', floss_completed_at=NOW() WHERE job_id=:jid"
            ), {"jid": job_id})
            conn.commit()

        await queue.put({
            "phase": "FLOSS_COMPLETE",
            "total_strings": strings_found,
            "total_iocs": total_iocs,
            "elapsed_seconds": round(time.time() - t0, 1),
        })

    except Exception as e:
        with db.engine.connect() as conn:
            conn.execute(text("""
                UPDATE behavioral_jobs SET floss_status='error', floss_error=:err,
                floss_completed_at=NOW() WHERE job_id=:jid
            """), {"err": str(e)[:500], "jid": job_id})
            conn.commit()
        await queue.put({"phase": "ERROR", "tool": "floss", "message": str(e)})


def _insert_floss_batch(conn, batch: list):
    for item in batch:
        conn.execute(text("""
            INSERT INTO floss_results
                (job_id, asset_id, string_value, string_type, is_ioc, ioc_type, string_offset)
            VALUES (:jid, :aid, :val, :stype, :is_ioc, :ioc_type, :offset)
        """), item)


# --- Speakeasy ---

async def _run_speakeasy(job_id: str, asset_id: int, filepath: str, queue: asyncio.Queue):
    t0 = time.time()
    if not SPEAKEASY_AVAILABLE:
        with db.engine.connect() as conn:
            conn.execute(text("""
                UPDATE behavioral_jobs SET speakeasy_status='error',
                speakeasy_error='speakeasy-emulator not installed', speakeasy_completed_at=NOW()
                WHERE job_id=:jid
            """), {"jid": job_id})
            conn.commit()
        await queue.put({"phase": "ERROR", "tool": "speakeasy",
                         "message": "speakeasy-emulator not installed"})
        return

    with db.engine.connect() as conn:
        conn.execute(text(
            "UPDATE behavioral_jobs SET speakeasy_status='running', speakeasy_started_at=NOW() WHERE job_id=:jid"
        ), {"jid": job_id})
        conn.commit()

    await queue.put({"phase": "SPEAKEASY_START",
                     "message": "Starting Speakeasy emulation (timeout: 120s)..."})

    report_path = f"{filepath}.speakeasy_report.json"
    try:
        # Runs as a real subprocess (like CAPA/FLOSS above), not in-process
        # via run_in_executor on the shared default thread pool.
        # asyncio.wait_for's timeout only cancels the *await* -- it can't
        # stop a thread already running synchronous C-extension emulation
        # code -- so a hung sample used to permanently occupy a slot in the
        # pool the whole app shares (including unrelated remote-collection/
        # SMB work elsewhere). A subprocess can actually be killed.
        speakeasy_cmd = [_SPEAKEASY_BIN, '-t', filepath, '-o', report_path]
        proc = await asyncio.create_subprocess_exec(
            *speakeasy_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=120.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise Exception("Emulation timeout after 120s")

        # The CLI runs the emulation in its own internal worker process and
        # swallows errors there (unsupported file type, corrupt PE, etc.) --
        # confirmed live it exits 0 either way, so the output file's
        # presence is the real success signal, not the exit code.
        if not os.path.isfile(report_path):
            err_lines = stderr.decode(errors='replace').strip().splitlines()
            raise Exception(err_lines[-1] if err_lines else "Speakeasy produced no report (unsupported or invalid file)")

        with open(report_path) as f:
            report = json.load(f)

        api_count = 0
        net_count = 0

        with db.engine.connect() as conn:
            for ep_idx, ep in enumerate(report.get('entry_points', [])):
                for api in ep.get('apis', []):
                    # Real field is `api_name`, not `func_name` -- confirmed
                    # against a live report (speakeasy/profiler.py builds
                    # each call as {'pc', 'api_name', 'args', 'ret_val'}).
                    fn = api.get('api_name', '')
                    args = api.get('args', [])
                    conn.execute(text("""
                        INSERT INTO speakeasy_results
                            (job_id, asset_id, result_type, entry_point, func_name, args, ret_val, pc)
                        VALUES (:jid, :aid, 'api_call', :ep, :fn, :args, :rv, :pc)
                    """), {
                        "jid": job_id, "aid": asset_id, "ep": ep_idx,
                        "fn": fn, "args": json.dumps(args if isinstance(args, list) else []),
                        "rv": str(api.get('ret_val', ''))[:200],
                        "pc": str(api.get('pc', ''))[:50],
                    })
                    api_count += 1
                    await queue.put({
                        "phase": "SPEAKEASY_API_CALL",
                        "func_name": fn,
                        "args": (args[:3] if isinstance(args, list) else []),
                    })

                net_events = ep.get('network_events', {})
                for traffic in net_events.get('traffic', []):
                    # Real field is `server`, not `host`/`dst` -- there is no
                    # `url` field at all (confirmed against speakeasy/
                    # profiler.py's log_http/log_network, which only ever
                    # emit {'server', 'proto', 'port', ...}). Both were
                    # silently always-blank before.
                    proto = traffic.get('proto', 'unknown')
                    host = str(traffic.get('server', ''))[:500]
                    port = traffic.get('port')
                    url = str(traffic.get('url', ''))[:1000]
                    conn.execute(text("""
                        INSERT INTO speakeasy_results
                            (job_id, asset_id, result_type, entry_point, protocol, host, port, url)
                        VALUES (:jid, :aid, 'network', :ep, :proto, :host, :port, :url)
                    """), {
                        "jid": job_id, "aid": asset_id, "ep": ep_idx,
                        "proto": proto, "host": host, "port": port, "url": url,
                    })
                    net_count += 1
                    await queue.put({"phase": "SPEAKEASY_NETWORK",
                                     "protocol": proto, "host": host})

            conn.execute(text(
                "UPDATE behavioral_jobs SET speakeasy_status='complete', speakeasy_completed_at=NOW() WHERE job_id=:jid"
            ), {"jid": job_id})
            conn.commit()

        await queue.put({
            "phase": "SPEAKEASY_COMPLETE",
            "api_call_count": api_count,
            "network_events": net_count,
            "elapsed_seconds": round(time.time() - t0, 1),
        })

    except Exception as e:
        with db.engine.connect() as conn:
            conn.execute(text("""
                UPDATE behavioral_jobs SET speakeasy_status='error', speakeasy_error=:err,
                speakeasy_completed_at=NOW() WHERE job_id=:jid
            """), {"err": str(e)[:500], "jid": job_id})
            conn.commit()
        await queue.put({"phase": "ERROR", "tool": "speakeasy", "message": str(e)})
    finally:
        try:
            if os.path.isfile(report_path):
                os.remove(report_path)
        except Exception:
            pass
