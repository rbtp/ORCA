import os, re, uuid, json, hashlib, asyncio, time, shutil, glob, sys
from typing import Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends, UploadFile, File, Form
from fastapi.responses import StreamingResponse
from sqlalchemy import text
from core.database_manager import db
from auth_utils import get_current_user
from config import cfg

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

# Module-level speakeasy import — slow to load so do it once at startup
try:
    import speakeasy as _speakeasy_mod
    SPEAKEASY_AVAILABLE = True
except ImportError:
    _speakeasy_mod = None
    SPEAKEASY_AVAILABLE = False

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
_IOC_PATTERNS = [
    ('URL',      re.compile(r'https?://[^\s"\'<>]+')),
    ('IP',       re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')),
    ('REGISTRY', re.compile(r'HKEY_[A-Z_]+\\[^\s"\n]+')),
    ('FILEPATH', re.compile(r'[A-Za-z]:\\[^"\'\n\r]+')),
    ('EMAIL',    re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b')),
    ('DOMAIN',   re.compile(r'\b[a-zA-Z0-9][a-zA-Z0-9\-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}\b')),
]

def check_ioc(s: str) -> Optional[str]:
    for ioc_type, pat in _IOC_PATTERNS:
        if pat.search(s):
            return ioc_type
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
        content = await file.read()
        if len(content) > _MAX_UPLOAD:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise HTTPException(status_code=413, detail="File exceeds 256 MB limit")
        with open(actual_path, 'wb') as fout:
            fout.write(content)
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
                        (job_id, technique_id, technique_name, tactic_name, namespace, severity, raw_result)
                    VALUES (:jid, :tid, :tn, :tac, :ns, :sev, :raw)
                """), {
                    "jid": job_id,
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
                ioc_type = check_ioc(s_val)
                is_ioc = ioc_type is not None
                if is_ioc:
                    total_iocs += 1

                batch.append({
                    "jid": job_id, "aid": asset_id,
                    "val": s_val[:2000], "stype": item["type"],
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
                (job_id, string_value, string_type, is_ioc, ioc_type, string_offset)
            VALUES (:jid, :val, :stype, :is_ioc, :ioc_type, :offset)
        """), item)


# --- Speakeasy ---

def _run_speakeasy_sync(filepath: str) -> dict:
    if not SPEAKEASY_AVAILABLE:
        raise Exception("speakeasy-emulator is not installed")
    se = _speakeasy_mod.Speakeasy()
    module = se.load_module(filepath)
    se.run_module(module)
    return se.get_report()


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
    try:
        loop = asyncio.get_event_loop()
        report = await asyncio.wait_for(
            loop.run_in_executor(None, _run_speakeasy_sync, filepath),
            timeout=120.0,
        )

        api_count = 0
        net_count = 0

        with db.engine.connect() as conn:
            for ep_idx, ep in enumerate(report.get('entry_points', [])):
                for api in ep.get('apis', []):
                    fn = api.get('func_name', '')
                    args = api.get('args', [])
                    conn.execute(text("""
                        INSERT INTO speakeasy_results
                            (job_id, result_type, entry_point, func_name, args, ret_val, pc)
                        VALUES (:jid, 'api_call', :ep, :fn, :args, :rv, :pc)
                    """), {
                        "jid": job_id, "ep": ep_idx,
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
                    proto = traffic.get('proto', 'unknown')
                    host = str(traffic.get('host') or traffic.get('dst', ''))[:500]
                    port = traffic.get('port') or traffic.get('dst_port')
                    url = str(traffic.get('url', ''))[:1000]
                    conn.execute(text("""
                        INSERT INTO speakeasy_results
                            (job_id, result_type, entry_point, protocol, host, port, url)
                        VALUES (:jid, 'network', :ep, :proto, :host, :port, :url)
                    """), {
                        "jid": job_id, "ep": ep_idx,
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

    except asyncio.TimeoutError:
        with db.engine.connect() as conn:
            conn.execute(text("""
                UPDATE behavioral_jobs SET speakeasy_status='error',
                speakeasy_error='Emulation timeout after 120s', speakeasy_completed_at=NOW()
                WHERE job_id=:jid
            """), {"jid": job_id})
            conn.commit()
        await queue.put({"phase": "ERROR", "tool": "speakeasy",
                         "message": "Emulation timeout after 120s"})
    except Exception as e:
        with db.engine.connect() as conn:
            conn.execute(text("""
                UPDATE behavioral_jobs SET speakeasy_status='error', speakeasy_error=:err,
                speakeasy_completed_at=NOW() WHERE job_id=:jid
            """), {"err": str(e)[:500], "jid": job_id})
            conn.commit()
        await queue.put({"phase": "ERROR", "tool": "speakeasy", "message": str(e)})
