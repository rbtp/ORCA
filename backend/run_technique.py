"""
run_technique.py
================
Standalone worker script for ORCA VR collection.
Spawned as an independent OS process per technique by run_vr_orchestrator.
Receives all context via JSON on stdin, writes results directly to DB.

Usage (internal — called by main.py):
  python run_technique.py < technique_job.json
"""

import sys
import os
import json
import subprocess
import re

# ---------------------------------------------------------------------------
# Channel → evtx file path map (local execution only)
# ---------------------------------------------------------------------------
_LOCAL_CHANNEL_MAP = {
    'security':                                    'C:/Windows/System32/winevt/Logs/Security.evtx',
    'system':                                      'C:/Windows/System32/winevt/Logs/System.evtx',
    'application':                                 'C:/Windows/System32/winevt/Logs/Application.evtx',
    'microsoft-windows-sysmon/operational':        'C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx',
    'microsoft-windows-powershell/operational':    'C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx',
    'microsoft-windows-taskscheduler/operational': 'C:/Windows/System32/winevt/Logs/Microsoft-Windows-TaskScheduler%4Operational.evtx',
    'microsoft-windows-winrm/operational':         'C:/Windows/System32/winevt/Logs/Microsoft-Windows-WinRM%4Operational.evtx',
    'microsoft-windows-wmi-activity/operational':  'C:/Windows/System32/winevt/Logs/Microsoft-Windows-WMI-Activity%4Operational.evtx',
}

_EVENTID_FILTER = re.compile(
    r'System\.EventID\.Value\s*(?:=|IN)\s*(?:\([\w,\s]+\)|\w+)',
    re.IGNORECASE | re.DOTALL
)
_WHERE_CLAUSE = re.compile(r'\bWHERE\b.+', re.IGNORECASE | re.DOTALL)


def convert_source_to_parse_evtx(vql_text):
    def replacer(m):
        channel = m.group(1).lower()
        path = _LOCAL_CHANNEL_MAP.get(channel)
        if path:
            return f"parse_evtx(filename='{path}')"
        return m.group(0)
    return re.sub(
        r"source\s*\(\s*artifact\s*=\s*['\"]Windows\.EventLogs\.Evtx['\"]\s*,\s*channel\s*=\s*['\"]([^'\"]+)['\"]\s*\)",
        replacer,
        vql_text,
        flags=re.IGNORECASE
    )


def build_fallback_vql(custom_vql):
    if not custom_vql:
        return None
    eid_match = _EVENTID_FILTER.search(custom_vql)
    if not eid_match:
        return None
    eid_filter = eid_match.group(0).strip()
    channel_match = re.search(r"channel\s*=\s*['\"]([^'\"]+)['\"]", custom_vql, re.IGNORECASE)
    channel = channel_match.group(1).lower() if channel_match else None
    evtx_path = _LOCAL_CHANNEL_MAP.get(channel) if channel else None
    if evtx_path:
        # Always SELECT * in fallback — named fields like EventData.Image don't resolve
        # against parse_evtx() directly; the raw dict comes through intact for analyst review
        return f"SELECT *\nFROM parse_evtx(filename='{evtx_path}')\nWHERE {eid_filter}\nLIMIT 10000"
    else:
        # No known evtx path — can't build a useful fallback
        return None


def count_jsonl_rows(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            return sum(1 for line in f if line.strip())
    except Exception:
        return 0


def run(job):
    t_code      = job['t_code']
    asset_id    = job['asset_id']
    output_root = job['output_root']
    tsource     = job['tsource']
    vr_exe      = job['vr_exe']
    custom_vql  = job.get('custom_vql') or ''
    surgical_yaml = job.get('surgical_yaml') or ''
    db_url      = job['db_url']   # sourced from cfg.DB_URL in run_vr_orchestrator

    output_json   = os.path.join(output_root, f"orca_{t_code}.jsonl")
    clean_tsource = tsource.replace('\\', '/').rstrip('/')
    creationflags = 0x08000000 if os.name == 'nt' else 0

    # Lazy DB import — each process gets its own connection
    from sqlalchemy import create_engine, text as sa_text
    engine = create_engine(db_url, pool_size=1, max_overflow=0)

    def normalize(path, is_fallback=False):
        import json as _json
        import time
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            return 0
        time.sleep(0.3)
        rows = []
        with open(path, 'r', encoding='utf-8-sig', errors='ignore') as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    raw = _json.loads(line)
                    if '_Source' in raw and len(raw) == 1:
                        continue
                    clean = {}
                    for k, v in raw.items():
                        clean[k] = _json.dumps(v) if isinstance(v, (dict, list)) else v
                    if is_fallback:
                        clean['_orca_fallback'] = True
                        clean['_orca_fallback_note'] = 'Primary query returned 0 hits — broad EventID collection for analyst review'
                    rows.append(clean)
                except Exception:
                    pass
        if not rows:
            return 0
        msg = (
            f"Broad Collection (Fallback): {len(rows)} entries — primary query returned 0 hits. Review for relevance."
            if is_fallback else
            f"Forensic Hit: {len(rows)} system entries found via {t_code}"
        )
        summary = _json.dumps({"message": msg})
        with engine.connect() as conn:
            conn.execute(sa_text("""
                INSERT INTO artifact_results (asset_id, t_code, verdict, evidence_summary, evidence_imported)
                VALUES (:aid, :t, 'Evidence Found', :s, TRUE)
                ON CONFLICT (asset_id, t_code)
                DO UPDATE SET verdict = 'Evidence Found', evidence_summary = EXCLUDED.evidence_summary, evidence_imported = TRUE
            """), {"aid": asset_id, "t": t_code, "s": summary})
            for item in rows:
                display_name = item.get('Name') or item.get('EventID') or item.get('ID') or t_code
                display_path = item.get('Key') or item.get('OSPath') or item.get('FullPath') or 'System'
                conn.execute(sa_text("""
                    INSERT INTO evidence (asset_id, t_code, file_name, file_path, raw_data)
                    VALUES (:aid, :t, :fname, :fpath, :raw)
                """), {"aid": asset_id, "t": t_code, "fname": display_name, "fpath": display_path, "raw": _json.dumps(item)})
            conn.commit()
        print(f"[+] SUCCESS: {t_code} ingested correctly ({len(rows)} rows){' [FALLBACK]' if is_fallback else ''}", flush=True)
        return len(rows)

    def write_no_artifacts():
        sql = (
            "INSERT INTO artifact_results (asset_id, t_code, verdict, evidence_summary, evidence_imported) "
            "VALUES (:aid, :t, 'NO_ARTIFACTS', :s, FALSE) "
            "ON CONFLICT (asset_id, t_code) "
            "DO UPDATE SET verdict = 'NO_ARTIFACTS', evidence_summary = EXCLUDED.evidence_summary"
        )
        msg = '{"message": "Collection executed — no artifacts found on this host for this technique. Manual evidence upload recommended."}'
        with engine.connect() as conn:
            conn.execute(sa_text(sql), {"aid": asset_id, "t": t_code, "s": msg})
            conn.commit()
        print(f"[VR] {t_code}: NO_ARTIFACTS — collection ran, host contains no evidence for this technique", flush=True)

    try:
        if surgical_yaml.strip():
            yaml_file = os.path.join(output_root, f"artifact_{t_code}.yaml")
            converted = convert_source_to_parse_evtx(surgical_yaml.strip().replace('\r\n', '\n'))
            with open(yaml_file, 'w', encoding='utf-8') as f:
                f.write(converted)
            try:
                artifact_name = surgical_yaml.split('name:')[1].split('\n')[0].strip()
            except Exception:
                print(f"[VR] {t_code}: could not parse artifact name", flush=True)
                return
            if not re.match(r'^[A-Za-z0-9._\-/ ]+$', artifact_name):
                print(f"[VR] {t_code}: invalid artifact name", flush=True)
                return
            proc = subprocess.run(
                [vr_exe, "--definitions", output_root, "artifacts", "collect", artifact_name, "--format", "jsonl"],
                capture_output=True, creationflags=creationflags
            )
            if proc.returncode != 0:
                stderr = proc.stderr.decode('utf-8', errors='replace')
                print(f"[VR] {t_code}: exit {proc.returncode} — {stderr[:200]}", flush=True)
                return
            with open(output_json, 'w', encoding='utf-8') as f:
                f.write(proc.stdout.decode('utf-8', errors='replace'))
            rows = count_jsonl_rows(output_json)
            if rows > 0:
                normalize(output_json)
            else:
                # surgical_yaml zero — try custom_vql fallback
                if custom_vql.strip():
                    fallback = build_fallback_vql(custom_vql)
                    if fallback:
                        print(f"[VR] {t_code}: surgical_yaml 0 rows — running fallback", flush=True)
                        fb_vql  = os.path.join(output_root, f"fallback_{t_code}.vql")
                        fb_out  = os.path.join(output_root, f"orca_fallback_{t_code}.jsonl")
                        with open(fb_vql, 'w', encoding='utf-8') as f:
                            f.write(fallback)
                        fb = subprocess.run(
                            [vr_exe, "query", "-f", fb_vql, "--format", "jsonl", "--output", fb_out],
                            capture_output=True, creationflags=creationflags
                        )
                        if fb.returncode == 0 and count_jsonl_rows(fb_out) > 0:
                            normalize(fb_out, is_fallback=True)
                        else:
                            write_no_artifacts()
                    else:
                        write_no_artifacts()
                else:
                    write_no_artifacts()

        elif custom_vql.strip():
            converted_vql = convert_source_to_parse_evtx(custom_vql.replace(':tsource', clean_tsource))
            vql_file = os.path.join(output_root, f"query_{t_code}.vql")
            with open(vql_file, 'w', encoding='utf-8') as f:
                f.write(converted_vql)
            proc = subprocess.run(
                [vr_exe, "query", "-f", vql_file, "--format", "jsonl", "--output", output_json],
                capture_output=True, creationflags=creationflags
            )
            if proc.returncode != 0:
                stderr = proc.stderr.decode('utf-8', errors='replace')
                print(f"[VR] {t_code}: exit {proc.returncode} — {stderr[:200]}", flush=True)
                return
            rows = count_jsonl_rows(output_json)
            if rows > 0:
                normalize(output_json)
            else:
                fallback = build_fallback_vql(custom_vql)
                if fallback:
                    print(f"[VR] {t_code}: primary 0 rows — running fallback", flush=True)
                    fb_vql  = os.path.join(output_root, f"fallback_{t_code}.vql")
                    fb_out  = os.path.join(output_root, f"orca_fallback_{t_code}.jsonl")
                    with open(fb_vql, 'w', encoding='utf-8') as f:
                        f.write(fallback)
                    fb = subprocess.run(
                        [vr_exe, "query", "-f", fb_vql, "--format", "jsonl", "--output", fb_out],
                        capture_output=True, creationflags=creationflags
                    )
                    if fb.returncode == 0 and count_jsonl_rows(fb_out) > 0:
                        normalize(fb_out, is_fallback=True)
                    else:
                        write_no_artifacts()
                else:
                    write_no_artifacts()

        else:
            vql_file = os.path.join(output_root, f"query_{t_code}.vql")
            with open(vql_file, 'w', encoding='utf-8') as f:
                f.write(f"SELECT *, '{t_code}' AS TCode FROM glob(globs='{clean_tsource}/**/{t_code}*')")
            proc = subprocess.run(
                [vr_exe, "query", "-f", vql_file, "--format", "jsonl", "--output", output_json],
                capture_output=True, creationflags=creationflags
            )
            if proc.returncode != 0:
                return
            if count_jsonl_rows(output_json) > 0:
                normalize(output_json)

    except Exception as e:
        print(f"[VR] {t_code}: FAILED — {e}", flush=True)


if __name__ == '__main__':
    job = json.loads(sys.stdin.read())
    run(job)