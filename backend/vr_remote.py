"""
vr_remote.py — Velociraptor remote deployment and collection for ORCA.
"""

import os
import io
import re
import json
import time
import uuid
import asyncio
import logging
import tempfile
import posixpath
import shutil
from datetime import datetime
from pathlib import Path
from typing import AsyncGenerator

import evidence_normalizer
from config import cfg

logger = logging.getLogger(__name__)

REMOTE_TEMP       = r"C:\Windows\Temp\orca_vr"
REMOTE_TEMP_POSIX = "/tmp/orca_vr"  # nosec B108 — path on the REMOTE investigation target, not the local server


def _sse(type_: str, data) -> str:
    return f"data: {json.dumps({'type': type_, 'data': data})}\n\n"

def _log(msg: str) -> str:   return _sse("log", msg)
def _error(msg: str) -> str: return _sse("error", msg)
def _done(msg: str = "REMOTE_COLLECTION_COMPLETE") -> str: return _sse("done", msg)

def _tech(t_code, status, rows=None, fallback=False, message=None):
    return _sse("technique_status", {"t_code": t_code, "status": status,
                                      "rows": rows, "fallback": fallback, "message": message})


_EVENTID_FILTER = re.compile(
    r'System\.EventID\.Value\s*(?:=|IN)\s*(?:\([\w,\s]+\)|\w+)', re.IGNORECASE | re.DOTALL)
_WHERE_CLAUSE = re.compile(r'\bWHERE\b.+', re.IGNORECASE | re.DOTALL)
_CHANNEL_TO_PATH = {
    'security': 'C:/Windows/System32/winevt/Logs/Security.evtx',
    'system': 'C:/Windows/System32/winevt/Logs/System.evtx',
    'application': 'C:/Windows/System32/winevt/Logs/Application.evtx',
    'microsoft-windows-sysmon/operational': 'C:/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx',
    'microsoft-windows-powershell/operational': 'C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx',
    'microsoft-windows-taskscheduler/operational': 'C:/Windows/System32/winevt/Logs/Microsoft-Windows-TaskScheduler%4Operational.evtx',
    'microsoft-windows-winrm/operational': 'C:/Windows/System32/winevt/Logs/Microsoft-Windows-WinRM%4Operational.evtx',
    'microsoft-windows-wmi-activity/operational': 'C:/Windows/System32/winevt/Logs/Microsoft-Windows-WMI-Activity%4Operational.evtx',
}

def build_fallback_vql(custom_vql):
    if not custom_vql: return None
    eid_match = _EVENTID_FILTER.search(custom_vql)
    if not eid_match: return None
    eid_filter = eid_match.group(0).strip()
    channel_match = re.search(r"channel\s*=\s*['\"]([^'\"]+)['\"]", custom_vql, re.IGNORECASE)
    channel = channel_match.group(1).lower() if channel_match else None
    evtx_path = _CHANNEL_TO_PATH.get(channel) if channel else None
    if evtx_path:
        select_cols = re.search(r'SELECT\s+(.+?)\s+FROM', custom_vql, re.IGNORECASE | re.DOTALL)
        cols = select_cols.group(1).strip() if select_cols else '*'
        return f"SELECT {cols}\nFROM parse_evtx(filename='{evtx_path}')\nWHERE {eid_filter}"  # nosec B608 — VQL for Velociraptor, not PostgreSQL; evtx_path from hardcoded map
    select_from = _WHERE_CLAUSE.sub('', custom_vql).strip()
    select_from = re.sub(r'\s+ORDER\s+BY\s+.*$', '', select_from, flags=re.IGNORECASE).strip()
    return f"{select_from}\nWHERE {eid_filter}"  # nosec B608 — VQL passthrough; eid_filter extracted from stored VQL, not raw user input


def build_collection_files(target_list, tsource, output_dir, remap_mounted=None, remap_original=None):
    from core.database_manager import db
    from sqlalchemy import text
    files = []
    clean_tsource = tsource.replace("\\", "/").rstrip("/")
    for item in target_list:
        t_code = item["t_code"]
        with db.engine.connect() as conn:
            lib = conn.execute(text(
                "SELECT custom_vql, surgical_yaml FROM ref_artifact_library WHERE t_code = :t"
            ), {"t": t_code}).fetchone()
        local_vql  = os.path.join(output_dir, f"query_{t_code}.vql")
        remote_vql = posixpath.join(REMOTE_TEMP, f"query_{t_code}.vql").replace("/", "\\")
        remote_out = posixpath.join(REMOTE_TEMP, f"orca_{t_code}.jsonl").replace("/", "\\")
        if lib and lib.surgical_yaml and lib.surgical_yaml.strip():
            content = lib.surgical_yaml.strip()
            fallback_content = None
        elif lib and lib.custom_vql and lib.custom_vql.strip():
            content = lib.custom_vql.replace(":tsource", clean_tsource)
            fallback_content = build_fallback_vql(lib.custom_vql)
        else:
            content = f"SELECT *, '{t_code}' AS TCode FROM glob(globs='{clean_tsource}/**/{item.get('orca_name', t_code)}*')"  # nosec B608 — VQL for Velociraptor; all values from DB MITRE data or analyst-configured tsource
            fallback_content = None
        if remap_mounted and remap_original:
            content = content.replace(f"{remap_original}:", f"{remap_mounted}:")
            content = content.replace(f"{remap_original.lower()}:", f"{remap_mounted.lower()}:")
            if fallback_content:
                fallback_content = fallback_content.replace(f"{remap_original}:", f"{remap_mounted}:")
                fallback_content = fallback_content.replace(f"{remap_original.lower()}:", f"{remap_mounted.lower()}:")
        with open(local_vql, "w", encoding="utf-8") as f:
            f.write(content)
        local_fallback = remote_fallback = remote_fallback_out = None
        if fallback_content:
            local_fallback      = os.path.join(output_dir, f"fallback_{t_code}.vql")
            remote_fallback     = posixpath.join(REMOTE_TEMP, f"fallback_{t_code}.vql").replace("/", "\\")
            remote_fallback_out = posixpath.join(REMOTE_TEMP, f"orca_fallback_{t_code}.jsonl").replace("/", "\\")
            with open(local_fallback, "w", encoding="utf-8") as f:
                f.write(fallback_content)
        files.append({"t_code": t_code, "orca_name": item.get("orca_name", t_code),
                       "local_vql": local_vql, "remote_vql": remote_vql, "remote_out": remote_out,
                       "local_fallback": local_fallback, "remote_fallback": remote_fallback,
                       "remote_fallback_out": remote_fallback_out})
    return files


def _count_jsonl_rows(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return sum(1 for line in f if line.strip())
    except Exception:
        return 0


async def _collect_ssh(ip, username, password, vr_exe, target_files, local_output_dir, asset_id, cleanup, queue):
    import paramiko
    async def q(msg): await queue.put(msg)
    # ssh/sftp are closed in `finally` below, not just at the end of the
    # happy path -- an exception anywhere in the per-technique loop that
    # isn't already caught by that item's own try/except used to skip
    # straight to `except Exception` and leave the connection open. This
    # runs against real investigation targets and can fail in a lot of
    # ordinary ways (auth hiccup, target reboot mid-collection), so that
    # leak was reachable in normal use, not just a theoretical edge case.
    ssh = None
    sftp = None
    try:
        await q(_log(f"SSH: connecting to {ip}..."))
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # nosec B507 — DFIR context: connecting to investigation targets whose keys aren't pre-registered
        await asyncio.get_event_loop().run_in_executor(None, lambda: ssh.connect(ip, username=username, password=password, timeout=15))
        sftp = await asyncio.get_event_loop().run_in_executor(None, ssh.open_sftp)
        await q(_log("SSH: connected"))
        ssh.exec_command(f"mkdir -p {REMOTE_TEMP_POSIX}")  # nosec B601 — REMOTE_TEMP_POSIX is a module constant; no user input
        await asyncio.sleep(0.5)
        remote_vr = f"{REMOTE_TEMP_POSIX}/velociraptor"
        await q(_log("SSH: pushing velociraptor binary..."))
        await asyncio.get_event_loop().run_in_executor(None, lambda: sftp.put(vr_exe, remote_vr))
        ssh.exec_command(f"chmod +x {remote_vr}")  # nosec B601 — path built from module constant only
        for item in target_files: await q(_tech(item["t_code"], "QUEUED"))
        results = []
        for item in target_files:
            t_code = item["t_code"]
            remote_vql = f"{REMOTE_TEMP_POSIX}/query_{t_code}.vql"
            remote_out = f"{REMOTE_TEMP_POSIX}/orca_{t_code}.jsonl"
            await asyncio.get_event_loop().run_in_executor(None, lambda: sftp.put(item["local_vql"], remote_vql))
            await q(_tech(t_code, "RUNNING"))
            _, stdout, _ = ssh.exec_command(f'{remote_vr} query -f "{remote_vql}" --format jsonl --output "{remote_out}"')  # nosec B601 — all path components derived from REMOTE_TEMP_POSIX constant
            await asyncio.get_event_loop().run_in_executor(None, stdout.channel.recv_exit_status)
            local_out = os.path.join(local_output_dir, f"orca_{t_code}.jsonl")
            try:
                await asyncio.get_event_loop().run_in_executor(None, lambda: sftp.get(remote_out, local_out))
                row_count = _count_jsonl_rows(local_out)
                if row_count > 0:
                    await q(_tech(t_code, "COMPLETE", rows=row_count)); results.append((t_code, item["orca_name"], local_out, False))
                elif item.get("local_fallback"):
                    await q(_tech(t_code, "FALLBACK_RUNNING", rows=0))
                    remote_fb = f"{REMOTE_TEMP_POSIX}/fallback_{t_code}.vql"
                    remote_fb_out = f"{REMOTE_TEMP_POSIX}/orca_fallback_{t_code}.jsonl"
                    await asyncio.get_event_loop().run_in_executor(None, lambda: sftp.put(item["local_fallback"], remote_fb))
                    _, stdout_fb, _ = ssh.exec_command(f'{remote_vr} query -f "{remote_fb}" --format jsonl --output "{remote_fb_out}"')
                    await asyncio.get_event_loop().run_in_executor(None, stdout_fb.channel.recv_exit_status)
                    local_fb_out = os.path.join(local_output_dir, f"orca_fallback_{t_code}.jsonl")
                    try:
                        await asyncio.get_event_loop().run_in_executor(None, lambda: sftp.get(remote_fb_out, local_fb_out))
                        fb_rows = _count_jsonl_rows(local_fb_out)
                        await q(_tech(t_code, "FALLBACK_COMPLETE", rows=fb_rows, fallback=True))
                        if fb_rows > 0: results.append((t_code, item["orca_name"], local_fb_out, True))
                        else: await q(_tech(t_code, "ZERO", rows=0))
                    except: await q(_tech(t_code, "ZERO", rows=0))
                else: await q(_tech(t_code, "ZERO", rows=0))
            except: await q(_tech(t_code, "ZERO", rows=0))
        for t_code, orca_name, local_out, is_fallback in results:
            if os.path.exists(local_out) and os.path.getsize(local_out) > 0:
                await asyncio.get_event_loop().run_in_executor(None, lambda: evidence_normalizer.normalize_and_ingest(local_out, asset_id, t_code, orca_name))
        if cleanup: ssh.exec_command(f"rm -rf {REMOTE_TEMP_POSIX}")
        await q(_done())
    except Exception as e:
        logger.error("SSH collection failed for %s: %s", ip, e)
        await q(_error("SSH_ERROR: connection or collection failed — see server logs")); await q(_done("REMOTE_COLLECTION_FAILED"))
    finally:
        if sftp is not None:
            try: sftp.close()
            except Exception: pass
        if ssh is not None:
            try: ssh.close()
            except Exception: pass


async def _collect_winrm(ip, username, password, domain, vr_exe, target_files, local_output_dir, asset_id, cleanup, queue):
    import winrm, base64
    async def q(msg): await queue.put(msg)
    async def push_file(session, local_path, remote_path):
        with open(local_path, "rb") as f: data = f.read()
        chunks = [data[i:i+8192] for i in range(0, len(data), 8192)]
        b64 = base64.b64encode(chunks[0]).decode()
        await asyncio.get_event_loop().run_in_executor(None, lambda: session.run_ps(f'[IO.File]::WriteAllBytes("{remote_path}", [Convert]::FromBase64String("{b64}"))'))
        for chunk in chunks[1:]:
            b64 = base64.b64encode(chunk).decode()
            await asyncio.get_event_loop().run_in_executor(None, lambda: session.run_ps(f'$f=[IO.File]::Open("{remote_path}",[IO.FileMode]::Append);$f.Write([Convert]::FromBase64String("{b64}"),0,{len(chunk)});$f.Close()'))
    async def pull_file(session, remote_path, local_path):
        r = await asyncio.get_event_loop().run_in_executor(None, lambda: session.run_ps(f'[Convert]::ToBase64String([IO.File]::ReadAllBytes("{remote_path}"))'))
        if r.status_code == 0 and r.std_out:
            with open(local_path, "wb") as f: f.write(base64.b64decode(r.std_out.strip()))
            return True
        return False
    try:
        await q(_log(f"WINRM: connecting to {ip}..."))
        auth_user = f"{domain}\\{username}" if domain else username
        session = await asyncio.get_event_loop().run_in_executor(None, lambda: winrm.Session(f"http://{ip}:5985/wsman", auth=(auth_user, password), transport="ntlm"))
        await asyncio.get_event_loop().run_in_executor(None, lambda: session.run_cmd(f'cmd /c mkdir "{REMOTE_TEMP}" 2>nul'))
        await q(_log("WINRM: connected"))
        remote_vr = f"{REMOTE_TEMP}\\velociraptor.exe"
        await push_file(session, vr_exe, remote_vr)
        for item in target_files: await q(_tech(item["t_code"], "QUEUED"))
        results = []
        for item in target_files:
            t_code = item["t_code"]
            remote_vql = f"{REMOTE_TEMP}\\query_{t_code}.vql"
            remote_out = f"{REMOTE_TEMP}\\orca_{t_code}.jsonl"
            await push_file(session, item["local_vql"], remote_vql)
            await q(_tech(t_code, "RUNNING"))
            await asyncio.get_event_loop().run_in_executor(None, lambda: session.run_cmd(f'"{remote_vr}" query -f "{remote_vql}" --format jsonl --output "{remote_out}"'))
            local_out = os.path.join(local_output_dir, f"orca_{t_code}.jsonl")
            pulled = await pull_file(session, remote_out, local_out)
            if pulled:
                row_count = _count_jsonl_rows(local_out)
                if row_count > 0:
                    await q(_tech(t_code, "COMPLETE", rows=row_count)); results.append((t_code, item["orca_name"], local_out, False))
                elif item.get("local_fallback"):
                    await q(_tech(t_code, "FALLBACK_RUNNING", rows=0))
                    remote_fb = f"{REMOTE_TEMP}\\fallback_{t_code}.vql"
                    remote_fb_out = f"{REMOTE_TEMP}\\orca_fallback_{t_code}.jsonl"
                    await push_file(session, item["local_fallback"], remote_fb)
                    await asyncio.get_event_loop().run_in_executor(None, lambda: session.run_cmd(f'"{remote_vr}" query -f "{remote_fb}" --format jsonl --output "{remote_fb_out}"'))
                    local_fb_out = os.path.join(local_output_dir, f"orca_fallback_{t_code}.jsonl")
                    fb_pulled = await pull_file(session, remote_fb_out, local_fb_out)
                    if fb_pulled:
                        fb_rows = _count_jsonl_rows(local_fb_out)
                        await q(_tech(t_code, "FALLBACK_COMPLETE", rows=fb_rows, fallback=True))
                        if fb_rows > 0: results.append((t_code, item["orca_name"], local_fb_out, True))
                        else: await q(_tech(t_code, "ZERO", rows=0))
                    else: await q(_tech(t_code, "ZERO", rows=0))
                else: await q(_tech(t_code, "ZERO", rows=0))
            else: await q(_tech(t_code, "ZERO", rows=0))
        for t_code, orca_name, local_out, is_fallback in results:
            if os.path.exists(local_out) and os.path.getsize(local_out) > 0:
                await asyncio.get_event_loop().run_in_executor(None, lambda: evidence_normalizer.normalize_and_ingest(local_out, asset_id, t_code, orca_name))
        if cleanup:
            await asyncio.get_event_loop().run_in_executor(None, lambda: session.run_cmd(f'cmd /c rmdir /s /q "{REMOTE_TEMP}"'))
        await q(_done())
    except Exception as e:
        logger.error("WinRM collection failed for %s: %s", ip, e)
        await q(_error("WINRM_ERROR: connection or collection failed — see server logs")); await q(_done("REMOTE_COLLECTION_FAILED"))


# NOTE: SMB+PsExec collection was removed -- psexec.exe is a Windows PE and
# cannot execute from this Linux container (see module docstring history /
# COLLECTION_AUDIT.md). SSH, WinRM, and SMB+Task Scheduler below remain the
# supported transports.


async def _collect_smb_task(ip, username, password, domain, vr_exe, target_files, local_output_dir, asset_id, cleanup, queue):
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import tsch, transport as dce_transport
    async def q(msg): await queue.put(msg)
    share = "ADMIN$"; remote_dir = "Temp\\orca_vr"
    # smb/dce are closed in `finally` below -- see the matching comment in
    # _collect_ssh above; same leak, same fix.
    smb = None
    dce = None
    async def smb_put(smb, local_path, remote_name):
        with open(local_path, "rb") as f: data = f.read()
        await asyncio.get_event_loop().run_in_executor(None, lambda: smb.putFile(share, f"{remote_dir}\\{remote_name}", io.BytesIO(data).read))
    async def smb_get(smb, remote_name, local_path):
        buf = io.BytesIO()
        await asyncio.get_event_loop().run_in_executor(None, lambda: smb.getFile(share, f"{remote_dir}\\{remote_name}", buf.write))
        with open(local_path, "wb") as f: f.write(buf.getvalue())
    async def run_task(dce, task_name, cmd):
        xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Triggers/>
  <Actions context="Author"><Exec><Command>cmd.exe</Command><Arguments>/c {cmd}</Arguments></Exec></Actions>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT1H</ExecutionTimeLimit><Priority>7</Priority></Settings>
</Task>"""
        await asyncio.get_event_loop().run_in_executor(None, lambda: tsch.hSchRpcRegisterTask(dce, task_name, xml, (tsch.TASK_CREATE | tsch.TASK_UPDATE), tsch.NULL, tsch.TASK_LOGON_SERVICE_ACCOUNT))
        await asyncio.get_event_loop().run_in_executor(None, lambda: tsch.hSchRpcRun(dce, task_name))
        for _ in range(60):
            await asyncio.sleep(1)
            try:
                info = await asyncio.get_event_loop().run_in_executor(None, lambda: tsch.hSchRpcGetLastRunInfo(dce, task_name))
                if info["pLastRunInfo"]["hrLastRunResult"] != 0x00041301: break
            except: break
        await asyncio.get_event_loop().run_in_executor(None, lambda: tsch.hSchRpcDelete(dce, task_name))
    try:
        await q(_log(f"SMB_TASK: connecting to {ip}..."))
        smb = await asyncio.get_event_loop().run_in_executor(None, lambda: SMBConnection(ip, ip))
        await asyncio.get_event_loop().run_in_executor(None, lambda: smb.login(username, password, domain or ""))
        try: await asyncio.get_event_loop().run_in_executor(None, lambda: smb.createDirectory(share, remote_dir))
        except: pass
        await smb_put(smb, vr_exe, "velociraptor.exe")
        from impacket.dcerpc.v5 import rpcrt
        string_binding = f"ncacn_np:{ip}[\\pipe\\atsvc]"
        rpctransport = dce_transport.DCERPCTransportFactory(string_binding)
        rpctransport.set_credentials(username, password, domain or "", "", "", None)
        dce = await asyncio.get_event_loop().run_in_executor(None, lambda: rpctransport.get_dce_rpc())
        dce.set_credentials(*rpctransport.get_credentials())
        dce.set_auth_type(rpcrt.RPC_C_AUTHN_WINNT)
        dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        await asyncio.get_event_loop().run_in_executor(None, dce.connect)
        await asyncio.get_event_loop().run_in_executor(None, lambda: dce.bind(tsch.MSRPC_UUID_TSCHS))
        for item in target_files: await q(_tech(item["t_code"], "QUEUED"))
        results = []
        for item in target_files:
            t_code = item["t_code"]
            task_name = f"\\orca_vr_{t_code.replace('.', '_')}"
            vql_name = f"query_{t_code}.vql"; out_name = f"orca_{t_code}.jsonl"
            remote_vr_path  = f"C:\\Windows\\{remote_dir}\\velociraptor.exe"
            remote_vql_path = f"C:\\Windows\\{remote_dir}\\{vql_name}"
            remote_out_path = f"C:\\Windows\\{remote_dir}\\{out_name}"
            await smb_put(smb, item["local_vql"], vql_name)
            await q(_tech(t_code, "RUNNING"))
            await run_task(dce, task_name, f'"{remote_vr_path}" query -f "{remote_vql_path}" --format jsonl --output "{remote_out_path}"')
            local_out = os.path.join(local_output_dir, f"orca_{t_code}.jsonl")
            try:
                await smb_get(smb, out_name, local_out)
                row_count = _count_jsonl_rows(local_out)
                if row_count > 0:
                    await q(_tech(t_code, "COMPLETE", rows=row_count)); results.append((t_code, item["orca_name"], local_out, False))
                elif item.get("local_fallback"):
                    await q(_tech(t_code, "FALLBACK_RUNNING", rows=0))
                    fb_task = f"\\orca_fb_{t_code.replace('.', '_')}"
                    fb_vql_name = f"fallback_{t_code}.vql"; fb_out_name = f"orca_fallback_{t_code}.jsonl"
                    remote_fb_path     = f"C:\\Windows\\{remote_dir}\\{fb_vql_name}"
                    remote_fb_out_path = f"C:\\Windows\\{remote_dir}\\{fb_out_name}"
                    await smb_put(smb, item["local_fallback"], fb_vql_name)
                    await run_task(dce, fb_task, f'"{remote_vr_path}" query -f "{remote_fb_path}" --format jsonl --output "{remote_fb_out_path}"')
                    local_fb_out = os.path.join(local_output_dir, f"orca_fallback_{t_code}.jsonl")
                    try:
                        await smb_get(smb, fb_out_name, local_fb_out)
                        fb_rows = _count_jsonl_rows(local_fb_out)
                        await q(_tech(t_code, "FALLBACK_COMPLETE", rows=fb_rows, fallback=True))
                        if fb_rows > 0: results.append((t_code, item["orca_name"], local_fb_out, True))
                        else: await q(_tech(t_code, "ZERO", rows=0))
                    except: await q(_tech(t_code, "ZERO", rows=0))
                else: await q(_tech(t_code, "ZERO", rows=0))
            except: await q(_tech(t_code, "ERROR", message="Failed to pull result file"))
        for t_code, orca_name, local_out, is_fallback in results:
            if os.path.exists(local_out) and os.path.getsize(local_out) > 0:
                await asyncio.get_event_loop().run_in_executor(None, lambda: evidence_normalizer.normalize_and_ingest(local_out, asset_id, t_code, orca_name))
        if cleanup: smb.deleteDirectory(share, remote_dir)
        await q(_done())
    except Exception as e:
        logger.error("SMB/Task Scheduler collection failed for %s: %s", ip, e)
        await q(_error("SMB_TASK_ERROR: connection or collection failed — see server logs")); await q(_done("REMOTE_COLLECTION_FAILED"))
    finally:
        if dce is not None:
            try: dce.disconnect()
            except Exception: pass
        if smb is not None:
            try: smb.logoff()
            except Exception: pass


def _scmr_run_bat(ip, username, password, domain, bat_name):
    """
    Run an already-staged `C:\\Windows\\Temp\\{bat_name}` via a throwaway
    Windows service (svcctl/SCM RPC) -- the trigger mechanism shared by both
    _run_remote_command_smb_task (stages the bat itself) and
    _run_remote_command_smb_push (stages a bat alongside a pushed package).
    Runs synchronously; call via run_in_executor. See
    _run_remote_command_smb_task's docstring for why hSchRpcRun-vs-svcctl
    naming aside, this returns almost immediately regardless of how long the
    triggered command actually runs.
    """
    from impacket.dcerpc.v5 import scmr, transport as dce_transport

    svc_name = f"orca{uuid.uuid4().hex[:8]}"
    rpctransport = dce_transport.DCERPCTransportFactory(f"ncacn_np:{ip}[\\pipe\\svcctl]")
    rpctransport.set_credentials(username, password, domain or "", "", "", None)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(scmr.MSRPC_UUID_SCMR)
    sc = scmr.hROpenSCManagerW(dce)['lpScHandle']
    bin_path = f'C:\\Windows\\System32\\cmd.exe /c "C:\\Windows\\Temp\\{bat_name}"'
    svc = scmr.hRCreateServiceW(
        dce, sc, svc_name, svc_name,
        lpBinaryPathName=bin_path,
        dwStartType=scmr.SERVICE_DEMAND_START,
        dwErrorControl=scmr.SERVICE_ERROR_IGNORE,
    )['lpServiceHandle']
    try:
        try:
            scmr.hRStartServiceW(dce, svc)
        except Exception:
            pass  # timeout expected — cmd.exe doesn't call SetServiceStatus
    finally:
        try:
            scmr.hRDeleteService(dce, svc)
        except Exception:
            pass
        scmr.hRCloseServiceHandle(dce, svc)
        scmr.hRCloseServiceHandle(dce, sc)
        dce.disconnect()


async def _run_remote_command_smb_task(ip, username, password, domain, command, timeout=60):
    """
    Trigger a Windows command line on a remote host via SMB + Task Scheduler
    RPC (impacket), fire-and-forget.

    Needs only port 445 (SMB) + local-admin credentials on the target — the
    same prerequisites the original psexec trigger had, and unlike WinRM, no
    target-side service (WinRM/5985) needs to be enabled.

    A throwaway scheduled task is registered whose action is `cmd.exe /c
    <command>`, then run via hSchRpcRun. hSchRpcRun only dispatches the task
    to the Task Scheduler service and returns — it does not wait for the
    task's process to exit — so this call returns almost immediately even
    though `command` (e.g. package_builder.py's bootstrap oneliner) runs the
    entire collection chain synchronously once started on the target. The
    task registration is then deleted as best-effort cleanup; this does not
    affect the already-launched process, since Task Scheduler deletion only
    removes the task's metadata, not any process it already started.
    """
    from impacket.smbconnection import SMBConnection
    import io as _io

    bat_name = f"orca_{uuid.uuid4().hex[:8]}.bat"
    # Write the oneliner into a BAT file so quote escaping in lpBinaryPathName
    # is avoided entirely.  start /b detaches PowerShell from cmd.exe so
    # cmd.exe exits immediately — the service "stops" from SCM's point of view
    # but the PowerShell collection process keeps running independently.
    bat_content = f"@echo off\r\nstart \"\" /b {command}\r\ndel \"%~f0\"\r\n".encode("utf-8")
    bat_remote = f"Temp\\{bat_name}"

    def _trigger():
        smb = SMBConnection(ip, ip)
        smb.login(username, password, domain or "")
        smb.putFile("ADMIN$", bat_remote, _io.BytesIO(bat_content).read)
        smb.logoff()
        _scmr_run_bat(ip, username, password, domain, bat_name)

    loop = asyncio.get_event_loop()
    try:
        await asyncio.wait_for(loop.run_in_executor(None, _trigger), timeout=timeout)
        return 0, "", ""
    except asyncio.TimeoutError:
        return -1, "", f"SMB_TASK_TIMEOUT: no response within {timeout}s"
    except Exception as e:
        return -1, "", f"SMB_TASK_ERROR: {e}"


def _smb_stage_package(ip, username, password, domain, local_zip_path, remote_dir):
    """
    Pushes the cert, package ZIP, and local launcher script to the target
    over SMB; returns the absolute Windows path they landed at. Shared by
    both push-delivery trigger mechanisms below (SMB_TASK's SCM RPC trigger
    and WinRM's direct invocation) -- staging itself is identical either
    way, only how the pushed launcher gets *run* differs.

    Synchronous/blocking -- callers run this via run_in_executor. Raises on
    any failure (SMB errors propagate directly), so "did the package
    actually get there" is a real, immediate answer, not something inferred
    from a timeout the way the launch step still has to be.

    `remote_dir`: same meaning as elsewhere (validated absolute Windows path,
    e.g. C:\\ORCA_Staging) — defaults to C:\\Windows\\Temp when not given,
    matching the SMB ADMIN$ share's target.
    """
    from impacket.smbconnection import SMBConnection
    import io as _io
    from package_builder import generate_smb_push_launcher_ps1

    # share + base_rel are SMB-relative (what putFile/createDirectory take);
    # stage_abs_base is the real Windows path they map to, which the pushed
    # launcher script needs since it runs locally on the target, not over
    # SMB. These aren't the same arithmetic for both cases: a custom
    # remote_dir's share (e.g. C$) maps to the drive root, but the default
    # ADMIN$ share maps to C:\Windows specifically, not C:\ -- so the
    # absolute path needs deriving per-case, not by formula from share alone.
    if remote_dir:
        drive, _, rest = remote_dir.partition(":\\")
        drive = drive.upper() or "C"
        share = f"{drive}$"
        base_rel = rest
        stage_abs_base = f"{drive}:\\{rest}" if rest else f"{drive}:\\"
    else:
        share, base_rel = "ADMIN$", "Temp"
        stage_abs_base = "C:\\Windows\\Temp"

    stage_name = f"orca_{uuid.uuid4().hex[:8]}"
    stage_rel = f"{base_rel}\\{stage_name}" if base_rel else stage_name
    stage_abs = f"{stage_abs_base}\\{stage_name}"

    launcher_content = generate_smb_push_launcher_ps1(stage_abs).encode("utf-8")
    zip_bytes = Path(local_zip_path).read_bytes()
    cert_bytes = None
    if cfg.SSL_CERTFILE and os.path.exists(cfg.SSL_CERTFILE):
        cert_bytes = Path(cfg.SSL_CERTFILE).read_bytes()

    smb = SMBConnection(ip, ip)
    smb.login(username, password, domain or "")
    smb.createDirectory(share, stage_rel)
    smb.putFile(share, f"{stage_rel}\\orca_pkg.zip", _io.BytesIO(zip_bytes).read)
    if cert_bytes:
        smb.putFile(share, f"{stage_rel}\\orca_cert.cer", _io.BytesIO(cert_bytes).read)
    smb.putFile(share, f"{stage_rel}\\orca_launch.ps1", _io.BytesIO(launcher_content).read)
    smb.logoff()

    return stage_abs


async def _run_remote_command_smb_push(ip, username, password, domain, local_zip_path, remote_dir=None, timeout=300):
    """
    Deliver an ORCA collection package over SMB (see _smb_stage_package),
    then trigger it via the same throwaway-service SCM RPC as
    _run_remote_command_smb_task -- instead of the old flow where the
    target reached back out over HTTPS to download the bootstrap script and
    then the package.

    This removes the two most heavily-signatured indicators in that old
    flow: the "fetch and execute" download-cradle shape (nothing is ever
    IEX'd or DownloadFile'd — the package is just... already there), and the
    dynamically-compiled ICertificatePolicy cert-validation bypass (the cert
    is trusted properly via Import-Certificate before the collection script
    ever runs, so it doesn't need its own bypass — see package_builder.py's
    cert_trusted parameter). The trigger mechanism itself is unchanged here
    (see _run_remote_command_winrm_push below for the WinRM-triggered
    variant, which also drops the SCM registration).
    """
    def _push_and_trigger():
        stage_abs = _smb_stage_package(ip, username, password, domain, local_zip_path, remote_dir)

        from impacket.smbconnection import SMBConnection
        import io as _io
        bat_name = f"orca_{uuid.uuid4().hex[:8]}.bat"
        trigger_command = f'powershell -ExecutionPolicy Bypass -File "{stage_abs}\\orca_launch.ps1"'
        bat_content = f"@echo off\r\nstart \"\" /b {trigger_command}\r\ndel \"%~f0\"\r\n".encode("utf-8")
        bat_remote = f"Temp\\{bat_name}"

        smb = SMBConnection(ip, ip)
        smb.login(username, password, domain or "")
        smb.putFile("ADMIN$", bat_remote, _io.BytesIO(bat_content).read)
        smb.logoff()
        _scmr_run_bat(ip, username, password, domain, bat_name)

    loop = asyncio.get_event_loop()
    try:
        await asyncio.wait_for(loop.run_in_executor(None, _push_and_trigger), timeout=timeout)
        return 0, "", ""
    except asyncio.TimeoutError:
        return -1, "", f"SMB_PUSH_TIMEOUT: no response within {timeout}s"
    except Exception as e:
        return -1, "", f"SMB_PUSH_ERROR: {e}"


def _interpret_winrm_launch_result(raw_out, raw_err, status_code, early_wait):
    """
    Shared interpretation of the ORCA_STILL_RUNNING / ORCA_EXIT_CODE /
    ORCA_STDOUT_B64 / ORCA_STDERR_B64 markers both WinRM launch scripts
    below emit (_run_remote_command_winrm's and
    _run_remote_command_winrm_push's). Returns (returncode, stdout, stderr).
    """
    import base64 as _b64
    still_running, exit_code, launch_stdout, launch_stderr = None, None, "", ""
    for line in raw_out.splitlines():
        if line.startswith("ORCA_STILL_RUNNING|"):
            still_running = line.split("|", 1)[1].strip().lower() == "true"
        elif line.startswith("ORCA_EXIT_CODE|"):
            exit_code = line.split("|", 1)[1].strip()
        elif line.startswith("ORCA_STDOUT_B64|"):
            try:
                launch_stdout = _b64.b64decode(line.split("|", 1)[1].strip()).decode(errors="replace")
            except Exception:
                pass
        elif line.startswith("ORCA_STDERR_B64|"):
            try:
                launch_stderr = _b64.b64decode(line.split("|", 1)[1].strip()).decode(errors="replace")
            except Exception:
                pass

    if still_running is None:
        # Marker lines never arrived -- the launcher script itself didn't
        # run to completion (e.g. died before Start-Sleep returned), so
        # fall back to whatever raw WinRM gave us rather than claiming a
        # launch status we don't actually have.
        return status_code, raw_out, raw_err

    if still_running:
        note = (
            f"Still running {early_wait}s after launch (expected — collection takes longer). "
            f"Output so far: {launch_stdout[:500] or '(none yet)'}"
        )
        return 0, note, launch_stderr[:500]

    # Process already exited within early_wait -- that's the failure signal
    # itself. exit_code 0 with real stdout is a legitimately fast success
    # (rare but possible for a trivial payload); anything else is treated
    # as a failed launch so the real error text surfaces instead of a false
    # "Agent launched" success.
    if exit_code == "0":
        return 0, launch_stdout[:1000], launch_stderr[:500]
    return -1, launch_stdout[:500], (
        f"WINRM_LAUNCH_FAILED: process exited (code {exit_code}) within {early_wait}s — "
        f"{launch_stderr[:500] or launch_stdout[:500] or 'no output captured'}"
    )


async def _run_remote_command_winrm(ip, username, password, domain, command, timeout=60, early_wait=10):
    """
    Trigger a Windows command line on a remote host over WinRM.

    Requires WinRM (port 5985) enabled on the target — not always available
    (e.g. on environments not under our administrative control), which is
    why SMB + Task Scheduler (`_run_remote_command_smb_task`) is the default
    transport; this remains available as an opt-in fallback.

    `command` (e.g. package_builder.py's bootstrap oneliner) runs the entire
    collection chain synchronously once started, which can take far longer
    than any reasonable WinRM call should block for -- so it's launched via
    `Start-Process` (no `-Wait`) rather than run directly through run_ps.
    `Start-Process` alone returns the instant the child process *exists*,
    with zero visibility into whether it then actually does anything -- a
    launch that starts fine and dies two seconds later (bad quoting, a
    blocked outbound connection, a cert error) reported identical "success"
    to a launch that ran the whole collection cleanly.

    The child's stdout/stderr are redirected to temp files, and after
    `early_wait` seconds (short -- long enough to catch a process that dies
    immediately, well short of how long the actual collection runs) this
    reads back whatever's accumulated. Still fire-and-forget for the
    collection itself (still running past early_wait keeps running in the
    background) -- this just no longer lies about having verified nothing.
    Note this command still fetches the package over HTTPS (see
    _run_remote_command_winrm_push for the push-delivery alternative,
    where early_wait actually means something since there's no unbounded
    download for it to be covering).
    """
    import winrm
    loop = asyncio.get_event_loop()
    auth_user = f"{domain}\\{username}" if domain else username

    if "'@" in command:
        return -1, "", "WINRM_ERROR: command contains an unescapable here-string terminator"

    tag = uuid.uuid4().hex[:8]
    launcher = (
        f"$__cmd = @'\n{command}\n'@\n"
        f"$outFile = [IO.Path]::Combine($env:TEMP, 'orca_wr_out_{tag}.log')\n"
        f"$errFile = [IO.Path]::Combine($env:TEMP, 'orca_wr_err_{tag}.log')\n"
        "$proc = Start-Process -FilePath cmd.exe -ArgumentList @('/c', $__cmd) -WindowStyle Hidden "
        "-PassThru -RedirectStandardOutput $outFile -RedirectStandardError $errFile\n"
        # Known Start-Process -PassThru quirk: .ExitCode silently comes back
        # empty even when HasExited is true unless .Handle is touched first
        # (forces .NET to associate/cache the process handle) -- confirmed
        # by testing both ways; without this every launch looked identical
        # regardless of whether it actually succeeded.
        "$proc.Handle | Out-Null\n"
        f"Start-Sleep -Seconds {early_wait}\n"
        "$proc.Refresh()\n"
        "$stillRunning = -not $proc.HasExited\n"
        "$exitCode = -1\n"
        "if (-not $stillRunning) { try { $exitCode = $proc.ExitCode } catch { $exitCode = -999 } }\n"
        "$outText = if (Test-Path $outFile) { Get-Content $outFile -Raw -ErrorAction SilentlyContinue } else { '' }\n"
        "$errText = if (Test-Path $errFile) { Get-Content $errFile -Raw -ErrorAction SilentlyContinue } else { '' }\n"
        "if (-not $outText) { $outText = '' }\n"
        "if (-not $errText) { $errText = '' }\n"
        "Write-Output \"ORCA_STILL_RUNNING|$stillRunning\"\n"
        "Write-Output \"ORCA_EXIT_CODE|$exitCode\"\n"
        "Write-Output \"ORCA_STDOUT_B64|$([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($outText)))\"\n"
        "Write-Output \"ORCA_STDERR_B64|$([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($errText)))\""
    )

    try:
        session = await loop.run_in_executor(
            None,
            lambda: winrm.Session(
                f"http://{ip}:5985/wsman",
                auth=(auth_user, password),
                transport="ntlm",
                operation_timeout_sec=min(timeout, 1800),
                read_timeout_sec=min(timeout, 1800) + 10,
            ),
        )
        result = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: session.run_ps(launcher)),
            timeout=max(timeout, early_wait + 15),
        )
        raw_out = result.std_out.decode(errors="replace") if isinstance(result.std_out, bytes) else str(result.std_out or "")
        raw_err = result.std_err.decode(errors="replace") if isinstance(result.std_err, bytes) else str(result.std_err or "")
        return _interpret_winrm_launch_result(raw_out, raw_err, result.status_code, early_wait)
    except asyncio.TimeoutError:
        return -1, "", f"WINRM_TIMEOUT: no response within {timeout}s"
    except Exception as e:
        return -1, "", f"WINRM_ERROR: {e}"


async def _run_remote_command_winrm_push(ip, username, password, domain, local_zip_path, remote_dir=None, timeout=300, early_wait=10):
    """
    Push-delivery over SMB (see _smb_stage_package / _run_remote_command_smb_push),
    triggered via WinRM instead of the throwaway-service SCM RPC -- avoids
    both the "suspicious service registration" finding that started this
    whole rework *and* the fragile multi-hop HTTP download chain the
    download-based WinRM path above depends on, since delivery no longer
    goes over HTTP at all.

    Needs BOTH port 445 (to stage the files -- an ordinary authenticated
    file copy, not the SCM RPC mechanism that got flagged) *and* port 5985
    (to trigger execution) -- a real prerequisite change from "WinRM only
    needs 5985," worth knowing before switching a deploy over to this.

    Staging happens first and is synchronous: it either succeeds or raises,
    so "did the package actually get there" is a real answer, not a guess.
    What's left to diagnose after that -- whether the local launcher
    actually ran -- is genuinely fast (local disk only, no network), so the
    same early_wait capture-and-report approach as the plain WinRM path is
    far more meaningful here than it is covering an unbounded download.
    """
    import winrm
    loop = asyncio.get_event_loop()
    auth_user = f"{domain}\\{username}" if domain else username

    try:
        stage_abs = await loop.run_in_executor(
            None, lambda: _smb_stage_package(ip, username, password, domain, local_zip_path, remote_dir)
        )
    except Exception as e:
        return -1, "", f"SMB_PUSH_ERROR: {e}"

    launch_path = f"{stage_abs}\\orca_launch.ps1"
    tag = uuid.uuid4().hex[:8]
    # No here-string smuggling needed here (unlike the download-based path
    # above) -- there's no complex, quote-heavy command to embed anymore,
    # just a known, fixed local file path to launch.
    launcher = (
        f"$outFile = [IO.Path]::Combine($env:TEMP, 'orca_wr_out_{tag}.log')\n"
        f"$errFile = [IO.Path]::Combine($env:TEMP, 'orca_wr_err_{tag}.log')\n"
        f"$proc = Start-Process -FilePath powershell.exe -ArgumentList @('-ExecutionPolicy', 'Bypass', '-File', '{launch_path}') "
        "-WindowStyle Hidden -PassThru -RedirectStandardOutput $outFile -RedirectStandardError $errFile\n"
        "$proc.Handle | Out-Null\n"
        f"Start-Sleep -Seconds {early_wait}\n"
        "$proc.Refresh()\n"
        "$stillRunning = -not $proc.HasExited\n"
        "$exitCode = -1\n"
        "if (-not $stillRunning) { try { $exitCode = $proc.ExitCode } catch { $exitCode = -999 } }\n"
        "$outText = if (Test-Path $outFile) { Get-Content $outFile -Raw -ErrorAction SilentlyContinue } else { '' }\n"
        "$errText = if (Test-Path $errFile) { Get-Content $errFile -Raw -ErrorAction SilentlyContinue } else { '' }\n"
        "if (-not $outText) { $outText = '' }\n"
        "if (-not $errText) { $errText = '' }\n"
        "Write-Output \"ORCA_STILL_RUNNING|$stillRunning\"\n"
        "Write-Output \"ORCA_EXIT_CODE|$exitCode\"\n"
        "Write-Output \"ORCA_STDOUT_B64|$([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($outText)))\"\n"
        "Write-Output \"ORCA_STDERR_B64|$([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($errText)))\""
    )

    try:
        session = await loop.run_in_executor(
            None,
            lambda: winrm.Session(
                f"http://{ip}:5985/wsman",
                auth=(auth_user, password),
                transport="ntlm",
                operation_timeout_sec=min(timeout, 1800),
                read_timeout_sec=min(timeout, 1800) + 10,
            ),
        )
        result = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: session.run_ps(launcher)),
            timeout=max(timeout, early_wait + 15),
        )
        raw_out = result.std_out.decode(errors="replace") if isinstance(result.std_out, bytes) else str(result.std_out or "")
        raw_err = result.std_err.decode(errors="replace") if isinstance(result.std_err, bytes) else str(result.std_err or "")
        return _interpret_winrm_launch_result(raw_out, raw_err, result.status_code, early_wait)
    except asyncio.TimeoutError:
        return -1, "", f"WINRM_TIMEOUT: no response within {timeout}s (package was already staged successfully)"
    except Exception as e:
        return -1, "", f"WINRM_ERROR: {e} (package was already staged successfully)"


async def run_remote_command(ip, username, password, domain, command, timeout=60, transport="SMB_TASK"):
    """
    Trigger a Windows command line on a remote host, fire-and-forget. Dispatches
    to one of the transport-specific implementations above based on `transport`:

    - "SMB_TASK" (default): SMB + Task Scheduler RPC via impacket. Needs only
      port 445 + admin credentials — the same prerequisites the original
      psexec trigger had, no target-side service needs to be enabled.
    - "WINRM": pywinrm. Needs WinRM (port 5985) enabled on the target; kept
      as an opt-in fallback for environments where it's already available.

    Returns (returncode, stdout, stderr) in all cases.
    """
    t = (transport or "SMB_TASK").upper()
    if t == "WINRM":
        return await _run_remote_command_winrm(ip, username, password, domain, command, timeout)
    if t == "SMB_TASK":
        return await _run_remote_command_smb_task(ip, username, password, domain, command, timeout)
    return -1, "", f"UNKNOWN_TRANSPORT: {transport}"


async def push_and_trigger_package(ip, username, password, domain, local_zip_path,
                                    remote_dir=None, timeout=300, transport="SMB_TASK"):
    """
    Public entry point for push package delivery -- deploy_routes.py's
    alternative to run_remote_command() + package_builder.py's HTTP-download
    bootstrap chain, for callers that want the package delivered without the
    target ever making an outbound HTTP(S) request to fetch it.

    - "SMB_TASK": staged over SMB, triggered via the throwaway-service SCM RPC.
    - "WINRM": staged over SMB (still needs port 445 for that part — see
      _run_remote_command_winrm_push), triggered via WinRM instead — no SCM
      service registration.
    """
    t = (transport or "SMB_TASK").upper()
    if t == "WINRM":
        return await _run_remote_command_winrm_push(ip, username, password, domain, local_zip_path, remote_dir, timeout)
    if t == "SMB_TASK":
        return await _run_remote_command_smb_push(ip, username, password, domain, local_zip_path, remote_dir, timeout)
    return -1, "", f"SMB_PUSH_UNSUPPORTED_TRANSPORT: {transport}"


async def _dispatch(transport, ip, username, password, domain, vr_exe, target_files, local_output_dir, asset_id, cleanup, queue):
    t = transport.upper()
    if t == "SSH":
        await _collect_ssh(ip, username, password, vr_exe, target_files, local_output_dir, asset_id, cleanup, queue)
    elif t == "WINRM":
        await _collect_winrm(ip, username, password, domain, vr_exe, target_files, local_output_dir, asset_id, cleanup, queue)
    elif t == "SMB_TASK":
        await _collect_smb_task(ip, username, password, domain, vr_exe, target_files, local_output_dir, asset_id, cleanup, queue)
    else:
        await queue.put(_error(f"Unknown transport: {transport}")); await queue.put(_done("REMOTE_COLLECTION_FAILED"))



async def run_triage_collection(asset_id, ip, transport, username, password,
                                 domain=None, cleanup=True, vr_exe=None, data_root=None):
    from core.database_manager import db
    from sqlalchemy import text
    queue = asyncio.Queue()

    async def generate():
        try:
            with db.engine.connect() as conn:
                case_row = conn.execute(
                    text("SELECT case_name FROM assets WHERE id = :id"), {"id": asset_id}
                ).fetchone()
            if not case_row:
                yield _error(f"Asset {asset_id} not found"); yield _done("TRIAGE_FAILED"); return

            run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
            local_output_dir = os.path.join(
                data_root or "data",
                case_row.case_name.replace(" ", "_"),
                f"triage_{run_id}"
            )
            os.makedirs(local_output_dir, exist_ok=True)

            target_list = [
                {"t_code": "EVENT_LOGS_SECURITY",    "orca_name": "Event Logs - Security"},
                {"t_code": "EVENT_LOGS_APPLICATION", "orca_name": "Event Logs - Application"},
                {"t_code": "EVENT_LOGS_SYSMON",      "orca_name": "Event Logs - Sysmon"},
                {"t_code": "EVENT_LOGS_POWERSHELL",  "orca_name": "Event Logs - PowerShell"},
                {"t_code": "EVENT_LOGS_SYSTEM",      "orca_name": "Event Logs - System"},
                {"t_code": "EVENT_LOGS_TASKSCHEDULER","orca_name": "Event Logs - Task Scheduler"},
                {"t_code": "EVENT_LOGS_WMI",         "orca_name": "Event Logs - WMI Activity"},
                {"t_code": "EVENT_LOGS_WINRM",       "orca_name": "Event Logs - WinRM"},
                {"t_code": "EVENT_LOGS_OTHER",       "orca_name": "Event Logs - Other"},
                {"t_code": "PREFETCH",               "orca_name": "Prefetch"},
                {"t_code": "MFT",                    "orca_name": "MFT"},
                {"t_code": "REGISTRY_SAM",           "orca_name": "Registry - SAM"},
                {"t_code": "REGISTRY_SYSTEM",        "orca_name": "Registry - SYSTEM"},
                {"t_code": "REGISTRY_SOFTWARE",      "orca_name": "Registry - SOFTWARE"},
                {"t_code": "REGISTRY_SECURITY",      "orca_name": "Registry - SECURITY"},
                {"t_code": "REGISTRY_NTUSER",        "orca_name": "Registry - NTUSER"},
                {"t_code": "REGISTRY_USRCLASS",      "orca_name": "Registry - UsrClass"},
                {"t_code": "REGISTRY_AMCACHE",       "orca_name": "Registry - Amcache"},
                {"t_code": "REGISTRY_OTHER",         "orca_name": "Registry - Other"},
                {"t_code": "BROWSER_CHROME",         "orca_name": "Browser - Chrome"},
                {"t_code": "BROWSER_EDGE",           "orca_name": "Browser - Edge"},
                {"t_code": "BROWSER_FIREFOX",        "orca_name": "Browser - Firefox"},
                {"t_code": "LNK_JUMPLISTS",          "orca_name": "LNK / Jump Lists"},
                {"t_code": "SCHEDULED_TASKS",        "orca_name": "Scheduled Tasks"},
                {"t_code": "WMI_PERSISTENCE",        "orca_name": "WMI Persistence"},
                {"t_code": "SRUM",                   "orca_name": "SRUM"},
                {"t_code": "TRIAGE_AMCACHE",         "orca_name": "Amcache"},
                {"t_code": "RECYCLE_BIN",            "orca_name": "Recycle Bin"},
                {"t_code": "USB_ARTIFACTS",          "orca_name": "USB Artifacts"},
                {"t_code": "TRIAGE_MISC",            "orca_name": "Misc"},
            ]
            target_files = build_collection_files(target_list, "", local_output_dir)

            task = asyncio.create_task(
                _dispatch(transport, ip, username, password, domain,
                          vr_exe, target_files, local_output_dir, asset_id, cleanup, queue)
            )
            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=600.0)
                    yield msg
                    if '"type": "done"' in msg: break
                except asyncio.TimeoutError:
                    yield _error("TIMEOUT: triage exceeded 600s"); task.cancel(); break
            await task
        except Exception as e:
            logger.error("run_triage_collection failed for asset %s: %s", asset_id, e, exc_info=True)
            yield _error("TRIAGE_ERROR: collection failed — see server logs"); yield _done("TRIAGE_FAILED")

    async for chunk in generate():
        yield chunk