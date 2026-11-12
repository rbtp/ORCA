import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import zipfile

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class OrcaAgent:
    def __init__(self, config):
        self.server = config["server_url"].rstrip("/")
        self.token = config["token"]
        self.bin_dir = config["bin_dir"]
        self.poll_interval = config.get("poll_interval", 5)
        self.headers = {"Authorization": f"Bearer {self.token}"}
        self.hostname = socket.gethostname()
        self.capabilities = self._detect_capabilities()
        self.agent_id = None

    def _detect_capabilities(self):
        caps = []
        bins = {
            "velociraptor": "velociraptor.exe",
            "clamav": os.path.join("clamav", "clamscan.exe"),
            "grype": "grype.exe",
            "syft": "syft.exe",
            "aim": os.path.join("arsenal", "aim_cli.exe"),
        }
        for cap, binary in bins.items():
            if os.path.exists(os.path.join(self.bin_dir, binary)):
                caps.append(cap)
        return caps

    def register(self):
        r = requests.post(
            f"{self.server}/api/agent/register",
            json={"hostname": self.hostname, "capabilities": self.capabilities},
            headers=self.headers,
            verify=False,
            timeout=10,
        )
        r.raise_for_status()
        data = r.json()
        self.agent_id = data["agent_id"]
        # /register mints a fresh token scoped to this specific agent_id and
        # returns it here -- the deploy-time bootstrap token (still in
        # self.token at this point) only proves "some agent," not "this
        # agent," so every call after this one switches to the scoped token.
        scoped_token = data.get("token")
        if scoped_token:
            self.token = scoped_token
            self.headers = {"Authorization": f"Bearer {self.token}"}
        print(f"[ORCA Agent] Registered as {self.agent_id} on {self.hostname}")
        print(f"[ORCA Agent] Capabilities: {self.capabilities}")

    def poll_and_execute(self):
        print(f"[ORCA Agent] Polling for jobs...")
        while True:
            try:
                r = requests.get(
                    f"{self.server}/api/agent/{self.agent_id}/jobs",
                    headers=self.headers,
                    timeout=35,
                    verify=False,
                )
                job = r.json()
                if job:
                    print(f"[ORCA Agent] Received job: {job['job_id']} ({job['job_type']})")
                    threading.Thread(
                        target=self.execute_job, args=(job,), daemon=True
                    ).start()
            except Exception as e:
                print(f"[ORCA Agent] Poll error: {e}")
                time.sleep(self.poll_interval)

    def execute_job(self, job):
        job_id = job["job_id"]
        jtype = job["job_type"]
        params = job["params"]
        print(f"[ORCA Agent] Executing {jtype} job {job_id}")

        try:
            if jtype == "velociraptor":
                self._run_velociraptor(job_id, params)
            elif jtype == "clamav":
                self._run_clamav(job_id, params)
            elif jtype == "grype":
                self._run_grype(job_id, params)
            elif jtype == "mount":
                self._run_mount(job_id, params)
            elif jtype == "dismount":
                self._run_dismount(job_id, params)
            elif jtype == "memory":
                self._run_memory(job_id, params)
            elif jtype == "vql_test":
                self._run_vql_test(job_id, params)
            elif jtype == "artifact_collection":
                self._run_artifact_collection(job_id, params)
            elif jtype == "list_dir":
                self._run_list_dir(job_id, params)
            elif jtype == "folder_sync":
                self._run_folder_sync(params)
                return  # fire-and-forget — no DB tracking for sync jobs
            else:
                raise ValueError(f"Unknown job type: {jtype}")
            self._complete(job_id, "SUCCESS", {})
        except Exception as e:
            print(f"[ORCA Agent] Job {job_id} error: {e}")
            self._stream_line(job_id, "error", {"message": str(e)})
            self._complete(job_id, "ERROR", {"error": str(e)})

    def _stream_line(self, job_id, line_type, data):
        line = json.dumps({"type": line_type, "data": data})
        try:
            requests.post(
                f"{self.server}/api/agent/{self.agent_id}/jobs/{job_id}/stream",
                data=line + "\n",
                headers={**self.headers, "Content-Type": "application/x-ndjson"},
                verify=False,
                timeout=10,
            )
        except Exception as e:
            print(f"[ORCA Agent] Stream error: {e}")

    @staticmethod
    def _require_path(path):
        """Fail loudly when a scan target doesn't exist on this machine (e.g.
        a mounted image's drive letter that Windows never assigned) -- the
        tools otherwise report a clean "0 files scanned"/"no artifacts"."""
        p = (path or "").strip()
        if re.match(r"^[A-Za-z]:$", p):
            p += "\\"
        if not os.path.exists(p):
            raise RuntimeError(f"PATH_NOT_FOUND: {path} does not exist on this machine "
                               f"(if it is a mounted image, check it is mounted and has that drive letter)")
        return p

    def _stream_batch(self, job_id, lines):
        """Sends many already-encoded NDJSON lines in one request, retrying
        so a transient network error doesn't silently drop evidence rows."""
        body = "".join(line + "\n" for line in lines)
        for attempt in range(3):
            try:
                r = requests.post(
                    f"{self.server}/api/agent/{self.agent_id}/jobs/{job_id}/stream",
                    data=body.encode("utf-8"),
                    headers={**self.headers, "Content-Type": "application/x-ndjson"},
                    verify=False,
                    timeout=120,
                )
                if r.status_code < 400:
                    return
                print(f"[ORCA Agent] Stream batch HTTP {r.status_code}")
            except Exception as e:
                print(f"[ORCA Agent] Stream batch error: {e}")
            time.sleep(2 * (attempt + 1))
        raise RuntimeError(f"could not upload {len(lines)} result rows to the server")

    def _complete(self, job_id, status, summary):
        try:
            requests.post(
                f"{self.server}/api/agent/{self.agent_id}/jobs/{job_id}/complete",
                json={"status": status, "summary": summary},
                headers=self.headers,
                verify=False,
                timeout=10,
            )
        except Exception as e:
            print(f"[ORCA Agent] Complete error: {e}")

    def _run_folder_sync(self, params):
        paths = params.get("paths", [])
        created = 0
        for path in paths:
            try:
                if not os.path.exists(path):
                    os.makedirs(path, exist_ok=True)
                    print(f"[ORCA Agent] Created dir: {path}")
                    created += 1
            except Exception as e:
                print(f"[ORCA Agent] mkdir failed ({path}): {e}")
        if created:
            print(f"[ORCA Agent] Folder sync: {created} new director{'y' if created == 1 else 'ies'} created")

    def _run_velociraptor(self, job_id, params):
        vql = params["vql"]
        exe = os.path.join(self.bin_dir, "velociraptor.exe")
        cmd = [exe, "query", "--format", "jsonl", vql]
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace"
        )
        rows = []
        for line in proc.stdout:
            line = line.strip()
            if line:
                rows.append(line)
                self._stream_line(job_id, "row", {"row": line})
        proc.wait()
        self._stream_line(job_id, "done", {"total_rows": len(rows)})

    # Channel -> real evtx path. Ported from backend/run_technique.py's
    # _LOCAL_CHANNEL_MAP: that map was written back when the backend ran
    # directly on Windows, with real access to these paths -- containerizing
    # the backend into Linux broke it there (C:/Windows/... doesn't exist in
    # that container), but it's exactly correct here, since this runs on a
    # genuine Windows machine. Kept in sync with run_technique.py manually
    # (same reason orca_agent.py's other mirrored logic is -- these two
    # files run in different processes/machines and can't share an import).
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

    @classmethod
    def _evtx_path(cls, name):
        """Channel name ("Security", "Microsoft-Windows-Sysmon/Operational"),
        file name ("Security.evtx") or full path -> full .evtx path."""
        name = (name or "").strip()
        if not name:
            return None
        if re.match(r"^[A-Za-z]:[\\/]", name):
            return name.replace("\\", "/")
        known = cls._LOCAL_CHANNEL_MAP.get(name.lower())
        if known:
            return known
        fname = name if name.lower().endswith(".evtx") else name.replace("/", "%4") + ".evtx"
        return "C:/Windows/System32/winevt/Logs/" + fname

    @classmethod
    def _convert_source_to_parse_evtx(cls, vql_text):
        """Makes library queries runnable in a standalone (client-side)
        collection. Many were written for a Velociraptor server, where
        source(artifact=...) reads results an earlier collection stored;
        standalone there are no stored results, so those calls failed or
        silently returned nothing. Also fixes the common bare `EventID`
        (parse_evtx rows have System.EventID.Value), which failed every run
        with "Symbol EventID not found"."""
        evtx = r"source\s*\(\s*artifact\s*=\s*['\"]Windows\.EventLogs\.Evtx['\"]\s*,\s*(?:channel|source|file)\s*=\s*['\"]([^'\"]+)['\"]\s*\)"

        def evtx_repl(m):
            path = cls._evtx_path(m.group(1))
            return f"parse_evtx(filename='{path}')" if path else m.group(0)
        vql_text = re.sub(evtx, evtx_repl, vql_text, flags=re.IGNORECASE)
        # source(artifact='Windows.X.Y'[, extra args]) -> Artifact.Windows.X.Y([extra args])
        vql_text = re.sub(
            r"source\s*\(\s*artifact\s*=\s*['\"]((?:Windows|Generic)\.[A-Za-z0-9_.]+)['\"]\s*(,\s*)?",
            lambda m: f"Artifact.{m.group(1)}(", vql_text)
        # FROM Windows.Registry.NTUser  (bare artifact name as a plugin)
        vql_text = re.sub(r"(\bFROM\s+)((?:Windows|Generic)\.[A-Za-z0-9_.]+)(?!\s*\()",
                          lambda m: f"{m.group(1)}Artifact.{m.group(2)}()", vql_text)
        vql_text = re.sub(r"(?<![.\w])EventID(?=\s*(?:=|!=|<|>|\bIN\b|\bin\b))", "System.EventID.Value", vql_text)
        # watch_evtx() is an event monitor: it waits forever for NEW events
        # and never returns, so a collection using it hung until the server
        # gave up (and left velociraptor.exe running here). Collection wants
        # what's already in the log.
        vql_text = re.sub(r"\bwatch_evtx\s*\(", "parse_evtx(", vql_text)
        return vql_text

    @classmethod
    def _build_fallback_vql(cls, custom_vql):
        if not custom_vql:
            return None
        eid_match = cls._EVENTID_FILTER.search(custom_vql)
        if not eid_match:
            return None
        evtx_path = None
        m = re.search(r"parse_evtx\s*\(\s*filename\s*=\s*['\"]([^'\"]+)['\"]", custom_vql, re.IGNORECASE)
        if m:
            evtx_path = m.group(1)
        else:
            channel_match = re.search(r"channel\s*=\s*['\"]([^'\"]+)['\"]", custom_vql, re.IGNORECASE)
            evtx_path = cls._evtx_path(channel_match.group(1)) if channel_match else None
        if not evtx_path:
            return None
        return f"SELECT *\nFROM parse_evtx(filename='{evtx_path}')\nWHERE {eid_match.group(0).strip()}\nLIMIT 10000"

    # ── Dead-disk (mounted image) collection ─────────────────────────────────
    # The technique library is written for a live Windows host: C:/Windows/...
    # paths, the live registry (HKEY_LOCAL_MACHINE, HKEY_USERS, CurrentControlSet),
    # %APPDATA%. Pointed at a mounted image on E:, those queries used to read
    # THIS machine's C: drive and registry. Velociraptor's own dead-disk
    # remapping fixes that without rewriting the library: with
    # `--config <deaddisk.yaml>`, C: is the image's drive, the registry
    # accessors read the image's hive files (SYSTEM/SOFTWARE/SAM/SECURITY,
    # every user's NTUSER.DAT), and live-only plugins (pslist, netstat, wmi...)
    # are disabled so they can't report this machine instead.

    # Per velociraptor run; the server gives each technique 20 minutes.
    VR_QUERY_TIMEOUT = 15 * 60

    _LIVE_ONLY_PLUGINS = ("pslist", "netstat", "wmi", "handles", "modules", "vad", "interfaces",
                          "users", "certificates", "proc_dump", "proc_yara", "winobj", "partitions",
                          "execve", "amsi", "lookupSID", "token")
    _remap_lock = threading.Lock()
    _remap_cache = {}

    @staticmethod
    def _drive_of(path):
        m = re.match(r"^\s*([A-Za-z]):", path or "")
        return m.group(1).upper() if m else None

    def _is_dead_disk(self, tsource):
        drive = self._drive_of(tsource)
        system = self._drive_of(os.environ.get("SystemDrive", "C:")) or "C"
        return bool(drive) and drive != system

    def _deaddisk_config(self, drive, vr_exe):
        """Returns (remap_yaml_path, control_set) for a mounted drive, cached
        per drive and keyed on the image's SYSTEM hive + user profiles so a
        different image mounted at the same letter gets a fresh config."""
        root = f"{drive}:\\"
        sys_hive = os.path.join(root, "Windows", "System32", "config", "SYSTEM")
        try:
            st = os.stat(sys_hive)
            key_bits = f"{st.st_size}-{st.st_mtime}"
        except OSError:
            key_bits = "nohive"
        try:
            users = ",".join(sorted(os.listdir(os.path.join(root, "Users"))))
        except OSError:
            users = ""
        cache_key = (drive, key_bits, users)
        with self._remap_lock:
            hit = self._remap_cache.get(drive)
            if hit and hit[0] == cache_key and os.path.exists(hit[1]):
                return hit[1], hit[2]
            remap_dir = os.path.join(self.bin_dir, "deaddisk")
            os.makedirs(remap_dir, exist_ok=True)
            remap = os.path.join(remap_dir, f"{drive}.yaml")
            proc = subprocess.run(
                [vr_exe, "deaddisk", f"--add_windows_directory={root}", "--hostname=MOUNTED-IMAGE", remap],
                capture_output=True, creationflags=0x08000000 if os.name == "nt" else 0,
            )
            if proc.returncode != 0 or not os.path.exists(remap):
                raise RuntimeError("could not build dead-disk config for "
                                   f"{root}: {proc.stderr.decode('utf-8', errors='replace')[-400:]}")
            control_set = "ControlSet001"
            q = subprocess.run(
                [vr_exe, "--config", remap, "query",
                 "SELECT Current FROM read_reg_key(globs='HKEY_LOCAL_MACHINE/System/Select')", "--format", "jsonl"],
                capture_output=True, creationflags=0x08000000 if os.name == "nt" else 0,
            )
            for line in q.stdout.decode("utf-8", errors="replace").splitlines():
                try:
                    cur = int(json.loads(line).get("Current"))
                    control_set = f"ControlSet{cur:03d}"
                    break
                except Exception:
                    continue
            self._remap_cache[drive] = (cache_key, remap, control_set)
            return remap, control_set

    @staticmethod
    def _rewrite_for_image(text, control_set):
        """Things the remap can't cover: CurrentControlSet only exists on a
        running system (a hive has ControlSet00N + Select\\Current), there is
        no "current user" on an image, and %APPDATA%-style variables expand
        to the analyst's own profile."""
        text = re.sub(r"CurrentControlSet", control_set, text, flags=re.IGNORECASE)
        text = re.sub(r"HKEY_CURRENT_USER(?=([\\/]+))", lambda m: "HKEY_USERS" + m.group(1) + "*", text, flags=re.IGNORECASE)
        text = re.sub(r"HKCU(?=([\\/]+))", lambda m: "HKEY_USERS" + m.group(1) + "*", text)
        for var, repl in (("%APPDATA%", "C:/Users/*/AppData/Roaming"),
                          ("%LOCALAPPDATA%", "C:/Users/*/AppData/Local"),
                          ("%USERPROFILE%", "C:/Users/*"),
                          ("%TEMP%", "C:/Users/*/AppData/Local/Temp"),
                          ("%TMP%", "C:/Users/*/AppData/Local/Temp"),
                          ("%SYSTEMROOT%", "C:/Windows"),
                          ("%WINDIR%", "C:/Windows"),
                          ("%PROGRAMDATA%", "C:/ProgramData"),
                          ("%PROGRAMFILES%", "C:/Program Files"),
                          ("%SYSTEMDRIVE%", "C:")):
            text = re.sub(re.escape(var), repl, text, flags=re.IGNORECASE)
        return text

    @classmethod
    def _live_only_plugins_used(cls, text):
        return sorted({p for p in cls._LIVE_ONLY_PLUGINS if re.search(r"\b" + re.escape(p) + r"\s*\(", text or "")})

    def _run_artifact_collection(self, job_id, params):
        """Runs one MITRE-technique artifact collection locally against
        `tsource` (any drive letter/path reachable on this machine) --
        the agent-dispatched counterpart to run_technique.py's in-container
        path, for scanning a drive that only this agent can see (a locally
        attached physical disk, or anything mounted here via Arsenal).
        Mirrors run_technique.py's VQL-building/fallback logic; results
        stream back as rows for the backend to write to evidence/
        artifact_results, since this process has no DB access of its own.
        """
        t_code        = params["t_code"]
        tsource        = params.get("tsource") or "C:"
        custom_vql     = params.get("custom_vql") or ""
        surgical_yaml  = params.get("surgical_yaml") or ""
        clean_tsource  = tsource.replace("\\", "/").rstrip("/")
        self._require_path(clean_tsource + "/")
        vr_exe = os.path.join(self.bin_dir, "velociraptor.exe")

        # A drive other than this machine's own system drive is a mounted
        # image: collect through Velociraptor's dead-disk remapping (see
        # _deaddisk_config) so C:, HKLM and HKEY_USERS mean the image.
        dead_disk = self._is_dead_disk(tsource)
        vr_base = [vr_exe]
        if dead_disk:
            remap, control_set = self._deaddisk_config(self._drive_of(tsource), vr_exe)
            vr_base = [vr_exe, "--config", remap]
            custom_vql = self._rewrite_for_image(custom_vql, control_set)
            surgical_yaml = self._rewrite_for_image(surgical_yaml, control_set)
            clean_tsource = "C:"  # the remap presents the image as C:
        live_only = self._live_only_plugins_used(custom_vql + "\n" + surgical_yaml) if dead_disk else []
        work_dir = tempfile.mkdtemp(prefix=f"orca_art_{t_code}_")

        def vr_run(args):
            """velociraptor with a hard time limit (below the server's own
            per-technique limit), so a query that never ends can't leave a
            velociraptor.exe running on this machine indefinitely."""
            try:
                return subprocess.run(vr_base + args, capture_output=True, timeout=self.VR_QUERY_TIMEOUT,
                                      creationflags=0x08000000 if os.name == "nt" else 0)
            except subprocess.TimeoutExpired:
                return subprocess.CompletedProcess(args, 1, b"", (
                    f"stopped after {self.VR_QUERY_TIMEOUT // 60} minutes without finishing").encode())

        def run_vql(vql_text, label):
            vql_file = os.path.join(work_dir, f"{label}.vql")
            out_file = os.path.join(work_dir, f"{label}.jsonl")
            with open(vql_file, "w", encoding="utf-8") as f:
                f.write(vql_text)
            proc = vr_run(["query", "-f", vql_file, "--format", "jsonl", "--output", out_file])
            if proc.returncode != 0:
                return [], proc.stderr.decode("utf-8", errors="replace")[:500]
            rows = []
            if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
                with open(out_file, "r", encoding="utf-8-sig", errors="ignore") as f:
                    rows = [line.strip() for line in f if line.strip()]
            return rows, None

        errors = []  # velociraptor failures; reported instead of a silent "0 rows"
        try:
            fallback_used = False
            if surgical_yaml.strip():
                converted = self._convert_source_to_parse_evtx(surgical_yaml.strip().replace("\r\n", "\n"))
                yaml_file = os.path.join(work_dir, "artifact.yaml")
                with open(yaml_file, "w", encoding="utf-8") as f:
                    f.write(converted)
                try:
                    artifact_name = surgical_yaml.split("name:")[1].split("\n")[0].strip()
                except Exception:
                    raise RuntimeError("could not parse artifact name from surgical_yaml")
                if not re.match(r'^[A-Za-z0-9._\-/ ]+$', artifact_name):
                    raise RuntimeError("invalid artifact name")
                out_file = os.path.join(work_dir, "artifact.jsonl")
                proc = vr_run(["--definitions", work_dir, "artifacts", "collect", artifact_name, "--format", "jsonl"])
                rows = []
                if proc.returncode != 0:
                    errors.append("artifact collect failed: " + proc.stderr.decode("utf-8", errors="replace")[-500:])
                if proc.returncode == 0:
                    # `artifacts collect` prints its own log lines ("[ERROR] ...
                    # While compiling artifact ...") on stdout and still exits 0.
                    # Those used to be counted as evidence rows (a false "hit")
                    # and the real failure was never reported.
                    for line in proc.stdout.decode("utf-8", errors="replace").lstrip("﻿").splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        if line.startswith("{"):
                            try:
                                if isinstance(json.loads(line), dict):
                                    rows.append(line)
                                    continue
                            except ValueError:
                                pass
                        if line.startswith("[ERROR]"):
                            errors.append("artifact collect failed: " + line[:500])
                if errors and not rows and custom_vql.strip():
                    # The artifact definition is broken (syntax error, undefined
                    # symbol...): the technique's plain VQL query usually isn't,
                    # so run that rather than giving up on the technique.
                    vql_rows, err = run_vql(
                        self._convert_source_to_parse_evtx(custom_vql.replace(":tsource", clean_tsource)), "query")
                    if vql_rows:
                        rows, errors = vql_rows, []
                    elif not err:
                        errors = []  # the query ran fine and found nothing
                    else:
                        errors.append("query failed: " + err)
                if not rows and custom_vql.strip():
                    fb = self._build_fallback_vql(custom_vql)
                    if fb:
                        rows, err = run_vql(fb, "fallback")
                        if err: errors.append("fallback query failed: " + err)
                        fallback_used = bool(rows)
            elif custom_vql.strip():
                converted_vql = self._convert_source_to_parse_evtx(custom_vql.replace(":tsource", clean_tsource))
                rows, err = run_vql(converted_vql, "query")
                if err: errors.append("query failed: " + err)
                if not rows:
                    fb = self._build_fallback_vql(custom_vql)
                    if fb:
                        rows, err = run_vql(fb, "fallback")
                        if err: errors.append("fallback query failed: " + err)
                        fallback_used = bool(rows)
            else:
                glob_vql = f"SELECT *, '{t_code}' AS TCode FROM glob(globs='{clean_tsource}/**/{t_code}*')"
                rows, err = run_vql(glob_vql, "query")
                if err: errors.append("query failed: " + err)

            if not rows and live_only:
                # Disabled on purpose in dead-disk mode: there is no running
                # system in an image. Not a failure, not "nothing found".
                self._stream_line(job_id, "notice", {"message":
                    f"Not applicable to a disk image: this technique reads live-system state "
                    f"({', '.join(live_only)}), which only exists on a running host."})
            elif not rows and errors:
                # Collection failed rather than finding nothing: say so, so the
                # backend doesn't record a silent "no artifacts".
                self._stream_line(job_id, "error", {"message": f"{t_code}: " + " | ".join(errors)[:1000]})

            # Rows go up in batches: one HTTP request per row made a 10,000-row
            # event-log hit take minutes to upload, long enough to hit the
            # server's per-technique timeout.
            batch = []
            for line in rows:
                batch.append(json.dumps({"type": "row", "data": {"row": line, "t_code": t_code}}))
                if len(batch) >= 500:
                    self._stream_batch(job_id, batch)
                    batch = []
            if batch:
                self._stream_batch(job_id, batch)
            self._stream_line(job_id, "done", {"total_rows": len(rows), "fallback_used": fallback_used, "t_code": t_code})
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)

    def _run_clamav(self, job_id, params):
        clamav_dir = os.path.join(self.bin_dir, "clamav")
        exe = os.path.join(clamav_dir, "clamscan.exe")
        if not os.path.exists(exe):
            raise RuntimeError(f"clamscan.exe not found at {exe}")
        path = self._require_path(params["scan_path"])
        # --database explicit, not left to clamscan's own default search --
        # main.cvd/daily.cld live in this same bundled folder, not
        # wherever clamscan would otherwise look by default.
        cmd = [exe, "-r", "--infected", f"--database={clamav_dir}", path]
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace"
        )
        scanned, infected, threats = 0, 0, []
        for line in proc.stdout:
            line = line.strip()
            self._stream_line(job_id, "log", {"message": line})
            if "Infected files:" in line:
                try:
                    infected = int(line.split(":")[1].strip())
                except Exception:
                    pass
            if "Scanned files:" in line:
                try:
                    scanned = int(line.split(":")[1].strip())
                except Exception:
                    pass
            if "FOUND" in line:
                threats.append(line)
        proc.wait()
        self._stream_line(
            job_id,
            "done",
            {"scanned_files": scanned, "infected_files": infected, "threats": threats},
        )

    # ── Disk image mounting (Arsenal Image Mounter CLI) ──────────────────────
    # aim_cli without --background keeps the virtual disk only while that
    # process keeps running ("Press Ctrl+C to dismount"), so waiting for it
    # either hung the job or the disk vanished with the process. Without
    # --online the partitions stay offline with no drive letter. Both meant
    # the image never showed up in Windows, so anything pointed at its
    # "drive letter" (ClamAV, Syft, artifact collection) found nothing.

    def _aim_exe(self):
        exe = os.path.join(self.bin_dir, "arsenal", "aim_cli.exe")
        if not os.path.exists(exe):
            raise RuntimeError(f"aim_cli.exe not found at {exe}")
        return exe

    def _aim_run(self, args, timeout=900):
        """Runs aim_cli with output to a file, not a pipe: with --background
        the detached child inherits the handles, so reading a pipe to EOF
        would wait until the image is dismounted."""
        exe = self._aim_exe()
        fd, out_path = tempfile.mkstemp(prefix="orca_aim_", suffix=".txt")
        try:
            with os.fdopen(fd, "w") as out:
                proc = subprocess.Popen(
                    [exe] + args, stdout=out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                    cwd=os.path.dirname(exe), creationflags=0x08000000 if os.name == "nt" else 0,
                )
                try:
                    rc = proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    rc = -1
            time.sleep(0.5)
            with open(out_path, "r", encoding="utf-8", errors="replace") as f:
                return rc, f.read()
        finally:
            try:
                os.remove(out_path)
            except OSError:
                pass  # still held by a detached aim_cli; it's a few bytes in %TEMP%

    def _aim_devices(self):
        """{device_number: {"physical_drive": ..., "disk_number": int|None}} from aim_cli --list."""
        _, out = self._aim_run(["--list"], timeout=60)
        devices, cur = {}, None
        for line in out.splitlines():
            line = line.strip()
            m = re.match(r"Device number\s+(\d+)", line)
            if m:
                cur = m.group(1)
                devices[cur] = {"physical_drive": None, "disk_number": None}
                continue
            m = re.match(r"Device is\s+(\S+)", line)
            if m and cur:
                devices[cur]["physical_drive"] = m.group(1)
                n = re.search(r"PhysicalDrive(\d+)", m.group(1), re.IGNORECASE)
                if n:
                    devices[cur]["disk_number"] = int(n.group(1))
        return devices

    @staticmethod
    def _powershell(script, timeout=120):
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
            creationflags=0x08000000 if os.name == "nt" else 0,
        )
        return proc.returncode, (proc.stdout or ""), (proc.stderr or "")

    def _online_and_letter(self, disk_number, wanted_letter=None):
        """Brings the mounted disk's partitions online and makes sure every
        partition with a readable file system has a drive letter (Windows
        policy on forensic workstations often leaves new disks offline or
        unlettered). Returns [{"letter", "label", "fs", "size"}], largest first."""
        wanted = (wanted_letter or "").strip().rstrip(":\\/").upper()[:1]
        script = r"""
$ErrorActionPreference = 'Continue'
$n = %d
$wanted = '%s'
$d = Get-Disk -Number $n
if ($d.IsOffline) { Set-Disk -Number $n -IsOffline $false }
Start-Sleep -Seconds 1
$parts = Get-Partition -DiskNumber $n | Where-Object { $_.Type -notin @('Reserved','Unknown') -and $_.Size -gt 50MB } | Sort-Object Size -Descending
$first = $true
foreach ($p in $parts) {
  $v = $p | Get-Volume -ErrorAction SilentlyContinue
  if (-not $v -or -not $v.FileSystem) { $first = $false; continue }
  $has = $p.DriveLetter -and $p.DriveLetter -ne [char]0
  $used = (Get-PSDrive -PSProvider FileSystem).Name
  if ($first -and $wanted -and ([string]$p.DriveLetter -ne $wanted) -and ($used -notcontains $wanted)) {
    # The analyst asked for this letter for the main volume (Windows may
    # have handed out a different or remembered one).
    $p | Set-Partition -NewDriveLetter $wanted -ErrorAction SilentlyContinue
  } elseif (-not $has) {
    $p | Add-PartitionAccessPath -AssignDriveLetter -ErrorAction SilentlyContinue
  }
  $first = $false
}
Start-Sleep -Seconds 1
Get-Partition -DiskNumber $n | Where-Object { $_.DriveLetter -and $_.DriveLetter -ne [char]0 } | Sort-Object Size -Descending | ForEach-Object {
  $v = $_ | Get-Volume -ErrorAction SilentlyContinue
  [pscustomobject]@{ letter = [string]$_.DriveLetter; label = [string]$v.FileSystemLabel; fs = [string]$v.FileSystem; size = [int64]$_.Size }
} | ConvertTo-Json -Compress
""" % (int(disk_number), wanted if re.match(r"^[D-Z]$", wanted or "") else "")
        rc, out, err = self._powershell(script)
        out = out.strip()
        if not out:
            return [], err.strip()[-500:]
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        return data, err.strip()[-500:]

    def _run_list_dir(self, job_id, params):
        """Directory listing for the UI's BROWSE dialog. Empty path = the drives."""
        path = (params.get("path") or "").strip()
        limit = 5000
        if not path:
            entries = []
            if os.name == "nt":
                import ctypes
                k32 = ctypes.windll.kernel32
                mask = k32.GetLogicalDrives()
                kinds = {2: "Removable", 3: "Local Disk", 4: "Network", 5: "CD/DVD", 6: "RAM Disk"}
                for i in range(26):
                    if not mask & (1 << i):
                        continue
                    root = f"{chr(65 + i)}:\\"
                    label = ctypes.create_unicode_buffer(261)
                    ok = k32.GetVolumeInformationW(root, label, 261, None, None, None, None, 0)
                    entries.append({"name": root, "path": root, "type": "drive",
                                    "label": label.value if ok else "",
                                    "kind": kinds.get(k32.GetDriveTypeW(root), ""),
                                    "ready": bool(ok)})
            else:
                entries.append({"name": "/", "path": "/", "type": "drive", "label": "", "kind": "", "ready": True})
            self._stream_line(job_id, "done", {"path": "", "parent": None, "entries": entries, "truncated": False})
            return

        if re.fullmatch(r"[A-Za-z]:", path):
            path += "\\"
        path = os.path.normpath(path)
        if re.fullmatch(r"[A-Za-z]:", path):
            path += "\\"
        if not os.path.isdir(path):
            raise RuntimeError(f"PATH_NOT_FOUND: no such folder on this machine: {path}")
        entries, truncated = [], False
        with os.scandir(path) as it:
            for e in it:
                try:
                    is_dir = e.is_dir()
                    st = e.stat()
                    entries.append({"name": e.name, "path": e.path, "type": "dir" if is_dir else "file",
                                    "size": None if is_dir else st.st_size, "mtime": int(st.st_mtime)})
                except OSError:
                    entries.append({"name": e.name, "path": e.path, "type": "file", "size": None, "mtime": None})
        entries.sort(key=lambda x: (x["type"] != "dir", x["name"].casefold()))
        if len(entries) > limit:
            entries, truncated = entries[:limit], True
        parent = os.path.dirname(path.rstrip("\\/")) if path.rstrip("\\/") else ""
        if parent == path or re.fullmatch(r"[A-Za-z]:\\?", path):
            parent = ""   # at a drive root: "up" goes to the drive list
        elif re.fullmatch(r"[A-Za-z]:", parent):
            parent += "\\"
        self._stream_line(job_id, "done", {"path": path, "parent": parent, "entries": entries, "truncated": truncated})

    @staticmethod
    def _image_segments(image, provider):
        """Split images: a raw image cut into image.001, .002, ... (FTK Imager,
        dd | split) must be mounted from its FIRST part with the MultiPartRaw
        provider, which then reads every part. E01 sets are opened from the
        .E01 and libewf finds the rest. Returns (path_to_mount, provider, parts)."""
        m = re.match(r"^(.*)\.(\d{3})$", image)
        if m and provider in ("auto", "MultiPartRaw"):
            stem = m.group(1)
            first = next((f"{stem}.{n:03d}" for n in (0, 1) if os.path.exists(f"{stem}.{n:03d}")), image)
            n0 = int(first[-3:])
            parts, n = [], n0
            while os.path.exists(f"{stem}.{n:03d}"):
                parts.append(f"{stem}.{n:03d}")
                n += 1
            folder = os.path.dirname(stem) or "."
            base = os.path.basename(stem)
            later = sorted(int(f[len(base) + 1:]) for f in os.listdir(folder)
                           if f.lower().startswith(base.lower() + ".") and re.fullmatch(r"\d{3}", f[len(base) + 1:]))
            if later and later[-1] >= n:
                raise RuntimeError(f"AIM_MOUNT_FAILED: split image is missing part {stem}.{n:03d} "
                                   f"(found parts up to .{later[-1]:03d}); mounting would cut the disk short")
            return first, "MultiPartRaw", parts
        m = re.match(r"^(.*)\.([EeLlSs])(\d{2})$", image)
        if m and provider in ("auto", "LibEwf") and m.group(3) != "01":
            first = f"{m.group(1)}.{m.group(2)}01"
            if os.path.exists(first):
                return first, "LibEwf", [first]
        return image, provider, [image]

    def _run_mount(self, job_id, params):
        image = params["image_path"]
        if not os.path.exists(image):
            raise RuntimeError(f"AIM_MOUNT_FAILED: image file not found on this machine: {image}")
        image, provider, parts = self._image_segments(image, params.get("provider", "auto"))
        if len(parts) > 1:
            total = sum(os.path.getsize(p) for p in parts)
            self._stream_line(job_id, "log", {"message":
                f"Split image: {len(parts)} parts ({os.path.basename(parts[0])} .. {os.path.basename(parts[-1])}), "
                f"{total / 1024 ** 3:.2f} GB, mounted with MultiPartRaw from {image}"})

        before = self._aim_devices()
        cmd = ["--mount"]
        cmd.append("--readonly" if params.get("readonly", True) else "--writable")
        cmd += ["--online", f"--filename={image}", f"--provider={provider}", "--background"]
        rc, output = self._aim_run(cmd)
        self._stream_line(job_id, "log", {"message": output})

        # The detached aim_cli finishes attaching after the launcher exits.
        new_dev = None
        for _ in range(60):
            after = self._aim_devices()
            added = [d for d in after if d not in before]
            if added:
                new_dev = added[0]
                break
            time.sleep(1)
        if not new_dev:
            raise RuntimeError(f"AIM_MOUNT_FAILED: no new virtual disk appeared. aim_cli output: {output[-800:]}")

        info = after[new_dev]
        volumes, ps_err = [], ""
        if info["disk_number"] is not None:
            for _ in range(3):
                volumes, ps_err = self._online_and_letter(info["disk_number"], params.get("drive_letter"))
                if volumes:
                    break
                time.sleep(2)

        letters = [v["letter"] for v in volumes]
        primary = letters[0] if letters else None
        listing = []
        if primary:
            try:
                listing = sorted(os.listdir(f"{primary}:\\"))[:25]
            except Exception as e:
                listing = [f"(could not list {primary}:\\ -- {e})"]
        if not letters:
            self._stream_line(job_id, "log", {"message":
                "Disk attached but Windows assigned no drive letter (no readable file system found, "
                "e.g. BitLocker-encrypted or unsupported). " + ps_err})

        self._stream_line(job_id, "done", {
            "device_number":  new_dev,
            "physical_drive": info["physical_drive"],
            "drive_letter":   primary,
            "volumes":        volumes,
            "root_listing":   listing,
            "image_path":     image,
            "provider":       provider,
            "segments":       len(parts),
            "output":         output,
        })

    def _run_dismount(self, job_id, params):
        dev = str(params.get("device_number") or "").strip()
        if not dev or dev.lower() == "none":
            # A session recorded by the old mount code, which often never
            # really attached a disk: nothing to dismount, let ORCA clear it.
            self._stream_line(job_id, "done", {"output": "No device recorded for this mount session; nothing to dismount."})
            return
        rc, output = self._aim_run([f"--dismount={dev}", "--force"], timeout=120)
        self._stream_line(job_id, "log", {"message": output})
        # "No device mounted with device number N": already gone (e.g. a
        # session from the old mount code, or the machine rebooted) -- the
        # goal state, so let ORCA clear the session instead of keeping it stuck.
        if rc != 0 and "dismounted" not in output.lower() and "no device mounted" not in output.lower():
            raise RuntimeError(f"AIM_DISMOUNT_FAILED: {output[:500]}")
        self._stream_line(job_id, "done", {"output": output})

    def _run_grype(self, job_id, params):
        syft_exe = os.path.join(self.bin_dir, "syft.exe")
        grype_exe = os.path.join(self.bin_dir, "grype.exe")
        path = self._require_path(params["scan_path"])
        # Never phone home: syft/grype check for a newer release on every run
        # by default (an outbound HTTPS attempt that just times out offline).
        tool_env = os.environ.copy()
        tool_env.update({
            "SYFT_CHECK_FOR_APP_UPDATE": "false",
            "GRYPE_CHECK_FOR_APP_UPDATE": "false",
            "SYFT_JAVA_USE_NETWORK": "false",
            "SYFT_GOLANG_SEARCH_REMOTE_LICENSES": "false",
            "SYFT_JAVASCRIPT_SEARCH_REMOTE_LICENSES": "false",
            "SYFT_PYTHON_SEARCH_REMOTE_LICENSES": "false",
        })
        # dir: makes syft treat a bare drive root ("E:\\") as a directory to
        # catalog instead of guessing (it otherwise also tries image sources).
        source = path if os.path.isfile(path) else "dir:" + path

        self._stream_line(job_id, "log", {"message": f"Running Syft on {path}"})
        sbom = subprocess.run(
            [syft_exe, source, "-o", "json"],
            capture_output=True,
            text=True, encoding="utf-8", errors="replace",
            env=tool_env,
        )
        if sbom.returncode != 0:
            raise RuntimeError(f"Syft failed: {sbom.stderr[:500]}")

        self._stream_line(job_id, "log", {"message": "Running Grype..."})
        # Without these, grype tries to reach the internet to check for a
        # newer DB on every single scan (this agent has none, by design),
        # and -- confirmed live -- outright REFUSES to run at all once its
        # bundled DB is older than the default 5-day max-allowed-built-age,
        # erroring instead of just warning. Always disabled here, unlike
        # the backend's equivalent (gated on an analyst-facing "offline"
        # toggle there) -- this agent has no such toggle, and exists
        # specifically for offline/standalone deployments.
        grype_env = tool_env.copy()
        grype_env["GRYPE_DB_AUTO_UPDATE"] = "false"
        grype_env["GRYPE_DB_VALIDATE_AGE"] = "false"
        # Grype's own default cache dir is some per-user profile path that
        # doesn't exist on a freshly deployed agent -- point it at the
        # bundled DB (downloaded as grype-db.zip in _bootstrap_binaries)
        # explicitly, same reasoning as the backend's equivalent.
        grype_env["GRYPE_DB_CACHE_DIR"] = os.path.join(self.bin_dir, "grype-db")
        proc = subprocess.Popen(
            [grype_exe, "-o", "json"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace",
            env=grype_env,
        )
        out, grype_err = proc.communicate(sbom.stdout)

        try:
            data = json.loads(out)
            vulns = data.get("matches", [])
            self._stream_line(
                job_id, "done", {"vulnerabilities": vulns, "total": len(vulns)}
            )
        except Exception:
            self._stream_line(
                job_id, "error", {"message": f"Grype failed (exit {proc.returncode}): {(grype_err or '').strip()[-500:]}"}
            )

    def _run_memory(self, job_id, params):
        exe = os.path.join(self.bin_dir, "velociraptor.exe")
        image = params["image_path"]
        plugins = params.get("plugins", ["windows.pslist"])

        for plugin in plugins:
            self._stream_line(job_id, "log", {"message": f"Running {plugin}"})
            vql = f"SELECT * FROM {plugin}()"
            cmd = [exe, "query", "--format", "jsonl", f"--add_plugins={image}", vql]
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace"
            )
            rows = []
            for line in proc.stdout:
                line = line.strip()
                if line:
                    rows.append(line)
                    self._stream_line(job_id, "row", {"plugin": plugin, "row": line})
            proc.wait()
            self._stream_line(
                job_id, "plugin_done", {"plugin": plugin, "rows": len(rows)}
            )

        self._stream_line(job_id, "done", {"plugins": plugins})

    def _run_vql_test(self, job_id, params):
        vql_text = params["vql"]
        is_yaml = params.get("is_yaml", vql_text.strip().startswith("name:"))
        exe = os.path.join(self.bin_dir, "velociraptor.exe")
        if not os.path.exists(exe):
            raise RuntimeError(f"velociraptor.exe not found at {exe}")

        tmp_dir = tempfile.mkdtemp(prefix="orca_vqltest_")
        try:
            if is_yaml:
                try:
                    artifact_name = vql_text.split("name:")[1].split("\n")[0].strip()
                except Exception:
                    raise RuntimeError("Could not parse 'name:' from YAML artifact.")
                yaml_path = os.path.join(tmp_dir, "artifact.yaml")
                with open(yaml_path, "w") as f:
                    f.write(vql_text)
                cmd = [exe, "--definitions", tmp_dir, "artifacts", "collect",
                       artifact_name, "--format", "jsonl"]
            else:
                vql_path = os.path.join(tmp_dir, "query.vql")
                with open(vql_path, "w") as f:
                    f.write(vql_text)
                cmd = [exe, "query", "-f", vql_path, "--format", "jsonl"]

            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace"
            )
            row_count = 0
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    # Skip Velociraptor's internal _Source-only metadata rows
                    if set(obj.keys()) == {"_Source"}:
                        continue
                    self._stream_line(job_id, "row", obj)
                    row_count += 1
                except Exception:
                    pass
            proc.wait()
            if proc.returncode != 0:
                stderr_out = proc.stderr.read().strip() if proc.stderr else ""
                if stderr_out and not row_count:
                    self._stream_line(job_id, "error", {"message": f"VR_ERROR: {stderr_out[:500]}"})
            self._stream_line(job_id, "done", {"total_rows": row_count})
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _download_bin(self, name, dest):
        url = f"{self.server}/api/agent/download/bin/{name}"
        r = requests.get(url, headers=self.headers, verify=False, stream=True, timeout=300)
        if r.status_code == 404:
            print(f"[ORCA Agent] {name} not on server — skipping", flush=True)
            return False
        r.raise_for_status()
        with open(dest, "wb") as f:
            for chunk in r.iter_content(chunk_size=65536):
                f.write(chunk)
        return True

    def _download_and_extract_zip(self, zip_name, marker_file, extract_subdir, label):
        """Shared helper for the three bundles that need their whole
        directory, not a single file: Arsenal (DLLs), ClamAV (DLLs +
        signature database), Grype's vulnerability DB. `marker_file` is
        checked first so an already-extracted bundle is never re-downloaded."""
        dest_marker = os.path.join(self.bin_dir, extract_subdir, marker_file)
        if os.path.exists(dest_marker):
            return
        zip_path = os.path.join(self.bin_dir, zip_name)
        print(f"[ORCA Agent] Downloading {zip_name}...", flush=True)
        try:
            if self._download_bin(zip_name, zip_path):
                extract_dir = os.path.join(self.bin_dir, extract_subdir)
                os.makedirs(extract_dir, exist_ok=True)
                with zipfile.ZipFile(zip_path) as zf:
                    zf.extractall(extract_dir)
                os.remove(zip_path)
                print(f"[ORCA Agent] {label} ready", flush=True)
        except Exception as e:
            print(f"[ORCA Agent] Warning: could not set up {label}: {e}", flush=True)

    def _bootstrap_binaries(self):
        needed = ["velociraptor.exe", "grype.exe", "syft.exe"]
        os.makedirs(self.bin_dir, exist_ok=True)
        for name in needed:
            dest = os.path.join(self.bin_dir, name)
            if os.path.exists(dest):
                continue
            print(f"[ORCA Agent] Downloading {name}...", flush=True)
            try:
                if self._download_bin(name, dest):
                    print(f"[ORCA Agent] {name} ready", flush=True)
            except Exception as e:
                print(f"[ORCA Agent] Warning: could not download {name}: {e}", flush=True)

        # Each of these needs its whole directory (DLLs, and for clamav/
        # grype-db a multi-hundred-MB-to-multi-GB database), not a single
        # file -- served pre-zipped and extracted here instead of written
        # straight to disk like the simple binaries above.
        self._download_and_extract_zip("arsenal.zip", "aim_cli.exe", "arsenal", "arsenal (Arsenal Image Mounter)")
        self._download_and_extract_zip("clamav.zip", "clamscan.exe", "clamav", "clamav (ClamAV + signatures)")
        # grype-db.zip's entries are already "6/vulnerability.db", "6/import.json"
        # (relative to the server's grype-db/), so extract into grype-db/ itself.
        # Extracting into grype-db/6 produced grype-db/6/6/..., which grype
        # (GRYPE_DB_CACHE_DIR=bin/grype-db, see _run_grype) never found, and the
        # marker never matched, so every agent start re-downloaded the ~3 GB DB.
        self._download_and_extract_zip("grype-db.zip", os.path.join("6", "vulnerability.db"), "grype-db", "grype-db (vulnerability database)")

    def run(self):
        self._bootstrap_binaries()
        self.capabilities = self._detect_capabilities()

        # Retry indefinitely instead of a single unguarded call -- this
        # runs from a Startup-folder shortcut at logon, possibly before
        # Docker Desktop (and therefore the ORCA server) has actually come
        # up. An exception here used to kill the whole process immediately
        # with no retry -- so one mistimed logon left the agent down until
        # someone noticed and restarted it by hand. poll_and_execute()'s
        # loop and the heartbeat thread below already retry on failure;
        # this just extends the same behavior to the one call that happens
        # before either of those exists yet.
        while True:
            try:
                self.register()
                break
            except Exception as e:
                print(f"[ORCA Agent] Registration failed, retrying in {self.poll_interval}s: {e}")
                time.sleep(self.poll_interval)

        def heartbeat():
            while True:
                time.sleep(60)
                try:
                    self.register()
                except Exception as e:
                    print(f"[ORCA Agent] Heartbeat error: {e}")

        threading.Thread(target=heartbeat, daemon=True).start()
        self.poll_and_execute()


if __name__ == "__main__":
    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    with open(config_path) as f:
        config = json.load(f)
    OrcaAgent(config).run()
