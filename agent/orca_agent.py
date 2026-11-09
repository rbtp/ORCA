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
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
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
    def _convert_source_to_parse_evtx(cls, vql_text):
        def replacer(m):
            path = cls._LOCAL_CHANNEL_MAP.get(m.group(1).lower())
            return f"parse_evtx(filename='{path}')" if path else m.group(0)
        return re.sub(
            r"source\s*\(\s*artifact\s*=\s*['\"]Windows\.EventLogs\.Evtx['\"]\s*,\s*channel\s*=\s*['\"]([^'\"]+)['\"]\s*\)",
            replacer, vql_text, flags=re.IGNORECASE
        )

    @classmethod
    def _build_fallback_vql(cls, custom_vql):
        if not custom_vql:
            return None
        eid_match = cls._EVENTID_FILTER.search(custom_vql)
        if not eid_match:
            return None
        channel_match = re.search(r"channel\s*=\s*['\"]([^'\"]+)['\"]", custom_vql, re.IGNORECASE)
        channel = channel_match.group(1).lower() if channel_match else None
        evtx_path = cls._LOCAL_CHANNEL_MAP.get(channel) if channel else None
        if not evtx_path:
            return None
        return f"SELECT *\nFROM parse_evtx(filename='{evtx_path}')\nWHERE {eid_match.group(0).strip()}\nLIMIT 10000"

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
        vr_exe = os.path.join(self.bin_dir, "velociraptor.exe")
        work_dir = tempfile.mkdtemp(prefix=f"orca_art_{t_code}_")

        def run_vql(vql_text, label):
            vql_file = os.path.join(work_dir, f"{label}.vql")
            out_file = os.path.join(work_dir, f"{label}.jsonl")
            with open(vql_file, "w", encoding="utf-8") as f:
                f.write(vql_text)
            proc = subprocess.run(
                [vr_exe, "query", "-f", vql_file, "--format", "jsonl", "--output", out_file],
                capture_output=True,
            )
            if proc.returncode != 0:
                return [], proc.stderr.decode("utf-8", errors="replace")[:500]
            rows = []
            if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
                with open(out_file, "r", encoding="utf-8-sig", errors="ignore") as f:
                    rows = [line.strip() for line in f if line.strip()]
            return rows, None

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
                proc = subprocess.run(
                    [vr_exe, "--definitions", work_dir, "artifacts", "collect", artifact_name, "--format", "jsonl"],
                    capture_output=True,
                )
                rows = []
                if proc.returncode == 0:
                    with open(out_file, "w", encoding="utf-8") as f:
                        f.write(proc.stdout.decode("utf-8", errors="replace"))
                    if os.path.getsize(out_file) > 0:
                        with open(out_file, "r", encoding="utf-8-sig", errors="ignore") as f:
                            rows = [line.strip() for line in f if line.strip()]
                if not rows and custom_vql.strip():
                    fb = self._build_fallback_vql(custom_vql)
                    if fb:
                        rows, _ = run_vql(fb, "fallback")
                        fallback_used = bool(rows)
            elif custom_vql.strip():
                converted_vql = self._convert_source_to_parse_evtx(custom_vql.replace(":tsource", clean_tsource))
                rows, _ = run_vql(converted_vql, "query")
                if not rows:
                    fb = self._build_fallback_vql(custom_vql)
                    if fb:
                        rows, _ = run_vql(fb, "fallback")
                        fallback_used = bool(rows)
            else:
                glob_vql = f"SELECT *, '{t_code}' AS TCode FROM glob(globs='{clean_tsource}/**/{t_code}*')"
                rows, _ = run_vql(glob_vql, "query")

            for line in rows:
                self._stream_line(job_id, "row", {"row": line, "t_code": t_code})
            self._stream_line(job_id, "done", {"total_rows": len(rows), "fallback_used": fallback_used, "t_code": t_code})
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)

    def _run_clamav(self, job_id, params):
        clamav_dir = os.path.join(self.bin_dir, "clamav")
        exe = os.path.join(clamav_dir, "clamscan.exe")
        if not os.path.exists(exe):
            raise RuntimeError(f"clamscan.exe not found at {exe}")
        path = params["scan_path"]
        # --database explicit, not left to clamscan's own default search --
        # main.cvd/daily.cld live in this same bundled folder, not
        # wherever clamscan would otherwise look by default.
        cmd = [exe, "-r", "--infected", f"--database={clamav_dir}", path]
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
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

    @staticmethod
    def _parse_aim_output(output):
        """Parse aim_cli stdout into structured dict. Mirrors main.py's
        _parse_aim_output -- kept in sync manually since this runs on the
        remote/local Windows side, not in the backend container."""
        result = {"device_number": None, "physical_drive": None, "drive_letter": None}
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Device number"):
                result["device_number"] = line.split()[-1]
            elif line.startswith("Device is"):
                result["physical_drive"] = line.split()[-1]
            elif "Drive letter" in line or (len(line) == 2 and line[1] == ":"):
                result["drive_letter"] = line.replace("Drive letter:", "").replace(":", "").strip()
        return result

    def _run_mount(self, job_id, params):
        exe = os.path.join(self.bin_dir, "arsenal", "aim_cli.exe")
        if not os.path.exists(exe):
            raise RuntimeError(f"aim_cli.exe not found at {exe}")

        cmd = [exe, "--mount"]
        if params.get("readonly", True):
            cmd.append("--readonly")
        cmd += [f"--filename={params['image_path']}", f"--provider={params.get('provider', 'auto')}"]

        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            cwd=os.path.join(self.bin_dir, "arsenal"),
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        self._stream_line(job_id, "log", {"message": output})

        if proc.returncode != 0:
            raise RuntimeError(f"AIM_MOUNT_FAILED: {output[:500]}")

        parsed = self._parse_aim_output(output)
        self._stream_line(job_id, "done", {
            "device_number": parsed["device_number"],
            "physical_drive": parsed["physical_drive"],
            "drive_letter": parsed["drive_letter"],
            "output": output,
        })

    def _run_dismount(self, job_id, params):
        exe = os.path.join(self.bin_dir, "arsenal", "aim_cli.exe")
        if not os.path.exists(exe):
            raise RuntimeError(f"aim_cli.exe not found at {exe}")

        cmd = [exe, f"--dismount={params['device_number']}", "--force"]
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            cwd=os.path.join(self.bin_dir, "arsenal"),
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        self._stream_line(job_id, "log", {"message": output})

        if proc.returncode != 0:
            raise RuntimeError(f"AIM_DISMOUNT_FAILED: {output[:500]}")

        self._stream_line(job_id, "done", {"output": output})

    def _run_grype(self, job_id, params):
        syft_exe = os.path.join(self.bin_dir, "syft.exe")
        grype_exe = os.path.join(self.bin_dir, "grype.exe")
        path = params["scan_path"]

        self._stream_line(job_id, "log", {"message": f"Running Syft on {path}"})
        sbom = subprocess.run(
            [syft_exe, path, "-o", "json"],
            capture_output=True,
            text=True,
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
        grype_env = os.environ.copy()
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
            text=True,
            env=grype_env,
        )
        out, _ = proc.communicate(sbom.stdout)

        try:
            data = json.loads(out)
            vulns = data.get("matches", [])
            self._stream_line(
                job_id, "done", {"vulnerabilities": vulns, "total": len(vulns)}
            )
        except Exception:
            self._stream_line(
                job_id, "error", {"message": "Failed to parse Grype output"}
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
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
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
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
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
        self._download_and_extract_zip("grype-db.zip", "vulnerability.db", os.path.join("grype-db", "6"), "grype-db (vulnerability database)")

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
