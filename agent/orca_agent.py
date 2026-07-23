import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time

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
            "clamav": "clamscan.exe",
            "grype": "grype.exe",
            "syft": "syft.exe",
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
        self.agent_id = r.json()["agent_id"]
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
            elif jtype == "memory":
                self._run_memory(job_id, params)
            elif jtype == "vql_test":
                self._run_vql_test(job_id, params)
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

    def _run_clamav(self, job_id, params):
        exe = os.path.join(self.bin_dir, "clamscan.exe")
        path = params["scan_path"]
        cmd = [exe, "-r", "--infected", path]
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
        proc = subprocess.Popen(
            [grype_exe, "-o", "json"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
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

    def _bootstrap_binaries(self):
        needed = ["velociraptor.exe", "clamscan.exe", "grype.exe", "syft.exe"]
        os.makedirs(self.bin_dir, exist_ok=True)
        for name in needed:
            dest = os.path.join(self.bin_dir, name)
            if os.path.exists(dest):
                continue
            url = f"{self.server}/api/agent/download/bin/{name}"
            print(f"[ORCA Agent] Downloading {name}...", flush=True)
            try:
                r = requests.get(url, headers=self.headers, verify=False, stream=True, timeout=300)
                if r.status_code == 404:
                    print(f"[ORCA Agent] {name} not on server — skipping", flush=True)
                    continue
                r.raise_for_status()
                with open(dest, "wb") as f:
                    for chunk in r.iter_content(chunk_size=65536):
                        f.write(chunk)
                print(f"[ORCA Agent] {name} ready", flush=True)
            except Exception as e:
                print(f"[ORCA Agent] Warning: could not download {name}: {e}", flush=True)

    def run(self):
        self._bootstrap_binaries()
        self.capabilities = self._detect_capabilities()
        self.register()

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
