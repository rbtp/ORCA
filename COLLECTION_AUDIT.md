# Remote Collection Audit — Containerized Backend

Date: 2026-06-18
Scope: Diagnose why `POST /api/deploy/bulk` ("Deploy to Host") no longer completes after the
backend moved from native Windows to a Linux Docker container. **Read-only diagnosis — no code
changed in this pass.**

---

## 1. What `POST /api/deploy/bulk` does, step by step

Route: `backend/deploy_routes.py:199` (`@router.post("/bulk")`, mounted at `/api/deploy/bulk`
via `app.include_router(deploy_router)` in `main.py:53`).

For each selected asset (concurrently, via `asyncio.gather`), `_deploy_single()` runs:

1. **`build_package(asset_id, user_id, orca_url)`** — `backend/package_builder.py`
   - Writes one VQL/YAML file per MITRE technique into a staging dir.
   - Copies a Velociraptor binary into the package:
     ```python
     vr_src = Path(cfg.VR_EXE)
     if vr_src.exists():
         shutil.copy2(vr_src, pkg_dir / "velociraptor.exe")
     else:
         logger.warning("velociraptor.exe not found at %s", cfg.VR_EXE)   # <- exact log line user saw
     ```
     This is **non-fatal** — the function continues and produces a ZIP with no `velociraptor.exe`
     inside it.
   - Templates `run_orca_collection.ps1` (`backend/run_orca_collection.ps1`) with the asset's
     token/case/URL, zips everything, registers a `package_tokens` row, and returns a one-liner.
   - The one-liner (`backend/package_builder.py:219-228`):
     ```
     powershell -ExecutionPolicy Bypass -c "<cert-trust-bypass>iex (iwr '<bootstrap_url>' -UseBasicParsing).Content"
     ```
     where `bootstrap_url = {orca_url}/api/packages/{token}/bootstrap`.

2. **`_run_psexec(psexec, ip, username, password, command)`** — `backend/deploy_routes.py`
   - Binary: `Path(__file__).parent / 'bin' / 'psexec.exe'` (exists on disk/in the container —
     confirmed earlier this session via `docker exec orca-backend ls /app/bin/`).
   - Launches: `psexec.exe \\<ip> -u <user> -p <pass> -accepteula -d -s -n 30 powershell.exe
     -ExecutionPolicy Bypass -WindowStyle Hidden -Command <oneliner>` via
     `asyncio.create_subprocess_exec`.
   - **This is a Windows PE.** In the Linux container it cannot run natively. Docker
     Desktop/WSL2's `binfmt_misc` interop handler intercepts the `exec()` and tries to hand it to
     the WSL interop launcher, which fails internally (`UtilGetPpid:1330: Failed to parse:
     /proc/1/stat, content: 1 (python)` — because the container's PID 1 is `python`/`uvicorn`,
     not a real init the interop layer expects). The subprocess returns a non-zero return code
     (observed: `1`) rather than raising `FileNotFoundError`/`OSError`, so Python-side this looks
     like "psexec ran and failed," not "psexec couldn't run at all."

3. **Soft-failure handling** — `_deploy_single()` in `deploy_routes.py`:
   ```python
   if returncode != 0 and <not a recognized auth/unreachable error>:
       logger.warning('PsExec non-zero (%d) for %s: %s', returncode, ip, stderr[:200])
       # falls through — does NOT return/abort
   ```
   The function then **unconditionally** emits `'EXECUTING'` and `'COLLECTING'` SSE phases to the
   frontend regardless of whether anything actually ran remotely. This is why the API call
   returns `200 OK` and the UI shows progress phases even though nothing was deployed — the
   non-zero psexec return code is logged as a warning and swallowed, not surfaced as a failure.

**Net result:** nothing ever executes on the remote Windows host. The ZIP (which itself is
missing `velociraptor.exe` due to point 1) is never even fetched, because the trigger command
that would fetch it never ran.

---

## 2. The agent path — how it's supposed to work, and where it's disconnected

`backend/agent_routes.py`, mounted at `/api/agent` (`main.py:46`).

- **`POST /api/agent/register`** — a Python agent (`agent/orca_agent.py`, deployed to and run ON
  the Windows target) calls this to register itself in `agent_registrations`. This is a pure
  Linux-container-safe HTTP endpoint; nothing Windows-specific happens here.
- **`GET /api/agent/{id}/jobs`** — long-poll (30s) endpoint the agent calls in a loop; returns a
  queued job dict or `null`. Also pure HTTP, container-safe.
- **`POST /api/agent/deploy`** — a *second, independent* psexec-push mechanism (separate from
  `deploy_routes.py`) that pushes a PowerShell bootstrap (`agent_routes.py:410-434`) which
  downloads `orca_agent.py` and schedules/starts it via `schtasks`/`Start-Process`. This **also**
  shells out to the same broken `psexec.exe` (`agent_routes.py:447-465`) and fails the same way —
  except this code path treats `rc not in (0, 1)` as the hard-failure condition, i.e. it
  explicitly tolerates return code `1` as "probably fine" (`agent_routes.py:487`). Given the
  observed psexec interop failure returns code `1`, **this path proceeds past the failure
  silently** and goes on to poll `agent_registrations` for *any* row with `last_seen` in the last
  60 seconds (`agent_routes.py:496-501`) — **not scoped to the specific IP being deployed**. If
  any previously-registered agent (from an earlier, unrelated, successful deployment) happens to
  send a heartbeat in that 60s window, `/api/agent/deploy` reports `"done": "SUCCESS"` for a
  deployment that never reached its actual target. This is the most plausible explanation for the
  user's log showing `/api/agent/register` / `/api/agent/<id>/jobs` 200s in temporal proximity to
  a failed `/api/deploy/bulk` call — they are very likely unrelated agents/requests, not evidence
  that the failed deploy "partly worked."

**Once an agent is actually running on a target**, its job-execution loop
(`agent/orca_agent.py:_run_velociraptor`, `_run_clamav`, `_run_grype`, `_run_memory`,
`_run_vql_test`) shells out to **Windows `.exe` binaries that exist on the target Windows
machine**, not in the Linux container — this is correct and unaffected by containerization.

**The critical gap:** the agent's job-type system supports exactly 5 hardcoded job types —
`velociraptor` (single ad-hoc VQL string), `clamav`, `grype`, `memory`, `vql_test` — and **none of
them represents "collect every MITRE technique relevant to this asset's case,"** which is what
`/api/deploy/bulk` is supposed to do. Confirmed via grep: the only production caller of
`dispatch_and_wait()` (the synchronous dispatch-and-block helper) is
`backend/routes/mitre_routes.py:1060` (`POST /library/test`), the admin "Test VQL" feature, which
dispatches one ad-hoc `vql_test` job to "whichever agent registered/heartbeated most recently" —
entirely disconnected from per-asset bulk technique collection. **Even with a fully working
deployment, the agent path today cannot perform the work `/api/deploy/bulk` is meant to do** — it
would need a new job type (e.g. `bulk_technique_collection`) plus wiring from
`deploy_routes.py`/`mitre_routes.py` into `dispatch_and_wait` per technique.

---

## 3. Every place the backend shells out to a Windows-only `.exe`

| Call site | Binary | Runs where | Container-safe? |
|---|---|---|---|
| `deploy_routes.py` `_run_psexec` (bulk deploy trigger) | `bin/psexec.exe` | **in the container** | ❌ broken — Windows PE, WSL interop failure |
| `agent_routes.py` `/deploy` (agent push trigger) | `bin/psexec.exe` | **in the container** | ❌ broken — same as above |
| `vr_remote.py` `_collect_smb_psexec` (triage transport) | `bin/psexec.exe` | **in the container** | ❌ broken — same as above |
| `velociraptor_manager.py` (local Velociraptor GUI feature) | `cfg.VR_EXE` → `bin/velociraptor` (no `.exe`, since container is Linux) | **in the container** | ❌ broken — file doesn't exist; only `velociraptor.exe` (Windows) is present. This is a **separate, local-only feature** (in-container Velociraptor GUI/hunt manager), unrelated to remote collection, but it shares the same broken `cfg.VR_EXE` resolution. |
| `package_builder.py` `build_package`/`build_triage_package` | `cfg.VR_EXE` → same broken path | resolved **in the container** but the binary is meant to be **shipped to and run on the Windows target** | ❌ broken for the wrong reason — needs the Windows `.exe` regardless of container OS, but `cfg.VR_EXE`'s `platform.system()` check resolves to the container's OS (Linux), not the target's |
| `agent/orca_agent.py` (`velociraptor.exe`, `clamscan.exe`, `grype.exe`, `syft.exe`) | various `.exe` | **on the remote Windows target**, by the agent process running there | ✅ fine — never executes in the container |
| `vr_remote.py` `_collect_winrm` | pushes `velociraptor.exe` bytes over WinRM, executes **on the remote target** via `session.run_cmd` | remote | ✅ fine — pure-Python `pywinrm` client in the container, no local exec |
| `vr_remote.py` `_collect_smb_task` | pushes `velociraptor.exe` over SMB (`impacket`), triggers via Windows Task Scheduler RPC | remote | ✅ fine — pure-Python `impacket` client in the container, no local exec |
| `vr_remote.py` `_collect_ssh` | pushes a **Linux** `velociraptor` binary, runs over SSH | remote (assumes a Linux target — not applicable to Windows assets) | N/A for Windows targets |

**Root cause #1 (delivery/trigger):** `psexec.exe` is shelled out to directly from the container
in three separate call sites. None of them can work as-is under Docker Desktop/WSL2 — the
failure is consistent, not transient, because it's an architectural mismatch (Windows PE vs.
Linux container), not a flaky environment issue.

**Root cause #2 (payload):** `cfg.VR_EXE` (`backend/config.py:11,42-45`) is computed from
`platform.system()` of the machine running the backend process — i.e. the **container's** OS
(Linux) — and used for two purposes that need *opposite* platform semantics:
- `package_builder.py` / `vr_remote.py` need the **Windows** binary (`velociraptor.exe`) because
  it's shipped to and executed on Windows targets, regardless of what OS is orchestrating the
  build.
- `velociraptor_manager.py` needs a binary matching the **container's actual platform** (Linux)
  because it executes the binary directly inside the container for the local GUI feature.

Both currently resolve to the same broken path (`/app/bin/velociraptor`, no extension), which
doesn't exist — only `velociraptor.exe` (Windows) is present in `backend/bin/`. This breaks both
use cases simultaneously, for different reasons.

---

## 4. Which mechanism is (or should be) load-bearing?

Three mechanisms exist today, all partially wired, none complete:

1. **PsExec push of a self-contained ZIP package** (`deploy_routes.py` + `package_builder.py` +
   `ingest_routes.py` + `run_orca_collection.ps1`) — this is what `/api/deploy/bulk` (the "Deploy
   to Host" button in `CaseDetail.jsx`) actually calls. **This is the one named in the bug
   report and is clearly intended to be the primary, load-bearing mechanism** — it's the only one
   wired to the per-asset, per-case, all-relevant-techniques bulk collection UI. Once triggered,
   its data path is sound and container-safe: the bootstrap PS1 and `run_orca_collection.ps1` run
   entirely on the Windows target and push results back to `backend/ingest_routes.py`'s
   `/api/ingest/remote/{asset_id}/...` endpoints over plain HTTPS — no further container-side
   Windows execution is needed once the package is delivered. **Only the trigger step (psexec)
   and the payload-bundling step (missing `velociraptor.exe`) are broken.**

2. **Lightweight persistent agent** (`agent_routes.py` + `agent/orca_agent.py`) — currently only
   used for the unrelated single-shot "Test VQL" admin feature. Architecturally sound (poll-based,
   no inbound connectivity needed to the target) but **does not have a job type for bulk
   technique collection** and its own deploy trigger (`/api/agent/deploy`) has the identical
   broken psexec dependency, currently masked by a non-IP-scoped "any agent checked in recently"
   success check.

3. **`velociraptor_manager.py`'s in-container Velociraptor GUI** — this is a **local** feature
   (case/hunt management UI embedded via iframe), not a remote-collection mechanism at all. It's
   broken by the same `cfg.VR_EXE` bug but is out of scope for "remote collection" — included here
   only because it shares the root cause.

**Not currently wired to `/api/deploy/bulk` at all, but already implemented and container-safe:**
`vr_remote.py`'s `WINRM` and `SMB_TASK` transports. These are pure-Python protocol clients
(`pywinrm`, `impacket`) that push `velociraptor.exe` to the target and trigger execution via
WinRM or the Windows Task Scheduler RPC — **no local Windows binary execution in the container at
all**. Today they're only reachable via the separate `/api/deploy/triage-execute` endpoint (the
"triage" feature, a fixed list of forensic artifact categories, not the per-technique MITRE
collection that `/api/deploy/bulk` performs).

**Conclusion:** mechanism (1) — PsExec push of the per-asset technique package — is the intended
load-bearing path for "Deploy to Host." It is fixable without an architecture change to the data
path; only the *trigger* (psexec → something container-safe) and the *payload bundling*
(`cfg.VR_EXE` platform bug) need to change.

---

## Phase 2 — Proposed directions

### Option A — Replace PsExec with WinRM/SMB-Task as the trigger (recommended)
Reuse `vr_remote.py`'s existing `_collect_winrm` / `_collect_smb_task` transport logic (or the
underlying `pywinrm`/`impacket` calls) as the trigger mechanism for `deploy_routes.py`'s
`_deploy_single()`, replacing the `psexec.exe` subprocess call. Concretely: instead of shelling
out to push+run the oneliner, open a WinRM (or SMB+Task Scheduler) session from the container
directly to the target and run the same PowerShell oneliner that fetches the bootstrap script.
Everything downstream (bootstrap → ZIP → `run_orca_collection.ps1` → HTTP push to
`ingest_routes.py`) is unchanged and already container-safe.
Also fix `cfg.VR_EXE` (see "Required regardless" below) so the ZIP actually contains
`velociraptor.exe`.
- **Pros:** Removes the WSL-interop dependency entirely; no local Windows binary execution
  anywhere in the container; reuses already-written, already-tested transport code
  (`vr_remote.py`); smallest behavioral change to the existing package/bootstrap/ingest pipeline;
  fixes all three psexec call sites (`deploy_routes.py`, `agent_routes.py`, `vr_remote.py`'s own
  `_collect_smb_psexec`) with one pattern.
  WinRM is usually already enabled in well-managed Windows fleets (it's how most EDR/RMM tools
  work); SMB+Task Scheduler works against stock Windows with just SMB/445 open (same prerequisite
  PsExec already had).
- **Cons:** WinRM (port 5985) may not be enabled on all targets by default — needs
  `winrm quickconfig` or GPO; NTLM-over-WinRM may be blocked by some hardening baselines. SMB+Task
  Scheduler (`impacket`) requires `ADMIN$` share access — same admin-credential requirement PsExec
  already had, so no new privilege requirement, but is a less common code path to maintain
  (`impacket` DCE/RPC is fiddly).
- **Effort:** Medium. Mostly plumbing — adapt the existing transport functions to call
  `package_builder.build_package`'s oneliner instead of `vr_remote`'s own VQL-per-technique loop,
  or vice versa: have `deploy_routes.py` call into `vr_remote._dispatch` with a "run-this-oneliner"
  variant.

### Option B — Make the agent path primary
Finish wiring the agent system: add a `bulk_technique_collection` job type to
`agent/orca_agent.py` that takes a `case_name`/`asset_id`/technique list and runs the same
VQL/YAML-per-technique logic `package_builder.py` currently templates into
`run_orca_collection.ps1`. Have `/api/deploy/bulk` dispatch this job type via
`dispatch_and_wait`/the job-queue system instead of building a ZIP+psexec. Initial agent
*installation* still needs a trigger (WinRM/SMB-Task per Option A, or manual one-time install via
the existing `MANUAL_INSTALL` flow already in `AgentDeployModal.jsx`), but ongoing collection runs
no longer need any trigger at all — the already-running agent just polls for jobs.
- **Pros:** Most robust long-term: once an agent is installed, it survives reboots
  (`schtasks ... /sc ONSTART`), needs no per-collection remote-exec round trip, and naturally
  supports re-running/re-trying jobs, streaming partial progress, and fleet-wide visibility
  (`AgentDeployModal.jsx` already has a fleet table). Also closes the "false success" bug in
  `/api/agent/deploy`'s unscoped last-60s check, since collection completion would now be a real
  per-job status instead of an `agent_registrations` heartbeat guess.
- **Cons:** Most implementation work — new job type, new params schema, new result-ingestion path
  (today's job results stream back as raw JSON lines via `_job_streams`/SSE, not via the existing
  `evidence_normalizer.normalize_and_ingest` JSONL-file pipeline the ZIP path uses — would need a
  bridge or a parallel ingestion path). Still needs *some* initial trigger mechanism (doesn't
  eliminate Option A's WinRM/SMB-Task work, just confines it to one-time install instead of every
  collection run). Largest behavior change relative to what's there today.
- **Effort:** High.

### Option C — Host-side helper for the Windows-only step
Keep PsExec, but move *only* the psexec invocation to a small native-Windows helper process
running outside the Linux container (on the Docker host, since this is Docker Desktop/WSL2 on
Windows) that the backend calls over a local HTTP/TCP socket (e.g. `host.docker.internal:<port>`).
The container sends `{ip, username, password, command}`; the helper runs real `psexec.exe`
natively on the Windows host OS (no WSL interop involved) and returns the result.
- **Pros:** Smallest code change to `deploy_routes.py`/`agent_routes.py`'s call sites (swap
  `asyncio.create_subprocess_exec` for an HTTP call); keeps PsExec's behavior/semantics exactly as
  they were pre-containerization; no new remote-target prerequisites (no WinRM enablement needed).
- **Cons:** Introduces a new always-on Windows-native process to install/manage/secure *outside*
  Docker — re-introduces exactly the "Windows-host-coupled" deployment friction the project's
  recent portability work (`CLAUDE.md`'s 2026-06-18 entry) was explicitly trying to eliminate.
  Only works at all because the Docker host happens to be Windows — breaks again if ORCA is ever
  deployed on a Linux Docker host (a real possibility given the portability work already done).
  Credentials would cross a container boundary over a local socket — needs care even though it's
  loopback-only.
- **Effort:** Medium, but ongoing operational cost (one more moving part to deploy/monitor) and
  conflicts with the portability direction already chosen this project.

### Required regardless of which option is picked
Fix `cfg.VR_EXE`'s platform detection (`backend/config.py`) — it currently conflates "the
container's OS" with "the target's OS." Concretely: introduce two separate config values, e.g.
`VR_EXE_WINDOWS` (always `bin/velociraptor.exe`, for packages shipped to Windows targets and for
`vr_remote.py`'s WinRM/SMB-Task pushes) and `VR_EXE_LOCAL` (platform-suffixed, for
`velociraptor_manager.py`'s in-container GUI feature — which would need a Linux `velociraptor`
binary added to `backend/bin/` to actually work, since none exists today). This is a small,
isolated fix needed under every option above.

### Recommendation
**Option A.** It fixes the exact bug reported, reuses already-correct, already-written code
(`vr_remote.py`'s WinRM/SMB-Task transports exist and work for the triage feature today), requires
no new remote-target software installation, and doesn't reintroduce a host-OS coupling the project
just finished removing. Option B is the better long-term architecture (and the agent fleet UI is
already half-built for it) but is significantly more work and isn't necessary to fix the reported
bug. Option C actively conflicts with the portability work already completed.

---

## Files read this session (Phase 1)
`backend/deploy_routes.py`, `backend/package_builder.py`, `backend/config.py`,
`backend/vr_remote.py`, `backend/agent_routes.py`, `agent/orca_agent.py`,
`backend/velociraptor_manager.py`, `backend/ingest_routes.py` (partial), `backend/main.py`
(router registration), `backend/routes/mitre_routes.py` (`/library/test` excerpt),
`backend/run_orca_collection.ps1` (header), `frontend/src/components/investigations/CaseDetail.jsx`
(`handleDeploy`), `frontend/src/components/AgentDeployModal.jsx`,
`frontend/src/components/VelociraptorModal.jsx`, `docker-compose.yml`, `frontend/nginx.conf`.

**No code was modified in this pass.** Awaiting direction (A / B / C / other) before implementing.
