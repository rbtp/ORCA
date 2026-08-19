# ORCA API Reference

All endpoints are served over HTTPS (TLS 1.2+). Unless marked **No auth**, requests must include:

```
Authorization: Bearer <jwt>
```

Server-Sent Event (SSE) endpoints that cannot carry headers use a query-string token:

```
GET /api/...?token=<jwt>
```

**Base URL**: `https://<server-ip>:8000`  
**Rate limit on login**: 5 requests per minute per IP

---

## Table of Contents

- [Authentication](#authentication)
- [Assets](#assets)
- [Package & Ingest](#package--ingest)
- [Deploy](#deploy)
- [Agent Fleet](#agent-fleet)
- [MITRE](#mitre)
- [Coverage](#coverage)
- [Investigation Profiles](#investigation-profiles)
- [IOC](#ioc)
- [Reports](#reports)
- [Network / TLS](#network--tls)
- [Admin — Users](#admin--users)
- [Admin — Audit Trail](#admin--audit-trail)
- [Velociraptor](#velociraptor)

---

## Authentication

### POST /api/auth/login

Rate-limited to **5 requests/minute** per IP.

**Request body**
```json
{ "username": "string", "password": "string" }
```

**Response 200**
```json
{
  "access_token": "eyJ...",
  "token_type": "bearer",
  "user": {
    "username": "analyst1",
    "initials": "A1",
    "role": "analyst",
    "id": 3
  }
}
```

**Errors**: `401 INVALID_CREDENTIALS`, `429 Rate limit exceeded`

---

## Assets

### POST /api/assets/execute

Trigger local Velociraptor collection for an asset (inline — runs inside the container against mounted evidence). Returns immediately; collection runs in a background thread pool.

**Request body**
```json
{
  "action": "string",
  "asset_id": 12,
  "tsource": "C:/"
}
```

**Response 200**
```json
{ "status": "initiated", "target_count": 14, "run_id": "20260101_120000" }
```

---

### POST /api/assets/remote-execute

SSE stream — push Velociraptor to a remote asset, collect, pull results back.

**Request body**
```json
{
  "asset_id": 12,
  "ip": "10.0.0.5",
  "transport": "SMB_TASK",
  "username": "Administrator",
  "password": "s3cr3t",
  "domain": null,
  "tsource": "C:",
  "cleanup": true,
  "remap_mounted": null,
  "remap_original": "C"
}
```

**Response**: `text/event-stream`. Each event is `data: {"type": "...", "data": "..."}`.

> Note: `vr_remote.run_remote_collection` is not yet implemented; this endpoint will return `AttributeError` if called.

---

### POST /api/assets/vuln-scan

SSE stream — runs Syft (SBOM generation) then Grype (CVE matching).

**Request body**
```json
{ "asset_id": 12, "scan_path": "/mnt/c/Windows", "offline": false }
```

**SSE event types**: `log`, `summary`, `error`, `done`

**Summary event data**
```json
{
  "total": 42, "critical": 2, "high": 8, "medium": 15, "low": 17,
  "sbom_path": "/app/evidence/asset_12/vuln/syft_sbom.json",
  "vuln_path": "/app/evidence/asset_12/vuln/grype_results.json"
}
```

---

### GET /api/assets/{asset_id}/vuln-results

Retrieve stored vulnerability scan results for an asset.

**Response 200** — array of:
```json
{
  "cve_id": "CVE-2024-1234",
  "severity": "High",
  "package": "openssl",
  "version": "1.1.1t",
  "fix_version": "1.1.1u",
  "fix_state": "fixed",
  "scanned_at": "2026-06-01T12:00:00"
}
```

Ordered by severity (Critical → Low), then CVE ID.

---

### POST /api/assets/mount

Mount a disk image via Arsenal Image Mounter CLI.

**Request body**
```json
{
  "asset_id": 12,
  "image_path": "/evidence/disk.e01",
  "drive_letter": null,
  "provider": "auto",
  "readonly": true
}
```

`provider` values: `"auto"` (detect by extension), `"LibEwf"`, `"DiscUtils"`, `"LibQcow"`, `"None"`.

**Response 200**
```json
{
  "status": "MOUNTED",
  "mount_id": 5,
  "device_number": "0",
  "drive_letter": "E",
  "physical_drive": "\\\\.\\PhysicalDrive2",
  "provider": "LibEwf",
  "output": "..."
}
```

---

### POST /api/assets/dismount

Dismount a mounted image by mount session ID.

**Query params**: `asset_id` (int), `mount_id` (int)

**Response 200**: `{ "status": "DISMOUNTED", "output": "..." }`

---

### GET /api/assets/{asset_id}/mounts

List all mount sessions for an asset.

**Response 200** — array of mount session objects including `id`, `image_path`, `device_number`, `drive_letter`, `status`, `mounted_at`, `dismounted_at`.

---

### POST /api/assets/{asset_id}/package

Generate a collection package for an asset. Returns the bootstrap one-liner and a time-limited download token.

**Response 200**
```json
{
  "token": "uuid",
  "oneliner": "powershell -ExecutionPolicy Bypass -c \"iex (iwr 'https://10.x.x.x:8000/api/packages/<token>/bootstrap').Content\"",
  "technique_count": 14,
  "expires_at": "2026-06-01T14:00:00"
}
```

---

## Package & Ingest

### GET /api/packages/{token}/bootstrap

Serve the bootstrap PowerShell script for a token. **No auth required** — the token itself is the credential.

**Response 200**: `text/plain` — a complete PS1 script that downloads the package ZIP, extracts it, and runs `run_orca_collection.ps1`.

---

### GET /api/packages/{token}/{filename}

Serve the collection ZIP file. **No auth required** — token-gated.

**Response 200**: `application/zip`

---

### DELETE /api/packages/{token}

Manually revoke a package token (marks it as revoked in the database).

**Response 200**: `{ "status": "revoked", "token": "..." }`

---

### POST /api/ingest/remote/{asset_id}/start

Agent check-in at the start of collection. **No JWT required** — authenticated by `X-ORCA-Token` header.

**Headers**: `X-ORCA-Token: <package-token>`

**Request body**
```json
{ "hostname": "DESKTOP-ABC123", "technique_count": 14, "case_name": "Op Phantom" }
```

**Response 200**: `{ "status": "ok", "message": "Ready. Expecting 14 techniques." }`

---

### POST /api/ingest/remote/{asset_id}/status

Per-technique heartbeat from the collection agent.

**Headers**: `X-ORCA-Token: <package-token>`

**Request body**
```json
{ "t_code": "T1059", "status": "RUNNING", "detail": "VQL query executing", "hostname": "DESKTOP-ABC123" }
```

**Response 200**: `{ "status": "ok" }`

---

### POST /api/ingest/remote/{asset_id}/{t_code}

Ingest JSONL evidence for a technique. Body is raw JSONL (one JSON object per line).

**Headers**: `X-ORCA-Token`, `X-Mode: primary|fallback|no_artifacts`, `X-Hostname`

**Response 200**: `{ "status": "ok", "rows": 23, "is_fallback": false }`

---

### POST /api/ingest/remote/{asset_id}/complete

Agent signals collection is complete. Token is auto-revoked.

**Headers**: `X-ORCA-Token`

**Response 200**: `{ "status": "ok", "message": "Token revoked. Collection complete." }`

---

### GET /api/ingest/remote/{asset_id}/progress

Poll collection progress for the UI.

**Response 200**
```json
{
  "asset_id": 12,
  "total": 14,
  "with_evidence": 9,
  "no_artifacts": 3,
  "pending": 2,
  "techniques": [
    { "t_code": "T1059", "technique_status": "COMPLETE", "verdict": null, "evidence_imported": true, "evidence_summary": "{...}" }
  ],
  "package_active": true,
  "package_info": { "technique_count": 14, "techniques_received": 12, "expires_at": "..." }
}
```

---

## Deploy

### POST /api/deploy/bulk

Deploy MITRE collection packages to one or more assets via SMB+Task Scheduler or WinRM. Returns **NDJSON** stream (one JSON object per line, no SSE framing).

**Request body**
```json
{
  "asset_ids": [12, 13, 14],
  "username": "Administrator",
  "password": "s3cr3t",
  "domain": null,
  "transport": "SMB_TASK"
}
```

`transport`: `"SMB_TASK"` (default, requires port 445) or `"WINRM"` (requires port 5985).

**Stream events** (NDJSON):
```json
{ "asset_id": 12, "phase": "DEPLOYING", "message": "DESKTOP-01: Building collection package...", "error": null, "ts": "..." }
{ "asset_id": 12, "phase": "CONNECTING", "message": "DESKTOP-01 (10.0.0.5): Establishing SMB/Task Scheduler session...", "error": null, "ts": "..." }
{ "asset_id": 12, "phase": "COLLECTING", "message": "DESKTOP-01: Collection running — monitor progress in PKG panel", "error": null, "ts": "..." }
```

Phase values: `DEPLOYING`, `CONNECTING`, `AUTHENTICATING`, `EXECUTING`, `COLLECTING`, `ERROR`

---

### GET /api/deploy/psexec-status

Check whether `psexec.exe` is present on the server (informational only; psexec is not used by the bulk deploy path).

**Response 200**: `{ "available": false, "path": "/app/bin/psexec.exe" }`

---

### GET /api/deploy/triage-categories

List available triage category names.

**Response 200**: `{ "categories": ["Event Logs", "Prefetch", "MFT", ...] }`

---

### POST /api/deploy/triage

Deploy triage collection to assets. Returns **NDJSON** stream.

**Request body**
```json
{
  "asset_ids": [12, 13],
  "username": "Administrator",
  "password": "s3cr3t",
  "categories": ["Event Logs", "MFT", "Registry"],
  "transport": "SMB_PSEXEC",
  "trigger_transport": "SMB_TASK",
  "domain": null,
  "cleanup": true
}
```

Stream events have the same shape as `/api/deploy/bulk`.

---

### POST /api/deploy/triage-execute

Execute triage collection against a single asset via a specified transport (SSE stream). Used for the live/interactive triage flow.

**Request body**
```json
{
  "asset_id": 12,
  "ip": "10.0.0.5",
  "transport": "WINRM",
  "username": "Administrator",
  "password": "s3cr3t",
  "categories": ["Event Logs", "MFT"],
  "domain": null,
  "cleanup": true
}
```

**Response**: `text/event-stream`

---

## Agent Fleet

### POST /api/agent/register

Register a persistent agent with the server.

**Request body**
```json
{ "hostname": "WORKSTATION-01", "capabilities": ["collect", "scan", "memory"] }
```

**Response 200**: `{ "agent_id": "a1b2c3d4e5f6a7b8" }`

Agent ID is deterministic: `sha256(hostname + username)[:16]`.

---

### GET /api/agent/list

List all registered agents with online/offline status.

**Response 200** — array of:
```json
{
  "agent_id": "a1b2c3d4e5f6a7b8",
  "hostname": "WORKSTATION-01",
  "analyst": "alice",
  "last_seen": "2026-06-01T12:30:00",
  "capabilities": ["collect", "scan"],
  "status": "ONLINE"
}
```

Agents are `ONLINE` if `last_seen > NOW() - 90 seconds`.

---

### DELETE /api/agent/{agent_id}

Delete an agent registration and all its jobs. **Admin only.**

**Response 200**: `{ "ok": true }`

---

### POST /api/agent/dispatch

Dispatch a job to a specific agent.

**Request body**
```json
{
  "agent_id": "a1b2c3d4e5f6a7b8",
  "job_type": "memory_scan",
  "params": { "image_path": "/evidence/mem.raw", "plugins": ["windows.pslist"] }
}
```

**Response 200**: `{ "job_id": "f3e2d1c0b9a8..." }`

---

### GET /api/agent/{agent_id}/jobs

Long-poll endpoint for an agent to receive its next job. Blocks up to 30 seconds; returns `null` on timeout.

**Response 200**: job object or `null`

---

### POST /api/agent/{agent_id}/jobs/{job_id}/stream

Agent posts streaming output lines for a running job (raw newline-delimited text in request body).

**Response 200**: `{ "ok": true }`

---

### POST /api/agent/{agent_id}/jobs/{job_id}/complete

Agent marks a job as completed.

**Request body**
```json
{ "status": "SUCCESS", "summary": { "rows": 42, "errors": 0 } }
```

**Response 200**: `{ "ok": true }`

---

### GET /api/agent/jobs/{job_id}/stream

SSE stream for the UI to subscribe to a job's output. Replays buffered lines, then streams live.

Auth: `?token=<jwt>` (SSE — headers not supported in browser EventSource).

**Response**: `text/event-stream` — each `data:` line is a raw JSON output line from the agent.

---

### GET /api/agent/download/bin/{filename}

Download a binary for agent deployment.

`filename` values: `velociraptor.exe`, `clamscan.exe`, `grype.exe`, `syft.exe`

**Response 200**: `application/octet-stream`

---

### GET /api/agent/download/orca_agent.py

Download the persistent agent Python script.

Auth: `?token=<jwt>`

**Response 200**: `text/plain`

---

### GET /api/agent/deploy/psexec-status

Check psexec availability on the server (informational).

**Response 200**: `{ "available": false, "path": "..." }`

---

### POST /api/agent/deploy

Deploy the persistent ORCA agent to a remote Windows host via SMB+Task Scheduler or WinRM. Returns SSE stream.

**Request body**
```json
{
  "ip": "10.0.0.5",
  "username": "Administrator",
  "password": "s3cr3t",
  "domain": null,
  "transport": "SMB_TASK"
}
```

**SSE event types**: `log`, `error`, `done`

On success, the agent:
1. Creates `C:\ORCA_Agent\` on the target
2. Downloads `orca_agent.py` and writes `config.json`
3. Installs a `SYSTEM`-run scheduled task (`ORCA_Agent`) for persistence
4. Starts the agent immediately

After triggering, the server polls for the new agent registration for up to 45 seconds and emits the registration confirmation via SSE.

---

## MITRE

All endpoints prefixed with `/api/mitre`.

### GET /api/mitre/cases

List all cases.

**Response 200** — array of case objects: `name`, `description`, `focus_country`, `selected_groups`, `created_at`, `map_data`

---

### POST /api/mitre/cases

Create a new case, or edit an existing one — this is an upsert (`INSERT ... ON CONFLICT (name) DO UPDATE`) keyed on `name`. The "Edit Investigation Details" UI (mission lead, team, support unit, personnel, country) reuses this same endpoint; always pass through `groups`/`case_type` on an edit so they aren't silently cleared.

**Request body**
```json
{
  "name": "Op Phantom",
  "description": "APT investigation Q2 2026",
  "focus_country": "Russia",
  "selected_groups": ""
}
```

**Response 200**: created/updated case object

---

### DELETE /api/mitre/cases/{case_name}

Delete a case and all associated assets, evidence, and notes.

**Response 200**: `{ "status": "deleted" }`

---

### GET /api/mitre/cases/{case_name}/map-background

Get the network map background image for a case (binary image response, or 404 if none set).

---

### PUT /api/mitre/cases/{case_name}/map-background

Upload/replace the network map background image. Multipart file upload, 8MB limit, must be `image/*`.

---

### DELETE /api/mitre/cases/{case_name}/map-background

Clear the network map background image.

---

### GET /api/mitre/cases/{case_name}/assets

List all assets for a case.

**Response 200** — array of: `id`, `hostname`, `ip`, `os`, `asset_type`, `analysis_mode`, `case_name`, `found_t_codes`

---

### POST /api/mitre/cases/{case_name}/assets

Add an asset to a case.

**Request body**
```json
{
  "hostname": "DESKTOP-01",
  "ip": "10.0.0.5",
  "os": "Windows",
  "asset_type": "WORKSTATION",
  "analysis_mode": "LIVE_REMOTE"
}
```

---

### GET /api/mitre/cases/{case_name}/completion

Get completion statistics for a case.

**Response 200**
```json
{
  "total": 20,
  "closed": 12,
  "completion_pct": 60.0,
  "malicious": 3,
  "non_malicious": 9
}
```

---

### GET /api/mitre/threat-profile/{identifier}

Get the technique list for an investigation scope. `identifier` is a case name, country, or profile name.

**Query params**: `asset_id` (optional, int) — if provided, includes per-asset verdict/status

**Response 200** — array of technique objects with `t_code`, `name`, `tactic`, `verdict`, `technique_status`, `evidence_imported`, `analyst_notes`

---

### GET /api/mitre/library/{t_code}

Get the artifact library entry for a technique.

**Response 200**
```json
{
  "t_code": "T1059",
  "name": "Command and Scripting Interpreter",
  "custom_vql": "SELECT ...",
  "surgical_yaml": "name: ...",
  "notes": "...",
  "updated_at": "2026-06-01T10:00:00"
}
```

---

### PUT /api/mitre/library/{t_code}

Update the artifact library entry for a technique.

**Request body**
```json
{
  "custom_vql": "SELECT ...",
  "surgical_yaml": "name: ...",
  "notes": "Updated for Windows 11"
}
```

---

### PUT /api/mitre/evidence/{asset_id}/{t_code}/verdict

Set the verdict for a technique on an asset.

**Request body**: `{ "verdict": "MALICIOUS" }`

Verdict values: `MALICIOUS`, `NON-MALICIOUS`, `Evidence Found`, `NO_ARTIFACTS`, `Undetermined`

---

### GET /api/mitre/evidence/{asset_id}/{t_code}

Get collected evidence records for an asset/technique combination.

**Response 200** — array of evidence rows (raw JSON from Velociraptor output)

---

### POST /api/mitre/evidence/{asset_id}/{t_code}/upload

Manually attach evidence to a technique — available for any technique that doesn't already have evidence, not only ones where automatic collection explicitly returned zero artifacts. Rows are parsed client-side from a JSON/JSONL/CSV/TXT file before this call. Sets `verdict = 'MANUAL_UPLOAD'` and `evidence_imported = TRUE` on the technique.

**Request body**
```json
{ "rows": [{ "...": "..." }], "filename": "manual_upload.json" }
```

**Response 200**: `{ "status": "ok", "rows_ingested": 12 }`

---

### DELETE /api/mitre/evidence/{asset_id}/{t_code}

Flush all evidence collected for one technique on one asset — **admin only** (`403` otherwise). Deletes the `evidence` rows and resets `evidence_imported`/`evidence_summary` on that technique; the verdict itself is left untouched. Every call writes a row to `audit_log` (operator, case, asset, technique, rows removed) in the same transaction, so a deletion can never happen without being logged. The frontend gates this behind a 3-step confirmation (confirm → math check → "this is logged" warning) before issuing the request.

**Response 200**: `{ "status": "SUCCESS", "rows_removed": 12 }`

---

### GET /api/mitre/evidence/{asset_id}/timeline

Get the analyst timeline across all techniques for an asset. Supports filtering, date range, source type selection, and pagination.

**Query params**: `from`, `to` (ISO datetime), `sources` (comma-separated), `filters` (pipe-separated strings), `page` (int, default 1)

**Response 200**
```json
{
  "entries": [...],
  "total": 1500,
  "page": 1,
  "page_size": 200
}
```

---

### GET /api/mitre/geopolitical/groups

Get the list of threat groups with their techniques, for the MITRE inspector sidebar.

**Response 200** — array of group objects with `id`, `name`, `stix_id`, `description`, `linkedTechniques`

---

### POST /api/mitre/map

Save the network map node/link data for a case.

**Request body**: `{ "nodes": [...], "links": [...] }`

---

### GET /api/mitre/map

Get the network map data for a case (query param `case_name`).

---

### POST /api/mitre/memory/run

Run one or more Volatility3 plugins against a memory image. Returns SSE stream.

**Request body**
```json
{
  "asset_id": "12",
  "image_path": "/evidence/mem.raw",
  "plugins": ["windows.pslist", "windows.malfind"],
  "os_profile": "windows",
  "args": [],
  "symbol_paths": null,
  "vol3_base": "/app/bin/remora/volatility3"
}
```

---

### POST /api/mitre/memory/full-scan

Run all Volatility3 plugins applicable to the target OS. Returns SSE stream.

**Request body**: Same as `/memory/run` but no `plugins` field (selected automatically).

---

### POST /api/mitre/memory/actor-scan

Run the subset of Volatility3 plugins mapped to a specific threat actor's known techniques.

**Request body**
```json
{
  "asset_id": "12",
  "image_path": "/evidence/mem.raw",
  "actor_name": "APT29 (Cozy Bear / The Dukes)",
  "os_profile": "windows",
  "vol3_base": "/app/bin/remora/volatility3"
}
```

---

### POST /api/mitre/memory/acquire

Acquire a live memory image via WinPMem. Returns SSE stream.

**Request body**
```json
{
  "asset_id": "12",
  "destination_path": "/evidence/mem.raw",
  "winpmem_base": "/app/bin/remora/volatility3"
}
```

---

### POST /api/mitre/memory/dump-process

Dump a specific process by PID. Returns SSE stream.

**Request body**
```json
{
  "asset_id": "12",
  "image_path": "/evidence/mem.raw",
  "pid": 1234,
  "destination_path": "/evidence/",
  "vol3_base": "/app/bin/remora/volatility3"
}
```

---

### POST /api/mitre/clamscan

Run a ClamAV scan. Returns SSE stream.

**Request body**
```json
{
  "asset_id": "12",
  "scan_path": "/mnt/c/Windows",
  "recursive": true,
  "remove": false,
  "clam_base": "/app/bin/clamav"
}
```

---

### POST /api/mitre/clamav-update

Trigger a freshclam signature update. Returns SSE stream.

**Request body**: `{ "clam_base": "/app/bin/clamav" }`

---

### GET /api/mitre/scan/clam/results/{asset_id}

Retrieve stored ClamAV scan results for an asset.

---

### GET /api/mitre/assets/{asset_id}/net-config

Get stored network device configuration text for an asset.

---

### POST /api/mitre/assets/{asset_id}/net-config

Save network device configuration text for an asset.

---

### GET /api/mitre/collaboration/stream

SSE stream for real-time collaboration: technique lock/unlock events, kickbacks, tool locks.

Auth: `?token=<jwt>`

**Event types**: `TECHNIQUE_CLAIMED`, `TECHNIQUE_RELEASED`, `TECHNIQUE_SUBMITTED`, `TECHNIQUE_CLOSED`, `KICKBACK`, `TOOL_LOCKED`, `TOOL_RELEASED`, `HEARTBEAT`

---

### POST /api/mitre/collaboration/claim

Claim a technique lock for the current analyst.

**Request body**: `{ "asset_id": 12, "t_code": "T1059" }`

---

### POST /api/mitre/collaboration/release

Release a technique lock.

**Request body**: `{ "asset_id": 12, "t_code": "T1059" }`

---

### POST /api/mitre/notes/case

Add a case-level note.

**Request body**: `{ "case_name": "Op Phantom", "note_text": "Initial access confirmed", "note_type": "BLUF" }`

---

### POST /api/mitre/notes/tcode

Add a technique-level note.

**Request body**
```json
{
  "asset_id": 12,
  "t_code": "T1059",
  "text": "PowerShell used to download and execute malware",
  "note_type": "NOTE"
}
```

---

## Coverage

### GET /api/coverage

Get detection coverage metrics for all countries and custom profiles.

**Response 200** — array of coverage entries (one per country or profile):
```json
{
  "type": "country",
  "name": "Russia",
  "total": 45,
  "covered": 32,
  "partial": 8,
  "coverage_pct": 71.1,
  "tcodes": [
    {
      "t_code": "T1059",
      "name": "Command and Scripting Interpreter",
      "has_vql": true,
      "has_yaml": true,
      "updated_at": "2026-06-01T10:00:00"
    }
  ]
}
```

`type` is `"country"` or `"profile"`. `covered` = techniques with custom VQL. `partial` = techniques with YAML only.

---

## Investigation Profiles

### GET /api/profiles

List all investigation profiles.

**Response 200** — array of: `id`, `name`, `tcodes` (array of T-code strings), `created_at`, `updated_at`

---

### POST /api/profiles

Create a new profile.

**Request body**
```json
{ "name": "Ransomware Initial Access", "tcodes": ["T1059", "T1086", "T1547.001"] }
```

**Response 200**: created profile object  
**Errors**: `409` if name already exists

---

### PUT /api/profiles/{profile_id}

Update a profile's name and/or T-code list.

**Request body**
```json
{ "name": "Updated Name", "tcodes": ["T1059", "T1055"] }
```

Both fields are optional.

---

### DELETE /api/profiles/{profile_id}

Delete a profile.

**Response 200**: `{ "status": "deleted", "id": 3 }`

---

### GET /api/profiles/tcodes/available

List all T-codes available for profile selection (from the artifact library).

**Response 200** — array of: `{ "t_code": "T1059", "name": "Command and Scripting Interpreter" }`

---

## IOC

### GET /api/ioc/cases/{case_name}

List discovered IOCs for a case.

**Response 200** — array of: `id`, `ioc_value`, `ioc_type`, `case_name`, `t_code`, `note`, `created_at`

---

### POST /api/ioc/cases/{case_name}

Add an IOC to a case.

**Request body**
```json
{
  "ioc_value": "185.220.101.45",
  "ioc_type": "IP_V4",
  "t_code": "T1071",
  "note": "C2 server observed in netstat output"
}
```

**Errors**: `409` if the same IOC value already exists for this case.

---

### DELETE /api/ioc/{ioc_id}

Delete an IOC.

**Response 200**: `{ "status": "deleted" }`

---

### POST /api/ioc/scan/{case_name}

Search all evidence records for a case for the given IOC value (substring match).

**Request body**: `{ "ioc_value": "185.220.101.45" }`

**Response 200**: array of evidence hit objects indicating which techniques contain the value.

---

## Reports

### GET /api/reports/{case_name}

Get the full report data for a case.

**Query params**: `asset_id` (optional int) — scope results to a single asset.

**Response 200**
```json
{
  "case_name": "Op Phantom",
  "focus_country": "Russia",
  "generated_at": "2026-06-01T14:00:00",
  "summary": {
    "total_techniques": 20,
    "closed": 12,
    "with_evidence": 15,
    "no_artifacts": 3,
    "pending": 2,
    "completion_pct": 60.0,
    "malicious": 3,
    "non_malicious": 9,
    "evidence_found": 2,
    "undetermined": 6
  },
  "bluf_notes": [...],
  "timeline": [...],
  "techniques": [...],
  "assets": [...],
  "per_asset_techniques": { "12": [...] },
  "map_data": { "nodes": [], "links": [] }
}
```

---

### POST /api/reports/{case_name}/export

Export a case report as DOCX or PDF.

**Query params**: `format` (`"docx"` default or `"pdf"`), `range_from`, `range_to` (ISO date strings for timeline filter)

**Request body** (optional)
```json
{
  "sections": [
    { "id": "summary", "detail": false },
    { "id": "network", "detail": false },
    { "id": "assets", "detail": true },
    { "id": "bluf", "detail": false },
    { "id": "timeline", "detail": false },
    { "id": "verdicts", "detail": false }
  ]
}
```

**Response 200**: binary file download  
- DOCX: `Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document`  
- PDF: `Content-Type: application/pdf`

PDF conversion requires LibreOffice headless (pre-installed in the backend container).

---

## Network / TLS

### GET /api/network/cert-info

Get TLS certificate information.

**Response 200**
```json
{
  "cert_exists": true,
  "sans": ["IP:10.0.0.1", "DNS:orca-backend", "DNS:localhost"],
  "key_type": "ECDSA P-256",
  "not_after": "2027-06-01T12:00:00",
  "days_remaining": 365
}
```

---

### GET /api/network/detected-identity

Get the server's auto-detected IP address and hostname.

**Response 200**: `{ "ip": "10.0.0.1", "hostname": "orca-server" }`

---

### POST /api/network/regenerate-cert

Regenerate the self-signed TLS certificate. **Admin only.**

Generates a new ECDSA P-256 cert with SANs for the current IP and hostname, writes it to the shared `orca-certs` volume, then restarts the backend process after 5 seconds. nginx detects the cert change and reloads automatically.

**Response 200**
```json
{
  "success": true,
  "ip": "10.0.0.1",
  "hostname": "orca-server",
  "san": "IP:10.0.0.1,DNS:orca-server,DNS:orca-backend,DNS:localhost",
  "restart_in_seconds": 5,
  "message": "Certificate regenerated. Backend restarting in 5s — page will reload automatically."
}
```

---

## Admin — Users

All admin endpoints require `role = "admin"`.

### GET /api/admin/users

List all users.

**Response 200** — array of: `{ "username": "alice", "initials": "ALC", "role": "analyst" }`

---

### POST /api/admin/users/create

Create a new user.

**Request body**
```json
{ "username": "alice", "password": "s3cur3pass", "initials": "ALC", "role": "analyst" }
```

`role` values: `"admin"`, `"analyst"`

**Response 200**: `{ "status": "USER_CREATED", "operator": "alice" }`  
**Errors**: `400 OPERATOR_ALREADY_EXISTS`, `400 MISSING_USER_PARAMETERS`

---

### DELETE /api/admin/users/{username}

Delete a user. Cannot delete yourself.

**Response 200**: `{ "status": "OPERATOR_PURGED", "target": "alice" }`  
**Errors**: `400 CANNOT_DELETE_SELF`, `404 USER_NOT_FOUND`

---

## Admin — Audit Trail

### GET /api/admin/audit-log

List logged admin activity (currently: evidence deletions — see `DELETE /api/mitre/evidence/{asset_id}/{t_code}`). **Admin only.** Backs the Options → Audit Trail view.

**Query params**: `case_name` (optional), `asset_id` (optional) — both filter server-side; omit either to get all rows. Capped at the 1000 most recent, newest first.

**Response 200** — array of:
```json
{
  "id": 14,
  "ts": "2026-08-19T10:22:31.000Z",
  "username": "alice",
  "user_initials": "ALC",
  "action": "DELETE_EVIDENCE",
  "case_name": "Op Phantom",
  "asset_id": 12,
  "asset_hostname": "DESKTOP-01",
  "t_code": "T1055",
  "details": "Deleted 8 evidence row(s)"
}
```

---

## Velociraptor

### GET /api/velociraptor/status

Check whether the Velociraptor GUI server is running inside the container.

**Response 200**: `{ "running": true, "port": 8889 }`

---

### POST /api/velociraptor/start

Start the Velociraptor GUI server inside the container (runs the local Velociraptor binary in GUI mode).

**Response 200**: `{ "status": "started", "port": 8889 }`
