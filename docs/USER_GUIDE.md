# ORCA User Guide

This guide covers day-to-day operation of the ORCA platform for analysts.

---

## Table of Contents

1. [Logging In](#logging-in)
2. [Dashboard](#dashboard)
3. [Creating a Case and Adding Assets](#creating-a-case-and-adding-assets)
4. [Configuring and Running an Investigation](#configuring-and-running-an-investigation)
5. [Remote Collection Deployment](#remote-collection-deployment)
6. [Reviewing Evidence in the Evidence Window](#reviewing-evidence-in-the-evidence-window)
7. [MITRE ATT&CK Matrix View, Verdict Workflow, and Analyst Notes](#mitre-attck-matrix-view-verdict-workflow-and-analyst-notes)
8. [Memory Forensics (Volatility3)](#memory-forensics-volatility3)
9. [Malware Scanning (ClamAV)](#malware-scanning-clamav)
10. [Vulnerability Scanning (Grype)](#vulnerability-scanning-grype)
11. [Disk Image Mounting](#disk-image-mounting)
12. [IOC Management](#ioc-management)
13. [Generating Reports](#generating-reports)
14. [Tools Menu](#tools-menu)
15. [Options Menu](#options-menu)

---

## Logging In

Navigate to `https://<server-ip>` in your browser. On first visit, accept the self-signed certificate warning (click **Advanced** → **Proceed**). Enter your username and password. Sessions expire after 60 minutes; you will be redirected to the login screen when your token expires.

---

## Dashboard

The **Dashboard** is the landing page after login. It shows:

- **SITUATION_ROOM_UPLINK** — a video feed widget (ambient situational awareness)
- **DATABASE_STATUS** — live indicator: `CONNECTED_STABLE` (green) or `OFFLINE_ERR_500` (red)
- **SYSTEM_INFO** — your current auth role
- **AGENT_FLEET** — count of online/offline persistent agents; click **MANAGE / DEPLOY** to open the Agent Fleet modal
- **ACTIVE_INVESTIGATIONS** — list of cases; click any case to jump to the Investigations view

---

## Creating a Case and Adding Assets

1. Click **INVESTIGATIONS** in the left nav.
2. The **Investigation Gallery** loads, showing all existing cases.
3. Click **+ NEW CASE** (or the equivalent create button) and fill in:
   - **Case Name** — unique identifier
   - **Focus Country** — binds the case to a geopolitical threat profile (all threat groups attributed to that country, and their ATT&CK techniques, are automatically in scope)
   - Or select **Custom Profile / Threat Groups** to scope by specific threat actors instead
4. After creating the case, click it to open **Case Detail**.
5. In the **ASSETS** section, click **+ ADD ASSET** and enter:
   - **Hostname**
   - **IP Address** (required for remote collection)
   - **OS** (`Windows`, `Linux`, `macOS`)
   - **Asset Type**
   - **Analysis Mode** (`LIVE_REMOTE`, `DEAD_DISK_LOCAL`, `DEAD_DISK_MOUNTED`)

### Network Map

The **OVERVIEW** tab contains an interactive D3.js network map. Drag nodes to arrange your asset topology; positions are auto-saved to the case. Use the link tool to draw connections between nodes. The map is rendered as an image in report exports.

### Case Notes

Under the **NOTES** tab, add free-text notes at the case level. Notes can be typed as:
- **NOTE** — general observation
- **BLUF** — executive-summary-level finding (appears in the report BLUF section)

---

## Configuring and Running an Investigation

### Country-Based Scope

When a case has a **Focus Country** set, ORCA automatically resolves:
1. All threat groups attributed to that country (via the `threat_attribution` table)
2. All ATT&CK techniques used by those groups (via STIX `uses` relationships)
3. Only techniques that have a VQL or YAML artifact collection entry in the library

The resulting technique list is your investigation scope. You can view it per asset by opening the **Evidence Window**.

### Custom Investigation Profile

Instead of a country, you can scope an investigation to a named profile (a curated T-code list you created in **Tools → Investigation Profiles**). Select the profile from the **GEOPOLITICAL_FOCUS** dropdown when creating or editing the case — custom profiles appear under "CUSTOM PROFILES" in the dropdown.

---

## Remote Collection Deployment

ORCA can push a complete Velociraptor collection package to a remote Windows endpoint and trigger it automatically. The remote host only needs **port 445 (SMB)** open and local administrator credentials.

### Deploy to Host (Full MITRE Collection)

1. Open a case → **ASSETS** tab.
2. Click **DEPLOY** (or the bulk-deploy button).
3. Select the assets to target.
4. Enter **Windows credentials** (domain optional) for the target hosts.
5. Choose **Transport**: `SMB/Task Scheduler` (default, port 445) or `WinRM` (opt-in, requires port 5985 on target).
6. Click **EXECUTE**.

ORCA will:
- Build a ZIP package containing the Velociraptor binary, a PowerShell bootstrap script, and per-technique VQL/YAML files
- Upload the package to the target via SMB
- Register and trigger a throwaway scheduled task to execute the bootstrap
- Monitor ingest progress in real time via the **PKG** panel

### Triage Deployment

Triage collection targets specific artifact categories without requiring the full MITRE technique scope:

1. Click the **TRIAGE** button (in the asset/deploy panel).
2. Select the target assets.
3. Select artifact categories:
   - Event Logs (Security, Application, Sysmon, PowerShell, System)
   - Prefetch
   - MFT
   - Registry
   - Browser Artifacts
   - LNK / Jump Lists
   - Scheduled Tasks
   - WMI Persistence
   - SRUM
   - Amcache
   - Recycle Bin
   - USB Artifacts
4. Enter credentials and trigger.

### Manual Package (Air-Gapped / Manual Deploy)

1. Click **GENERATE PKG** on an asset.
2. ORCA generates a bootstrap one-liner command.
3. Copy the command and run it on the target host manually (e.g. via an existing remote access method).
4. The package self-destructs after all techniques report back (token auto-revokes on completion).

### Collection Progress

The **PKG** panel on each asset shows live collection progress:
- Total techniques expected
- Techniques received (with evidence or reported no-artifacts)
- Per-technique status: `UNCLAIMED`, `IN_PROGRESS`, `COMPLETE`, `NO_ARTIFACTS`, `FALLBACK_COMPLETE`

---

## Reviewing Evidence in the Evidence Window

1. From **Case Detail → ASSETS**, click **INVESTIGATE** on an asset.
2. The **Evidence Window** opens (full-screen overlay) showing all techniques in scope for this asset's case.
3. Techniques are listed by **tactic** (Discovery, Persistence, etc.).
4. Click a technique row to expand:
   - **Evidence data** — raw JSON records collected for this technique, displayed in a scrollable table
   - **Verdict selector** — set the verdict for this technique on this asset
   - **Notes** — add analyst annotations at the technique level
   - **Status** — change the lifecycle status (UNCLAIMED → IN_PROGRESS → PENDING_REVIEW → CLOSED)

### Timeline View

Click **TIMELINE** (per-asset button in Case Detail) to open the Timeline Viewer, which shows all analyst notes across all techniques for this asset in chronological order.

### Collaboration

The Evidence Window includes real-time collaboration. When an analyst opens a technique, other analysts see it as "claimed." A notification tray shows active collaborators.

---

## MITRE ATT&CK Matrix View, Verdict Workflow, and Analyst Notes

### MITRE ATT&CK Browser (Tools)

Navigate to **Tools → MITRE ATT&CK** to browse the full ATT&CK knowledge base:
- Search threat groups, actors, and campaigns
- Click any group to open a **Dossier** view showing:
  - Group description
  - All associated techniques organised by tactic
  - Links to the MITRE ATT&CK website for each technique

### Verdict Workflow

Each technique on each asset follows this verdict lifecycle:

| Verdict | Meaning |
|---------|---------|
| `MALICIOUS` | Evidence found and confirmed malicious activity |
| `NON-MALICIOUS` | Evidence found but assessed as benign |
| `Evidence Found` | Evidence present, assessment pending |
| `NO_ARTIFACTS` | Velociraptor found no relevant artifacts |
| `Undetermined` | Not yet reviewed |

Set the verdict from the Evidence Window or the AssetInvestigation panel. Setting a verdict of `MALICIOUS` or `NON-MALICIOUS` counts as "closed" in the completion percentage.

### Analyst Notes

Notes can be added at two levels:
- **Case notes** (BLUF or NOTE type) — from the NOTES tab in Case Detail
- **Technique notes** — from inside the Evidence Window, attached to a specific T-code and asset

All notes carry author initials and a timestamp. They appear in the report timeline.

### Case Completion

The case header shows a **completion percentage** (techniques with a definitive verdict / total techniques in scope). This updates live as verdicts are submitted.

---

## Memory Forensics (Volatility3)

Memory analysis is available from the **AssetActionTab** in Case Detail (the analysis actions panel for each asset).

### Run Specific Plugins

1. Select an asset → click the memory analysis action.
2. Enter the **memory image path** (local to the ORCA server or a mounted path).
3. Select **OS** (Windows, Linux, macOS).
4. Select one or more **plugins** from the categorised list (Process Analysis, Code Injection, Credentials, Registry, Network, Rootkit/Evasion, DLL/Module, Files/MFT, Persistence, System Info).
5. Optionally provide a symbol path for Volatility3.
6. Click **Run** — results stream back via SSE and are stored per asset/T-code.

### Full Scan

Full-scan mode automatically selects all OS-appropriate plugins and runs them in sequence. Results are correlated with MITRE ATT&CK technique mappings.

### Actor-Targeted Scan

Select a known threat actor (26 actors are pre-mapped, including APT28, APT29, Lazarus Group, LockBit, Conti, etc.). ORCA selects only the Volatility3 plugins whose outputs are mapped to that actor's known techniques.

### Memory Acquisition

Use the **Acquire** action with a destination path to run WinPMem and capture a live memory image to disk.

### Process Dump

Dump the memory of a specific process by PID using the `windows.pedump` plugin path.

---

## Malware Scanning (ClamAV)

From the asset action panel:

1. Enter the **scan path** (directory to scan).
2. Toggle **Recursive** (default: on).
3. Toggle **Remove infected files** (use with caution).
4. Click **Scan**.

Results stream back in real time. Any malware hits are logged per asset with the malware name and file path.

### Update Signatures

Click **Update ClamAV Signatures** to trigger a `freshclam` run. ClamAV signatures are also updated automatically on each container start. For air-gapped deployments, copy the `.cvd`/`.cld` files into `backend/bin/clamav/` manually.

---

## Vulnerability Scanning (Grype)

From the asset action panel:

1. Enter the **scan path** (directory containing binaries or packages).
2. Toggle **Offline mode** (limits to vulnerabilities with known fixes, avoiding DB update calls).
3. Click **Scan**.

ORCA runs **Syft** first to generate a CycloneDX SBOM, then feeds it to **Grype** for CVE matching. Results are stored per asset and displayed as a severity-bucketed table (Critical / High / Medium / Low).

---

## Disk Image Mounting

From the asset action panel or the **MOUNTS** section of an asset:

1. Enter the **image path** (accessible from the ORCA server).
2. Select a **provider** (auto-detected by extension) or override:
   - `.e01`, `.ex01`, `.s01` → LibEwf
   - `.vmdk`, `.vhd`, `.vhdx` → DiscUtils
   - `.qcow`, `.qcow2` → LibQcow
3. Toggle **Read-only** (default: on).
4. Click **Mount**.

The asset's analysis mode changes to `DEAD_DISK_LOCAL` on successful mount. Use the drive letter returned by Arsenal Image Mounter as the source path for Velociraptor collection (`tsource` parameter).

To dismount, click **Dismount** next to the active mount session.

---

## IOC Management

Navigate to **IOCs** in the left nav.

- **View IOCs** — filter by case to see all discovered IOCs
- **Add IOC** — enter an IOC value, type (IP, domain, hash, email, etc.), and optional note
- **Scan Evidence** — ORCA searches all evidence records for the IOC value (substring match against the `raw_data` JSON column) and reports hits by technique

---

## Generating Reports

Navigate to **Reports** in the left nav.

1. Select a case from the list.
2. Review the summary: total techniques, completion percentage, verdict breakdown, BLUF notes, analyst timeline.
3. Click **Export DOCX** or **Export PDF**.

The report includes:
- Cover page with case name and generation timestamp
- Investigation summary tiles (total, malicious, non-malicious, pending)
- Asset breakdown
- BLUF / executive summary notes
- Chronological analyst timeline
- Technique verdicts table (T-code, name, associated actors, verdict, status)
- Network map image

PDF export uses LibreOffice headless conversion (pre-warmed on container start to eliminate cold-start delay).

---

## Tools Menu

### MITRE ATT&CK

Browse the full ATT&CK knowledge base. Select a threat group or actor to view its full TTP profile. Click a technique to navigate to the MITRE ATT&CK website. Use the "intel select" event (emitted when you click a group from the investigation gallery) to auto-populate the dossier.

### Detection Coverage

Shows coverage metrics for every country and custom profile in the database:

- **Summary tiles** — total techniques, % with VQL coverage, % with YAML-only coverage
- **Coverage bars** — stacked bar per country/profile showing VQL-covered vs YAML-only vs uncovered
- **Expandable T-code tables** — per-technique detail: VQL present, YAML present, last updated date
- **Search filter** — narrow by country/profile name or T-code

### Artifact Library Editor

A power-user view for editing the `ref_artifact_library` table directly:

- Browse all techniques that have collection entries
- Edit the **Custom VQL** (Velociraptor Query Language) for a technique
- Edit the **Surgical YAML** (Velociraptor artifact YAML) for a technique
- Changes take effect immediately for future package builds

### Investigation Profiles

Create and manage named custom technique sets:

1. Click **+ New Profile**.
2. Enter a profile name.
3. Select T-codes from the available list (all techniques in the artifact library).
4. Save.

Profiles appear in the **GEOPOLITICAL_FOCUS** dropdown when creating a case (under "CUSTOM PROFILES"), and in the Detection Coverage tool.

---

## Options Menu

### General

**Text Clarity** — a brightness slider (range 0.6–1.4) that adjusts the visual brightness of the entire UI. The setting persists across sessions via `localStorage`. Use the reset button to return to 1.0 (default).

### Network (TLS)

- **Server Identity** — detected IP and hostname of the ORCA server
- **Certificate Info** — expiry date, days remaining, Subject Alternative Names, key type (ECDSA P-256)
- **Regenerate Certificate** (admin only) — generates a new self-signed ECDSA P-256 cert including the current server IP and hostname as SANs. The backend restarts in 5 seconds to load the new cert; nginx detects the cert file change and reloads automatically. You will need to accept the new certificate in your browser.

### User Registry (Admin Only)

- **View all users** — username, initials, role
- **Create user** — username, password, initials, role (`admin` or `analyst`)
- **Delete user** — cannot delete your own account

### Velociraptor GUI

Click **VELOCIRAPTOR** in the Options sidebar to open the Velociraptor web GUI in a modal. This launches the Velociraptor server inside the backend container and opens the GUI URL based on the current hostname. Use this for advanced VQL queries and direct server management.
