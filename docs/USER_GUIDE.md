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

**New account:** an admin sends you an enrollment link (by email, or directly if the server has no email). Open it within 7 days, choose a password (at least 8 characters), and then log in normally.

**Forgot your password:** click the forgot-password link on the login screen and enter your username or email. This only works if the server has email configured. Otherwise, ask an admin to generate a reset link for you. Reset links are valid for 1 hour.

A deactivated account can't log in. Contact an admin.

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
4. After creating the case, click it to open **Case Detail**. Click **[ EDIT_DETAILS ]** next to the case name at any time to update mission lead, team, support unit, personnel, or country — this doesn't create a new case, it updates the existing one.
5. In the **ASSETS** section, click **+ ADD ASSET** and enter:
   - **Hostname**
   - **IP Address** (required for remote collection)
   - **Asset Type** — set this first. It drives which MITRE techniques get associated with the asset, so the fields below it cascade from this choice: choosing `Network Device` locks **Operating System** to `Network` (the only ATT&CK platform that applies to routers/switches/firewalls) and narrows **Form Factor** to network-hardware options; any other type unlocks the normal OS list and host form factors. This prevents ending up with an asset whose type says "Network Device" but whose OS still says "Windows" — which used to silently pull in the wrong technique set.
   - **Operating System** (`Windows`, `Linux`, `macOS`, `Other`, or the locked `Network` value)
   - **Form Factor**
   - **Analysis Mode** (`LIVE_REMOTE`, `DEAD_DISK_LOCAL`, `DEAD_DISK_MOUNTED`)

### Network Map

The **OVERVIEW** tab contains an interactive D3.js network map. Drag nodes to arrange your asset topology; positions are auto-saved to the case. Use the link tool to draw connections between nodes. New nodes spawn near the center of the map instead of stacking on top of each other. Right-click a device (router, switch, firewall, etc.) for **RENAME_DEVICE** to give it a display name independent of its hostname. Use the upload button next to the maximize-map control to set an optional background image behind the map (e.g. a floor plan or topology diagram); it can be replaced or cleared the same way. The map is rendered as an image in report exports.

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
5. Any technique with no evidence yet shows a **manual upload** option (JSON/JSONL/CSV/TXT) — use it to attach evidence that wasn't collected automatically, regardless of whether a collection was ever attempted for that technique.
6. **Running collection from the Evidence Window**: enter a **DRIVE** (e.g. `C:` or `E:`), then either:
   - **▶ RUN ON SERVER** runs collection inside the ORCA server (a Linux container). It cannot see Windows drives, mounted images, Windows event logs or the registry; it only sees the folders ORCA shares with it (cases, memory dumps).
   - pick an online agent under **SELECT AGENT...** and click **▶ RUN ON ANALYST WORKSTATION (AGENT)**. Collection runs on that agent's Windows computer and can reach any drive it sees: its own C:, or a disk image mounted via [Disk Image Mounting](#disk-image-mounting).

   Hover over either button for the same explanation.

   | | Run on server | Run on analyst workstation (agent) |
   |---|---|---|
   | Where it runs | Linux container on the ORCA server | Windows computer running the agent |
   | Can see a mounted image | No | Yes, by its drive letter |
   | Windows event logs / registry | No | Yes |

   **Collecting from a mounted image:** set DRIVE to the image's drive letter (shown in the mount panel). When DRIVE is not the agent computer's own system drive, the agent collects in *dead-disk mode* (Velociraptor's remapping): every technique's `C:\...` paths, event logs, `HKEY_LOCAL_MACHINE` (SYSTEM / SOFTWARE / SAM / SECURITY hives) and `HKEY_USERS` (each user's `NTUSER.DAT`) are read **from the image**, `CurrentControlSet` is resolved to the image's active control set, and `%APPDATA%`-style paths cover every user profile on the image. Techniques that need a running system (process list, network connections, WMI) are marked **not applicable to a disk image** instead of reporting the workstation's own state.

   **Progress:** while a collection runs, a panel under the buttons shows done / total, hits, empty, not-applicable and failed counts, which techniques are running and for how long, and at the end the failed techniques with the reason. Several techniques run at once on the agent: the workstation's cores minus 2 (at least 2, at most 10; 3 with an agent older than this version), 20-minute limit each. Most techniques re-read the same large event logs, so this is what makes a full run faster; the workstation is busy while it runs. Only one collection can run per asset at a time.

   **Running again:** re-running a collection (or re-uploading the same file) only adds rows that are new. A row identical to one already stored for that asset and technique is skipped, so running twice never doubles the evidence; stars and notes on existing rows stay.
7. **Admins only**: a technique that already has evidence shows a red **⚠ FLUSH_EVIDENCE** button next to the verdict selector. This permanently deletes the evidence collected for that technique and is logged — see [Audit Trail (Admin Only)](#audit-trail-admin-only) below.

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

**On a mounted image:** use **RUN ON ANALYST WORKSTATION (AGENT)** with the image's drive letter as the scan path (e.g. `E:\`). If the path doesn't exist on the agent computer the scan fails with `PATH_NOT_FOUND` rather than reporting 0 files. Windows Defender on the workstation may block reading malware on the mounted image (ClamAV then never sees those files); add a Defender exclusion for the mounted drive letter while you scan.

**Agent scans (ClamAV and Syft/Grype) show live progress** in a panel under the path:

- ClamAV: files done / total (the total fills in while the agent lists the files), %, data scanned, threats, unreadable files, files per minute, estimated time left, and the files being scanned right now with how long each has taken. Threats appear in the list as soon as they are found. The agent loads the signatures once (`clamd`) and scans several files at a time (computer's cores minus 2, at most 8): about 2.5x faster than the old single `clamscan` in testing. Installers and archives are unpacked and scanned inside, so a single file can take up to 2 minutes while the others continue. Junctions and symbolic links are not followed (on a mounted image they point at the workstation's own C:). A file with several names (hard links: Windows keeps many files under both `System32` and `WinSxS`) is scanned once, under the first name found; the panel counts the skipped names (about 14% of the files under `C:\Windows`).
- Syft/Grype: step 1/2 (Syft finding installed software) and 2/2 (Grype matching), the target's size, how much the tool has read from disk, and its latest log line. Syft reports no count while it indexes files, so the "read" figure is the sign it's working.
- **Windows Defender** real-time protection on the agent computer scans every file the scanner opens and is usually what makes these scans slow (measured: Defender using a full CPU core while Syft used under a tenth of one). The panel and the log say when Defender is on and the target isn't excluded, with the command to add an exclusion (`Add-MpPreference -ExclusionPath 'E:\'` in an administrator PowerShell; remove it afterwards with `Remove-MpPreference`). ORCA never changes Defender settings itself.
- **STOP** stops the scan on the agent computer (within a few seconds), not only in the browser.
- Closing the Evidence Window or reloading the page doesn't stop the scan; reopening the tab re-attaches to it. Results are saved by the server when the agent finishes, even if nobody has the window open. "No update from the agent for ..." in red means the agent stopped reporting (computer asleep, offline, agent restarted).
- Files ClamAV could not read (locked, access denied, blocked by Defender) are counted as **UNREADABLE** and listed after the scan.

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

1. Pick the agent under **MOUNT_VIA_AGENT** (it needs Arsenal Image Mounter, installed with the agent, and must run as administrator).
2. Enter the **image path** as seen from the agent computer (e.g. `D:\evidence\suspect.E01`), or click **📂 BROWSE** to pick it from that computer's drives and folders (disk-image files are shown in amber). You can also type a folder or UNC path (`\\server\share`) in the dialog's path bar.
3. Optionally pick a **DRIVE_LETTER** for the image's main volume (AUTO lets Windows choose). The letter is applied if it is free.
4. Select a **provider** (auto-detected by extension) or override:
   - `.e01`, `.ex01`, `.s01` → LibEwf
   - `.vmdk`, `.vhd`, `.vhdx` → DiscUtils
   - `.qcow`, `.qcow2` → LibQcow
   - `.001`, `.002`, ... (a raw image split into parts, e.g. by FTK Imager or `split`) → MultiPartRaw: all parts are mounted together as one disk. Pick any part; ORCA mounts from the first (`.001`, or `.000`). If a part in the middle of the set is missing, the mount is refused (it would cut the disk short). The mount panel shows how many parts were mounted.
   - E01 sets: pick any segment; the set is opened from the `.E01` and the remaining segments are found automatically.
5. Click **MOUNT_IMAGE**. The image is mounted read-only.

The image becomes a real Windows disk on the agent computer: it appears in File Explorer and Disk Management, its partitions are brought online and each readable volume gets a drive letter. The mount panel shows the letters Windows actually assigned, each volume's file system, label and size, and the files at the top of the main volume so you can confirm it is the right image. Use that letter as DRIVE for collection and as the scan path for ClamAV / Grype. On the **KNOWN MALWARE SIGNATURES** and **VULN SCAN** tabs, once an agent is selected, **📂 BROWSE** next to the path picks a folder (or, for ClamAV, a single file) on that agent's computer, including the mounted image's drive. If Windows can't give the image a letter (BitLocker, damaged or unsupported file system), the panel says so in red.

The asset's analysis mode changes to `DEAD_DISK_LOCAL` on successful mount. To dismount, click **DISMOUNT** next to the active mount session; the drive letter disappears from the agent computer.

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

The library was audited and largely repaired in November 2026 (`docs/LIBRARY_QUALITY.md`): most queries could never return a row (event looked for in the wrong log, regexes broken by VQL string escaping, fields that don't exist in the event, ...). Before writing or editing a query, read that document's **Rules for writing library queries**, and check a YAML with `velociraptor artifacts verify <file>`. The update keeps any query you edited yourself; `docs/library_scorecard.csv` lists every technique's status and what was changed.

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

### My Account

Edit your own initials and email, and change your password (requires your current password).

### User Registry (Admin Only)

- **View all users**: username, initials, role, email, active status, last login
- **Invite user**: username, initials, role (`admin` or `analyst`), optional email. This produces a one-time enrollment link (valid 7 days) that the user opens to set their own password. If the server has email configured, the link is emailed too. Either way it's shown to you so you can pass it on.
- **Reset password**: produces a one-time reset link (valid 1 hour), delivered the same way
- **Edit**: initials, role, email (you can't change your own role)
- **Deactivate / reactivate**: blocks login without deleting the account or its history. Prefer this over deleting.
- **Delete user**: cannot delete your own account

### Audit Trail (Admin Only)

A log of logged admin activity — currently, every evidence deletion (see [Reviewing Evidence in the Evidence Window](#reviewing-evidence-in-the-evidence-window)) — showing timestamp, operator, action, investigation, asset, technique, and details. Use the **INVESTIGATION** and **ASSET** dropdowns to narrow the list; the asset dropdown only offers assets from the currently selected investigation.

### Velociraptor GUI (Admin Only)

Click **VELOCIRAPTOR** in the Options sidebar, then **START**. ORCA starts a Velociraptor server inside the backend container and shows **OPEN VELOCIRAPTOR ↗** plus the Velociraptor login (username `admin` and a password generated on first start). The GUI opens on port 8889 of the ORCA server, with its own self-signed certificate (accept the browser warning once). Its config, datastore and login are kept in the evidence volume, so they survive restarts. Starting the GUI and seeing its password are admin-only, because the GUI can run arbitrary VQL inside the ORCA server. Stop it from the same panel when you're done.
