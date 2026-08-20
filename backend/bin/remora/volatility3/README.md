<p align="center">
  <img src="remora-logo.png" alt="Remora logo" width="500"/>
</p>

# Remora

> A forensically-conscious PyQt6 graphical frontend for the [Volatility3](https://github.com/volatilityfoundation/volatility3) memory forensics framework.
> Built for analysts who need speed, auditability, and intelligence-informed triage — without touching the command line for every query.

---

## Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Installation](#installation)
- [Interface Layout](#interface-layout)
- [Loading a Memory Image](#loading-a-memory-image)
- [Plugin Browser](#plugin-browser)
- [MITRE ATT&CK / Threat Actor Filter](#mitre-attck--threat-actor-filter)
- [Plugin Configuration Panel](#plugin-configuration-panel)
- [Running Plugins](#running-plugins)
- [Results Tabs](#results-tabs)
- [Exporting Results](#exporting-results)
- [Case Files](#case-files)
- [MITRE Coverage Matrix](#mitre-coverage-matrix)
- [Custom Symbol Tables](#custom-symbol-tables-linux--macos)
- [Embedded Volshell](#embedded-volshell)
- [Automatic Log Files](#automatic-log-files)
- [Theme](#theme)
- [Keyboard Shortcuts](#keyboard-shortcuts)
- [Menu Reference](#menu-reference)
- [Forensic Soundness](#forensic-soundness)
- [Directory Structure](#directory-structure)
- [Troubleshooting](#troubleshooting)
- [Extending the Mapping](#extending-the-mapping--remora_mitrejson)
- [Tests](#tests)
- [License](#license)

---

## Overview

`remora.py` is a single-file graphical frontend that lives inside your cloned Volatility3 repository and wraps the `vol.py` and `volshell.py` entry points. It exposes every discovered plugin through a categorised, searchable browser, auto-generates argument forms from each plugin's declared requirements, streams output into tabbed result views, and writes a persistent timestamped audit log for every action taken against a memory image.

Every plugin is mapped to the MITRE ATT&CK framework and known threat actor groups, making plugin selection and result exports intelligence-aware from the start.

**Built for:**

- **Digital forensic examiners** who need a defensible chain-of-custody record of every analysis step
- **Incident responders** triaging live or acquired memory who need fast, repeatable plugin execution guided by known adversary TTPs
- **Threat hunters** correlating memory artefacts against specific threat actor toolkits
- **Malware analysts** pivoting between structured plugin output and interactive Volshell access
- **Trainers and students** learning memory forensics in a visual, discoverable interface

---

## Requirements

| Dependency | Version | Notes |
|---|---|---|
| Python | ≥ 3.8 | 3.10+ recommended |
| PyQt6 | ≥ 6.4 | Required |
| Volatility3 | latest | Cloned from GitHub |
| openpyxl | any | Optional — XLSX export only |
| PyQt6.QtPrintSupport | included with most PyQt6 installs | Optional — PDF export only |

---

## Installation

### 1. Clone Volatility3

```bash
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
```

### 2. Install GUI Dependencies

```bash
pip install PyQt6

# Optional: Excel export
pip install openpyxl
```

### 3. Place remora.py

`remora.py` must live in the **root of the cloned Volatility3 repository** — the same directory as `vol.py` and `volshell.py`. Remora inserts its own parent directory into `sys.path` at startup so Volatility3 is importable without additional configuration.

```
volatility3/
├── vol.py
├── volshell.py
├── remora.py          ← place here
├── volatility3/
│   ├── framework/
│   ├── plugins/
│   │   ├── windows/
│   │   ├── linux/
│   │   └── mac/
│   └── symbols/
├── requirements.txt
└── setup.py
```

### 4. Launch

```bash
python3 remora.py
```

---

## Interface Layout

```
┌─────────────────────────────────────────────────────────────────────────┐
│  ▌ REMORA  /  memory forensics    [image · size]  ▶ plugin   [ LIGHT ] │  ← header bar (40px)
├────────────────────────────────────────────────────────────────────────-│
│  IMG  Drop a memory image here  —  or click to browse                   │  ← drop zone (52px)
├───────────────┬──────────────────┬─────────────────────────────────────-│
│  PLUGINS  [N] │  CONFIGURE       │  (results tabs)                      │
│  ─────────    │  ─────────────── │                                      │
│  [Filter…]    │  Plugin name     │  plugin · N rows · image.raw         │
│  MITRE FILTER │  Description     │  [Filter rows…] [Columns▾] [Export▾] │
│  [Combo ▾]    │                  │  ┌─────────────────────────────────┐ │
│               │  * Required arg  │  │ col1   col2   col3   col4  ...  │ │
│  ▶ WINDOWS    │    Optional arg  │  │ ...                             │ │
│     malfind   │                  │  └─────────────────────────────────┘ │
│     pslist    │  OUTPUT DIR      │  N rows                  timestamp   │
│     netscan   │  [path…] [Browse]│                                      │
│  ▶ LINUX      │                  │  ───────────────────────────────────  │
│  ▶ MACOS      │  [▶  Run Plugin] │  LOG  → image_2026-01-01.log  [Clear]│
│  ▶ OTHER      │                  │  [HH:MM:SS] log output...            │
├───────────────┴──────────────────┴─────────────────────────────────────-│
│ ░░░░░░░░░░░░░░ (2px indeterminate progress bar — visible when running)  │
│ Ready                              Running Malfind…  [■ Stop]           │  ← status bar
└─────────────────────────────────────────────────────────────────────────┘
```

The window defaults to **1480 × 920** pixels. All three primary panes are separated by draggable splitters:

- **Left** — Plugin browser (190–300px): categorised tree, text search, MITRE/actor filter
- **Centre** — Plugin configuration (260–400px): auto-generated argument form, output directory, run button
- **Right** — Vertical splitter: results tabs (top) above log panel (72–180px, bottom)

---

## Loading a Memory Image

**Method 1 — Drag and drop:** Drag any supported memory image file directly onto the drop zone bar. The bar highlights with an accent border on drag-enter.

**Method 2 — File menu:** `File > Open Image…` (`Ctrl+O`).

**Method 3 — Click the drop zone:** Clicking anywhere on the bar opens the file browser. The last-used directory is remembered between sessions.

**Supported extensions:** `.dmp` `.mem` `.vmem` `.raw` `.img` `.bin` `.lime` `.dd` `.E01` `.e01`

Once loaded:
- The file name and size appear in green in the header bar
- The log file is created (or appended) next to the evidence file — a session separator is written immediately
- **Chain-of-custody hashing** starts automatically in the background (SHA-256 + MD5). Progress is shown in the status bar (`Hashing nn%…`); when complete, the digests are written to the audit log and a short SHA-256 prefix is appended to the header chip (full hashes in its tooltip). Hashing runs on a worker thread and never blocks analysis — you can start running plugins immediately. See [Forensic Soundness](#forensic-soundness).
- The **▶ Run Plugin** button activates
- The drop zone label changes to `Image loaded — drop another to replace`
- The status bar updates to show filename and size

To load a different image, drag another file or use `File > Open Image…` again.

---

## Plugin Browser

The plugin browser occupies the left panel. All Volatility3 plugins are discovered at startup in a background thread (`PluginDiscoveryThread`) and organised into four categories:

| Category | Contents |
|---|---|
| **WINDOWS** | All `windows.*` plugins |
| **LINUX** | All `linux.*` plugins |
| **MACOS** | All `mac.*` plugins |
| **OTHER** | Cross-platform plugins: `timeliner`, `yarascan`, `banners`, `regexscan`, etc. |

The count badge in the panel header shows the total number of plugins, or `visible/total` when any filter is active.

### Navigation

- **Single-click** a plugin to load its configuration form in the centre panel
- **Double-click** a plugin to run it immediately with default settings (image must be loaded first)
- **Right-click** a plugin for a context menu with two options: **Configure** and **Run with defaults**

### Text Search

The **Filter plugins…** bar narrows the tree in real time by substring match against the full plugin name. Matching categories auto-expand; empty categories are hidden.

### Plugin Tooltips

Hovering over any plugin shows a tooltip with:
- The first line of the plugin's own docstring (truncated at 140 characters)
- All MITRE ATT&CK technique IDs and names the plugin maps to

---

## MITRE ATT&CK / Threat Actor Filter

The dropdown below the text search filters the plugin tree to show **only plugins that map to the selected ATT&CK technique or threat actor group**.

### How to Use

1. Click the dropdown — it opens with three sections:
   - `— All Plugins —` (clears the filter)
   - **── MITRE ATT&CK Techniques ──** — 65 technique IDs listed as `T1055  –  Process Injection`
   - **── Known Threat Actors / Groups ──** — 26 profiles

2. Select a technique ID or actor name
3. The plugin tree immediately filters; the count badge updates to `visible/total`
4. Text search and MITRE filter combine with **AND logic** — you can search for "scan" among APT29 plugins simultaneously

### Technique Filter Logic

Selecting a technique also reveals plugins mapped to related subtechniques, and vice versa — the matching uses a `startswith` check in both directions. For example, selecting `T1003` reveals plugins mapped to `T1003.001`, `T1003.002`, `T1003.004`, and `T1003.005`. Selecting `T1003.002` shows only plugins with that specific mapping.

### Threat Actor Profiles

Each threat actor profile is a set of technique IDs. Selecting an actor shows all plugins relevant to **any** technique in that actor's toolkit (OR logic across techniques within the actor's set).

**Included threat actor profiles (26 total):**

| Actor | Also Known As |
|---|---|
| APT1 | Comment Crew, Unit 61398 |
| APT28 | Fancy Bear, Sofacy, Pawn Storm |
| APT29 | Cozy Bear, The Dukes |
| APT32 | OceanLotus, Cobalt Kitty |
| APT38 / Lazarus Group | Hidden Cobra |
| APT41 | Winnti, BARIUM, Double Dragon |
| BlackCat / ALPHV | — |
| Carbanak / FIN7 | Navigator Group |
| Cl0p Ransomware | — |
| Conti Ransomware | — |
| DarkHotel | Tapaoux |
| Equation Group | NSA/GCHQ-linked |
| Gamaredon | Primitive Bear |
| Hive Ransomware | — |
| Kimsuky | Thallium, Black Banshee |
| LockBit Ransomware | — |
| MuddyWater | Static Kitten |
| NotPetya / Sandworm | GRU Unit 74455 |
| REvil / Sodinokibi | — |
| Ryuk Ransomware | — |
| ShadowPad | APT41-linked |
| TA505 | Evil Corp-linked |
| Turla | Venomous Bear, Waterbug |
| WannaCry | Lazarus Group |
| Winnti Group | APT41 overlap |
| Wizard Spider | Ryuk / TrickBot |

### MITRE Data at a Glance

| Data Set | Count |
|---|---|
| ATT&CK technique IDs mapped | 65 |
| Plugin-to-technique mapping keys | 137 |
| Threat actor / group profiles | 26 |

### What Is Not Mapped

Plugins that are **forensic infrastructure only** — `windows.info`, `windows.crashinfo`, `windows.statistics`, `windows.virtmap`, `windows.poolscanner`, and similar — carry **no ATT&CK mapping**. These plugins establish ground truth about the system; they do not detect adversary behaviour. Mapping them would pollute threat-actor filters with noise.

### Technical Detail — Mapping Architecture

The mapping is implemented in four data structures near the top of `remora.py`:

```
MITRE_TECHNIQUES        Dict[str, str]              65 technique IDs → names
PLUGIN_MITRE_MAP        Dict[str, List[str]]        137 plugin keys → technique ID lists
PLUGIN_MITRE_CONFIDENCE Dict[str, Dict[str, str]]   per-plugin per-technique H/M/L ratings
THREAT_ACTORS           Dict[str, List[str]]        26 actor names → technique ID sets
MITRE_TACTICS           Dict[str, List[str]]        10 tactic groupings → technique prefixes
```

Plugin name keys are matched by sliding a window of matching segments over the full dot-separated plugin name. For example, the key `"hashdump"` matches `windows.hashdump` and `windows.registry.hashdump` without requiring separate entries.

---

## Plugin Configuration Panel

The centre panel auto-generates an argument form from each plugin's declared requirements via `cls.get_requirements()`. Infrastructure requirement types (`TranslationLayerRequirement`, `SymbolTableRequirement`, `ModuleRequirement`, `VersionRequirement`, `LayerListRequirement`, `MultiRequirement`, `PluginRequirement`) and auto-filled arguments (`single_location`, which is filled from the loaded image path) are hidden from the form.

### Field Types

| Requirement Type | Widget |
|---|---|
| `BooleanRequirement` | Checkbox |
| `IntRequirement` | Spinner (range −2³⁰ to 2³⁰) |
| `ChoiceRequirement` | Dropdown populated with valid values; optional fields include `(any)` |
| `URIRequirement` | Text field with `file:///path` placeholder + `…` browse button |
| `ListRequirement` | Space-separated text field |
| String / other | Free text field with description as placeholder |

Required fields are prefixed with `*` in the label. Optional fields can be left blank. Each label shows a tooltip containing the requirement's description string.

The plugin info block at the top of the panel displays the plugin's short name (in accent colour) and its docstring truncated at 220 characters.

### Output Directory

Below the arguments form, an **Output Directory** field accepts a path for plugins that write dumped files (`windows.dumpfiles`, `windows.pedump`, etc.). Files are written there, not alongside the evidence image. Blank means no `-o` flag is passed.

---

## Running Plugins

### Standard Run

Click **▶ Run Plugin** in the configuration panel. The plugin executes in a background thread (`PluginRunnerThread`) and runs the command:

```
python3 vol.py -q --renderer json -f <image> [--symbols <path>...] [-o <output_dir>] <plugin> [args...]
```

Execution is non-blocking — the GUI remains fully responsive while a plugin runs.

### Quick Run

Double-click any plugin in the browser to run it with default settings immediately, bypassing the configuration form.

### While Running

- The header bar shows `▶ pluginname` in amber
- A 2-pixel indeterminate progress bar appears at the bottom of the window
- The **■ Stop** button appears in the status bar — click it at any time to terminate the plugin process cleanly
- All stderr output from Volatility3 streams into the log panel in real time, with lines containing the word "error" highlighted accordingly

### Running Multiple Plugins

Only one plugin runs at a time. If you attempt to run a second plugin while one is active, a dialog offers to stop the current one first. If you confirm, the running thread is aborted and the new plugin starts.

### Triage Profiles & Batch Execution

For triage workflows that mean "run this whole battery of plugins and come back", the plugin browser includes a **TRIAGE / BATCH** panel:

- Every plugin in the browser has a **checkbox**. Tick as many as you like, then click **Run Checked (n)** to queue them.
- The **Apply triage profile…** dropdown ticks a curated set of plugins in one click. Built-in profiles:
  - **Windows · Quick Triage** — pslist, pstree, psscan, cmdline, netscan, netstat, malfind, dlllist, svcscan, hashdump
  - **Windows · Ransomware** — pslist, cmdline, netscan, malfind, filescan, mutantscan, dlllist
  - **Windows · Rootkit / Hidden** — psscan, ssdt, modules, modscan, malfind, ldrmodules, callbacks, driverirp
  - **Linux · Quick Triage** — pslist, pstree, psaux, bash, lsof, malfind, check_syscall, check_modules
  - **macOS · Quick Triage** — pslist, pstree, lsof, bash, netstat, malfind
- Selecting a profile **replaces** the current selection (it first clears every checkbox, then ticks only that profile's plugins), so the **Run Checked (n)** count always reflects exactly the chosen profile. The log confirms how many plugins were checked. Use **Clear** to reset to zero.
- Queued plugins run **sequentially with default arguments**, each opening its own result tab. Progress is logged as `Batch [n/total]`.
- Profile entries not present in your Volatility build are silently skipped, so a profile works across Volatility versions. (Volatility reports plugin names with a trailing class segment, e.g. `windows.pslist.PsList` — profiles match these by prefix.)
- Starting a manual run, or pressing **■ Stop**, cancels any remaining queued plugins.

> **Tip:** combine this with the [MITRE / threat-actor filter](#mitre-attck--threat-actor-filter) — filter the browser to a threat actor's techniques, then tick the surviving plugins and run them as a batch.

### Output Parsing

Remora handles several output formats from `vol.py --renderer json`:
- JSON array of row-dicts (standard Volatility3 output)
- JSON lines (one dict per line)
- Single JSON dict with `"columns"` and `"rows"` keys
- Nested records with `"__children"` (displayed with indentation in the first column)
- Raw text fallback if JSON parsing fails entirely

---

## Results Tabs

Each completed plugin run opens in a new closeable, movable tab in the right panel. Tabs show the plugin's short name as the label.

### Tab Toolbar

```
plugin · N rows · image.raw    [Filter rows…]  [Columns ▾]  [Export ▾]
```

- **Filter rows** — full-text search across all visible columns; the row count updates live
- **Columns** — toggle individual column visibility; hidden columns are excluded from all exports
- **Export** — opens the export format menu

### Table Features

- Alternating row colours (theme-aware)
- Monospace font: `JetBrains Mono` → `Fira Code` → `Cascadia Code` → `Consolas`
- Row height: 26px; columns capped at 360px width; all columns sized to content on load
- Click any column header to sort ascending/descending
- Semantic cell colouring: `true`/`yes` → green, `false`/`no` → red, `N/A`/`None`/`-` → muted
- Footer bar shows row count (left) and run timestamp (right)

### Right-Click Context Menu

Right-clicking any cell offers:
- **Copy Cell** — copies the cell text to the clipboard
- **Copy Row (TSV)** — copies the entire row as tab-separated values
- Export submenu (same options as the toolbar Export button)

### Managing Tabs

- Close individual tabs with the `✕` on each tab
- **Results > Close All Tabs** clears everything and returns to the welcome screen
- When all tabs are closed, the welcome screen is shown automatically
- Closing the Volshell tab kills the volshell process

---

## Exporting Results

Every result tab can be exported in seven formats. All exports respect the **active column visibility** and **active row filter** — only visible columns and visible rows are exported.

Every format embeds MITRE ATT&CK metadata: technique IDs/names and threat actor names that overlap with the plugin's mapping.

---

### CSV

```
# Plugin: windows.malfind.Malfind
# Image: memdump.raw
# Timestamp: 2026-04-10 14:32:19
# MITRE Techniques: T1055 – Process Injection; T1055.001 – DLL Injection; ...
# Threat Actors: APT28 (Fancy Bear); APT29 (Cozy Bear); ...

PID,Process,Start VPN,End VPN,...
```

`#` comment lines appear before a blank separator and the data header. Importable into Excel and LibreOffice without issue.

---

### TSV

Same structure as CSV: MITRE comment header block, blank line, then tab-separated data. Suitable for `cut`, `awk`, and database imports.

---

### JSON

```json
{
  "plugin": "windows.malfind.Malfind",
  "image": "/cases/exhibit_001/memdump.raw",
  "timestamp": "2026-04-10 14:32:19",
  "mitre": {
    "techniques": [
      { "id": "T1055",     "name": "Process Injection" },
      { "id": "T1055.001", "name": "Process Injection: DLL Injection" }
    ],
    "threat_actors": [
      "APT28 (Fancy Bear / Sofacy / Pawn Storm)",
      "APT29 (Cozy Bear / The Dukes)"
    ]
  },
  "rows": [
    { "PID": "1234", "Process": "svchost.exe", ... }
  ]
}
```

The `"mitre"` block is machine-parseable for ingestion into SIEMs or case management tools.

---

### TXT (Plain Text)

```
Plugin    : windows.malfind.Malfind
Image     : /cases/exhibit_001/memdump.raw
Timestamp : 2026-04-10 14:32:19
Rows      : 14
MITRE     : T1055 – Process Injection; T1055.001 – DLL Injection; ...
Actors    : APT28 (Fancy Bear); APT29 (Cozy Bear); APT38 / Lazarus Group; ...
            Carbanak / FIN7; Conti Ransomware; ...

PID       Process       Start VPN          End VPN            ...
--------- ------------- ------------------ ------------------ ...
```

Actor names wrap onto continuation lines (indented) at four per line. Suitable for copy-paste into reports or as an exhibit attachment.

---

### HTML

A self-contained, dark-themed HTML report with no external CSS or JavaScript dependencies. A **MITRE badge section** appears above the data table when the plugin has ATT&CK mappings:

```
┌──────────────────────────────────────────────────────────────────┐
│  MITRE ATT&CK   [T1055] [T1055.001] [T1055.002] [T1620] [...]   │
│  Threat Actors  [APT28] [APT29] [APT38] [Carbanak] [...]         │
└──────────────────────────────────────────────────────────────────┘
```

- Technique IDs render as dark-blue monospace chips; hovering shows the full technique name as a browser tooltip
- Threat actor names render as dark-red chips
- The badge section is omitted entirely if the plugin has no ATT&CK mapping

---

### PDF

Rendered via `QPrinter` (Qt print support). A metadata table appears above the results grid:

```
windows.malfind.Malfind
/cases/exhibit_001/memdump.raw · 2026-04-10 14:32:19 · 14 rows

MITRE Techniques   T1055 – Process Injection; T1055.001 – DLL Injection; ...
Threat Actors      APT28 (Fancy Bear); APT29 (Cozy Bear); ...

PID    Process       Start VPN    ...
```

Output is A4, landscape orientation. The PDF export menu item is disabled (greyed out) if `PyQt5.QtPrintSupport` is not available.

---

### XLSX (Excel)

Requires `pip install openpyxl`.

**Main data sheet** — named after the plugin's short name — contains styled metadata rows above the data:

| Row | Label | Value |
|---|---|---|
| 1 | Plugin | `windows.malfind.Malfind` |
| 2 | Image | `/cases/exhibit_001/memdump.raw` |
| 3 | Timestamp | `2026-04-10 14:32:19` |
| 4 | Rows | `14` |
| 5 | MITRE Techniques | `T1055 – Process Injection; ...` |
| 6 | Threat Actors | `APT28 (Fancy Bear); ...` |
| 7 | *(blank)* | |
| 8+ | *(column headers + data)* | |

Column widths are auto-sized (capped at 50 characters). Cells use the dark theme colour palette.

**"MITRE Coverage" sheet** — added automatically when the plugin has ATT&CK mappings:

| Column A | Column B |
|---|---|
| Plugin | `windows.malfind.Malfind` |
| Timestamp | `2026-04-10 14:32:19` |
| | |
| Technique ID | Technique Name |
| T1055 | Process Injection |
| T1055.001 | Process Injection: DLL Injection |
| ... | |
| | |
| Threat Actors | |
| APT28 (Fancy Bear / Sofacy / Pawn Storm) | |
| ... | |

---

## Case Files

Open result tabs live only in memory and are lost on exit. To persist an investigation, save it as a **case file** — a single self-contained JSON document.

- **`File > Save Case…`** (`Ctrl+S`) writes the loaded image path, byte size, **SHA-256 / MD5**, custom symbol-table paths, and every open result tab (plugin name, columns, rows, and per-result timestamp) to a `*_case.json` file.
- **`File > Open Case…`** (`Ctrl+Shift+O`) restores all of that without re-running any plugins. The header chip and exports are repopulated with the recorded image hashes, so reopened results remain tied to their source image.
- If the original image is no longer present on disk, the case still opens **read-only**: you can browse, filter, and re-export the saved results, but the **Run** button stays disabled until the image is available again.

This lets you close down mid-analysis and resume later, or hand the entire case — evidence hashes and all findings — to a colleague.

---

## MITRE Coverage Matrix

**Tools > MITRE Coverage Matrix…** (`Ctrl+Shift+M`)

Opens a standalone window (1280 × 820) showing every Volatility3 plugin that has an ATT&CK mapping, displayed as a grid against 10 ATT&CK tactic columns.

### What It Shows

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│  MITRE ATT&CK COVERAGE MATRIX   ● H = primary   ◉ M = secondary   ○ L = circumstantial │
│  [Filter plugins…]  [All Tactics ▾]  [All Confidence ▾]  [Export CSV ▾]             │
├──────────────────────────────┬─────────┬──────┬───────┬───────┬──────┬───────┬──────┤
│ Plugin                       │ OS      │ Exec │ Perst │ PrivE │ DefE │ Cred  │ Disc │
├──────────────────────────────┼─────────┼──────┼───────┼───────┼──────┼───────┼──────┤
│ windows.malfind.Malfind      │ Win     │      │       │ ● H   │ ◉ M  │       │      │
│ windows.hashdump.Hashdump    │ Win     │      │       │       │      │ ● H   │      │
│ windows.netscan.NetScan      │ Win     │      │       │       │      │       │ ● H  │
│ linux.check_syscall.Check_.. │ Linux   │      │       │       │ ● H  │       │      │
└──────────────────────────────┴─────────┴──────┴───────┴───────┴──────┴───────┴──────┘
│ 181 plugins mapped                                                                   │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

### Confidence Levels

Each tactic cell shows the **highest confidence level** among the techniques the plugin maps to within that tactic column:

| Symbol | Level | Meaning | Colour |
|---|---|---|---|
| `● H` | High | Plugin was specifically engineered for this detection | Red/accent |
| `◉ M` | Medium | Strong secondary signal (default when not explicitly rated) | Amber |
| `○ L` | Low | Circumstantial or indirect evidence only | Muted |
| *(blank)* | None | No mapping for this tactic | — |

### Tactic Columns

| Column | ATT&CK Tactic | Example High-Confidence Plugins |
|---|---|---|
| Execution | TA0002 | `cmdline`, `cmdscan`, `bash`, `direct_system_calls` |
| Persistence | TA0003 | `scheduled_tasks`, `svcscan`, `shimcachemem`, `callbacks` |
| Priv Escalation | TA0004 | `malfind`, `hollowprocesses`, `processghosting`, `privileges` |
| Def Evasion | TA0005 | `ssdt`, `etwpatch`, `check_idt`, `unhooked_system_calls` |
| Cred Access | TA0006 | `hashdump`, `cachedump`, `lsadump`, `skeleton_key_check` |
| Discovery | TA0007 | `netscan`, `pslist`, `filescan`, `hivelist` |
| Lat Movement | TA0008 | `netscan`, `netstat`, `sessions` |
| Collection | TA0009 | `dumpfiles`, `mftscan`, `pedump` |
| C2 | TA0011 | `netscan`, `netstat`, `mutantscan` |
| Impact | TA0040 | `truecrypt` |

### Filtering the Matrix

All three filters combine with AND logic:

- **Text search** — filter by plugin name substring
- **Tactic dropdown** — show only plugins with any coverage in the selected tactic; the confidence filter applies to that tactic column only
- **Confidence dropdown** — `All Confidence` / `High only` / `High + Medium`

### Exporting the Matrix

Click **Export CSV ▾** to save the currently visible matrix. Cells contain raw `H`, `M`, `L`, or blank — not the display symbols — for downstream processing.

---

## Custom Symbol Tables (Linux & macOS)

Volatility3 requires ISF (Intermediate Symbol Format) JSON files to analyse Linux and macOS memory images. These must match the exact kernel version of the image being examined.

### Loading via the GUI

1. Open **Symbols > Linux Symbol Tables** or **Symbols > macOS Symbol Tables**
2. Choose **Add Symbol Table File(s)…** to select one or more `.json` / `.json.gz` / `.isf` / `.isf.gz` files, or **Add Symbol Table Directory…** to point at a folder
3. The menu item updates to show `Loaded: N path(s) — view…` — click it to see all loaded paths in a dialog
4. All subsequent plugin runs automatically include `--symbols <path>` for each loaded path
5. Use **Clear Linux Symbols**, **Clear macOS Symbols**, or **Clear All Custom Symbols** to remove paths

The last-used symbol directory is remembered between sessions.

### Generating Symbol Tables

```bash
# Install dwarf2json
git clone https://github.com/volatilityfoundation/dwarf2json.git
cd dwarf2json && go build

# Generate from a Linux kernel with debug symbols
./dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-$(uname -r) \
    > linux-$(uname -r).json
```

Pre-built tables are also available from the [Volatility3 symbols repository](https://github.com/volatilityfoundation/volatility3-symbols).

---

## Embedded Volshell

**Tools > Open Volshell…** (`Ctrl+Shift+S`)

Opens an interactive Python REPL tab backed by `volshell.py`, giving direct access to Volatility3's layer, context, and symbol APIs against the loaded image. Communication with the process uses Qt's `QProcess` with merged stdout/stderr.

### Requirements

- A memory image must be loaded before opening Volshell
- Only one Volshell tab can be open at a time; invoking the menu item while one exists switches focus to it rather than opening a second

### Using Volshell

Type Python expressions in the `>>>` input bar and press **Enter** or click **Send**. Output streams into the display above.

```python
# List all running processes
for proc in context.modules["primary"].object_table:
    print(f"PID {proc.UniqueProcessId}  {proc.ImageFileName}")

# Inspect a specific PID
ps = next(p for p in context.modules["primary"].object_table
          if p.UniqueProcessId == 1234)
print(ps.ImageFileName, hex(ps.obj_offset))

# Access the kernel module directly
krnl = context.modules["kernel"]
```

**Command history:** The ↑ / ↓ arrow keys in the input bar cycle through previously entered commands within the current session.

### Tab Toolbar Controls

| Button | Action |
|---|---|
| **Restart** | Kills the current process and starts a fresh Volshell against the same image |
| **Kill** | Terminates the process without restarting |

Closing the Volshell tab kills the process automatically.

---

## Automatic Log Files

A log file is created the moment a memory image is loaded. No configuration required.

### File Naming and Location

```
<image_stem>_<YYYY-MM-DD>.log
```

Saved **next to the evidence image**, keeping artefacts co-located with the exhibit:

| Image Path | Log Path |
|---|---|
| `/cases/exhibit_001/memdump.raw` | `/cases/exhibit_001/memdump_2026-04-10.log` |
| `/mnt/evidence/WIN10.vmem` | `/mnt/evidence/WIN10_2026-04-10.log` |

Non-filesystem-safe characters in the image stem are replaced with `_`.

### Session Separators

If the same image is re-examined on the same date, entries are appended. Each session is delimited:

```
========================================================================
  Session started : 2026-04-10 09:14:22
  Image           : /cases/exhibit_001/memdump.raw
========================================================================
```

### Entry Format

Every log entry uses full ISO 8601 timestamps and a fixed-width level tag:

```
[2026-04-10 14:32:01] [SUCCESS] Loaded: /cases/exhibit_001/memdump.raw
[2026-04-10 14:32:07] [INFO   ] → windows.malfind.Malfind
[2026-04-10 14:32:08] [CMD    ] $ python3 vol.py -q --renderer json -f /cases/exhibit_001/memdump.raw windows.malfind.Malfind
[2026-04-10 14:32:19] [SUCCESS] ← Malfind  14 rows
[2026-04-10 14:35:01] [WARNING] Plugin stopped by user.
```

### Log Levels

| Level | When It Appears |
|---|---|
| `SUCCESS` | Plugin completed, image loaded |
| `INFO` | Plugin dispatched, status messages |
| `CMD` | Exact `vol.py` command executed |
| `WARNING` | Plugin stopped by user, non-fatal issues |
| `ERROR` | Volatility3 error output, process failures |
| `DEBUG` | Verbose Volatility3 stderr |

### In-GUI Log Panel

The log panel mirrors entries in real time with colour-coded severity. The current log filename is shown in the panel header. **Results > Clear Log** (or the **Clear** button) clears the in-GUI display only — the file on disk is not affected.

Log writes fail silently (with a `pass`) if the evidence directory is read-only, to avoid crashing the GUI.

---

## Theme

The **[ LIGHT ] / [ DARK ]** toggle button in the header bar switches between two palettes. The chosen theme is persisted between sessions via `QSettings`.

**Dark (default):** Near-black charcoal backgrounds designed for extended analysis sessions. Background `#0d0f14`, panels `#11141a`, accent `#1f9cd8`. Sharp edges, dense layout, uppercase section labels — modelled after professional security tooling.

**Light:** Cool slate-grey. Background `#f0f3f7`, elevated `#ffffff`, accent `#1470a8`.

On theme toggle, all open result tabs, browser category items, and the Coverage Matrix (if open) are restyled immediately without requiring a restart.

The application font is `Inter` / `SF Pro Text` / `Segoe UI` / `Ubuntu` at 11pt. Monospace areas use `JetBrains Mono` / `Fira Code` / `Cascadia Code` / `Consolas`.

---

## Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+O` | Open memory image |
| `Ctrl+Shift+O` | Open case file |
| `Ctrl+S` | Save case file |
| `Ctrl+Q` | Exit |
| `Ctrl+Shift+S` | Open Volshell |
| `Ctrl+Shift+M` | Open MITRE Coverage Matrix |
| `F5` | Refresh plugin list |
| `↑` / `↓` | Cycle command history in Volshell input bar |

---

## Menu Reference

| Menu | Item | Shortcut | Action |
|---|---|---|---|
| **File** | Open Image… | `Ctrl+O` | Open a memory image via file browser |
| **File** | Open Case… | `Ctrl+Shift+O` | Restore a saved investigation (results + image hashes) |
| **File** | Save Case… | `Ctrl+S` | Save the loaded image metadata and all result tabs to a case file |
| **File** | Exit | `Ctrl+Q` | Close the application |
| **Symbols** | Linux Symbol Tables > Add Symbol Table File(s)… | — | Add .json/.json.gz/.isf/.isf.gz files for Linux analysis |
| **Symbols** | Linux Symbol Tables > Add Symbol Table Directory… | — | Add a directory of Linux symbol tables |
| **Symbols** | Linux Symbol Tables > Loaded: N path(s) — view… | — | Display loaded Linux symbol paths |
| **Symbols** | Linux Symbol Tables > Clear Linux Symbols | — | Remove all Linux symbol paths |
| **Symbols** | macOS Symbol Tables > (same structure) | — | Same as Linux, for macOS |
| **Symbols** | Clear All Custom Symbols | — | Remove all Linux and macOS symbol paths |
| **Results** | Close All Tabs | — | Close all result tabs and show welcome screen |
| **Results** | Clear Log | — | Clear the in-GUI log display (file unaffected) |
| **Plugins** | Refresh Plugin List | `F5` | Re-run plugin discovery |
| **Tools** | Open Volshell… | `Ctrl+Shift+S` | Open interactive Volshell tab |
| **Tools** | MITRE Coverage Matrix… | `Ctrl+Shift+M` | Open the coverage matrix window |
| **Help** | About | — | Show version info dialog |

---

## Directory Structure

After setup your repository root will look like this:

```
volatility3/
├── vol.py                      ← Volatility3 CLI
├── volshell.py                 ← Volatility3 interactive shell
├── remora.py                   ← GUI frontend (this tool)
├── remora_mitre.json           ← optional MITRE mapping overrides (if present)
├── tests/                      ← unittest suite for the Qt-free core
├── requirements.txt
├── setup.py
├── volatility3/
│   ├── framework/
│   ├── plugins/
│   │   ├── windows/            ← Windows plugins
│   │   ├── linux/              ← Linux plugins
│   │   └── mac/                ← macOS plugins
│   └── symbols/
│       ├── generic/
│       └── (your .json symbol files)
└── (case directory — logs written here, alongside evidence)
```

---

## Forensic Soundness

Forensic soundness is a core design principle, not an afterthought.

### Chain-of-Custody Hashing

On load, Remora computes the **SHA-256 and MD5** of the memory image in a single streamed pass on a background thread (4 MiB chunks, so multi-GB images never freeze the UI). The digests are:

- Written verbatim into the persistent audit log as `Image SHA-256:` / `Image MD5:` lines
- Shown (SHA-256 prefix) in the header chip, with the full digests in its tooltip alongside the byte-exact size
- **Stamped into every export** (CSV/TSV/JSON/TXT/HTML/PDF/XLSX) metadata block, so any exported artefact is self-describing and tied to a specific, verifiable source image
- Recorded in saved [case files](#case-files)

This means an exported finding can be independently tied back to the exact image it came from, and the hash can be re-verified against the original evidence at any time.

### Read-Only Evidence Handling

- `remora.py` passes evidence files to Volatility3 exclusively via the `-f` flag
- No write operations are performed against the image at any point
- The tool never copies, modifies, or moves the original file
- File name and size are displayed on load so the examiner can confirm the correct image before running any plugin

### Exact Command Transparency

Every plugin invocation logs the full `vol.py` command including all flags. Any finding can be independently reproduced by re-running the logged command verbatim.

### Non-Destructive Stop

The **■ Stop** button terminates the running plugin process via `proc.terminate()`. Stopping a plugin does not affect the evidence file, does not corrupt in-progress output, and writes a `[WARNING] Plugin stopped by user.` entry to the audit log.

### Output Directory Isolation

Plugins that dump files (e.g. `windows.dumpfiles`) write to an explicitly specified output directory, not alongside the evidence image.

### No Network Access

`remora.py` makes no outbound network connections. All processing is local. PDB downloads (if used via the Windows symbol resolver) are a Volatility3 core function, not initiated by Remora.

---

## Troubleshooting

### `ERROR: PyQt6 is required`

```bash
pip install PyQt6
```

### No plugins appear in the browser

Ensure you are running `remora.py` from inside the cloned `volatility3/` directory — specifically that `vol.py` and `volshell.py` exist in the same folder. Press `F5` to retry plugin discovery. Check the log panel for the specific import error message.

### Linux/macOS plugins fail with `No symbol table`

You need a matching ISF symbol file for the target kernel. Load it via **Symbols > Linux Symbol Tables > Add Symbol Table File(s)…**

### MITRE filter shows no plugins for a technique

A small number of techniques only map to a few plugins. Try the parent technique (e.g. select `T1003` rather than `T1003.001`). Also confirm that plugin discovery completed — the status bar should show a plugin count. Press `F5` to refresh if the list is empty.

### MITRE Coverage Matrix is empty

Plugin discovery must complete before the matrix can be opened. Wait for the status bar to show the plugin count, then try again.

### PDF export button is greyed out

```bash
pip install PyQt6        # full install usually includes print support
# On some Linux distributions:
apt install python3-pyqt6.qtprintsupport
```

### XLSX export shows `pip install openpyxl`

```bash
pip install openpyxl
```

### Volshell tab shows `Failed to start volshell.py`

Confirm `volshell.py` exists in the same directory as `remora.py` and that Volatility3's dependencies are fully installed:

```bash
pip install -r requirements.txt
```

### Log file not created

The log file is written next to the evidence image. If that directory is read-only (e.g. a mounted ISO or write-protected share), log writes silently fail to avoid crashing the GUI. Copy the image to a writable location, or check directory permissions.

### Theme reverts to dark on every launch

Theme preference is stored via `QSettings` under the organisation name `vol3gui`. On Linux this is typically `~/.config/vol3gui/prefs.conf`. If the file is not writable, the preference cannot be saved.

---

## MITRE ATT&CK Mapping — Design Notes

The mapping was built with the following principles:

**1. Map what the plugin detects, not what it is.**
`netscan` is used by the analyst. What it *detects evidence of* is adversary network activity (T1049, T1071, T1021). The mapping reflects the adversary technique, not the analyst action.

**2. Forensic infrastructure has no mapping.**
Plugins like `windows.info`, `windows.crashinfo`, `windows.statistics`, and `windows.virtmap` establish ground truth about the system. They do not detect adversary behaviour. Mapping them to T1082 (System Information Discovery) would mean "the adversary ran remora.py", which is incorrect. They are intentionally absent.

**3. Confidence levels are conservative.**
A plugin gets `High` only if it was specifically engineered for that detection — `skeleton_key_check` → T1556.001 is `High`; `strings` → T1071 is `Low` because finding a C2 URI in strings output is circumstantial. The default confidence when no explicit entry exists in `PLUGIN_MITRE_CONFIDENCE` is `Medium`.

**4. Parent technique selection cascades.**
Selecting T1003 in the filter reveals plugins mapped to T1003, T1003.001, T1003.002, T1003.004, and T1003.005. This mirrors how ATT&CK itself is structured.

**5. Known gaps.**
The following techniques are detectable only with custom Volatility3 plugins or manual VAD analysis — no native plugin maps to them currently:
- T1055.013 (Process Doppelgänging)
- T1134.003/004/005 (token impersonation subtechniques)
- T1070.001 (Clear Windows Event Logs — the artefact is in the event log, not memory)

### Extending the Mapping — `remora_mitre.json`

You can extend or override the built-in mappings **without editing code** by placing a `remora_mitre.json` file next to `remora.py`. On startup Remora merges it over the inline defaults and logs a confirmation line. Any subset of these top-level keys is accepted:

```json
{
  "techniques":    { "T1611": "Escape to Host" },
  "plugin_map":    { "windows.malfind": ["T1611"] },
  "threat_actors": { "FIN-X": ["T1003", "T1055"] },
  "tactics":       { "TA0004": ["T1611"] },
  "confidence":    { "malfind": { "T1611": "M" } }
}
```

Each section is merged into (and overrides) the corresponding inline map, so you can correct a name, add a new plugin mapping, or define your own threat-actor toolkits. Malformed files are ignored with a logged warning rather than crashing the GUI.

---

## Tests

A standard-library `unittest` suite covers the Qt-free core — output parsing (JSON / JSONL / `__children` tree flattening / plain-text fallback), MITRE technique lookup, and the `remora_mitre.json` override loader:

```bash
python3 -m unittest discover -s tests
# or, if pytest is installed:
python3 -m pytest tests/
```

The tests register a minimal PyQt6 stub before importing `remora`, so they run on a bare machine or in CI **without PyQt6 or Volatility3 installed**.

---

## License

Remora is released under the [MIT License](LICENSE). Copyright (c) 2026 BushidoCyb3r.

Volatility3 is copyright the Volatility Foundation and contributors, distributed under its own license — see the [Volatility3 repository](https://github.com/volatilityfoundation/volatility3) for details.

MITRE ATT&CK® is a registered trademark of The MITRE Corporation. Technique descriptions and actor profiles are derived from the publicly available ATT&CK knowledge base.

---

*Built to complement [Volatility3](https://github.com/volatilityfoundation/volatility3) — the world's leading open-source memory forensics framework.*
