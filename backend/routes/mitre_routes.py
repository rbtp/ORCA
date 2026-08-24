from fastapi import APIRouter, HTTPException, Depends, Body, BackgroundTasks, Request, UploadFile, File
from fastapi.responses import StreamingResponse, Response
from core.database_manager import db, get_db
from services.mitre_service import MitreIntelService
from sqlalchemy import text
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Union, Any, Dict, Optional
import json, os, re, uuid, subprocess, shutil, yaml, asyncio, glob
import logging

from auth_utils import get_current_user, require_admin
from config import cfg
import vr_remote

router = APIRouter(prefix="/api/mitre")

# ── Schemas ────────────────────────────────────────────────────────────────────
class MapUpdatePayload(BaseModel):
    nodes: List[Dict[str, Any]] = []
    links: List[Dict[str, Any]] = []

class VerdictUpdate(BaseModel):
    verdict: str

class StarredUpdate(BaseModel):
    starred: bool

class VQLTestRequest(BaseModel):
    vql: str

class TCodeNotePayload(BaseModel):
    text: str
    note_type: Optional[str] = "NOTE"

class MemoryRunRequest(BaseModel):
    asset_id: str
    image_path: str
    plugins: List[str]
    os_profile: Optional[str] = "windows"
    args: Optional[List[str]] = []
    symbol_paths: Optional[str] = None

class MemoryFullScanRequest(BaseModel):
    asset_id: str
    image_path: str
    os_profile: Optional[str] = "windows"
    symbol_paths: Optional[str] = None

class MemoryActorScanRequest(BaseModel):
    asset_id: str
    image_path: str
    actor_name: str
    os_profile: Optional[str] = "windows"
    symbol_paths: Optional[str] = None

class MemoryAcquireRequest(BaseModel):
    asset_id: str
    destination_path: str

class MemoryDumpRequest(BaseModel):
    asset_id: str
    image_path: str
    pid: int
    destination_path: str

class ClamScanRequest(BaseModel):
    asset_id: str
    scan_path: str
    recursive: bool = True
    remove: bool = False

class ClamUpdateRequest(BaseModel):
    pass


def _get_clam_db_args(clam_base: str) -> List[str]:
    cvd_files = glob.glob(os.path.join(clam_base, "*.cvd"))
    cld_files  = glob.glob(os.path.join(clam_base, "*.cld"))
    valid_dbs  = cvd_files + cld_files
    if valid_dbs:
        return [f"--database={f}" for f in valid_dbs]
    return [f"--database={clam_base}"]


PLUGIN_MITRE_MAP: Dict[str, List[str]] = {
    "pslist":["T1057","T1036.005"],"psscan":["T1057","T1014","T1036"],
    "pstree":["T1057","T1059.001","T1059.003","T1036.005"],
    "psxview":["T1057","T1014"],"psaux":["T1057"],"pidhashtable":["T1057"],
    "proc":["T1057"],"pscallstack":["T1057","T1055"],
    "malfind":["T1055","T1055.001","T1055.002","T1055.012","T1620","T1027.007"],
    "hollowprocesses":["T1055.012","T1055"],"processghosting":["T1055.015","T1055","T1014"],
    "ptrace":["T1055"],"pebmasquerade":["T1036.005","T1055"],
    "suspicious_threads":["T1055","T1055.003"],"orphan_kernel_threads":["T1055","T1014"],
    "debugregisters":["T1622","T1055"],"vmaregexscan":["T1055","T1027"],
    "vadinfo":["T1055","T1620","T1140"],"vadwalk":["T1055","T1620"],
    "vadregexscan":["T1055","T1027"],"vadyarascan":["T1055","T1027","T1059"],
    "vmayarascan":["T1055","T1027","T1005"],"threads":["T1055","T1055.003"],
    "thrdscan":["T1055","T1055.003","T1055.004"],"suspended_threads":["T1055"],
    "proc_maps":["T1055","T1620"],"elfs":["T1083"],"memmap":["T1055","T1620","T1005"],
    "pedump":["T1055","T1620","T1005"],"pe_symbols":["T1027.007","T1055"],
    "hashdump":["T1003","T1003.002"],"cachedump":["T1003","T1003.005"],
    "lsadump":["T1003.004"],"check_creds":["T1003"],"skeleton_key_check":["T1556.001"],
    "truecrypt":["T1552.001","T1027","T1486"],
    "hivelist":["T1012"],"hivescan":["T1012","T1112"],
    "printkey":["T1012","T1547.001","T1112"],"userassist":["T1012","T1059"],
    "getcellroutine":["T1014","T1562.001"],"certificates":["T1553.004"],
    "amcache":["T1059","T1218","T1036"],"shimcachemem":["T1546.011","T1059","T1218"],
    "scheduled_tasks":["T1053.005"],
    "cmdline":["T1059","T1059.001","T1059.003","T1218","T1027"],
    "cmdscan":["T1059","T1059.003","T1562"],"consoles":["T1059","T1059.003","T1105","T1057"],
    "bash":["T1059.004"],"joblinks":["T1059"],"kthreads":["T1059"],
    "netscan":["T1049","T1071","T1021"],"netstat":["T1049","T1071","T1021"],
    "sockstat":["T1049"],"sockscan":["T1049"],"ip":["T1016"],"ifconfig":["T1016"],
    "handles":["T1083","T1016","T1057","T1012","T1082"],"sessions":["T1563","T1078"],
    "ssdt":["T1014","T1562.001"],"callbacks":["T1014"],"check_afinfo":["T1014"],
    "check_idt":["T1014"],"check_modules":["T1014"],"check_syscall":["T1014"],
    "check_sysctl":["T1014"],"check_trap_table":["T1014"],"hidden_modules":["T1014"],
    "modxview":["T1014"],"modscan":["T1014"],"modules":["T1014","T1543.003"],
    "module_extract":["T1014"],"lsmod":["T1082","T1014"],"timers":["T1014","T1543.003"],
    "kauth_listeners":["T1014"],"kauth_scopes":["T1014"],"socket_filters":["T1014"],
    "netfilter":["T1014"],"trustedbsd":["T1553"],"ebpf":["T1014","T1055"],
    "devicetree":["T1014"],"driverirp":["T1014","T1543.003"],
    "driverscan":["T1014","T1543.003"],"drivermodule":["T1014"],
    "unloadedmodules":["T1014","T1070"],"unhooked_system_calls":["T1106","T1055","T1562.001"],
    "direct_system_calls":["T1106","T1055","T1562.001"],
    "indirect_system_calls":["T1106","T1055","T1562.001"],
    "etwpatch":["T1562.006","T1562.001"],"ftrace":["T1014","T1056.001"],
    "perf_events":["T1014"],"tracepoints":["T1014"],"tracing":["T1014"],
    "keyboard_notifiers":["T1056.001"],"tty_check":["T1056.001","T1014"],
    "privileges":["T1134"],"getsids":["T1069","T1134"],"getservicesids":["T1069"],
    "capabilities":["T1134","T1068"],
    "svcscan":["T1007","T1543.003"],"svclist":["T1007","T1543.003"],"svcdiff":["T1543.003"],
    "dlllist":["T1055.001","T1055","T1574","T1129"],"ldrmodules":["T1055.001","T1055","T1574.001"],
    "iat":["T1574","T1055","T1027.007"],"library_list":["T1574.006"],
    "filescan":["T1083","T1005"],"mftscan":["T1083","T1070.004","T1564.001","T1564.004"],
    "dumpfiles":["T1005"],"lsof":["T1083","T1049"],"list_files":["T1083"],
    "vfsevents":["T1083"],"strings":["T1027","T1059","T1071"],"pagecache":["T1005"],
    "regexscan":["T1005"],"symlinkscan":["T1083","T1564.001"],"mutantscan":["T1071","T1105"],
    "mountinfo":["T1082","T1083"],"mount":["T1082"],
    "envars":["T1082","T1059"],"iomem":["T1082"],"kallsyms":["T1082"],"kmsg":["T1082"],
    "boottime":["T1082"],"vmcoreinfo":["T1082"],"desktops":["T1082"],"deskscan":["T1082"],
    "windowstations":["T1082"],"dmesg":["T1082"],"kevents":["T1082"],"fbdev":["T1082"],
    "bigpools":["T1082","T1014"],"timeliner":["T1082"],
    "verinfo":["T1036"],"process_spoofing":["T1036","T1036.005"],
    "mbrscan":["T1542.003"],"yarascan":["T1518","T1027"],
}

PLUGIN_MITRE_CONFIDENCE: Dict[str, Dict[str, str]] = {
    "malfind":{"T1055":"H","T1055.012":"H","T1620":"M"},
    "hollowprocesses":{"T1055.012":"H"},"psxview":{"T1014":"H","T1057":"H"},
    "hashdump":{"T1003.002":"H","T1003":"H"},"cachedump":{"T1003.005":"H","T1003":"H"},
    "lsadump":{"T1003.004":"H"},"ssdt":{"T1014":"H","T1562.001":"H"},
    "callbacks":{"T1014":"H"},"direct_system_calls":{"T1106":"H","T1562.001":"H"},
    "unhooked_system_calls":{"T1106":"H","T1562.001":"H"},
    "etwpatch":{"T1562.006":"H","T1562.001":"H"},"mbrscan":{"T1542.003":"H"},
    "process_spoofing":{"T1036":"H","T1036.005":"H"},
    "ldrmodules":{"T1055.001":"H","T1574.001":"H"},
    "shimcachemem":{"T1546.011":"H"},"scheduled_tasks":{"T1053.005":"H"},
    "svcdiff":{"T1543.003":"H"},"mftscan":{"T1070.004":"H","T1564.004":"H","T1564.001":"M"},
    "unloadedmodules":{"T1070":"H"},"netscan":{"T1049":"H","T1071":"M","T1021":"M"},
    "dlllist":{"T1055.001":"H","T1574":"M"},"cmdline":{"T1059":"H","T1059.001":"H"},
    "certificates":{"T1553.004":"H"},
}

THREAT_ACTORS: Dict[str, List[str]] = {
    "APT1 (Comment Crew / Unit 61398)":["T1059","T1082","T1057","T1083","T1049","T1012"],
    "APT28 (Fancy Bear / Sofacy / Pawn Storm)":["T1055","T1059","T1059.001","T1082","T1003","T1014","T1547.001","T1574","T1027"],
    "APT29 (Cozy Bear / The Dukes)":["T1055.012","T1059","T1059.001","T1082","T1003","T1003.001","T1547.001","T1027","T1620"],
    "APT32 (OceanLotus / Cobalt Kitty)":["T1055","T1059","T1082","T1574.001","T1027"],
    "APT38 / Lazarus Group (Hidden Cobra)":["T1055","T1059","T1082","T1003","T1014","T1486","T1036","T1620"],
    "APT41 (Winnti / BARIUM / Double Dragon)":["T1055","T1059","T1003","T1082","T1014","T1053.005","T1574","T1106"],
    "BlackCat / ALPHV":["T1486","T1082","T1083","T1003","T1003.001"],
    "Carbanak / FIN7 / Navigator Group":["T1059","T1059.001","T1055","T1082","T1003","T1543.003","T1547.001"],
    "Cl0p Ransomware":["T1486","T1082","T1083","T1003","T1036"],
    "Conti Ransomware":["T1486","T1082","T1083","T1003","T1003.001","T1059","T1059.001","T1543.003"],
    "DarkHotel (Tapaoux)":["T1059","T1055","T1082","T1574.001"],
    "Equation Group (NSA / GCHQ-linked)":["T1014","T1082","T1003","T1055","T1542.003","T1027","T1106"],
    "Gamaredon (Primitive Bear)":["T1059","T1082","T1083","T1547.001"],
    "Hive Ransomware":["T1486","T1082","T1083","T1003","T1059"],
    "Kimsuky (Thallium / Black Banshee)":["T1059","T1082","T1083","T1056.001","T1003"],
    "LockBit Ransomware":["T1486","T1082","T1083","T1003","T1059","T1543.003","T1070"],
    "MuddyWater (Static Kitten)":["T1059","T1059.001","T1082","T1083","T1027","T1055"],
    "NotPetya / Sandworm (GRU Unit 74455)":["T1486","T1003","T1003.001","T1082","T1059","T1106"],
    "REvil / Sodinokibi":["T1486","T1082","T1083","T1003","T1059","T1547.001"],
    "Ryuk Ransomware":["T1486","T1082","T1083","T1003","T1003.001","T1059","T1543.003","T1070"],
    "ShadowPad (APT41-linked)":["T1055","T1082","T1014","T1574","T1106"],
    "TA505 (Evil Corp-linked)":["T1059","T1059.001","T1055","T1082","T1543.003","T1027"],
    "Turla (Venomous Bear / Waterbug)":["T1055","T1059","T1014","T1082","T1056.001","T1574","T1106"],
    "WannaCry (Lazarus Group)":["T1486","T1082","T1059"],
    "Winnti Group (APT41 overlap)":["T1055","T1014","T1082","T1574","T1543.003"],
    "Wizard Spider (Ryuk / TrickBot)":["T1059","T1059.001","T1082","T1003","T1003.001","T1486","T1543.003","T1070"],
}

VOL_PLUGINS_BY_OS: Dict[str, Dict[str, List[str]]] = {
    "windows": {
        "Process Analysis":  [
            "windows.pslist","windows.psscan","windows.pstree",
            "windows.malware.psxview","windows.cmdline","windows.cmdscan",
            "windows.consoles","windows.envars","windows.handles",
            "windows.sessions","windows.getsids","windows.getservicesids",
            "windows.privileges","windows.joblinks","windows.kpcrs",
        ],
        "Code Injection":    [
            "windows.malware.malfind","windows.malware.hollowprocesses",
            "windows.malware.processghosting","windows.vadinfo","windows.vadwalk",
            "windows.vadyarascan","windows.vadregexscan","windows.dlllist",
            "windows.malware.ldrmodules","windows.memmap","windows.pedump",
            "windows.threads","windows.thrdscan","windows.suspended_threads",
            "windows.malware.pebmasquerade","windows.malware.suspicious_threads",
            "windows.orphan_kernel_threads","windows.pe_symbols","windows.virtmap",
        ],
        "Credentials":       [
            "windows.registry.hashdump","windows.registry.cachedump",
            "windows.registry.lsadump","windows.malware.skeleton_key_check",
            "windows.truecrypt",
        ],
        "Registry":          [
            "windows.registry.hivelist","windows.registry.hivescan",
            "windows.registry.printkey","windows.registry.userassist",
            "windows.registry.certificates","windows.registry.getcellroutine",
            "windows.registry.amcache","windows.shimcachemem",
        ],
        "Network":           [
            "windows.netscan","windows.netstat","windows.mutantscan",
        ],
        "Rootkit/Evasion":   [
            "windows.ssdt","windows.callbacks","windows.modules","windows.modscan",
            "windows.driverscan","windows.driverirp","windows.malware.drivermodule",
            "windows.unloadedmodules","windows.etwpatch",
            "windows.malware.unhooked_system_calls","windows.malware.direct_system_calls",
            "windows.malware.indirect_system_calls","windows.mbrscan",
            "windows.bigpools","windows.timers","windows.devicetree","windows.poolscanner",
        ],
        "DLL/Module":        [
            "windows.dlllist","windows.malware.ldrmodules","windows.iat",
            "windows.pe_symbols",
        ],
        "Files/MFT":         [
            "windows.filescan","windows.mftscan","windows.dumpfiles",
            "windows.symlinkscan","windows.strings","windows.verinfo",
        ],
        "Persistence":       [
            "windows.svcscan","windows.malware.svcdiff","windows.registry.scheduled_tasks",
            "windows.windows","windows.windowstations","windows.statistics",
        ],
        "System Info":       [
            "windows.info","windows.psxview",
        ],
    },
    "linux": {
        "Process Analysis":  ["linux.pslist","linux.psscan","linux.pstree","linux.cmdline","linux.bash","linux.envars","linux.proc","linux.pidhashtable","linux.pscallstack"],
        "Code Injection":    ["linux.malfind","linux.proc_maps","linux.memmap","linux.vadinfo","linux.vmaregexscan","linux.vmayarascan","linux.ptrace","linux.suspicious_threads","linux.orphan_kernel_threads"],
        "Network":           ["linux.sockstat","linux.sockscan","linux.netfilter","linux.ifconfig","linux.ip","linux.lsof"],
        "Rootkit/Evasion":   ["linux.check_afinfo","linux.check_modules","linux.check_syscall","linux.check_sysctl","linux.ebpf","linux.ftrace","linux.hidden_modules","linux.lsmod","linux.kthreads","linux.tracepoints","linux.tty_check","linux.keyboard_notifiers"],
        "Files":             ["linux.filescan","linux.lsof","linux.symlinkscan","linux.mountinfo","linux.mount","linux.list_files","linux.pagecache","linux.regexscan"],
        "Credentials":       ["linux.tty_check","linux.keyboard_notifiers","linux.capabilities"],
        "System Info":       ["linux.dmesg","linux.vmcoreinfo","linux.kallsyms","linux.kmsg","linux.boottime","linux.iomem","linux.yarascan","linux.strings"],
    },
    "mac": {
        "Process Analysis":  ["mac.pslist","mac.psscan","mac.pstree","mac.cmdline","mac.bash","mac.envars"],
        "Code Injection":    ["mac.malfind","mac.proc_maps","mac.memmap","mac.vadinfo"],
        "Network":           ["mac.sockstat","mac.sockscan","mac.lsof","mac.ifconfig","mac.ip"],
        "Rootkit/Evasion":   ["mac.check_syscall","mac.hidden_modules","mac.kauth_listeners","mac.kauth_scopes","mac.socket_filters","mac.trustedbsd"],
        "Files":             ["mac.filescan","mac.lsof","mac.symlinkscan","mac.mountinfo","mac.pagecache"],
        "System Info":       ["mac.dmesg","mac.yarascan","mac.strings"],
    },
}

def _get_plugins_for_techniques(technique_ids: list, os_profile: str = "windows") -> list:
    ns = os_profile.lower() + "."
    matched, seen = [], set()
    for plugin_key, techs in PLUGIN_MITRE_MAP.items():
        if any(t in technique_ids for t in techs):
            full = f"{ns}{plugin_key}"
            if full not in seen:
                matched.append(full)
                seen.add(full)
    return matched

_WIN_DRIVE_RE = re.compile(r'^([A-Za-z]):[/\\](.*)', re.DOTALL)
_MEMORY_DUMPS_DIR = "/app/memory-dumps"   # container path of the MEMORY_DUMPS_DIR bind-mount

def _resolve_image_path(image_path: str):
    """
    Normalise a user-supplied memory image path for the Linux container.
    Returns (resolved_path: str, error: str | None).

    Resolution order for Windows paths (C:\\...):
      1. /mnt/{drive}/...         — MEMORY_DUMPS_DIR=C:\\ in .env mounts C: here
      2. /{drive}/...             — alternative mount convention
      3. /app/memory-dumps/{name} — MEMORY_DUMPS_DIR pointing at the dump's directory
    """
    if not image_path:
        return image_path, "image_path is empty"

    m = _WIN_DRIVE_RE.match(image_path)
    if m:
        drive = m.group(1).lower()
        rest  = m.group(2).replace("\\", "/")
        filename = rest.split("/")[-1]
        candidates = [
            f"/mnt/{drive}/{rest}",              # MEMORY_DUMPS_DIR=C:\ → C: at /mnt/c
            f"/{drive}/{rest}",                  # WSL2 / alternative convention
            f"{_MEMORY_DUMPS_DIR}/{rest}",       # MEMORY_DUMPS_DIR=C:\ → C: at /app/memory-dumps
            f"{_MEMORY_DUMPS_DIR}/{filename}",   # MEMORY_DUMPS_DIR=the dump's folder directly
        ]
        for candidate in candidates:
            if os.path.exists(candidate):
                return candidate, None
        drive_upper = drive.upper()
        return image_path, (
            f"Windows path '{image_path}' is not accessible from inside the Docker container.\n"
            f"To fix, set MEMORY_DUMPS_DIR in your .env to the folder containing the dump:\n"
            f"  MEMORY_DUMPS_DIR={drive_upper}:\\{chr(92).join(rest.split('/')[:-1]) or ''}\n"
            f"Then restart: docker compose up -d --no-deps orca-backend\n"
            f"The file will be available at /app/memory-dumps/{filename}\n"
            f"Or copy the dump into the ORCA memory-dumps folder and use /app/memory-dumps/{filename}"
        )

    # Linux path — if it's a directory, look for the first image file inside it
    if os.path.isdir(image_path):
        _img_exts = {".raw", ".mem", ".dmp", ".vmem", ".lime", ".bin", ".img", ".dd"}
        try:
            for fname in sorted(os.listdir(image_path)):
                if os.path.splitext(fname)[1].lower() in _img_exts:
                    return os.path.join(image_path, fname), None
        except PermissionError:
            pass
        return image_path, (
            f"Path '{image_path}' is a directory with no recognised memory image files.\n"
            f"Drop a .raw/.mem/.dmp/.vmem file into that folder, then click BROWSE to select it."
        )

    if not os.path.exists(image_path):
        return image_path, f"File not found: {image_path}"

    return image_path, None


def _build_vol_cmd(vol3_base, image_path, plugin, symbol_paths, args):
    vol_py = os.path.join(vol3_base, "vol.py")
    # -r quick: tab-separated output required by the tab-based parser.
    # --parallelism threads: uses multiple cores for the PDB signature scan
    # (the scan that finds the kernel PDB GUID in the dump — bottleneck for
    # large files).  "processes" is unsafe in containers; "threads" is safe.
    # -u: force unbuffered stdout/stderr so progress writes flush immediately
    # through the pipe instead of accumulating until process exit.
    # NOTE: --parallelism threads breaks the PageMapScanner DTB detection on
    # raw physical dumps and must NOT be used.
    cmd = ["python", "-u", vol_py, "--offline", "-r", "quick", "-f", image_path]
    if symbol_paths:
        cmd.extend(["-s", symbol_paths])
    cmd.append(plugin)
    if args:
        cmd.extend(args)
    return cmd

async def _stream_plugin(vol3_base, image_path, plugin, symbol_paths, extra_args, pmap, pconf):
    columns = None
    row_count = 0
    resolved, path_err = _resolve_image_path(image_path)
    if path_err:
        yield {"type": "plugin_error", "data": {"plugin": plugin, "error": path_err}}
        return

    # Show file size upfront so the user knows why scanning takes time
    try:
        size_gb = os.path.getsize(resolved) / (1024 ** 3)
        yield {"type": "log", "data": f"Image: {resolved} ({size_gb:.1f} GB) — scanning for kernel PDB…"}
    except OSError:
        yield {"type": "log", "data": f"Image: {resolved}"}

    cmd = _build_vol_cmd(vol3_base, resolved, plugin, symbol_paths, extra_args)
    plugin_key = plugin.split(".")[-1]
    mapped_techs = pmap.get(plugin_key, [])
    confidence_map = pconf.get(plugin_key, {})

    try:
        # 10 MB line limit — Volatility3's quick renderer puts one row per line;
        # some fields (raw bytes, long paths) exceed the default 64 KB limit and
        # raise asyncio.LimitOverrunError ("Separator is not found, and chunk
        # exceed the limit").
        process = await asyncio.create_subprocess_exec(
            *cmd, cwd=vol3_base,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            limit=10 * 1024 * 1024
        )

        # Interleave stdout and stderr reads so Volatility3's progress messages
        # (written to stderr) appear in real-time instead of only after the
        # plugin finishes.  This also prevents the stderr pipe from filling up
        # and causing a deadlock on large dumps.
        # stdout: readline() — rows are newline-terminated
        # stderr: read(4096) — Volatility3 progress uses \r (no newline), so
        #         readline() would block until program exit; read() returns as
        #         soon as any bytes are available.
        stdout_fut = asyncio.ensure_future(process.stdout.readline())
        stderr_fut = asyncio.ensure_future(process.stderr.read(4096))

        # Throttle state: only emit "Updating caches" progress every 5 %
        _last_cache_pct: float = -5.0
        # True when Volatility3 outputs a requirements-check table instead of
        # real plugin data (happens when the symbol table isn't found).  In that
        # case we route every stdout line to the log rather than the data table.
        _requirements_error: bool = False

        while stdout_fut is not None or stderr_fut is not None:
            active = [f for f in (stdout_fut, stderr_fut) if f is not None]
            done, _ = await asyncio.wait(active, return_when=asyncio.FIRST_COMPLETED)

            if stdout_fut in done:
                raw = stdout_fut.result()
                if raw:
                    line = raw.decode("utf-8", errors="replace").rstrip()
                    if line:
                        if _requirements_error:
                            # Already flagged as error output — log every line
                            yield {"type": "log", "data": f"[PLUGIN] {line.replace(chr(9), ' ')}" }
                        elif columns is None and '\t' not in line:
                            pass  # skip non-tab banner lines
                        elif columns is None:
                            first_col = line.split("\t")[0].strip()
                            # Real column headers are short identifiers (PID, PPID…).
                            # Volatility3's requirements-check output starts with
                            # long sentences like "A file was provided to create…"
                            if len(first_col) > 40 or ' was ' in first_col or 'requirement' in first_col.lower():
                                _requirements_error = True
                                yield {"type": "log", "data": f"[PLUGIN] {line.replace(chr(9), ' ')}"}
                            else:
                                columns = [c.strip() for c in line.split("\t")]
                                yield {"type": "columns", "data": columns}
                        else:
                            values = [v.strip() for v in line.split("\t")]
                            if len(values) < len(columns):
                                values += [''] * (len(columns) - len(values))
                            row = dict(zip(columns, values))
                            row["_mitre_techniques"] = [
                                {"t_code": t, "confidence": confidence_map.get(t, "M")}
                                for t in mapped_techs
                            ]
                            row_count += 1
                            yield {"type": "row", "data": row}
                    stdout_fut = asyncio.ensure_future(process.stdout.readline())
                else:
                    stdout_fut = None  # EOF

            if stderr_fut in done:
                raw = stderr_fut.result()
                if raw:
                    # Split on both \r and \n so \r-based progress updates each
                    # become their own log line.
                    parts = raw.decode("utf-8", errors="replace").replace('\r\n', '\n').replace('\r', '\n').split('\n')
                    for part in parts:
                        part = part.strip()
                        if not part:
                            continue
                        # Throttle symbol-cache rebuild progress to one line per 5%
                        m = re.search(r'Progress:\s+([\d.]+)\s+Updating caches', part)
                        if m:
                            pct = float(m.group(1))
                            if pct - _last_cache_pct < 5.0:
                                continue
                            _last_cache_pct = pct
                        yield {"type": "log", "data": part}
                    stderr_fut = asyncio.ensure_future(process.stderr.read(4096))
                else:
                    stderr_fut = None  # EOF

        await process.wait()
        if _requirements_error:
            yield {"type": "plugin_error", "data": {
                "plugin": plugin,
                "error": (
                    "Symbol table not found for this memory image. "
                    "Volatility3 needs a pre-built Windows ISF symbol file that matches the "
                    "exact kernel build in the dump. Download the Volatility3 Windows symbol "
                    "pack (windows.zip from the Volatility Foundation releases) and extract it "
                    "into the Volatility3 symbols/windows/ directory inside the container, or "
                    "specify the path via the Symbol Paths field."
                ),
            }}
        else:
            yield {"type": "plugin_done", "data": {"plugin": plugin, "rows": row_count}}
    except Exception as e:
        yield {"type": "plugin_error", "data": {"plugin": plugin, "error": str(e)}}

def to_dict(row):
    if row is None:
        return None
    if hasattr(row, '_mapping'):
        data = dict(row._mapping)
    elif hasattr(row, '__table__'):
        # SQLAlchemy ORM model instance
        data = {c.name: getattr(row, c.name) for c in row.__table__.columns}
    else:
        data = dict(row)
    return {
        "id": data.get('id') or data.get('s_code') or data.get('m_code') or "",
        "stix_id": data.get('stix_id') or "",
        "name": data.get('name') or "Unknown",
        "description": data.get('description') or "",
        "domain": data.get('domain') or "enterprise-attack"
    }

# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/techniques")
def get_all_techniques(current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        results = session.execute(text("""
            SELECT t_code, name AS technique_name
            FROM public.mitre_techniques
            WHERE NOT COALESCE(is_deprecated, FALSE)
              AND NOT COALESCE(is_revoked, FALSE)
            ORDER BY t_code ASC
        """)).mappings().all()
        return [dict(r) for r in results]
    except Exception as _e:
        logging.error(f"[mitre_routes] {_e}")
        return []
    finally:
        session.close()


@router.get("/evidence/{asset_id}/timeline")
async def get_unified_timeline(
    asset_id: int,
    page: int = 0,
    page_size: int = 200,
    date_from: str = "",
    date_to: str = "",
    sources: str = "",
    filters: str = "",
    current_user: dict = Depends(get_current_user),
):
    import re as _re

    source_filter = set(s.strip().upper() for s in sources.split(",") if s.strip()) if sources else set()
    filter_list = [f.strip() for f in filters.split("||") if f.strip()] if filters else []
    unions = []
    params: dict = {"aid": asset_id}

    def _valid_date(s: str) -> bool:
        return bool(s and _re.match(r'^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2})?$', s.strip()))

    def _date_clauses(ts_col: str, prefix: str) -> str:
        clauses = []
        if _valid_date(date_from):
            clauses.append(f"{ts_col} >= :{prefix}_from")
            params[f"{prefix}_from"] = date_from.strip()
        if _valid_date(date_to):
            clauses.append(f"{ts_col} < (:{prefix}_to ::date + interval '1 day')")
            params[f"{prefix}_to"] = date_to.strip()
        return (" AND " + " AND ".join(clauses)) if clauses else ""

    def _filter_clauses(title_col: str, detail_col: str) -> str:
        if not filter_list:
            return ""
        clauses = []
        for i, f in enumerate(filter_list):
            k = f"flt{i}"
            params[k] = f"%{f.lower()}%"
            clauses.append(f"(LOWER(COALESCE({title_col}, '')) LIKE :{k} OR LOWER(COALESCE({detail_col}, '')) LIKE :{k})")
        return " AND " + " AND ".join(clauses)

    # MFT
    if not source_filter or "MFT" in source_filter:
        dc = _date_clauses("si_created", "mft")
        sc = _filter_clauses("file_name", "full_path")
        unions.append(
            "SELECT si_created AS ts, 'MFT' AS source, file_name AS title, full_path AS detail,"
            " CASE WHEN in_use = FALSE THEN 'DELETED'"
            " WHEN si_lt_fn = TRUE THEN 'TIMESTOMP'"
            " WHEN has_ads = TRUE THEN 'ADS'"
            " ELSE 'NORMAL' END AS flag,"
            " file_size::text AS extra"
            " FROM mft_entries"
            f" WHERE asset_id = :aid AND si_created IS NOT NULL AND is_dir = FALSE {dc}{sc}"  # nosec B608 — dc/sc are server-computed parameterized clauses; no user input
        )

    # Event Logs
    event_log_tcodes = [
        'EVENT_LOGS_SECURITY','EVENT_LOGS_SYSTEM','EVENT_LOGS_APPLICATION',
        'EVENT_LOGS_SYSMON','EVENT_LOGS_POWERSHELL','EVENT_LOGS_WMI',
        'EVENT_LOGS_WINRM','EVENT_LOGS_TASKSCHEDULER',
    ]
    active_el = [t for t in event_log_tcodes if not source_filter or t in source_filter or "EVENT_LOGS" in source_filter]
    if active_el:
        params["el_tcodes"] = active_el
        ts_expr = "to_timestamp((raw_data->>'EventTime')::double precision)"
        dc = _date_clauses(ts_expr, "el")
        sc = _filter_clauses("raw_data->>'EventID'", "COALESCE(raw_data->>'Message', raw_data->>'Description', '')")
        unions.append(
            f"SELECT {ts_expr} AS ts, t_code AS source,"  # nosec B608 — ts_expr is a hardcoded SQL expression; no user input
            " COALESCE(raw_data->>'EventID', raw_data->>'EventId', '?') AS title,"
            " COALESCE(raw_data->>'Message', raw_data->>'Description', '') AS detail,"
            " COALESCE(raw_data->>'Level', '') AS flag,"
            " COALESCE(raw_data->>'Computer', '') AS extra"
            " FROM evidence"
            " WHERE asset_id = :aid AND t_code = ANY(:el_tcodes)"
            " AND raw_data ? 'EventTime' AND (raw_data->>'EventTime') IS NOT NULL"
            f" {dc}{sc}"  # nosec B608 — dc/sc are server-computed parameterized clauses
        )

    # Prefetch
    if not source_filter or "PREFETCH" in source_filter:
        dc = _date_clauses("(rtime)::timestamptz", "pf")
        sc = _filter_clauses("raw_data->>'Executable'", "raw_data->>'Path'")
        unions.append(f"""
            SELECT (rtime)::timestamptz AS ts, 'PREFETCH' AS source,
                COALESCE(raw_data->>'Executable', 'UNKNOWN') AS title,
                COALESCE(raw_data->>'Path', '') AS detail,
                'RUN' AS flag,
                COALESCE(raw_data->>'RunCount', '') AS extra
            FROM evidence,
                 jsonb_array_elements_text(
                     CASE jsonb_typeof(raw_data->'LastRunTimes')
                         WHEN 'array' THEN raw_data->'LastRunTimes'
                         ELSE '[]' ::jsonb END
                 ) AS rtime
            WHERE asset_id = :aid AND t_code = 'PREFETCH'
              AND (rtime) IS NOT NULL AND (rtime) != '' AND (rtime) != 'null'
              {dc}{sc}
        """)

    # LNK
    if not source_filter or "LNK_JUMPLISTS" in source_filter or "LNK" in source_filter:
        dc = _date_clauses("(raw_data->>'Mtime')::timestamptz", "lnk")
        sc = _filter_clauses("raw_data->>'FileName'", "raw_data->>'SourceFile'")
        unions.append(f"""
            SELECT (raw_data->>'Mtime')::timestamptz AS ts, 'LNK_JUMPLISTS' AS source,
                COALESCE(raw_data->>'FileName', 'UNKNOWN') AS title,
                COALESCE(raw_data->>'SourceFile', '') AS detail,
                'LNK' AS flag,
                COALESCE(raw_data->>'Size', '') AS extra
            FROM evidence
            WHERE asset_id = :aid AND t_code = 'LNK_JUMPLISTS'
              AND (raw_data->>'Mtime') IS NOT NULL {dc}{sc}
        """)

    # Scheduled Tasks
    if not source_filter or "SCHEDULED_TASKS" in source_filter:
        dc = _date_clauses("(raw_data->>'ModTime')::timestamptz", "st")
        sc = _filter_clauses("raw_data->>'Path'", "raw_data->>'URI'")
        unions.append(f"""
            SELECT (raw_data->>'ModTime')::timestamptz AS ts, 'SCHEDULED_TASKS' AS source,
                COALESCE(raw_data->>'Path', raw_data->>'URI', 'UNKNOWN') AS title,
                '' AS detail, 'TASK' AS flag, '' AS extra
            FROM evidence
            WHERE asset_id = :aid AND t_code = 'SCHEDULED_TASKS'
              AND (raw_data->>'ModTime') IS NOT NULL {dc}{sc}
        """)

    if not unions:
        return {"total": 0, "page": page, "page_size": page_size, "entries": []}

    union_sql = " UNION ALL ".join(f"({u})" for u in unions)
    count_sql = f"SELECT COUNT(*) FROM ({union_sql}) AS tl WHERE ts IS NOT NULL"
    paged_sql = f"""
        SELECT ts, source, title, detail, flag, extra
        FROM ({union_sql}) AS tl
        WHERE ts IS NOT NULL
        ORDER BY ts DESC
        LIMIT :limit OFFSET :offset
    """
    params["limit"]  = page_size
    params["offset"] = page * page_size

    try:
        with db.engine.connect() as conn:
            total = conn.execute(text(count_sql), params).scalar() or 0
            rows  = conn.execute(text(paged_sql), params).mappings().all()
    except Exception as e:
        print(f"[TIMELINE ERROR] asset_id={asset_id}: {e}")
        import traceback; traceback.print_exc()
        return {"total": 0, "page": page, "page_size": page_size, "entries": [], "error": str(e)}

    entries = [
        {
            "ts":     r["ts"].isoformat() if r["ts"] else None,
            "source": r["source"],
            "title":  r["title"] or "",
            "detail": (r["detail"] or "")[:2000],
            "flag":   r["flag"] or "",
            "extra":  r["extra"] or "",
        }
        for r in rows
    ]
    return {"total": total, "page": page, "page_size": page_size, "entries": entries}


# Maps each REGISTRY_* sub-technique to (hive_root, path_segments), mirroring the
# `globs=` path each sub-technique's own VQL actually collects. path_segments is a
# list walked one level at a time:
#   '*'      matches (and keeps) every child at that level
#   callable matches (and keeps) only children whose key name passes the predicate
#   str      matches that one literal child key
# Empty list = whole hive.
#
# HKEY_USERS mounts two hives per user, as siblings: the SID key itself is
# NTUSER.DAT; a second "<SID>_Classes" key is UsrClass.dat — a genuinely separate
# hive file, not a subtree of the SID key. NTUSER/USRCLASS must partition on that
# suffix or each one's view bleeds into the other's.
_NOT_CLASSES_HIVE = lambda k: not k.endswith('_Classes')
_CLASSES_HIVE     = lambda k: k.endswith('_Classes')

_REGISTRY_SUBTREE_MAP = {
    'REGISTRY_CLASSES_ROOT':   ('HKEY_CLASSES_ROOT', []),
    'REGISTRY_NTUSER':         ('HKEY_USERS', [_NOT_CLASSES_HIVE]),
    'REGISTRY_USRCLASS':       ('HKEY_USERS', [_CLASSES_HIVE]),
    'REGISTRY_SAM':            ('HKEY_LOCAL_MACHINE', ['SAM']),
    'REGISTRY_SECURITY':       ('HKEY_LOCAL_MACHINE', ['SECURITY']),
    'REGISTRY_SOFTWARE':       ('HKEY_LOCAL_MACHINE', ['SOFTWARE']),
    'REGISTRY_SYSTEM':         ('HKEY_LOCAL_MACHINE', ['SYSTEM']),
    'REGISTRY_CURRENT_CONFIG': ('HKEY_LOCAL_MACHINE',
                                ['SYSTEM', 'CurrentControlSet', 'Hardware Profiles', 'Current']),
}


def _slice_registry_subtree(node, path_segments):
    """Walk `node` along path_segments, returning only the matched branches
    (still keyed by their real names) instead of the whole node. '*' keeps
    every child at that level; a callable keeps children whose name it accepts."""
    if not path_segments:
        return node
    seg, rest = path_segments[0], path_segments[1:]
    items = [(k, v) for k, v in node.items() if k not in ('_values', '_meta')]
    if seg == '*':
        candidates = items
    elif callable(seg):
        candidates = [(k, v) for k, v in items if seg(k)]
    else:
        candidates = [(seg, node[seg])] if seg in node else []
    result = {}
    for k, v in candidates:
        if not isinstance(v, dict):
            continue
        sliced = _slice_registry_subtree(v, rest) if rest else v
        if sliced:
            result[k] = sliced
    return result


@router.get("/evidence/{asset_id}/{t_code}")
async def get_modular_evidence(asset_id: int, t_code: str, current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        summary_res = session.execute(
            text("SELECT evidence_summary FROM artifact_results WHERE asset_id = :aid AND t_code = :t"),
            {"aid": asset_id, "t": t_code}
        ).mappings().first()
        summary_text = summary_res['evidence_summary'] if summary_res else ""
        if isinstance(summary_text, dict):
            summary_text = summary_text.get("message", str(summary_text))
        rows = session.execute(text("""
            SELECT id, starred, COALESCE(raw_data, json_build_object('file_name', file_name, 'file_path', file_path)::jsonb) as data
            FROM evidence WHERE asset_id = :aid AND t_code = :t
        """), {"aid": asset_id, "t": t_code}).mappings().all()
        evidence_list = []
        for r in rows:
            d = json.loads(r['data']) if isinstance(r['data'], str) else dict(r['data'])
            d['_orca_row_id'] = r['id']
            d['_orca_starred'] = r['starred']
            evidence_list.append(d)

        # For REGISTRY_* sub-techniques with no direct rows, slice from the merged REGISTRY rollup.
        if not evidence_list and t_code in _REGISTRY_SUBTREE_MAP:
            rollup = session.execute(text("""
                SELECT raw_data FROM evidence
                WHERE asset_id = :aid AND t_code = 'REGISTRY'
                LIMIT 1
            """), {"aid": asset_id}).mappings().first()
            if rollup:
                try:
                    doc = json.loads(rollup['raw_data']) if isinstance(rollup['raw_data'], str) else rollup['raw_data']
                    hive_root, path_segments = _REGISTRY_SUBTREE_MAP[t_code]
                    full_tree = doc.get('tree', {})
                    hive_tree = full_tree.get(hive_root, {})
                    subtree = {hive_root: _slice_registry_subtree(hive_tree, path_segments)}
                    evidence_list = [{
                        'tree': subtree,
                        'key_count': doc.get('key_count', 0),
                        'hives': [hive_root],
                        '_sliced_from': 'REGISTRY',
                    }]
                except Exception:
                    pass

        return {"t_code": t_code, "summary": summary_text, "rows": evidence_list}
    finally:
        session.close()

@router.get("/evidence/{asset_id}/{t_code}/rows")
async def get_evidence_rows_paginated(
    asset_id: int,
    t_code: str,
    page: int = 0,
    page_size: int = 100,
    search: str = "",
    starred_only: bool = False,
    current_user: dict = Depends(get_current_user),
):
    """
    Paginated evidence rows with optional server-side search.
    Used by EvidenceWindow for large artifacts (Event Logs, SRUM, etc.)
    Search is a case-insensitive substring match across the full raw_data JSONB.
    starred_only, when true, restricts to rows the analyst has starred —
    combines with search (AND), not a replacement for it.
    """
    params: dict = {
        "aid": asset_id,
        "t": t_code,
        "limit": page_size,
        "offset": page * page_size,
    }

    if search:
        # Cast JSONB to text for substring search — fast enough for analyst use
        where_search = "AND raw_data::text ILIKE :search"
        params["search"] = f"%{search}%"
    else:
        where_search = ""

    where_starred = "AND starred = true" if starred_only else ""

    with db.engine.connect() as conn:
        total = conn.execute(text(
            "SELECT COUNT(*) FROM evidence"
            f" WHERE asset_id = :aid AND t_code = :t {where_search} {where_starred}"  # nosec B608 — where_search/where_starred are fixed literals, not user data
        ), params).scalar() or 0

        rows = conn.execute(text(
            "SELECT id, starred, raw_data FROM evidence"
            f" WHERE asset_id = :aid AND t_code = :t {where_search} {where_starred}"  # nosec B608 — same as above
            " ORDER BY id ASC LIMIT :limit OFFSET :offset"
        ), params).fetchall()

    evidence = []
    for r in rows:
        d = json.loads(r.raw_data) if isinstance(r.raw_data, str) else (dict(r.raw_data) if r.raw_data else {})
        d['_orca_row_id'] = r.id
        d['_orca_starred'] = r.starred
        evidence.append(d)

    return {
        "t_code":    t_code,
        "total":     total,
        "page":      page,
        "page_size": page_size,
        "rows":      evidence,
    }


@router.post("/evidence/{asset_id}/{t_code}/row/{row_id}/star")
async def set_evidence_row_starred(asset_id: int, t_code: str, row_id: int, data: StarredUpdate, current_user: dict = Depends(get_current_user)):
    with db.engine.begin() as conn:
        result = conn.execute(text("""
            UPDATE evidence SET starred = :starred
            WHERE id = :row_id AND asset_id = :aid AND t_code = :t
        """), {"starred": data.starred, "row_id": row_id, "aid": asset_id, "t": t_code})
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Evidence row not found")
    return {"status": "SUCCESS", "id": row_id, "starred": data.starred}


@router.post("/evidence/{asset_id}/{t_code}/verdict")
async def update_technique_verdict(asset_id: int, t_code: str, data: VerdictUpdate, current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        session.execute(
            text("UPDATE artifact_results SET verdict = :v, closed_at = CASE WHEN :v IN ('MALICIOUS', 'NON-MALICIOUS') THEN NOW() ELSE closed_at END WHERE asset_id = :aid AND t_code = :t"),
            {"v": data.verdict, "aid": asset_id, "t": t_code}
        )
        session.commit()
        return {"status": "SUCCESS", "verdict": data.verdict}
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

# ── TCode Notes ────────────────────────────────────────────────────────────────
@router.get("/evidence/{asset_id}/{t_code}/notes")
async def get_tcode_notes(asset_id: int, t_code: str, current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        results = session.execute(text("""
            SELECT id, note_text, note_type, created_at FROM public.tcode_notes
            WHERE asset_id = :aid AND t_code = :t ORDER BY created_at DESC
        """), {"aid": asset_id, "t": t_code}).mappings().all()
        return [{"id": r['id'], "text": r['note_text'], "type": r['note_type'],
                 "time": r['created_at'].strftime("%H:%M") if r['created_at'] else ""} for r in results]
    except Exception as _e:
        logging.error(f"[mitre_routes] {_e}")
        return []
    finally:
        session.close()

@router.post("/evidence/{asset_id}/{t_code}/notes")
async def add_tcode_note(asset_id: int, t_code: str, data: TCodeNotePayload, current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        session.execute(text("""
            CREATE TABLE IF NOT EXISTS public.tcode_notes (
                id SERIAL PRIMARY KEY,
                asset_id INTEGER NOT NULL,
                t_code VARCHAR(20) NOT NULL,
                note_text TEXT NOT NULL,
                note_type VARCHAR(10) DEFAULT 'NOTE',
                created_at TIMESTAMP DEFAULT NOW(),
                author_id INTEGER,
                author_initials VARCHAR(10)
            )
        """))
        result = session.execute(text("""
            INSERT INTO public.tcode_notes (asset_id, t_code, note_text, note_type)
            VALUES (:aid, :t, :text, :type) RETURNING id, created_at
        """), {"aid": asset_id, "t": t_code, "text": data.text, "type": data.note_type}).mappings().first()
        session.commit()
        return {"status": "SUCCESS", "id": result['id'], "time": result['created_at'].strftime("%H:%M")}
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

@router.delete("/evidence/{asset_id}/{t_code}/notes/{note_id}")
async def delete_tcode_note(asset_id: int, t_code: str, note_id: int, current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        session.execute(
            text("DELETE FROM public.tcode_notes WHERE id = :id AND asset_id = :aid AND t_code = :t"),
            {"id": note_id, "aid": asset_id, "t": t_code}
        )
        session.commit()
        return {"status": "SUCCESS"}
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

@router.post("/evidence/{asset_id}/{t_code}/upload")
async def upload_evidence_manual(asset_id: int, t_code: str, payload: dict, current_user: dict = Depends(get_current_user)):
    rows = payload.get("rows", [])
    filename = payload.get("filename", "manual_upload")
    if not rows:
        raise HTTPException(status_code=400, detail="No rows provided")
    import json
    with db.engine.connect() as conn:
        for item in rows:
            clean = {}
            for k, v in item.items():
                clean[k] = json.dumps(v) if isinstance(v, (dict, list)) else v
            display_name = item.get("Name") or item.get("EventID") or item.get("ID") or filename
            display_path = item.get("Key") or item.get("OSPath") or item.get("FullPath") or "ManualUpload"
            conn.execute(text("""
                INSERT INTO evidence (asset_id, t_code, file_name, file_path, raw_data)
                VALUES (:aid, :t, :fname, :fpath, :raw)
            """), {"aid": asset_id, "t": t_code, "fname": display_name, "fpath": display_path, "raw": json.dumps(clean)})
        summary = json.dumps({"message": f"Manual upload: {len(rows)} rows from {filename}"})
        conn.execute(text("""
            INSERT INTO artifact_results (asset_id, t_code, verdict, evidence_summary, evidence_imported)
            VALUES (:aid, :t, 'MANUAL_UPLOAD', :s, TRUE)
            ON CONFLICT (asset_id, t_code)
            DO UPDATE SET verdict = 'MANUAL_UPLOAD', evidence_summary = EXCLUDED.evidence_summary, evidence_imported = TRUE
        """), {"aid": asset_id, "t": t_code, "s": summary})
        conn.commit()
    return {"status": "ok", "rows_ingested": len(rows)}

@router.delete("/evidence/{asset_id}/{t_code}")
async def delete_evidence(asset_id: int, t_code: str, db: Session = Depends(get_db), current_user: dict = Depends(require_admin)):
    """Flush all evidence collected for one technique on one asset. Admin-only — every call is written to audit_log."""
    try:
        asset_row = db.execute(
            text("SELECT hostname, case_name FROM assets WHERE id = :aid"), {"aid": asset_id}
        ).mappings().first()
        if not asset_row:
            raise HTTPException(status_code=404, detail="ASSET_NOT_FOUND")

        deleted = db.execute(
            text("DELETE FROM evidence WHERE asset_id = :aid AND t_code = :t"),
            {"aid": asset_id, "t": t_code}
        )
        rows_removed = deleted.rowcount or 0

        db.execute(text("""
            UPDATE artifact_results
            SET evidence_imported = FALSE, evidence_summary = NULL
            WHERE asset_id = :aid AND t_code = :t
        """), {"aid": asset_id, "t": t_code})

        db.execute(text("""
            INSERT INTO audit_log (username, user_initials, action, case_name, asset_id, asset_hostname, t_code, details)
            VALUES (:username, :initials, 'DELETE_EVIDENCE', :case_name, :aid, :hostname, :t, :details)
        """), {
            "username": current_user.get("sub"),
            "initials": current_user.get("initials"),
            "case_name": asset_row["case_name"],
            "aid": asset_id,
            "hostname": asset_row["hostname"],
            "t": t_code,
            "details": f"Deleted {rows_removed} evidence row(s)",
        })

        db.commit()
        return {"status": "SUCCESS", "rows_removed": rows_removed}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

# ── Cases ──────────────────────────────────────────────────────────────────────
@router.get("/cases")
def get_all_cases(current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        results = session.execute(text(
            "SELECT name, team_name, mission_lead, focus_country, selected_groups, support, personnel, map_data, case_type, local_dir FROM public.cases"
        )).mappings().all()
        return [{"name": r['name'], "teamName": r['team_name'], "missionLead": r['mission_lead'],
                 "country": r['focus_country'], "support": r['support'] or "N/A",
                 "personnel": r['personnel'] or "0",
                 "case_type": r['case_type'] or 'INVESTIGATION',
                 "local_dir": r['local_dir'],
                 "groups": r['selected_groups'].split(",") if r['selected_groups'] else [],
                 "mapData": json.loads(r['map_data']) if isinstance(r['map_data'], str) else (r['map_data'] or [])} for r in results]
    except Exception as _e:
        logging.error(f"[mitre_routes] {_e}")
        return []
    finally:
        session.close()

@router.post("/cases")
def save_case(case_data: dict, current_user: dict = Depends(get_current_user)):
    case_name = (case_data.get('name') or '').strip()
    if not case_name:
        raise HTTPException(status_code=400, detail="Case name is required")

    session = db.get_session()
    try:
        groups_csv = ",".join(case_data.get('groups') or []) if isinstance(case_data.get('groups'), list) else ""
        session.execute(text("""
            INSERT INTO public.cases (name, team_name, mission_lead, focus_country, selected_groups, support, personnel, case_type)
            VALUES (:name, :team, :lead, :country, :groups, :support, :personnel, :case_type)
            ON CONFLICT (name) DO UPDATE SET
                team_name=EXCLUDED.team_name, mission_lead=EXCLUDED.mission_lead,
                focus_country=EXCLUDED.focus_country, selected_groups=EXCLUDED.selected_groups,
                support=EXCLUDED.support, personnel=EXCLUDED.personnel,
                case_type=EXCLUDED.case_type
        """), {"name": case_name, "team": case_data.get('teamName'), "lead": case_data.get('missionLead'),
               "country": case_data.get('country'), "groups": groups_csv,
               "support": case_data.get('support', 'N/A'), "personnel": case_data.get('personnel', '0'),
               "case_type": case_data.get('case_type', 'INVESTIGATION')})

        local_dir = None
        host_path = None
        if case_data.get('create_local_dir'):
            safe_name = re.sub(r'[^A-Za-z0-9_\-.]', '_', case_name or 'unnamed').strip('_') or 'unnamed'
            local_dir = f"/app/cases/{safe_name}"
            try:
                os.makedirs(local_dir, exist_ok=True)
                session.execute(text(
                    "UPDATE public.cases SET local_dir = :dir WHERE name = :name"
                ), {"dir": local_dir, "name": case_name})
                # Build the host-side path for display in the UI
                cases_dir_env = os.environ.get("CASES_DIR", "").strip()
                if cases_dir_env:
                    host_path = cases_dir_env.rstrip("/\\") + os.sep + safe_name
                else:
                    host_path = f"<ORCA folder>{os.sep}cases{os.sep}{safe_name}"
            except OSError as e:
                logging.warning(f"[cases] Could not create local dir {local_dir}: {e}")
                local_dir = None

        session.commit()
        return {"status": "SUCCESS", "message": "CASE_UPSERTED", "local_dir": local_dir, "host_path": host_path}
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        logging.error(f"[cases] save_case failed for '{case_name}': {e}")
        raise HTTPException(status_code=500, detail="Failed to save case")
    finally:
        session.close()

@router.post("/assets/triage-execute")
async def triage_execute(request: Request, current_user=Depends(get_current_user)):
    body = await request.json()
    asset_id   = int(body["asset_id"])
    ip         = body["ip"]
    transport  = body.get("transport", "WINRM")
    username   = body["username"]
    password   = body.get("password", "")
    domain     = body.get("domain")
    cleanup    = body.get("cleanup", True)
    categories = body.get("categories", list(vr_remote.TRIAGE_CATEGORY_MAP.keys()))

    async def event_stream():
        async for chunk in vr_remote.run_triage_collection(
            asset_id=asset_id, ip=ip, transport=transport,
            username=username, password=password,
            categories=categories, domain=domain, cleanup=cleanup,
            vr_exe=cfg.VR_EXE_WINDOWS, data_root=cfg.DATA_ROOT,
        ):
            yield chunk

    return StreamingResponse(event_stream(), media_type="text/event-stream")

@router.get("/evidence/{asset_id}/triage/categories")
async def get_triage_categories(asset_id: int, current_user=Depends(get_current_user)):
    """Return triage artifact categories that have evidence rows for this asset."""
    triage_codes = [
        'EVENT_LOGS_SECURITY','EVENT_LOGS_APPLICATION','EVENT_LOGS_SYSMON',
        'EVENT_LOGS_POWERSHELL','EVENT_LOGS_SYSTEM','EVENT_LOGS_TASKSCHEDULER',
        'EVENT_LOGS_WMI','EVENT_LOGS_WINRM',
        'PREFETCH','MFT',
        'REGISTRY',
        'BROWSER_CHROME','BROWSER_EDGE','BROWSER_FIREFOX',
        'LNK_JUMPLISTS','SCHEDULED_TASKS','WMI_PERSISTENCE',
        'SRUM','AMCACHE','RECYCLE_BIN','USB_ARTIFACTS',
    ]
    with db.engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT DISTINCT t_code FROM artifact_results
            WHERE asset_id = :asset_id AND t_code = ANY(:codes)
            ORDER BY t_code
        """), {"asset_id": asset_id, "codes": triage_codes}).fetchall()
    return {"categories": [r.t_code for r in rows]}


# ── Suspicious path prefixes for SUSPICIOUS view ──────────────────────────────
_MFT_SUSPICIOUS_PATHS = [
    'users\\', 'programdata\\', 'windows\\temp\\', 'appdata\\local\\temp\\',
    'appdata\\roaming\\', 'recycle', '$recycle.bin', 'temp\\', 'tmp\\',
    'public\\', 'windows\\system32\\tasks\\', 'windows\\syswow64\\',
]

@router.get("/evidence/{asset_id}/mft/query")
async def query_mft(
    asset_id: int,
    view: str = "suspicious",          # suspicious | timeline | search | tree
    page: int = 0,
    page_size: int = 200,
    search: str = "",
    path_prefix: str = "",
    date_from: str = "",
    date_to: str = "",
    deleted_only: bool = False,
    timestomp_only: bool = False,
    ads_only: bool = False,
    include_dirs: bool = False,
    current_user=Depends(get_current_user),
):
    """SQL-backed MFT query against mft_entries table."""

    # ── Base conditions ──────────────────────────────────────────────────────
    where = ["asset_id = :asset_id"]
    params: dict = {"asset_id": asset_id, "offset": page * page_size, "limit": page_size}

    if not include_dirs:
        where.append("is_dir = FALSE")
    if deleted_only:
        where.append("in_use = FALSE")
    if timestomp_only:
        where.append("si_lt_fn = TRUE")
    if ads_only:
        where.append("has_ads = TRUE")

    # ── View-specific conditions ─────────────────────────────────────────────
    order = "si_created DESC"

    if view == "suspicious":
        suspicious_clauses = " OR ".join([
            f"path_lower LIKE :{f'sp{i}'}"
            for i, _ in enumerate(_MFT_SUSPICIOUS_PATHS)
        ])
        for i, sp in enumerate(_MFT_SUSPICIOUS_PATHS):
            params[f"sp{i}"] = f"%{sp}%"
        # Root-level: path has no backslash  OR matches suspicious paths  OR deleted
        where.append(f"(path_lower NOT LIKE '%\\\\%' OR {suspicious_clauses} OR in_use = FALSE)")
        order = "in_use ASC, si_created DESC"

    elif view == "timeline":
        where.append("si_created IS NOT NULL")
        if date_from:
            where.append("si_created >= :date_from")
            params["date_from"] = date_from
        if date_to:
            where.append("si_created <= :date_to")
            params["date_to"] = date_to
        order = "si_created DESC"

    elif view == "tree":
        prefix = path_prefix.lower().rstrip("\\")
        if prefix:
            # Direct children only: path starts with prefix and has no further backslash after it
            where.append("path_lower LIKE :prefix_like")
            where.append(r"SUBSTRING(path_lower FROM LENGTH(:prefix_len) + 1) NOT LIKE '%\\%'")
            params["prefix_like"] = prefix + "%"
            params["prefix_len"] = prefix
        else:
            # Root level: no backslash in path at all
            where.append(r"path_lower NOT LIKE '%\\%'")
        order = "is_dir DESC, file_name ASC"

    elif view == "search":
        if not search:
            return {"view": view, "total": 0, "page": page, "page_size": page_size,
                    "file_count": 0, "meta_count": 0, "results": []}
        where.append("(path_lower LIKE :search OR LOWER(file_name) LIKE :search)")
        params["search"] = f"%{search.lower()}%"

    # ── Build and execute queries ────────────────────────────────────────────
    where_sql = " AND ".join(where)

    row_sql = (
        "SELECT entry_num, parent_num, file_name, full_path,"
        " is_dir, in_use, has_ads, si_lt_fn, copied, file_size, alt_names,"
        " si_created, si_modified, si_accessed, si_rc,"
        " fn_created, fn_modified, fn_accessed"
        " FROM mft_entries"
        f" WHERE {where_sql}"  # nosec B608 — where_sql built from hardcoded column conditions; user values are :parameterized
        f" ORDER BY {order}"  # nosec B608 — order is one of hardcoded column names validated server-side
        " LIMIT :limit OFFSET :offset"
    )
    count_sql = f"SELECT COUNT(*) FROM mft_entries WHERE {where_sql}"  # nosec B608 — same as above

    # Get total file/meta counts from sentinel evidence row
    with db.engine.connect() as conn:
        total = conn.execute(text(count_sql), params).scalar() or 0
        rows  = conn.execute(text(row_sql), params).mappings().all()

        sentinel = conn.execute(text("""
            SELECT raw_data FROM evidence WHERE asset_id = :aid AND t_code = 'MFT' LIMIT 1
        """), {"aid": asset_id}).fetchone()

    file_count = 0
    meta_count = 0
    if sentinel:
        doc = json.loads(sentinel.raw_data) if isinstance(sentinel.raw_data, str) else sentinel.raw_data
        file_count = doc.get("file_count", 0)
        meta_count = doc.get("meta_count", 0)

    def _fmt_row(r):
        return {
            "e":   r["entry_num"],
            "pe":  r["parent_num"],
            "n":   r["file_name"],
            "p":   r["full_path"],
            "d":   1 if r["is_dir"] else 0,
            "u":   1 if r["in_use"] else 0,
            "ads": 1 if r["has_ads"] else 0,
            "si_lt_fn": 1 if r["si_lt_fn"] else 0,
            "cp":  1 if r["copied"] else 0,
            "sz":  r["file_size"],
            "fn":  r["alt_names"] if isinstance(r["alt_names"], list) else (json.loads(r["alt_names"]) if r["alt_names"] else []),
            "c":   r["si_created"].isoformat()  if r["si_created"]  else None,
            "m":   r["si_modified"].isoformat() if r["si_modified"] else None,
            "a":   r["si_accessed"].isoformat() if r["si_accessed"] else None,
            "rc":  r["si_rc"].isoformat()       if r["si_rc"]       else None,
            "c3":  r["fn_created"].isoformat()  if r["fn_created"]  else None,
            "m3":  r["fn_modified"].isoformat() if r["fn_modified"] else None,
            "a3":  r["fn_accessed"].isoformat() if r["fn_accessed"] else None,
        }

    return {
        "view":       view,
        "total":      total,
        "page":       page,
        "page_size":  page_size,
        "file_count": file_count,
        "meta_count": meta_count,
        "results":    [_fmt_row(r) for r in rows],
    }


@router.get("/library/{t_code}")
async def get_artifact_library(t_code: str, current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        row = session.execute(text("""
            SELECT t_code, name AS technique_name, live_analysis, dead_disk_analysis,
                   collection_strategy, custom_vql, surgical_yaml
            FROM public.ref_artifact_library WHERE t_code = :t_code
        """), {"t_code": t_code.strip()}).mappings().first()
        return dict(row) if row else {"t_code": t_code, "technique_name": "", "live_analysis": "",
                                       "dead_disk_analysis": "", "collection_strategy": "", "custom_vql": "", "surgical_yaml": ""}
    finally:
        session.close()


@router.get("/analytics/{t_code}")
async def get_technique_analytics(t_code: str, current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        rows = session.execute(text("""
            SELECT
                ds.det_code,
                ds.name                 AS strategy_name,
                a.analytic_code,
                a.platforms,
                a.description           AS detection_narrative,
                a.log_source_refs,
                a.mutable_elements
            FROM mitre_detection_strategies ds
            JOIN mitre_analytics a        ON a.det_code = ds.det_code
            JOIN mitre_techniques mt      ON mt.t_code  = ds.t_code
            WHERE ds.t_code = :t_code
              AND NOT COALESCE(mt.is_deprecated, FALSE)
              AND NOT COALESCE(mt.is_revoked, FALSE)
            ORDER BY a.analytic_code ASC
        """), {"t_code": t_code.strip()}).mappings().all()

        if not rows:
            return {"t_code": t_code, "strategy_name": None, "analytics_by_platform": {}, "platforms": []}

        strategy_name = rows[0]["strategy_name"]
        det_code      = rows[0]["det_code"]

        by_platform = {}
        for row in rows:
            raw_plat = row["platforms"] or []
            if isinstance(raw_plat, str):
                raw_plat = json.loads(raw_plat) if raw_plat.startswith("[") else \
                           [p.strip() for p in raw_plat.strip("{}").split(",") if p.strip()]

            log_refs = row["log_source_refs"]
            if isinstance(log_refs, str):
                try:    log_refs = json.loads(log_refs)
                except: log_refs = []

            mutable = row["mutable_elements"]
            if isinstance(mutable, str):
                try:    mutable = json.loads(mutable)
                except: mutable = []

            entry = {
                "analytic_code":       row["analytic_code"],
                "detection_narrative": row["detection_narrative"] or "",
                "log_sources": [
                    {"name": ls.get("name", ""), "channel": ls.get("channel", "")}
                    for ls in (log_refs or [])
                ],
                "tuning_parameters": [
                    {"field": m.get("field", ""), "description": m.get("description", "")}
                    for m in (mutable or [])
                ],
            }

            for plat in raw_plat:
                plat = plat.strip()
                if not plat:
                    continue
                by_platform.setdefault(plat, []).append(entry)

        return {
            "t_code":               t_code,
            "det_code":             det_code,
            "strategy_name":        strategy_name,
            "platforms":            list(by_platform.keys()),
            "analytics_by_platform": by_platform,
        }
    finally:
        session.close()

@router.post("/library/{t_code}/update")
async def update_artifact_library(t_code: str, data: dict = Body(...), current_user: dict = Depends(require_admin)):
    session = db.get_session()
    try:
        # Real upsert, not a bare UPDATE -- a t_code with no existing row
        # (a genuinely new mapping) used to match zero rows and still
        # return {"status": "SUCCESS"}, a phantom save that silently did
        # nothing. t_code has a UNIQUE constraint (ref_artifact_library_
        # t_code_key), so ON CONFLICT works directly off it.
        session.execute(text("""
            INSERT INTO public.ref_artifact_library
                (t_code, live_analysis, dead_disk_analysis, collection_strategy, custom_vql, surgical_yaml, updated_at)
            VALUES (:t, :live, :dead, :coll, :vql, :yaml, NOW())
            ON CONFLICT (t_code) DO UPDATE SET
                live_analysis=:live, dead_disk_analysis=:dead,
                collection_strategy=:coll, custom_vql=:vql, surgical_yaml=:yaml,
                updated_at=NOW()
        """), {"live": data.get("live_analysis"), "dead": data.get("dead_disk_analysis"),
               "coll": data.get("collection_strategy"), "vql": data.get("custom_vql"),
               "yaml": data.get("surgical_yaml"), "t": t_code})
        session.commit()
        return {"status": "SUCCESS"}
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

@router.post("/library/test")
async def test_vql_artifact(request: VQLTestRequest, current_user: dict = Depends(require_admin)):
    from agent_routes import dispatch_and_wait

    raw_payload = request.vql.strip()
    is_yaml = raw_payload.startswith("name:")

    # Pick the most recently seen online agent — transparent to the analyst
    with db.engine.connect() as conn:
        row = conn.execute(text("""
            SELECT agent_id FROM agent_registrations
            WHERE last_seen > NOW() - INTERVAL '90 seconds'
            ORDER BY last_seen DESC LIMIT 1
        """)).fetchone()

    if not row:
        return {
            "success": False,
            "error": "No agent online. Run orca_agent.py on a Windows endpoint to enable live VQL testing.",
        }

    agent_id = row[0]
    try:
        lines = await dispatch_and_wait(
            agent_id, "vql_test",
            {"vql": raw_payload, "is_yaml": is_yaml},
            timeout=120.0,
        )
    except TimeoutError as exc:
        return {"success": False, "error": str(exc)}
    except Exception as exc:
        return {"success": False, "error": f"Dispatch error: {exc}"}

    results = []
    error_msg = None
    for line in lines:
        try:
            obj = json.loads(line)
            t = obj.get("type")
            if t == "row":
                results.append(obj.get("data", obj))
            elif t == "error":
                error_msg = obj.get("data", {}).get("message", "VQL execution error")
        except Exception:
            pass

    if error_msg and not results:
        return {"success": False, "error": error_msg}

    return {"success": True, "data": results, "total_count": len(results)}

@router.get("/cases/{case_name}/map")
async def get_map_data(case_name: str, current_user: dict = Depends(get_current_user)):
    """Return saved map layout (nodes + links) for a case."""
    with db.engine.connect() as conn:
        row = conn.execute(text(
            "SELECT map_data, map_links FROM public.cases WHERE name = :name"
        ), {"name": case_name}).fetchone()
    if not row:
        return {"nodes": [], "links": []}
    raw_map   = row.map_data
    raw_links = row.map_links
    if not raw_map:
        return {"nodes": [], "links": []}
    parsed = json.loads(raw_map) if isinstance(raw_map, str) else raw_map
    if isinstance(parsed, dict) and "nodes" in parsed:
        return parsed
    nodes = parsed if isinstance(parsed, list) else []
    links = json.loads(raw_links) if raw_links and isinstance(raw_links, str) else (raw_links or [])
    return {"nodes": nodes, "links": links if isinstance(links, list) else []}


@router.post("/cases/{case_name}/map-sync")
async def sync_map_layout(case_name: str, payload: MapUpdatePayload, db_session: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    try:
        map_json = json.dumps({"nodes": payload.nodes, "links": payload.links})
        db_session.execute(text("UPDATE public.cases SET map_data = :data WHERE name = :name"),
                           {"data": map_json, "name": case_name})
        db_session.commit()
        return {"status": "SUCCESS"}
    except Exception as e:
        db_session.rollback()
        raise HTTPException(status_code=500, detail=str(e))

_MAX_MAP_BACKGROUND_BYTES = 8 * 1024 * 1024  # generous for a floor plan / rack diagram image


@router.get("/cases/{case_name}/map-background")
async def get_map_background(case_name: str, current_user: dict = Depends(get_current_user)):
    with db.engine.connect() as conn:
        row = conn.execute(text(
            "SELECT map_background, map_background_content_type FROM public.cases WHERE name = :name"
        ), {"name": case_name}).fetchone()
    if not row or row.map_background is None:
        raise HTTPException(status_code=404, detail="No map background set for this case")
    return Response(
        content=bytes(row.map_background),
        media_type=row.map_background_content_type or "application/octet-stream",
    )


@router.put("/cases/{case_name}/map-background", status_code=204)
async def put_map_background(
    case_name: str, file: UploadFile = File(...),
    db_session: Session = Depends(get_db), current_user: dict = Depends(get_current_user),
):
    if not (file.content_type or "").startswith("image/"):
        raise HTTPException(status_code=400, detail="File must be an image")
    data = await file.read()
    if len(data) > _MAX_MAP_BACKGROUND_BYTES:
        raise HTTPException(status_code=413, detail="Image too large (max 8MB)")
    try:
        db_session.execute(text(
            "UPDATE public.cases SET map_background = :data, map_background_content_type = :ct WHERE name = :name"
        ), {"data": data, "ct": file.content_type, "name": case_name})
        db_session.commit()
    except Exception as e:
        db_session.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/cases/{case_name}/map-background", status_code=204)
async def delete_map_background(
    case_name: str, db_session: Session = Depends(get_db), current_user: dict = Depends(get_current_user),
):
    try:
        db_session.execute(text(
            "UPDATE public.cases SET map_background = NULL, map_background_content_type = NULL WHERE name = :name"
        ), {"name": case_name})
        db_session.commit()
    except Exception as e:
        db_session.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/users/assignable")
async def list_assignable_users(current_user: dict = Depends(get_current_user)):
    """Just enough to populate an assignment picker -- id/username/initials,
    none of the admin-only user-management data GET /api/admin/users returns.
    Any authenticated user can see this list (assignment itself is likewise
    open to any authenticated user, not admin-only -- see set_case_assignments)."""
    with db.engine.connect() as conn:
        rows = conn.execute(text(
            "SELECT id, username, initials FROM public.users WHERE role != 'agent' ORDER BY username"
        )).mappings().all()
    return [dict(r) for r in rows]


@router.get("/cases/{case_name}/assignments")
async def get_case_assignments(case_name: str, current_user: dict = Depends(get_current_user)):
    with db.engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT u.id, u.username, u.initials
            FROM case_assignments ca JOIN public.users u ON u.id = ca.user_id
            WHERE ca.case_name = :name ORDER BY u.username
        """), {"name": case_name}).mappings().all()
    return [dict(r) for r in rows]


@router.put("/cases/{case_name}/assignments")
async def set_case_assignments(case_name: str, payload: dict = Body(...), current_user: dict = Depends(get_current_user)):
    """Replaces the full assignment list for a case. Deliberately not
    admin-gated -- same low-friction editing model as the rest of the case
    details (mission lead, team, etc). An empty list is a real, meaningful
    state (falls back to "open to all analysts" everywhere this is
    enforced), not an error."""
    user_ids = payload.get("user_ids", [])
    with db.engine.connect() as conn:
        conn.execute(text("DELETE FROM case_assignments WHERE case_name = :name"), {"name": case_name})
        for uid in user_ids:
            conn.execute(text("""
                INSERT INTO case_assignments (case_name, user_id) VALUES (:name, :uid)
                ON CONFLICT (case_name, user_id) DO NOTHING
            """), {"name": case_name, "uid": uid})
        conn.commit()
    return {"status": "SUCCESS", "assigned_count": len(user_ids)}


@router.delete("/cases/{case_name}")
async def delete_case(case_name: str, db: Session = Depends(get_db), current_user: dict = Depends(require_admin)):
    try:
        p = {"name": case_name}
        asset_subq = "SELECT id FROM assets WHERE case_name = :name"

        # nosec B608 — asset_subq is a hardcoded literal string; :name is parameterized
        db.execute(text(f"DELETE FROM artifact_results  WHERE asset_id IN ({asset_subq})"), p)  # nosec B608
        db.execute(text(f"DELETE FROM evidence          WHERE asset_id IN ({asset_subq})"), p)  # nosec B608
        db.execute(text(f"DELETE FROM mft_entries       WHERE asset_id IN ({asset_subq})"), p)  # nosec B608
        db.execute(text(f"DELETE FROM asset_evidence    WHERE asset_id IN ({asset_subq})"), p)  # nosec B608
        db.execute(text(f"DELETE FROM tcode_notes       WHERE asset_id IN ({asset_subq})"), p)  # nosec B608
        db.execute(text(f"DELETE FROM technique_locks   WHERE asset_id IN ({asset_subq})"), p)  # nosec B608
        db.execute(text(f"DELETE FROM tool_locks        WHERE asset_id IN ({asset_subq})"), p)  # nosec B608
        db.execute(text(f"DELETE FROM mount_sessions    WHERE asset_id IN ({asset_subq})"), p)  # nosec B608
        db.execute(text(f"DELETE FROM package_tokens    WHERE asset_id IN ({asset_subq})"), p)  # nosec B608
        db.execute(text(f"DELETE FROM vuln_results      WHERE asset_id IN ({asset_subq})"), p)  # nosec B608
        db.execute(text(  # nosec B608 — asset_subq is hardcoded literal
            f"DELETE FROM network_links WHERE source_id IN ({asset_subq}) OR target_id IN ({asset_subq})"  # nosec B608
        ), p)
        db.execute(text("DELETE FROM ioc_scans  WHERE case_name = :name"), p)
        db.execute(text("DELETE FROM case_notes WHERE case_name = :name"), p)
        db.execute(text("DELETE FROM assets     WHERE case_name = :name"), p)
        db.execute(text("DELETE FROM cases      WHERE name      = :name"), p)

        db.commit()
        return {"status": "SUCCESS"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/assets/{asset_id}")
async def delete_asset(asset_id: int, db: Session = Depends(get_db), current_user: dict = Depends(require_admin)):
    """Delete a single asset and all associated evidence, notes, and results."""
    try:
        p = {"aid": asset_id}
        db.execute(text("DELETE FROM artifact_results  WHERE asset_id = :aid"), p)
        db.execute(text("DELETE FROM evidence          WHERE asset_id = :aid"), p)
        db.execute(text("DELETE FROM mft_entries       WHERE asset_id = :aid"), p)
        db.execute(text("DELETE FROM asset_evidence    WHERE asset_id = :aid"), p)
        db.execute(text("DELETE FROM tcode_notes       WHERE asset_id = :aid"), p)
        db.execute(text("DELETE FROM technique_locks   WHERE asset_id = :aid"), p)
        db.execute(text("DELETE FROM tool_locks        WHERE asset_id = :aid"), p)
        db.execute(text("DELETE FROM mount_sessions    WHERE asset_id = :aid"), p)
        db.execute(text("DELETE FROM package_tokens    WHERE asset_id = :aid"), p)
        db.execute(text("DELETE FROM vuln_results      WHERE asset_id = :aid"), p)
        db.execute(text("""
            DELETE FROM network_links
            WHERE source_id = :aid OR target_id = :aid
        """), p)
        db.execute(text("DELETE FROM assets WHERE id = :aid"), p)
        db.commit()
        return {"status": "SUCCESS", "asset_id": asset_id}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/geopolitical/groups")
def get_geo_groups(current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        return MitreIntelService.get_all_geopolitical_groups(session)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

@router.get("/sidebar")
def get_sidebar_data(current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        return MitreIntelService.get_sidebar_structure(session)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

@router.get("/groups/{identifier}")
def get_group_details(identifier: str, current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        group_info = MitreIntelService.get_group_details(session, identifier)
        if not group_info:
            raise HTTPException(status_code=404, detail="Group not found")
        return group_info
    finally:
        session.close()

@router.get("/softwares/{identifier}")
def get_soft_details(identifier: str, current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        result = MitreIntelService.get_software_details(session, identifier)
        if not result:
            raise HTTPException(status_code=404, detail="Software not found")
        return result
    finally:
        session.close()

@router.get("/mitigations/{identifier}")
def get_mit_details(identifier: str, current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        result = MitreIntelService.get_mitigation_details(session, identifier)
        if not result:
            raise HTTPException(status_code=404, detail="Mitigation not found")
        return result
    finally:
        session.close()

@router.post("/aggregate")
def aggregate_intel(payload: Union[List[str], dict], current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        stix_ids = payload if isinstance(payload, list) else (payload.get("stix_ids") or payload.get("ids"))
        if not stix_ids:
            return {"techniques": [], "count": 0}
        t_codes = MitreIntelService.get_aggregate_techniques(session, stix_ids)
        return {"techniques": t_codes, "count": len(t_codes)}
    finally:
        session.close()

@router.get("/matrix-layout")
def get_matrix(current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        return MitreIntelService.get_matrix_layout(session)
    finally:
        session.close()

@router.get("/cases/{case_name}/assets")
def get_case_assets(case_name: str, current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        results = session.execute(text("""
            SELECT a.id, a.hostname, a.ip, a.os, a.type, a.country_focus,
                a.os_version, a.form_factor, a.asset_notes, a.analysis_mode, a.mac_address,
                a.asset_type, a.net_config_text, a.net_config_filename, a.local_dir,
                (SELECT string_agg(DISTINCT ar.t_code, ',')
                 FROM artifact_results ar WHERE ar.asset_id = a.id AND ar.evidence_imported = True) as found_t_codes
            FROM public.assets a WHERE a.case_name = :name
        """), {"name": case_name}).mappings().all()
        return [dict(r) for r in results]
    except Exception as _e:
        logging.error(f"[mitre_routes] {_e}")
        return []
    finally:
        session.close()

@router.get("/assets/{asset_id}/net-config")
def get_net_config(asset_id: int, current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        row = session.execute(text(
            "SELECT net_config_text, net_config_filename FROM assets WHERE id = :id"
        ), {"id": asset_id}).mappings().first()
        if not row:
            raise HTTPException(status_code=404, detail="ASSET_NOT_FOUND")
        return {"text": row["net_config_text"] or "", "filename": row["net_config_filename"] or ""}
    finally:
        session.close()

@router.post("/assets/{asset_id}/net-config")
def save_net_config(asset_id: int, payload: dict, current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        session.execute(text("""
            UPDATE assets SET net_config_text = :text, net_config_filename = :filename
            WHERE id = :id
        """), {"text": payload.get("text", ""), "filename": payload.get("filename", ""), "id": asset_id})
        session.commit()
        return {"status": "SAVED"}
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

@router.post("/cases/{case_name}/assets")
def add_asset(case_name: str, asset_data: dict, current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        # Normalise OS — DB constraint only allows Windows/Linux/macOS/Unknown
        os_value = asset_data.get('os', 'Unknown')
        if os_value not in ('Windows', 'Linux', 'macOS', 'Unknown', 'Network'):
            os_value = 'Unknown'

        # Normalise asset_type — strip spaces to match DB constraint values
        type_map = {
            'Workstation': 'Workstation',
            'Server': 'Server',
            'Domain Controller': 'DomainController',
            'DomainController': 'DomainController',
            'Network Device': 'NetworkDevice',
            'NetworkDevice': 'NetworkDevice',
            'Cloud Instance': 'CloudInstance',
            'CloudInstance': 'CloudInstance',
            'Unknown': 'Unknown',
        }
        asset_type = type_map.get(asset_data.get('type', 'Unknown'), 'Unknown')

        result = session.execute(text("""
            INSERT INTO public.assets
                (case_name, hostname, ip, subnet_mask, gateway, mac_address,
                 os, os_version, form_factor, asset_notes, asset_type)
            VALUES
                (:case, :host, :ip, :subnet, :gateway, :mac,
                 :os, :version, :form, :notes, :asset_type)
            RETURNING id
        """), {
            "case":       case_name,
            "host":       asset_data.get('hostname'),
            "ip":         asset_data.get('ip'),
            "subnet":     asset_data.get('subnet'),
            "gateway":    asset_data.get('gateway'),
            "mac":        asset_data.get('mac'),
            "os":         os_value,
            "version":    asset_data.get('version'),
            "form":       asset_data.get('formFactor'),
            "notes":      asset_data.get('assetNotes'),
            "asset_type": asset_type,
        })
        asset_id = result.scalar()

        # If the parent investigation has a local working directory, create an asset subfolder
        case_row = session.execute(text(
            "SELECT local_dir FROM public.cases WHERE name = :name"
        ), {"name": case_name}).mappings().first()
        if case_row and case_row['local_dir']:
            hostname = asset_data.get('hostname') or f"asset_{asset_id}"
            safe_host = re.sub(r'[^A-Za-z0-9_\-.]', '_', hostname).strip('_') or f"asset_{asset_id}"
            asset_dir = f"{case_row['local_dir']}/{safe_host}"
            try:
                os.makedirs(asset_dir, exist_ok=True)
                session.execute(text(
                    "UPDATE public.assets SET local_dir = :dir WHERE id = :id"
                ), {"dir": asset_dir, "id": asset_id})
            except OSError as e:
                logging.warning(f"[assets] Could not create asset dir {asset_dir}: {e}")

        session.commit()
        return {"status": "SUCCESS"}
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

@router.post("/cases/{case_name}/notes")
def add_case_note(case_name: str, data: dict, current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        session.execute(
            text("INSERT INTO public.case_notes (case_name, note_text) VALUES (:name, :text)"),
            {"name": case_name, "text": data.get('text')}
        )
        session.commit()
        return {"status": "SUCCESS"}
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

@router.get("/threat-profile/{identifier}")
async def get_threat_profile(identifier: str, asset_id: Optional[int] = None, current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        case_result = session.execute(
            text("SELECT focus_country, selected_groups FROM public.cases WHERE name = :id"), {"id": identifier}
        ).mappings().first()

        raw_country = (case_result['focus_country'] or '').strip() if case_result else ''
        selected_groups_csv = case_result['selected_groups'] if case_result else ''
        selected_groups = [g.strip() for g in selected_groups_csv.split(',') if g.strip()] if selected_groups_csv else []

        # Profile mode: focus_country starts with [PROFILE], selected_groups are T-codes directly
        if raw_country.upper().startswith('[PROFILE]') and selected_groups:
            result = session.execute(text("""
                SELECT ref.t_code,
                    COALESCE(mt.name, ref.name) AS technique_name,
                    '' AS associated_actors,
                    ref.live_analysis, ref.dead_disk_analysis, ref.collection_strategy AS bluf_text,
                    COALESCE(ar.verdict, 'Undetermined') AS verdict,
                    COALESCE(ar.evidence_imported, False) AS evidence_imported,
                    EXISTS (
                        SELECT 1 FROM public.evidence ev
                        WHERE ev.asset_id = :asset_id AND ev.t_code = ref.t_code
                          AND (ev.raw_data->>'_orca_fallback')::boolean = TRUE
                    ) AS has_fallback_evidence,
                    mt.platforms,
                    mt.parent_t_code,
                    COALESCE(mt.is_subtechnique, FALSE) AS is_subtechnique,
                    (SELECT COUNT(*) > 0 FROM public.tcode_notes tn
                     WHERE tn.asset_id = :asset_id AND tn.t_code = ref.t_code) AS has_notes,
                    (SELECT tn2.author_initials FROM public.tcode_notes tn2
                     WHERE tn2.asset_id = :asset_id AND tn2.t_code = ref.t_code
                     ORDER BY tn2.created_at DESC LIMIT 1) AS last_note_author
                FROM ref_artifact_library ref
                LEFT JOIN mitre_techniques mt ON ref.t_code = mt.t_code
                LEFT JOIN artifact_results ar ON (ref.t_code = ar.t_code AND ar.asset_id = :asset_id)
                WHERE ref.t_code = ANY(:tcodes)
                ORDER BY ref.t_code ASC
            """), {"tcodes": selected_groups, "asset_id": asset_id}).mappings().all()
            return [dict(r) for r in result]

        target_country = raw_country.upper()
        if target_country:
            actor_filter = "UPPER(ta.attribution) = :country"
            params = {"country": target_country, "asset_id": asset_id}
        elif selected_groups:
            actor_filter = "ta.group_name = ANY(:groups)"
            params = {"groups": selected_groups, "asset_id": asset_id}
        else:
            return []

        result = session.execute(text(
            "SELECT mt.t_code, mt.name AS technique_name,"
            " string_agg(DISTINCT ta.group_name, ', ') as associated_actors,"
            " ref.live_analysis, ref.dead_disk_analysis, ref.collection_strategy AS bluf_text,"
            " COALESCE(ar.verdict, 'Undetermined') as verdict,"
            " COALESCE(ar.evidence_imported, False) as evidence_imported,"
            " EXISTS ("
            "     SELECT 1 FROM public.evidence ev"
            "     WHERE ev.asset_id = :asset_id AND ev.t_code = mt.t_code"
            "       AND (ev.raw_data->>'_orca_fallback')::boolean = TRUE"
            " ) AS has_fallback_evidence,"
            " mt.platforms, mt.parent_t_code,"
            " COALESCE(mt.is_subtechnique, FALSE) as is_subtechnique,"
            " (SELECT COUNT(*) > 0 FROM public.tcode_notes tn"
            "  WHERE tn.asset_id = :asset_id AND tn.t_code = mt.t_code) AS has_notes,"
            " (SELECT tn2.author_initials FROM public.tcode_notes tn2"
            "  WHERE tn2.asset_id = :asset_id AND tn2.t_code = mt.t_code"
            "  ORDER BY tn2.created_at DESC LIMIT 1) AS last_note_author"
            " FROM threat_attribution ta"
            " JOIN mitre_actors ma ON ta.group_name = ma.name"
            " JOIN mitre_relationships ma_rel ON ma.stix_id = ma_rel.source_ref"
            " JOIN mitre_techniques mt ON ma_rel.target_ref = mt.stix_id"
            " JOIN ref_artifact_library ref ON mt.t_code = ref.t_code"
            " LEFT JOIN artifact_results ar ON (mt.t_code = ar.t_code AND ar.asset_id = :asset_id)"
            f" WHERE {actor_filter}"  # nosec B608 — actor_filter is one of two hardcoded literals; user values use :country/:groups params
            " AND ma_rel.relationship_type = 'uses'"
            " AND NOT COALESCE(mt.is_deprecated, FALSE)"
            " AND NOT COALESCE(mt.is_revoked, FALSE)"
            " AND ("
            " :asset_id IS NULL OR mt.platforms IS NULL OR mt.platforms = '[]'::jsonb"
            " OR EXISTS ("
            "     SELECT 1 FROM assets a WHERE a.id = :asset_id AND ("
            "         a.os = 'Unknown'"
            "         OR mt.platforms @> to_jsonb(ARRAY["
            "             CASE WHEN a.os = 'Network' THEN 'Network Devices' ELSE a.os END"
            "         ]::text[])"
            "     )"
            " ))"
            " GROUP BY mt.t_code, mt.name, ref.live_analysis, ref.dead_disk_analysis,"
            " ref.collection_strategy, ar.verdict, ar.evidence_imported,"
            " mt.platforms, mt.parent_t_code, mt.is_subtechnique"
            " ORDER BY mt.t_code ASC"
        ), params).mappings().all()
        return [dict(r) for r in result]
    finally:
        session.close()

# ═══════════════════════════════════════════════════════════════════════════════
# MEMORY / VOLATILITY ROUTES
# ═══════════════════════════════════════════════════════════════════════════════
              
# ═══════════════════════════════════════════════════════════════════════════════
# MEMORY / VOLATILITY ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/memory/list-images")
async def list_memory_images(dir: str = None, current_user: dict = Depends(get_current_user)):
    image_exts = {".raw", ".mem", ".dmp", ".vmem", ".lime", ".bin", ".img", ".dd"}
    results = []
    seen = set()

    def scan_flat(d, label=None):
        if not os.path.isdir(d):
            return
        try:
            for fname in sorted(os.listdir(d)):
                fpath = os.path.join(d, fname)
                if not os.path.isfile(fpath) or fpath in seen:
                    continue
                if os.path.splitext(fname)[1].lower() not in image_exts:
                    continue
                seen.add(fpath)
                try:
                    size = os.path.getsize(fpath)
                except OSError:
                    size = 0
                results.append({"path": fpath, "filename": fname, "size": size, "dir": label or d})
        except PermissionError:
            pass

    # Priority: the asset's own local dir first (so it appears at the top of BROWSE)
    if dir and os.path.isdir(dir):
        scan_flat(dir, dir)

    # Fixed known locations
    for d in ["/app/memory-dumps", "/app/evidence/memory-dumps"]:
        scan_flat(d)

    # Walk /app/cases/ two levels deep (case → asset subfolder)
    cases_root = "/app/cases"
    if os.path.isdir(cases_root):
        try:
            for case_dir in sorted(os.listdir(cases_root)):
                case_path = os.path.join(cases_root, case_dir)
                if not os.path.isdir(case_path):
                    continue
                scan_flat(case_path)
                try:
                    for asset_dir in sorted(os.listdir(case_path)):
                        asset_path = os.path.join(case_path, asset_dir)
                        if os.path.isdir(asset_path):
                            scan_flat(asset_path)
                except PermissionError:
                    pass
        except PermissionError:
            pass

    return results


@router.get("/memory/plugins")
async def get_vol_plugins(os_profile: str = "windows", current_user: dict = Depends(get_current_user)):
    groups = VOL_PLUGINS_BY_OS.get(os_profile.lower(), VOL_PLUGINS_BY_OS["windows"])
    return {"os_profile": os_profile, "plugin_groups": groups, "threat_actors": list(THREAT_ACTORS.keys())}

@router.post("/memory/acquire")
async def acquire_memory(payload: MemoryAcquireRequest, user: dict = Depends(get_current_user)):
    winpmem_exe = None
    for name in ["winpmem_mini_x64_rc2.exe", "winpmem.exe", "winpmem_mini_x64.exe", "winpmem64.exe"]:
        candidate = os.path.join(cfg.WINPMEM_BASE, name)
        if os.path.exists(candidate):
            winpmem_exe = candidate
            break
    if not winpmem_exe:
        raise HTTPException(status_code=404, detail="winpmem binary not found in configured WINPMEM_BASE")

    dest = payload.destination_path
    dest_dir = os.path.dirname(dest)
    if dest_dir and not os.path.exists(dest_dir):
        os.makedirs(dest_dir, exist_ok=True)

    async def event_stream():
        yield f"data: {json.dumps({'type': 'log', 'data': f'Starting memory acquisition to: {dest}'})}\n\n"
        yield f"data: {json.dumps({'type': 'log', 'data': f'Using binary: {winpmem_exe}'})}\n\n"
        try:
            process = await asyncio.create_subprocess_exec(
                winpmem_exe, "acquire", dest,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT
            )
            async for raw_line in process.stdout:
                line = raw_line.decode("utf-8", errors="replace").rstrip()
                if line:
                    yield f"data: {json.dumps({'type': 'log', 'data': line})}\n\n"
            await process.wait()
            if process.returncode == 0 and os.path.exists(dest):
                size_mb = os.path.getsize(dest) / (1024 * 1024)
                yield f"data: {json.dumps({'type': 'done', 'data': {'path': dest, 'size_mb': round(size_mb, 1)}})}\n\n"
            else:
                yield f"data: {json.dumps({'type': 'error', 'data': f'winpmem exited with code {process.returncode}'})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'data': str(e)})}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@router.post("/memory/dump")
async def dump_process_memory(payload: MemoryDumpRequest, user: dict = Depends(get_current_user)):
    if not os.path.exists(cfg.VOL3_BASE):
        raise HTTPException(status_code=404, detail="Volatility3 not found — check ORCA_VOL3_BASE configuration")
    resolved_img, path_err = _resolve_image_path(payload.image_path)
    if path_err:
        raise HTTPException(status_code=400, detail=path_err)
    os.makedirs(payload.destination_path, exist_ok=True)
    cmd = _build_vol_cmd(cfg.VOL3_BASE, resolved_img, "windows.dumpfiles",
                         None, ["--pid", str(payload.pid), "--dump-dir", payload.destination_path])

    async def event_stream():
        yield f"data: {json.dumps({'type': 'log', 'data': f'Dumping PID {payload.pid} -> {payload.destination_path}'})}\n\n"
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd, cwd=cfg.VOL3_BASE,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            async for raw_line in process.stdout:
                line = raw_line.decode("utf-8", errors="replace").rstrip()
                if line:
                    yield f"data: {json.dumps({'type': 'log', 'data': line})}\n\n"
            stderr_raw = await process.stderr.read()
            for l in stderr_raw.decode("utf-8", errors="replace").splitlines():
                if l.strip():
                    yield f"data: {json.dumps({'type': 'log', 'data': '[WARN] ' + l})}\n\n"
            await process.wait()
            dumped = [f for f in os.listdir(payload.destination_path) if str(payload.pid) in f]
            yield f"data: {json.dumps({'type': 'done', 'data': {'pid': payload.pid, 'files': dumped, 'dest': payload.destination_path}})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'data': str(e)})}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@router.post("/memory/run")
async def run_volatility_streaming(payload: MemoryRunRequest, user: dict = Depends(get_current_user)):
    if not os.path.exists(cfg.VOL3_BASE):
        raise HTTPException(status_code=404, detail="Volatility3 not found — check ORCA_VOL3_BASE configuration")

    async def event_stream():
        yield f"data: {json.dumps({'type': 'log', 'data': f'Queued {len(payload.plugins)} plugin(s)'})}\n\n"
        for plugin in payload.plugins:
            yield f"data: {json.dumps({'type': 'plugin_start', 'data': plugin})}\n\n"
            async for evt in _stream_plugin(cfg.VOL3_BASE, payload.image_path, plugin,
                                            payload.symbol_paths, payload.args,
                                            PLUGIN_MITRE_MAP, PLUGIN_MITRE_CONFIDENCE):
                yield f"data: {json.dumps(evt)}\n\n"
        yield f"data: {json.dumps({'type': 'done', 'data': 'COMPLETE'})}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@router.post("/memory/fullscan")
async def run_volatility_fullscan(payload: MemoryFullScanRequest, user: dict = Depends(get_current_user)):
    if not os.path.exists(cfg.VOL3_BASE):
        raise HTTPException(status_code=404, detail="Volatility3 not found — check ORCA_VOL3_BASE configuration")
    all_plugins = [p for group in VOL_PLUGINS_BY_OS.get(payload.os_profile.lower(), VOL_PLUGINS_BY_OS["windows"]).values() for p in group]

    async def event_stream():
        yield f"data: {json.dumps({'type': 'log', 'data': f'FULL_SCAN: {len(all_plugins)} plugins queued'})}\n\n"
        for plugin in all_plugins:
            yield f"data: {json.dumps({'type': 'plugin_start', 'data': plugin})}\n\n"
            async for evt in _stream_plugin(cfg.VOL3_BASE, payload.image_path, plugin,
                                            payload.symbol_paths, [], PLUGIN_MITRE_MAP, PLUGIN_MITRE_CONFIDENCE):
                yield f"data: {json.dumps(evt)}\n\n"
        yield f"data: {json.dumps({'type': 'done', 'data': 'FULL_SCAN_COMPLETE'})}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@router.post("/memory/actorscan")
async def run_volatility_actor_scan(payload: MemoryActorScanRequest, user: dict = Depends(get_current_user)):
    if not os.path.exists(cfg.VOL3_BASE):
        raise HTTPException(status_code=404, detail="Volatility3 not found — check ORCA_VOL3_BASE configuration")
    actor_techniques = THREAT_ACTORS.get(payload.actor_name)
    if not actor_techniques:
        raise HTTPException(status_code=404, detail=f"ACTOR_NOT_FOUND: {payload.actor_name}")
    plugins = _get_plugins_for_techniques(actor_techniques, payload.os_profile)

    async def event_stream():
        yield f"data: {json.dumps({'type': 'log', 'data': f'ACTOR_SCAN: {payload.actor_name}'})}\n\n"
        yield f"data: {json.dumps({'type': 'log', 'data': f'Techniques: {len(actor_techniques)} -> Plugins: {len(plugins)}'})}\n\n"
        for plugin in plugins:
            yield f"data: {json.dumps({'type': 'plugin_start', 'data': plugin})}\n\n"
            async for evt in _stream_plugin(cfg.VOL3_BASE, payload.image_path, plugin,
                                            payload.symbol_paths, [], PLUGIN_MITRE_MAP, PLUGIN_MITRE_CONFIDENCE):
                yield f"data: {json.dumps(evt)}\n\n"
        yield f"data: {json.dumps({'type': 'done', 'data': 'ACTOR_SCAN_COMPLETE'})}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

# ═══════════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════════
# ANALYSIS RESULTS PERSISTENCE
# ═══════════════════════════════════════════════════════════════════════════════

class MemoryResultsPayload(BaseModel):
    asset_id: int
    image_path: Optional[str] = None
    plugins: list  # [{ plugin, columns, rows }]

class ClamResultsPayload(BaseModel):
    asset_id: int
    scan_path: Optional[str] = None
    scanned: int = 0
    infected: int = 0
    threats: list = []

@router.post("/memory/results/save")
async def save_memory_results(payload: MemoryResultsPayload, user: dict = Depends(get_current_user)):
    """Persist memory scan results to DB so they survive browser close."""
    session = db.get_session()
    try:
        for p in payload.plugins:
            session.execute(text("""
                INSERT INTO memory_results (asset_id, plugin, columns, rows, row_count, image_path)
                VALUES (:aid, :plugin, :cols, :rows, :rc, :img)
                ON CONFLICT (asset_id, plugin) DO UPDATE
                SET columns = EXCLUDED.columns, rows = EXCLUDED.rows,
                    row_count = EXCLUDED.row_count, image_path = EXCLUDED.image_path,
                    scanned_at = NOW()
            """), {
                "aid":    payload.asset_id,
                "plugin": p.get("plugin"),
                "cols":   json.dumps(p.get("columns", [])),
                "rows":   json.dumps(p.get("rows", [])),
                "rc":     len(p.get("rows", [])),
                "img":    payload.image_path,
            })
        session.commit()
        return {"status": "OK", "plugins_saved": len(payload.plugins)}
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

@router.get("/memory/results/{asset_id}")
async def load_memory_results(asset_id: int, user: dict = Depends(get_current_user)):
    """Load persisted memory scan results for an asset."""
    session = db.get_session()
    try:
        rows = session.execute(text("""
            SELECT plugin, columns, rows, row_count, image_path, scanned_at
            FROM memory_results WHERE asset_id = :aid ORDER BY scanned_at DESC
        """), {"aid": asset_id}).mappings().all()
        return [{"plugin": r["plugin"], "columns": r["columns"] or [],
                 "rows": r["rows"] or [], "row_count": r["row_count"],
                 "image_path": r["image_path"],
                 "scanned_at": str(r["scanned_at"])} for r in rows]
    finally:
        session.close()

@router.post("/scan/clam/results/save")
async def save_clam_results(payload: ClamResultsPayload, user: dict = Depends(get_current_user)):
    """Persist ClamAV scan results."""
    session = db.get_session()
    try:
        session.execute(text("""
            INSERT INTO clam_results (asset_id, scan_path, scanned, infected, threats)
            VALUES (:aid, :path, :scanned, :infected, :threats)
            ON CONFLICT (asset_id) DO UPDATE
            SET scan_path = EXCLUDED.scan_path, scanned = EXCLUDED.scanned,
                infected = EXCLUDED.infected, threats = EXCLUDED.threats,
                scanned_at = NOW()
        """), {
            "aid":      payload.asset_id,
            "path":     payload.scan_path,
            "scanned":  payload.scanned,
            "infected": payload.infected,
            "threats":  json.dumps(payload.threats),
        })
        session.commit()
        return {"status": "OK"}
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

@router.get("/scan/clam/results/{asset_id}")
async def load_clam_results(asset_id: int, user: dict = Depends(get_current_user)):
    """Load persisted ClamAV results for an asset."""
    session = db.get_session()
    try:
        row = session.execute(text("""
            SELECT scan_path, scanned, infected, threats, scanned_at
            FROM clam_results WHERE asset_id = :aid
        """), {"aid": asset_id}).mappings().first()
        if not row:
            return None
        return {"scan_path": row["scan_path"], "scanned": row["scanned"],
                "infected": row["infected"], "threats": row["threats"] or [],
                "scanned_at": str(row["scanned_at"])}
    finally:
        session.close()

# CLAMAV ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/scan/clam/update")
async def update_clam_defs(payload: ClamUpdateRequest, user: dict = Depends(get_current_user)):
    freshclam_exe = os.path.join(cfg.CLAM_BASE, "freshclam.exe")
    if not os.path.exists(freshclam_exe):
        raise HTTPException(status_code=404, detail="freshclam not found — check ORCA_CLAM_BASE configuration")
    try:
        result = subprocess.run(
            [freshclam_exe, f"--datadir={cfg.CLAM_BASE}", "--stdout"],
            capture_output=True, text=True, timeout=300
        )
        output = (result.stdout + result.stderr).strip()
        success = result.returncode in (0, 1)
        return {
            "status": "SUCCESS" if success else "FAILED",
            "return_code": result.returncode,
            "output": output,
            "message": (
                "Definitions updated successfully." if result.returncode == 0
                else "Definitions already up to date." if result.returncode == 1
                else "freshclam encountered an error — see output for details."
            )
        }
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="freshclam timed out after 300s")
    except Exception as e:
        logging.error(f"[clam/update] {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/scan/clam")
async def run_clamscan_streaming(payload: ClamScanRequest, user: dict = Depends(get_current_user)):
    exe_path = os.path.join(cfg.CLAM_BASE, "clamscan.exe")
    if not os.path.exists(exe_path):
        raise HTTPException(status_code=404, detail="clamscan not found — check ORCA_CLAM_BASE configuration")

    db_args = _get_clam_db_args(cfg.CLAM_BASE)
    cmd = [exe_path] + db_args + ["--stdout"]
    if payload.recursive:
        cmd.append("-r")
    if payload.remove:
        cmd.append("--remove")
    cmd.append(payload.scan_path)

    async def event_stream():
        yield f"data: {json.dumps({'type': 'log', 'data': f'ClamAV scan: {payload.scan_path}'})}\n\n"
        threats, scanned = [], 0
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT
            )
            async for raw_line in process.stdout:
                line = raw_line.decode("utf-8", errors="replace").rstrip()
                if not line:
                    continue
                if " FOUND" in line:
                    threats.append(line)
                    yield f"data: {json.dumps({'type': 'threat', 'data': line})}\n\n"
                elif "Scanned files:" in line:
                    try:
                        scanned = int(line.split(":")[1].strip())
                    except Exception:
                        pass
                    yield f"data: {json.dumps({'type': 'summary', 'data': line})}\n\n"
                elif line.startswith("---") or "Infected files:" in line or "Engine version:" in line:
                    yield f"data: {json.dumps({'type': 'summary', 'data': line})}\n\n"
                else:
                    yield f"data: {json.dumps({'type': 'log', 'data': line})}\n\n"
            await process.wait()
            yield f"data: {json.dumps({'type': 'done', 'data': {'scanned_files': scanned, 'infected_files': len(threats), 'exit_code': process.returncode}})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'data': str(e)})}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

# ═══════════════════════════════════════════════════════════════════════════════
# TECHNIQUE STATE MACHINE + COLLABORATION LAYER
# ═══════════════════════════════════════════════════════════════════════════════

import asyncio
from datetime import datetime, timedelta
from typing import Dict, Set

class TechniqueClaimPayload(BaseModel):
    asset_id: int
    t_code: str

class TechniqueTransitionPayload(BaseModel):
    asset_id: int
    t_code: str

class ToolLockPayload(BaseModel):
    asset_id: int
    tool_name: str

class AssetModePayload(BaseModel):
    analysis_mode: str

class CaseNotePayload(BaseModel):
    text: str
    note_type: Optional[str] = "NOTE"

# One user_id -> list of queues, not a single queue -- a user with two tabs
# open used to have the second tab's connection silently overwrite the
# first's single dict entry, so the first tab stopped receiving broadcasts
# with no error. Worse: if that orphaned first tab's connection later closed
# on its own, its cleanup did `_sse_clients.pop(user_id, None)` unconditionally
# -- deleting the SECOND tab's still-live queue too, killing both.
_sse_clients: Dict[int, List[asyncio.Queue]] = {}

async def _broadcast(event_type: str, payload: dict):
    msg = json.dumps({"type": event_type, **payload})
    for uid, queues in list(_sse_clients.items()):
        dead = []
        for q in queues:
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            queues.remove(q)
        if not queues:
            _sse_clients.pop(uid, None)

async def _notify_user(user_id: int, event_type: str, payload: dict):
    msg = json.dumps({"type": event_type, **payload})
    for q in list(_sse_clients.get(user_id, [])):
        try:
            q.put_nowait(msg)
        except asyncio.QueueFull:
            pass

@router.get("/collaboration/stream")
async def collaboration_stream(current_user: dict = Depends(get_current_user)):
    user_id = current_user["id"]
    q: asyncio.Queue = asyncio.Queue(maxsize=50)
    _sse_clients.setdefault(user_id, []).append(q)

    async def event_generator():
        yield f"data: {json.dumps({'type': 'connected', 'user_id': user_id})}\n\n"
        try:
            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=30.0)
                    yield f"data: {msg}\n\n"
                except asyncio.TimeoutError:
                    yield f"data: {json.dumps({'type': 'ping'})}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            # Remove only this connection's own queue, not the whole
            # per-user list -- one tab closing must never affect another
            # still-live tab for the same user.
            queues = _sse_clients.get(user_id)
            if queues and q in queues:
                queues.remove(q)
                if not queues:
                    _sse_clients.pop(user_id, None)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )

def _expire_technique_locks(session):
    session.execute(text("DELETE FROM public.technique_locks WHERE expires_at < NOW()"))

def _expire_tool_locks(session):
    session.execute(text("DELETE FROM public.tool_locks WHERE expires_at < NOW()"))

@router.get("/techniques/{asset_id}/status")
async def get_technique_statuses(asset_id: int, current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        _expire_technique_locks(session)
        results = session.execute(text("""
            SELECT
                ar.t_code,
                ar.technique_status,
                ar.verdict,
                ar.claimed_by,
                ar.claimed_at,
                ar.closed_at,
                ar.evidence_imported,
                u_claim.username   AS claimed_by_username,
                u_claim.initials   AS claimed_by_initials,
                tl.locked_by       AS lock_held_by,
                tl.expires_at      AS lock_expires_at,
                u_lock.username    AS lock_held_by_username,
                u_lock.initials    AS lock_held_by_initials
            FROM public.artifact_results ar
            LEFT JOIN public.users u_claim ON ar.claimed_by = u_claim.id
            LEFT JOIN public.technique_locks tl
                ON tl.asset_id = ar.asset_id AND tl.t_code = ar.t_code
            LEFT JOIN public.users u_lock ON tl.locked_by = u_lock.id
            WHERE ar.asset_id = :aid
            ORDER BY ar.t_code ASC
        """), {"aid": asset_id}).mappings().all()
        session.commit()
        return [dict(r) for r in results]
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

@router.post("/techniques/claim")
async def claim_technique(payload: TechniqueClaimPayload, current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        _expire_technique_locks(session)
        asset_id = payload.asset_id
        t_code = payload.t_code
        user_id = current_user["id"]
        username = current_user.get("sub", "UNKNOWN")
        initials = current_user.get("initials", "??")

        platform_check = session.execute(text("""
            SELECT 1 FROM mitre_techniques mt
            JOIN assets a ON a.id = :aid
            WHERE mt.t_code = :t
              AND mt.platforms IS NOT NULL
              AND mt.platforms != '[]'::jsonb
              AND a.os != 'Unknown'
              AND NOT (mt.platforms @> to_jsonb(ARRAY[CASE WHEN a.os = 'Network' THEN 'Network Devices' ELSE a.os END]::text[]))
        """), {"aid": asset_id, "t": t_code}).first()

        if platform_check:
            return {"status": "PLATFORM_MISMATCH", "detail": f"{t_code} does not apply to this asset's OS"}

        # Acquiring the lock has to be a single atomic statement, not a
        # check-then-insert -- two concurrent callers both reading "no lock
        # held" before either commits was exactly how two analysts could
        # both get back "CLAIMED" for the same technique. Postgres takes a
        # row lock on the conflicting key during INSERT ... ON CONFLICT, so
        # the second caller's statement blocks until the first commits, then
        # re-evaluates against the now-committed row -- only the row's real
        # owner ever comes back in `locked_by`. Expired locks are already
        # deleted above by _expire_technique_locks, so a conflict here always
        # means a currently-valid lock (ours or someone else's).
        lock_row = session.execute(text("""
            INSERT INTO public.technique_locks (asset_id, t_code, locked_by, locked_at, expires_at)
            VALUES (:aid, :t, :uid, NOW(), NOW() + INTERVAL '30 minutes')
            ON CONFLICT (asset_id, t_code) DO UPDATE
                SET expires_at = CASE WHEN technique_locks.locked_by = :uid
                                       THEN NOW() + INTERVAL '30 minutes'
                                       ELSE technique_locks.expires_at END,
                    locked_at  = CASE WHEN technique_locks.locked_by = :uid
                                       THEN NOW() ELSE technique_locks.locked_at END
            RETURNING locked_by, locked_at, expires_at
        """), {"aid": asset_id, "t": t_code, "uid": user_id}).mappings().first()
        session.commit()

        if lock_row["locked_by"] != user_id:
            owner = session.execute(text(
                "SELECT username, initials FROM public.users WHERE id = :id"
            ), {"id": lock_row["locked_by"]}).mappings().first()
            await _notify_user(lock_row["locked_by"], "technique_access_attempt", {
                "asset_id": asset_id, "t_code": t_code,
                "attempted_by": username, "attempted_by_initials": initials,
            })
            return {
                "status": "LOCKED",
                "locked_by": owner["username"] if owner else None,
                "locked_by_initials": owner["initials"] if owner else None,
                "locked_at": lock_row["locked_at"].isoformat() if lock_row["locked_at"] else None,
                "expires_at": lock_row["expires_at"].isoformat() if lock_row["expires_at"] else None,
            }

        session.execute(text("""
            INSERT INTO public.artifact_results (asset_id, t_code, technique_status, claimed_by, claimed_at, verdict, evidence_imported)
            VALUES (:aid, :t, 'IN_PROGRESS', :uid, NOW(), 'Undetermined', False)
            ON CONFLICT (asset_id, t_code) DO UPDATE
                SET technique_status = CASE
                        WHEN artifact_results.technique_status = 'UNCLAIMED' THEN 'IN_PROGRESS'
                        ELSE artifact_results.technique_status
                    END,
                    claimed_by  = COALESCE(artifact_results.claimed_by, :uid),
                    claimed_at  = COALESCE(artifact_results.claimed_at, NOW())
        """), {"aid": asset_id, "t": t_code, "uid": user_id})
        session.commit()

        await _broadcast("technique_claimed", {
            "asset_id": asset_id, "t_code": t_code,
            "claimed_by": username, "claimed_by_initials": initials,
        })

        return {"status": "CLAIMED", "technique_status": "IN_PROGRESS"}

    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

@router.post("/techniques/release")
async def release_technique(payload: TechniqueTransitionPayload, current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        user_id = current_user["id"]
        asset_id = payload.asset_id
        t_code = payload.t_code

        lock = session.execute(text("""
            SELECT locked_by FROM public.technique_locks
            WHERE asset_id = :aid AND t_code = :t
        """), {"aid": asset_id, "t": t_code}).mappings().first()

        if lock and lock["locked_by"] != user_id and current_user.get("role") != "admin":
            raise HTTPException(status_code=403, detail="NOT_LOCK_OWNER")

        session.execute(text("""
            DELETE FROM public.technique_locks WHERE asset_id = :aid AND t_code = :t
        """), {"aid": asset_id, "t": t_code})

        session.commit()

        await _broadcast("technique_released", {
            "asset_id": asset_id, "t_code": t_code,
            "released_by": current_user.get("sub"),
        })

        return {"status": "RELEASED"}

    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

@router.post("/techniques/submit")
async def submit_technique(payload: TechniqueTransitionPayload, current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        user_id = current_user["id"]
        asset_id = payload.asset_id
        t_code = payload.t_code

        result = session.execute(text("""
            UPDATE public.artifact_results
            SET technique_status = 'PENDING_REVIEW'
            WHERE asset_id = :aid AND t_code = :t
              AND technique_status = 'IN_PROGRESS'
              AND claimed_by = :uid
            RETURNING technique_status
        """), {"aid": asset_id, "t": t_code, "uid": user_id}).mappings().first()

        if not result:
            raise HTTPException(status_code=409, detail="TRANSITION_NOT_ALLOWED — must be IN_PROGRESS and owned by you")

        session.commit()

        await _broadcast("technique_submitted", {
            "asset_id": asset_id, "t_code": t_code,
            "submitted_by": current_user.get("sub"),
            "submitted_by_initials": current_user.get("initials"),
        })

        return {"status": "PENDING_REVIEW"}

    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

@router.post("/techniques/close")
async def close_technique(payload: TechniqueTransitionPayload, current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        if current_user.get("role") not in ("admin", "lead"):
            raise HTTPException(status_code=403, detail="LEAD_ROLE_REQUIRED")

        asset_id = payload.asset_id
        t_code = payload.t_code

        result = session.execute(text("""
            UPDATE public.artifact_results
            SET technique_status = 'CLOSED', closed_at = NOW()
            WHERE asset_id = :aid AND t_code = :t
              AND technique_status = 'PENDING_REVIEW'
            RETURNING technique_status
        """), {"aid": asset_id, "t": t_code}).mappings().first()

        if not result:
            raise HTTPException(status_code=409, detail="TRANSITION_NOT_ALLOWED — must be PENDING_REVIEW")

        session.execute(text("""
            DELETE FROM public.technique_locks WHERE asset_id = :aid AND t_code = :t
        """), {"aid": asset_id, "t": t_code})

        session.commit()

        await _broadcast("technique_closed", {
            "asset_id": asset_id, "t_code": t_code,
            "closed_by": current_user.get("sub"),
        })

        return {"status": "CLOSED"}

    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

@router.post("/techniques/kickback")
async def kickback_technique(payload: TechniqueTransitionPayload, current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        if current_user.get("role") not in ("admin", "lead"):
            raise HTTPException(status_code=403, detail="LEAD_ROLE_REQUIRED")

        asset_id = payload.asset_id
        t_code = payload.t_code

        result = session.execute(text("""
            UPDATE public.artifact_results
            SET technique_status = 'IN_PROGRESS'
            WHERE asset_id = :aid AND t_code = :t
              AND technique_status = 'PENDING_REVIEW'
            RETURNING claimed_by
        """), {"aid": asset_id, "t": t_code}).mappings().first()

        if not result:
            raise HTTPException(status_code=409, detail="TRANSITION_NOT_ALLOWED — must be PENDING_REVIEW")

        session.commit()

        if result["claimed_by"]:
            await _notify_user(result["claimed_by"], "technique_kicked_back", {
                "asset_id": asset_id, "t_code": t_code,
                "kicked_back_by": current_user.get("sub"),
            })

        await _broadcast("technique_kickback", {"asset_id": asset_id, "t_code": t_code})

        return {"status": "IN_PROGRESS"}

    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

@router.post("/tools/lock")
async def acquire_tool_lock(payload: ToolLockPayload, current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        _expire_tool_locks(session)
        user_id = current_user["id"]
        asset_id = payload.asset_id
        tool_name = payload.tool_name

        existing = session.execute(text("""
            SELECT tl.locked_by, u.username, u.initials, tl.locked_at, tl.expires_at
            FROM public.tool_locks tl
            JOIN public.users u ON tl.locked_by = u.id
            WHERE tl.asset_id = :aid AND tl.tool_name = :tool
        """), {"aid": asset_id, "tool": tool_name}).mappings().first()

        if existing and existing["locked_by"] != user_id:
            return {
                "status": "LOCKED",
                "locked_by": existing["username"],
                "locked_by_initials": existing["initials"],
                "locked_at": existing["locked_at"].isoformat() if existing["locked_at"] else None,
                "expires_at": existing["expires_at"].isoformat() if existing["expires_at"] else None,
            }

        is_long = tool_name in ("volatility", "clamav")
        session.execute(text("""
            INSERT INTO public.tool_locks (asset_id, tool_name, locked_by, locked_at, expires_at)
            VALUES (:aid, :tool, :uid, NOW(),
                    CASE WHEN :is_long THEN NOW() + INTERVAL '2 hours'
                         ELSE NOW() + INTERVAL '30 minutes' END)
            ON CONFLICT (asset_id, tool_name) DO UPDATE
                SET expires_at = CASE WHEN :is_long THEN NOW() + INTERVAL '2 hours'
                                      ELSE NOW() + INTERVAL '30 minutes' END
        """), {"aid": asset_id, "tool": tool_name, "uid": user_id, "is_long": is_long})

        session.commit()

        await _broadcast("tool_locked", {
            "asset_id": asset_id, "tool_name": tool_name,
            "locked_by": current_user.get("sub"),
            "locked_by_initials": current_user.get("initials"),
        })

        return {"status": "ACQUIRED", "tool_name": tool_name}

    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

@router.post("/tools/release")
async def release_tool_lock(payload: ToolLockPayload, current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        user_id = current_user["id"]
        asset_id = payload.asset_id
        tool_name = payload.tool_name

        lock = session.execute(text("""
            SELECT locked_by FROM public.tool_locks
            WHERE asset_id = :aid AND tool_name = :tool
        """), {"aid": asset_id, "tool": tool_name}).mappings().first()

        if lock and lock["locked_by"] != user_id and current_user.get("role") != "admin":
            raise HTTPException(status_code=403, detail="NOT_LOCK_OWNER")

        session.execute(text("""
            DELETE FROM public.tool_locks WHERE asset_id = :aid AND tool_name = :tool
        """), {"aid": asset_id, "tool": tool_name})

        session.commit()

        await _broadcast("tool_released", {
            "asset_id": asset_id, "tool_name": tool_name,
            "released_by": current_user.get("sub"),
        })

        return {"status": "RELEASED"}

    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

@router.get("/tools/locks/{asset_id}")
async def get_tool_locks(asset_id: int, current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        _expire_tool_locks(session)
        results = session.execute(text("""
            SELECT tl.tool_name, tl.locked_at, tl.expires_at, u.username, u.initials
            FROM public.tool_locks tl
            JOIN public.users u ON tl.locked_by = u.id
            WHERE tl.asset_id = :aid
        """), {"aid": asset_id}).mappings().all()
        session.commit()
        return [dict(r) for r in results]
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

@router.get("/cases/{case_name}/completion")
async def get_case_completion(case_name: str, current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        result = session.execute(text("""
            WITH case_info AS (
                SELECT focus_country FROM public.cases WHERE name = :name
            ),
            total_techniques AS (
                SELECT COUNT(DISTINCT mt.t_code) as total
                FROM threat_attribution ta
                JOIN mitre_actors ma ON ta.group_name = ma.name
                JOIN mitre_relationships ma_rel ON ma.stix_id = ma_rel.source_ref
                JOIN mitre_techniques mt ON ma_rel.target_ref = mt.stix_id
                WHERE UPPER(ta.attribution) = UPPER((SELECT focus_country FROM case_info))
                  AND ma_rel.relationship_type = 'uses'
            ),
            asset_stats AS (
                SELECT
                    a.id as asset_id,
                    a.hostname,
                    a.ip,
                    COUNT(ar.t_code)                                          as total_worked,
                    COUNT(ar.t_code) FILTER (WHERE ar.technique_status = 'CLOSED')          as closed,
                    COUNT(ar.t_code) FILTER (WHERE ar.technique_status = 'PENDING_REVIEW')  as pending_review,
                    COUNT(ar.t_code) FILTER (WHERE ar.technique_status = 'IN_PROGRESS')     as in_progress,
                    -- Verdicts are actually written as upper-case 'MALICIOUS'/'NON-MALICIOUS' by the
                    -- analyst-facing save (see EvidenceWindow.jsx); 'Clean'/title-case 'Malicious' are
                    -- never written by any code path, and interim automated-pipeline values ('Evidence
                    -- Found', 'NO_ARTIFACTS', 'MANUAL_UPLOAD') and NULL all count as undetermined --
                    -- same "not explicitly malicious/non-malicious" convention used in EvidenceWindow.jsx.
                    COUNT(ar.t_code) FILTER (WHERE UPPER(ar.verdict) = 'MALICIOUS')                                    as malicious,
                    COUNT(ar.t_code) FILTER (WHERE UPPER(ar.verdict) = 'NON-MALICIOUS')                                as clean,
                    COUNT(ar.t_code) FILTER (WHERE COALESCE(UPPER(ar.verdict), '') NOT IN ('MALICIOUS', 'NON-MALICIOUS')) as undetermined
                FROM public.assets a
                LEFT JOIN public.artifact_results ar ON ar.asset_id = a.id
                WHERE a.case_name = :name
                GROUP BY a.id, a.hostname, a.ip
            )
            SELECT
                as2.*,
                tt.total as total_techniques,
                CASE WHEN tt.total > 0
                    THEN ROUND((as2.closed::numeric / tt.total) * 100, 1)
                    ELSE 0
                END as completion_pct
            FROM asset_stats as2
            CROSS JOIN total_techniques tt
            ORDER BY as2.hostname ASC
        """), {"name": case_name}).mappings().all()

        rows = [dict(r) for r in result]

        if rows:
            total_t = rows[0]["total_techniques"]
            total_closed = sum(r["closed"] for r in rows)
            aggregate_pct = round((total_closed / (total_t * len(rows))) * 100, 1) if total_t and rows else 0
        else:
            total_t = 0
            aggregate_pct = 0

        return {
            "case_name": case_name,
            "total_techniques": total_t,
            "aggregate_completion_pct": aggregate_pct,
            "assets": rows,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

@router.patch("/cases/{case_name}/assets/{asset_id}/mode")
async def set_asset_analysis_mode(
    case_name: str,
    asset_id: int,
    payload: AssetModePayload,
    current_user: dict = Depends(get_current_user)
):
    valid_modes = {"LIVE_REMOTE", "DEAD_DISK_LOCAL", "DEAD_DISK_REMOTE", "UNKNOWN"}
    if payload.analysis_mode not in valid_modes:
        raise HTTPException(status_code=400, detail=f"Invalid mode. Must be one of: {valid_modes}")

    session = db.get_session()
    try:
        result = session.execute(text("""
            UPDATE public.assets
            SET analysis_mode = :mode
            WHERE id = :aid AND case_name = :case
            RETURNING id, hostname, analysis_mode
        """), {"mode": payload.analysis_mode, "aid": asset_id, "case": case_name}).mappings().first()

        if not result:
            raise HTTPException(status_code=404, detail="ASSET_NOT_FOUND")

        session.commit()

        await _broadcast("asset_mode_changed", {
            "asset_id": asset_id, "case_name": case_name,
            "analysis_mode": payload.analysis_mode,
            "changed_by": current_user.get("sub"),
        })

        return dict(result)

    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

@router.post("/evidence/{asset_id}/{t_code}/notes/v2")
async def add_tcode_note_v2(
    asset_id: int,
    t_code: str,
    data: TCodeNotePayload,
    current_user: dict = Depends(get_current_user)
):
    session = db.get_session()
    try:
        user_id = current_user["id"]
        initials = current_user.get("initials", "??")

        result = session.execute(text("""
            INSERT INTO public.tcode_notes (asset_id, t_code, note_text, note_type, author_id, author_initials)
            VALUES (:aid, :t, :text, :type, :uid, :initials)
            RETURNING id, created_at
        """), {
            "aid": asset_id, "t": t_code, "text": data.text,
            "type": data.note_type, "uid": user_id, "initials": initials
        }).mappings().first()

        session.execute(text("""
            UPDATE public.technique_locks
            SET expires_at = NOW() + INTERVAL '30 minutes'
            WHERE asset_id = :aid AND t_code = :t AND locked_by = :uid
        """), {"aid": asset_id, "t": t_code, "uid": user_id})

        session.commit()
        return {
            "status": "SUCCESS",
            "id": result["id"],
            "time": result["created_at"].strftime("%Y-%m-%d %H:%M"),
            "author_initials": initials,
            "note_type": data.note_type,
        }
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

@router.get("/evidence/{asset_id}/{t_code}/notes/v2")
async def get_tcode_notes_v2(asset_id: int, t_code: str, current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        results = session.execute(text("""
            SELECT n.id, n.note_text, n.note_type, n.created_at,
                   COALESCE(n.author_initials, 'SYS') as author_initials,
                   u.username as author_username
            FROM public.tcode_notes n
            LEFT JOIN public.users u ON n.author_id = u.id
            WHERE n.asset_id = :aid AND n.t_code = :t
            ORDER BY n.created_at ASC
        """), {"aid": asset_id, "t": t_code}).mappings().all()
        return [{
            "id": r["id"],
            "text": r["note_text"],
            "type": r["note_type"],
            "time": r["created_at"].strftime("%Y-%m-%d %H:%M") if r["created_at"] else "",
            "author_initials": r["author_initials"],
            "author_username": r["author_username"],
        } for r in results]
    except Exception as _e:
        logging.error(f"[mitre_routes] {_e}")
        return []
    finally:
        session.close()

@router.post("/cases/{case_name}/notes/v2")
async def add_case_note_v2(
    case_name: str,
    data: CaseNotePayload,
    current_user: dict = Depends(get_current_user)
):
    session = db.get_session()
    try:
        if data.note_type == "BLUF" and current_user.get("role") not in ("admin", "lead"):
            raise HTTPException(status_code=403, detail="LEAD_ROLE_REQUIRED_FOR_BLUF")

        result = session.execute(text("""
            INSERT INTO public.case_notes (case_name, note_text, author_id, author_initials, note_type)
            VALUES (:name, :text, :uid, :initials, :type)
            RETURNING id, created_at
        """), {
            "name": case_name,
            "text": data.text,
            "uid": current_user["id"],
            "initials": current_user.get("initials", "??"),
            "type": data.note_type,
        }).mappings().first()

        session.commit()
        return {
            "status": "SUCCESS",
            "id": result["id"],
            "time": result["created_at"].strftime("%Y-%m-%d %H:%M"),
            "author_initials": current_user.get("initials"),
            "note_type": data.note_type,
        }
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

@router.get("/cases/{case_name}/notes/v2")
async def get_case_notes_v2(case_name: str, current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        results = session.execute(text("""
            SELECT n.id, n.note_text, n.note_type, n.created_at,
                   COALESCE(n.author_initials, 'SYS') as author_initials,
                   u.username as author_username
            FROM public.case_notes n
            LEFT JOIN public.users u ON n.author_id = u.id
            WHERE n.case_name = :name
            ORDER BY n.created_at ASC
        """), {"name": case_name}).mappings().all()
        return [{
            "id": r["id"],
            "text": r["note_text"],
            "type": r["note_type"],
            "time": r["created_at"].strftime("%Y-%m-%d %H:%M") if r["created_at"] else "",
            "author_initials": r["author_initials"],
            "author_username": r["author_username"],
        } for r in results]
    except Exception as _e:
        logging.error(f"[mitre_routes] {_e}")
        return []
    finally:
        session.close()