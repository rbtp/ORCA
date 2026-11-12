"""Real EventData/UserData field names per (log, EventID), read from this machine's logs.
usage: python schemas.py VELOCIRAPTOR_EXE OUT_JSON"""
import subprocess, sys, json, os

VR, OUT = sys.argv[1], sys.argv[2]
LOGS = {
    "Sysmon": "Microsoft-Windows-Sysmon%4Operational.evtx",
    "Security": "Security.evtx",
    "PowerShellOperational": "Microsoft-Windows-PowerShell%4Operational.evtx",
    "WindowsPowerShell": "Windows PowerShell.evtx",
    "System": "System.evtx",
    "Application": "Application.evtx",
    "TaskScheduler": "Microsoft-Windows-TaskScheduler%4Operational.evtx",
    "WMIActivity": "Microsoft-Windows-WMI-Activity%4Operational.evtx",
    "Defender": "Microsoft-Windows-Windows Defender%4Operational.evtx",
    "RDPCoreTS": "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx",
    "TSLocalSession": "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
    "BITS": "Microsoft-Windows-Bits-Client%4Operational.evtx",
    "CodeIntegrity": "Microsoft-Windows-CodeIntegrity%4Operational.evtx",
    "Firewall": "Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx",
}
only = sys.argv[3:] or list(LOGS)
out = json.load(open(OUT)) if os.path.exists(OUT) else {}
for name in only:
    path = "C:/Windows/System32/winevt/Logs/" + LOGS[name]
    if not os.path.exists(path):
        print(f"{name}: no log here", flush=True); continue
    # one sample event per (event ID, number of fields): small output even for a 1 GB log
    q = (f"SELECT System.EventID.Value AS id, len(list=EventData) AS nf, count() AS n, EventData AS ed "
         f"FROM parse_evtx(filename='{path}') WHERE EventData GROUP BY id, nf")
    p = subprocess.run([VR, "query", "--format", "jsonl", q], capture_output=True, text=True, encoding="utf-8", errors="replace")
    try:
        rows = [json.loads(l) for l in p.stdout.splitlines() if l.strip()]
    except Exception:
        open(name + ".raw", "w", encoding="utf-8").write(p.stdout); print(name, "parse failed", len(p.stdout), repr(p.stdout[-200:]), p.stderr[-300:], flush=True); continue
    ids = {}
    for r in rows:
        e = ids.setdefault(str(r["id"]), {"count": 0, "eventdata": set(), "types": {}, "examples": {}})
        e["count"] += r["n"]
        if isinstance(r.get("ed"), dict):
            for k, v in r["ed"].items():
                e["eventdata"].add(k)
                e["types"].setdefault(k, set()).add(type(v).__name__)
                if k not in e["examples"] and v not in (None, "", "-"):
                    e["examples"][k] = str(v)[:120]
    out[name] = {k: {"count": v["count"], "eventdata": sorted(v["eventdata"]),
                     "types": {f: sorted(t) for f, t in v["types"].items()}, "examples": v["examples"]}
                 for k, v in ids.items()}
    print(f"{name}: {len(ids)} event IDs, {sum(v['count'] for v in ids.values())} events", flush=True)
    json.dump(out, open(OUT, "w"), indent=1)
