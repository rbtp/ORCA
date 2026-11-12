"""Run every Windows technique's effective query, source by source, on this host.
usage: python runall.py QUALITY_DIR REPO_DIR VELOCIRAPTOR_EXE [PARALLEL]
writes QUALITY_DIR/run_results.json (resumable: finished sources are kept)"""
import concurrent.futures as cf, importlib.util, json, os, re, subprocess, sys, threading, time, yaml

QD, REPO, VR = sys.argv[1], sys.argv[2], sys.argv[3]
PAR = int(sys.argv[4]) if len(sys.argv) > 4 else 8
MAX_ROWS, TIMEOUT = 5000, 240
SEC_COPY = os.path.join(QD, "logs", "Security.evtx").replace("\\", "/")

spec = importlib.util.spec_from_file_location("orca_agent", os.path.join(REPO, "agent", "orca_agent.py"))
agent = importlib.util.module_from_spec(spec); spec.loader.exec_module(agent)
CONVERT = agent.OrcaAgent._convert_source_to_parse_evtx

lib = {r["t"]: r for r in json.load(open(os.path.join(QD, "library.json"), encoding="utf-8"))}
rows = json.load(open(os.path.join(QD, "findings.json"), encoding="utf-8"))["rows"]
out_path = os.path.join(QD, "run_results.json")
done = json.load(open(out_path, encoding="utf-8")) if os.path.exists(out_path) else {}
lock = threading.Lock()

def sources_for(r):
    row = lib[r["t_code"]]
    if r["runs"] == "yaml":
        d = yaml.safe_load(CONVERT(row["y"].replace("\r\n", "\n")))
        qs = [(s.get("name") or "source", s["query"]) for s in d.get("sources") or [] if isinstance(s, dict) and s.get("query")]
        if d.get("export"):
            qs = [(n, d["export"] + "\n" + q) for n, q in qs]
        return qs
    return [("vql", CONVERT(row["v"]))]

SEC_RX = re.compile(r"C:[/\\]+Windows[/\\]+System32[/\\]+winevt[/\\]+Logs[/\\]+Security\.evtx", re.I)

def run(key, q):
    q2 = SEC_RX.sub(SEC_COPY, q)
    t0 = time.time()
    # query from a file, like the agent: Defender blocks a velociraptor command line that contains
    # indicator strings (invoke-mimikatz, lsadump::secrets, ...)
    qdir = os.path.join(QD, "tmpq"); os.makedirs(qdir, exist_ok=True)
    qf = os.path.join(qdir, re.sub(r"[^\w.-]", "_", key) + ".vql")
    open(qf, "w", encoding="utf-8").write(q2)
    try:
        p = subprocess.Popen([VR, "query", "-f", qf, "--format", "jsonl"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, encoding="utf-8", errors="replace")
    except OSError as e:
        res = {"rows": 0, "capped": False, "timeout": False, "secs": 0, "errors": [f"could not start velociraptor: {e}"], "first": None}
        with lock:
            done[key] = res; json.dump(done, open(out_path, "w", encoding="utf-8"))
        return key, res
    errs = []
    def rd_err():
        for line in p.stderr:
            if "[ERROR]" in line or "rror:" in line:
                if len(errs) < 5: errs.append(line.strip()[-300:])
    th = threading.Thread(target=rd_err, daemon=True); th.start()
    n, first, timed_out, capped = 0, None, False, False
    timer = threading.Timer(TIMEOUT, lambda: p.kill()); timer.start()
    try:
        for line in p.stdout:
            if not line.strip(): continue
            if not line.lstrip().startswith("{"):          # velociraptor also logs [ERROR] lines to stdout
                if ("[ERROR]" in line or "rror" in line) and len(errs) < 5:
                    errs.append(line.strip()[-300:])
                continue
            n += 1
            if first is None: first = line.strip()[:600]
            if n >= MAX_ROWS:
                capped = True; p.kill(); break
    finally:
        timer.cancel()
    p.wait()
    if not capped and time.time() - t0 >= TIMEOUT - 1: timed_out = True
    th.join(timeout=2)
    res = {"rows": n, "capped": capped, "timeout": timed_out, "secs": round(time.time() - t0, 1), "errors": errs, "first": first}
    with lock:
        done[key] = res
        json.dump(done, open(out_path, "w", encoding="utf-8"))
    return key, res

jobs = []
for r in rows:
    if r.get("platform") != "windows": continue
    try:
        for name, q in sources_for(r):
            key = f"{r['t_code']}|{name}"
            if key not in done: jobs.append((key, q))
    except Exception as e:
        done[f"{r['t_code']}|*"] = {"rows": 0, "errors": [f"could not load sources: {e}"]}
print(f"{len(jobs)} sources to run ({len(done)} already done), {PAR} at a time", flush=True)
t0 = time.time()
with cf.ThreadPoolExecutor(PAR) as ex:
    for i, fut in enumerate(cf.as_completed([ex.submit(run, k, q) for k, q in jobs]), 1):
        k, r = fut.result()
        if i % 25 == 0 or i == len(jobs):
            print(f"{i}/{len(jobs)} done, {int(time.time() - t0)}s", flush=True)
print("finished", flush=True)
