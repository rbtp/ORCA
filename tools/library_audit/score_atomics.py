"""(env: ORCA_AUDIT_WORK = audit work folder, ORCA_URL = ORCA address, default https://localhost)
Atomic Red Team ground truth: does each technique's query see the activity its Atomic tests produced?
The VM's disk before the attacks (baseline) and after (attacked) are clones of one disk, so Windows only
brings one online at a time: collect each disk separately, then score.

  python score_atomics.py collect ADMIN_PASSWORD LABEL DRIVE ATOMIC_RUNS_JSONL [PARALLEL] [LIBDIR]
      runs every executed technique's original and repaired queries through the ORCA agent against DRIVE,
      saving per technique/version the row fingerprints + timestamps to collect_LABEL.json (resumable).
      Identical original/repaired query text is collected once. LIBDIR: another fixed library to collect
      (e.g. a hand-fixed round), stored under version name = basename(LIBDIR).
  python score_atomics.py score ATOMIC_RUNS_JSONL OUT_JSON [VERSION...]
      fires     - the query returns rows on the attacked disk that it doesn't return on the baseline disk
      in_window - ... and at least one of those rows is timestamped inside that technique's own test window
"""
import concurrent.futures as cf, datetime as dt, hashlib, json, os, re, sys, threading, time
QD = os.environ.get("ORCA_AUDIT_WORK") or os.path.dirname(os.path.abspath(__file__))   # audit work folder
MODE = sys.argv[1]


def iso_utc(s):
    m = re.match(r"(\d{4}-\d\d-\d\d)[T ](\d\d:\d\d:\d\d)(\.\d+)?", s)
    base = dt.datetime.strptime(m.group(1) + "T" + m.group(2), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=dt.timezone.utc)
    return base.timestamp() + (float("0" + m.group(3)) if m.group(3) else 0.0)


def load_runs(path):
    runs = [json.loads(l) for l in open(path, encoding="utf-8-sig", errors="replace") if l.strip()]
    return {r["t"]: r for r in runs}


def epoch_of(v):
    if isinstance(v, dict):
        for k in ("SystemTime", "Time", "Value"):
            if k in v: return epoch_of(v[k])
        return None
    if isinstance(v, (int, float)) and 1.5e9 < v < 2.2e9: return float(v)
    if isinstance(v, str) and re.match(r"^\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d", v):
        try: return iso_utc(v)
        except Exception: return None
    return None


def row_times(row):
    out = []
    for v in row.values():
        if isinstance(v, str) and v.startswith("{"):
            try: v = json.loads(v)
            except Exception: pass
        if isinstance(v, dict) and "TimeCreated" in v:   # whole System block
            v = v["TimeCreated"]
        t = epoch_of(v)
        if t: out.append(round(t))
    return out


def row_key(row):
    r = {k: v for k, v in row.items() if k not in ("_Source",)}
    return hashlib.md5(json.dumps(r, sort_keys=True, default=str).encode()).hexdigest()[:16]


if MODE == "collect":
    PW, LABEL, DRIVE, RUNS = sys.argv[2:6]
    PAR = int(sys.argv[6]) if len(sys.argv) > 6 else 8
    EXTRA = sys.argv[7] if len(sys.argv) > 7 else None
    sys.argv = [sys.argv[0], os.environ.get("ORCA_URL", "https://localhost"), "admin", PW, os.environ.get("ORCA_BACKEND", "orca-backend")]
    exec(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "orca_api.py"), encoding="utf-8").read())
    libs = {"original": {r["t"]: r for r in json.load(open(os.path.join(QD, "library.json"), encoding="utf-8"))},
            "fixed": {r["t"]: r for r in json.load(open(os.path.join(QD, "fixed", "library.json"), encoding="utf-8"))}}
    if EXTRA:
        libs = {os.path.basename(EXTRA.rstrip("/\\")): {r["t"]: r for r in json.load(open(os.path.join(EXTRA, "library.json"), encoding="utf-8"))}}
    runs = load_runs(RUNS)
    executed = sorted(t for t, r in runs.items() if r.get("tests", 0) > 0)
    if EXTRA and os.path.exists(os.path.join(EXTRA, "..", "changed.json")):
        # round-2 library: collect every changed technique (Atomic-tested or not, for the run check)
        executed = sorted(json.load(open(os.path.join(EXTRA, "..", "changed.json")))["changed"])
    req("POST", "/api/auth/login", {"username": "admin", "password": PW})
    AGENT = next(a for a in js(req("GET", "/api/agent/list")[1]) if a.get("status") == "ONLINE")["agent_id"]
    OUT = os.path.join(QD, f"collect_{LABEL}.json")
    results = json.load(open(OUT, encoding="utf-8")) if os.path.exists(OUT) else {}

    def qtext(row):
        return ((row or {}).get("y") or "").strip() + "\n----\n" + ((row or {}).get("v") or "").strip()

    def collect(t, row):
        if not row or not ((row["y"] or "").strip() or (row["v"] or "").strip()):
            return {"skipped": "no query in library"}
        for attempt in range(3):
            if attempt:
                time.sleep(10); req("POST", "/api/auth/login", {"username": "admin", "password": PW})
            s, c = req("POST", "/api/agent/dispatch", {"agent_id": AGENT, "job_type": "artifact_collection", "params": {
                "t_code": t, "tsource": f"{DRIVE}:", "custom_vql": row["v"] or "", "surgical_yaml": row["y"] or ""}})
            job = (js(c) or {}).get("job_id")
            if job: break
        if not job: return {"error": f"dispatch {s}: {c[:200]}"}
        keys, times, errors, fallback, samples, done = [], [], [], False, [], False
        st, resp = req("GET", f"/api/agent/jobs/{job}/stream", timeout=1800, stream=True)
        for line in resp:
            line = line.decode(errors="replace").strip()
            if not line.startswith("data:"): continue
            e = js(line[5:].strip())
            if not isinstance(e, dict): continue
            if e.get("type") == "row":
                try: row = json.loads(e["data"]["row"])
                except Exception: continue
                keys.append(row_key(row)); times.append(row_times(row))
                if len(samples) < 3: samples.append(json.dumps(row)[:600])
            elif e.get("type") == "error":
                errors.append(str(e.get("data", {}).get("message"))[:300]); done = True; break
            elif e.get("type") == "done":
                fallback = bool(e.get("data", {}).get("fallback_used")); done = True; break
        resp.close()
        return {"keys": keys, "times": times, "fallback": fallback, "errors": errors[:3], "samples": samples,
                "complete": done}

    jobs, alias = [], {}
    for t in executed:
        seen = {}
        for v, lib in libs.items():
            k = f"{t}|{v}"
            q = qtext(lib.get(t))
            if q in seen:
                alias[k] = seen[q]; continue
            seen[q] = k
            if k not in results or "error" in results[k]:
                jobs.append((t, v, lib.get(t)))
    lock = threading.Lock()
    print(f"{LABEL} on {DRIVE}: {len(executed)} techniques, {len(jobs)} collections to run ({len(alias)} identical-query pairs reuse), {PAR} at a time", flush=True)
    t0 = time.time()
    with cf.ThreadPoolExecutor(PAR) as ex:
        futs = {ex.submit(collect, t, row): (t, v) for t, v, row in jobs}
        for i, f in enumerate(cf.as_completed(futs), 1):
            t, v = futs[f]
            try: res = f.result()
            except Exception as e: res = {"error": str(e)[:300]}
            with lock:
                results[f"{t}|{v}"] = res
                if i % 10 == 0 or i == len(jobs):
                    for a, b in alias.items():
                        if b in results: results[a] = {"alias": b}
                    json.dump(results, open(OUT, "w", encoding="utf-8"))
            if i % 20 == 0: print(f"{i}/{len(jobs)} ({int(time.time()-t0)}s)", flush=True)
    for a, b in alias.items():
        results[a] = {"alias": b}
    json.dump(results, open(OUT, "w", encoding="utf-8"))
    print(f"COLLECT DONE {LABEL}: {sum(1 for r in results.values() if 'error' in r)} errors, {int(time.time()-t0)}s", flush=True)

elif MODE == "score":
    RUNS, OUT = sys.argv[2:4]
    versions = sys.argv[4:] or ["original", "fixed"]
    runs = load_runs(RUNS)
    A = json.load(open(os.path.join(QD, "collect_attacked.json"), encoding="utf-8"))
    B = json.load(open(os.path.join(QD, "collect_baseline.json"), encoding="utf-8"))

    def get(d, k):
        r = d.get(k)
        while r and "alias" in r: r = d.get(r["alias"])
        return r
    # PowerShell logs on the attacked disk filled up and only reach back to here
    PS_START = iso_utc(open(os.path.join(QD, "ps_log_start.txt")).read().strip()) if os.path.exists(os.path.join(QD, "ps_log_start.txt")) else 0
    out = {}
    for t, run in sorted(runs.items()):
        if run.get("tests", 0) == 0: continue
        win = (iso_utc(run["start"]) - 30, iso_utc(run["end"]) + 120)
        for v in versions:
            a, b = get(A, f"{t}|{v}"), get(B, f"{t}|{v}")
            if v == "fixed2" and not a:   # unchanged by the hand repair: same text as round 1
                a, b = get(A, f"{t}|fixed"), get(B, f"{t}|fixed")
            if not a: continue
            if "skipped" in a or "error" in a:
                out[f"{t}|{v}"] = a; continue
            base = set((b or {}).get("keys", []))
            new = [i for i, k in enumerate(a["keys"]) if k not in base]
            in_win = sum(1 for i in new if any(win[0] <= x <= win[1] for x in a["times"][i]))
            fb = a["fallback"]
            out[f"{t}|{v}"] = {"rows_attacked": len(a["keys"]), "rows_baseline": len((b or {}).get("keys", [])),
                               "new_rows": len(new), "fallback": fb, "fires": len(new) > 0 and not fb,
                               "in_window": 0 if fb else in_win,
                               "new_without_time": sum(1 for i in new if not a["times"][i]),
                               "errors": a["errors"], "incomplete": not a.get("complete", True),
                               "ps_log_lost": win[1] < PS_START, "sample": a["samples"][:1]}
    json.dump(out, open(OUT, "w", encoding="utf-8"), indent=1)
    for v in versions:
        rs = {k.split("|")[0]: r for k, r in out.items() if k.endswith("|" + v) and "skipped" not in r and "error" not in r}
        print(f"{v}: scored {len(rs)}, fire {sum(1 for r in rs.values() if r['fires'])}, "
              f"in own window {sum(1 for r in rs.values() if r['in_window'] > 0)}, fallback only {sum(1 for r in rs.values() if r['fallback'])}")
