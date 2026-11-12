"""Drop fixed-run results for techniques whose fixed text changed since that run (so runall re-runs them)."""
import json, os, sys
FD = sys.argv[1]
lib = {r["t"]: r for r in json.load(open(os.path.join(FD, "library.json"), encoding="utf-8"))}
snap_p = os.path.join(FD, "library_at_run.json")
path = os.path.join(FD, "run_results.json")
done = json.load(open(path, encoding="utf-8"))
if os.path.exists(snap_p):
    snap = json.load(open(snap_p, encoding="utf-8"))
    changed = {t for t, r in lib.items() if (r["y"], r["v"]) != tuple(snap.get(t, [None, None]))}
else:  # first time: everything whose errors mention FullPath, or whose text mentions OSPath now
    changed = {k.split("|")[0] for k, v in done.items() if any("FullPath" in e for e in v.get("errors", []))}
    changed |= {t for t, r in lib.items() if "OSPath" in ((r["y"] or "") + (r["v"] or ""))}
drop = [k for k in done if k.split("|")[0] in changed]
for k in drop: done.pop(k)
json.dump(done, open(path, "w", encoding="utf-8"))
json.dump({t: [r["y"], r["v"]] for t, r in lib.items()}, open(snap_p, "w", encoding="utf-8"))
print("techniques changed:", len(changed), "results dropped for re-run:", len(drop))
