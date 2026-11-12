"""Techniques whose repaired queries flood a normal workstation (any query part >= THRESHOLD rows) while the
original didn't: the repair made a too-broad query run. Those repairs are held back (see mkmigration.py).
usage: python floods.py WORK [THRESHOLD]   -> WORK\\floods.json"""
import collections, json, os, sys
W = sys.argv[1]
TH = int(sys.argv[2]) if len(sys.argv) > 2 else 2000
before = json.load(open(os.path.join(W, "run_results.json"), encoding="utf-8"))
after = json.load(open(os.path.join(W, "fixed", "run_results.json"), encoding="utf-8"))
mx = lambda run: {t: max(v) for t, v in _group(run).items()}
def _group(run):
    g = collections.defaultdict(list)
    for k, v in run.items():
        g[k.split("|")[0]].append(v.get("rows", 0))
    return g
# "before" = what the agent really ran: when the original YAML failed to load it fell back to the VQL
runs = {r["t_code"]: r["runs"] for r in json.load(open(os.path.join(W, "findings.json"), encoding="utf-8"))["rows"]}
before = {k: v for k, v in before.items()
          if (runs.get(k.split("|")[0]) == "vql") == (k.split("|")[1] == "vql")}
b, a = mx(before), mx(after)
floods = {t: {"rows_after": a[t], "rows_before": b.get(t, 0)} for t in a if a[t] >= TH and b.get(t, 0) < TH}
already = {t: a[t] for t in a if a[t] >= TH and b.get(t, 0) >= TH}
json.dump({"threshold": TH, "held_back": floods, "noisy_before_and_after": already},
          open(os.path.join(W, "floods.json"), "w", encoding="utf-8"), indent=1)
print(f"threshold {TH}: repair held back for {len(floods)} techniques; {len(already)} were already that noisy before")
for t, d in sorted(floods.items(), key=lambda x: -x[1]["rows_after"]): print(f"  {t}: {d['rows_before']} -> {d['rows_after']}")
