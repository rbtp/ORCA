"""Round 2: hand repairs on top of the automatic repair.
Reads QUALITY_DIR/manual/fix/<T>.yaml / <T>.vql (full replacement text) and <T>.md (note; first line
NOT_OBSERVABLE for techniques that happen off the host) and
  build  -> QUALITY_DIR/manual/fixed2/ (library.json = shipping library + hand repairs, plus the schema/manifest/log
            files analyze.py and runall.py expect), and manual/changed.json (techniques touched)
  migration REPO -> REPO/migrations/repair_library_queries_2.sql
A column is replaced only while it still holds the original seed text or the round-1 repaired text
(md5 guard, line endings ignored), so analyst edits are kept.
usage: python manual.py QUALITY_DIR build | python manual.py QUALITY_DIR migration REPO"""
import glob, hashlib, json, os, shutil, sys
QD, MODE = sys.argv[1], sys.argv[2]
CR = chr(13)
MD = os.path.join(QD, "manual")
F2 = os.path.join(MD, "fixed2")
orig = {r["t"]: r for r in json.load(open(os.path.join(QD, "library.json"), encoding="utf-8"))}
ship = {r["t"]: r for r in json.load(open(os.path.join(QD, "fixed", "library.json"), encoding="utf-8"))}


def fixes():
    out = {}
    for p in glob.glob(os.path.join(MD, "fix", "*.md")):
        t = os.path.basename(p)[:-3]
        note = open(p, encoding="utf-8").read().strip()
        f = {"note": note, "not_observable": note.upper().startswith("NOT_OBSERVABLE")}
        for key, ext in (("y", "yaml"), ("v", "vql")):
            fp = os.path.join(MD, "fix", f"{t}.{ext}")
            if os.path.exists(fp):
                f[key] = open(fp, encoding="utf-8").read().replace(CR, "").strip() + "\n"
        out[t] = f
    return out


FX = fixes()
if MODE == "build":
    os.makedirs(os.path.join(F2, "logs"), exist_ok=True)
    for f in ("schemas.json", "manifests.json"):
        shutil.copy(os.path.join(QD, "fixed", f), os.path.join(F2, f))
    if not os.path.exists(os.path.join(F2, "logs", "Security.evtx")):
        shutil.copy(os.path.join(QD, "fixed", "logs", "Security.evtx"), os.path.join(F2, "logs", "Security.evtx"))
    out, changed = [], []
    for t, r in ship.items():
        f = FX.get(t, {})
        nr = dict(r, y=f.get("y", r["y"]), v=f.get("v", r["v"]))
        if nr["y"] != r["y"] or nr["v"] != r["v"]:
            changed.append(t)
        out.append(nr)
    json.dump(out, open(os.path.join(F2, "library.json"), "w", encoding="utf-8"))
    json.dump({"changed": sorted(changed), "not_observable": sorted(t for t, f in FX.items() if f["not_observable"]),
               "notes": {t: f["note"] for t, f in FX.items()}}, open(os.path.join(MD, "changed.json"), "w", encoding="utf-8"), indent=1)
    print(f"{len(FX)} notes, {len(changed)} techniques changed, {sum(f['not_observable'] for f in FX.values())} not observable")

elif MODE == "migration":
    REPO = sys.argv[3]
    TAG = "$orcafix2$"
    NO_OBS = ("NOT OBSERVABLE ON THE HOST: ATT&CK lists no host data source for this technique (it happens on "
              "attacker infrastructure or in public sources). An empty collection result is expected and is not "
              "evidence that it didn't happen.")
    out = ["-- Round 2 of the artifact-library repair (see docs/LIBRARY_QUALITY.md): hand-written repairs of the",
           "-- queries the automatic repair could not fix or had to hold back (too broad), each tested against the",
           "-- Atomic Red Team attack VM's disk and checked for noise on a normal workstation.",
           "-- A column is replaced only while it still holds the original seed text or the round-1 repaired text",
           "-- (md5 guard, line endings ignored): queries edited in the Artifact Library Editor are kept.",
           ""]
    n = 0
    for t in sorted(FX):
        f = FX[t]
        for col, key in (("surgical_yaml", "y"), ("custom_vql", "v")):
            if key not in f:
                continue
            new = f[key]
            olds = {(orig[t][key] or "").replace(CR, ""), (ship[t][key] or "").replace(CR, "")}
            if new in olds:
                continue
            assert TAG not in new
            md5s = ", ".join(f"'{hashlib.md5(o.encode('utf-8')).hexdigest()}'" for o in sorted(olds))
            out.append(f"UPDATE ref_artifact_library SET {col} = {TAG}{new}{TAG}, updated_at = NOW()")
            out.append(f"WHERE t_code = '{t}' AND md5(replace(COALESCE({col}, ''), chr(13), '')) IN ({md5s});")
            out.append("")
            n += 1
        if f["not_observable"]:
            out.append(f"UPDATE ref_artifact_library SET analysis_steps = {TAG}{NO_OBS}{TAG} || chr(10) || chr(10) || COALESCE(analysis_steps, '')")
            out.append(f"WHERE t_code = '{t}' AND COALESCE(analysis_steps, '') NOT LIKE 'NOT OBSERVABLE ON THE HOST%';")
            out.append("")
            n += 1
    path = os.path.join(REPO, "migrations", "repair_library_queries_2.sql")
    open(path, "w", encoding="utf-8", newline="\n").write("\n".join(out))
    print(f"{n} updates written to {path}")
