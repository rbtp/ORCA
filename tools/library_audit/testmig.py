"""Apply migrations/repair_library_queries.sql to a database container and check the result.
usage: python testmig.py QUALITY_DIR REPO_DIR CONTAINER"""
import hashlib, json, os, subprocess, sys
QD, REPO, CT = sys.argv[1], sys.argv[2], sys.argv[3]
CR = chr(13)
mig = os.path.join(REPO, "migrations", "repair_library_queries.sql")
def psql(args, stdin=None):
    return subprocess.run(["docker", "exec", "-i", CT, "psql", "-U", "postgres", "-d", "orca_db"] + args,
                          input=stdin, capture_output=True, text=True, encoding="utf-8")
sql = open(mig, encoding="utf-8").read()
r = psql(["-v", "ON_ERROR_STOP=1"], sql)
updates = [l for l in r.stdout.splitlines() if l.startswith("UPDATE")]
print("run 1: errors:", r.returncode, r.stderr[-300:].strip(), "| statements:", len(updates),
      "| rows updated:", sum(int(l.split()[1]) for l in updates))
r2 = psql(["-v", "ON_ERROR_STOP=1"], sql)
u2 = [l for l in r2.stdout.splitlines() if l.startswith("UPDATE")]
print("run 2 (re-run): rows updated:", sum(int(l.split()[1]) for l in u2))
fx = json.load(open(os.path.join(QD, "fixed_library.json"), encoding="utf-8"))
q = "select t_code||'|'||md5(replace(coalesce(surgical_yaml,''),chr(13),''))||'|'||md5(replace(coalesce(custom_vql,''),chr(13),'')) from ref_artifact_library"
got = {l.split("|")[0]: l.split("|")[1:] for l in psql(["-tAc", q]).stdout.splitlines() if l}
md5 = lambda s: hashlib.md5((s or "").replace(CR, "").encode("utf-8")).hexdigest()
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from holdback import held_back
hb = held_back(QD)
lib = {r["t"]: r for r in json.load(open(os.path.join(QD, "library.json"), encoding="utf-8"))}
want = {t: (lib[t] if t in hb else f) for t, f in fx.items()}
bad = [t for t, f in want.items() if got.get(t) != [md5(f["y"]), md5(f["v"])]]
print("rows equal to the expected library (repaired, held-back ones original):", len(want) - len(bad), "/", len(want), "| held back:", len(hb), "| mismatches:", bad[:10])
