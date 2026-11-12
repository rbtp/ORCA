"""Build quality\\fixed\\ (library.json = repaired library) so analyze.py / runall.py can run on it unchanged."""
import os, sys, json, shutil
QD = sys.argv[1]  # the audit work folder
FD = os.path.join(QD, "fixed")
os.makedirs(os.path.join(FD, "logs"), exist_ok=True)
for f in ("schemas.json", "manifests.json"):
    shutil.copy(os.path.join(QD, f), os.path.join(FD, f))
if not os.path.exists(os.path.join(FD, "logs", "Security.evtx")):
    shutil.copy(os.path.join(QD, "logs", "Security.evtx"), os.path.join(FD, "logs", "Security.evtx"))
lib = json.load(open(os.path.join(QD, "library.json"), encoding="utf-8"))
fx = json.load(open(os.path.join(QD, "fixed_library.json"), encoding="utf-8"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from holdback import held_back
hb = held_back(QD)
out = []
for r in lib:
    f = None if r["t"] in hb else fx.get(r["t"])   # held back: repaired version floods a normal workstation
    out.append(dict(r, y=f["y"] if f else r["y"], v=f["v"] if f else r["v"]))
print("repairs held back:", len(hb))
json.dump(out, open(os.path.join(FD, "library.json"), "w", encoding="utf-8"))
print("fixed library written:", len(out))
