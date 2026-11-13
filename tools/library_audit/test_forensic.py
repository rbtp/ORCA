"""Runs every forensic dead-disk collection through the ORCA agent against a mounted image, exactly the
dead-disk path an analyst uses, and checks each returns rows (or is a documented-empty artifact).
usage: ORCA_URL=https://localhost:8443 python test_forensic.py ADMIN_PW DRIVE [MIGRATION_SQL]
DRIVE = the mounted image drive the agent can see (e.g. P). Reads the FORENSIC_* rows from the migration
(default migrations/add_live_dead_query_variants_forensic_collections.sql) so it tests the exact shipped text."""
import os, re, sys, json
PW, DRIVE = sys.argv[1], sys.argv[2]
HERE = os.path.dirname(os.path.abspath(__file__))
MIG = sys.argv[3] if len(sys.argv) > 3 else os.path.join(HERE, "..", "..", "migrations", "add_live_dead_query_variants_forensic_collections.sql")
sys.argv = [sys.argv[0], os.environ.get("ORCA_URL", "https://localhost"), "admin", PW, os.environ.get("ORCA_BACKEND", "orca-backend")]
exec(open(os.path.join(HERE, "orca_api.py"), encoding="utf-8").read())

sql = open(MIG, encoding="utf-8").read()
# pull each VALUES('FORENSIC_x', 'desc', 'Windows','Forensic', $orcaforensic$...$orcaforensic$, ...)
items = re.findall(r"VALUES \('(FORENSIC_[^']+)',.*?\$orcaforensic\$(.*?)\$orcaforensic\$", sql, re.S)
print(f"{len(items)} forensic collections to test against {DRIVE}:")
req("POST", "/api/auth/login", {"username": "admin", "password": PW})
AGENT = next(a for a in js(req("GET", "/api/agent/list")[1]) if a.get("status") == "ONLINE")["agent_id"]


def run_one(t, yaml_text):
    s, c = req("POST", "/api/agent/dispatch", {"agent_id": AGENT, "job_type": "artifact_collection", "params": {
        "t_code": t, "tsource": f"{DRIVE}:", "custom_vql": "", "surgical_yaml": yaml_text}})
    job = (js(c) or {}).get("job_id")
    if not job:
        return 0, [f"dispatch {s}"], False
    rows, errors, na = 0, [], False
    st, resp = req("GET", f"/api/agent/jobs/{job}/stream", timeout=1800, stream=True)
    for line in resp:
        line = line.decode(errors="replace").strip()
        if not line.startswith("data:"):
            continue
        e = js(line[5:].strip())
        if not isinstance(e, dict):
            continue
        tp = e.get("type")
        if tp == "row":
            rows += 1
        elif tp == "error":
            errors.append(str(e.get("data", {}).get("message"))[:200])
        elif tp == "notice":
            na = True
        elif tp == "done":
            break
    resp.close()
    return rows, errors, na


# Collections that legitimately return 0 rows on a freshly-installed clean image
# (they return data on a real image with user activity / a cleanly-acquired DB):
#   SRUM        - SRUDB.dat is a dirty ESE database on a live-captured image (needs esentutl recovery)
#   SHELLBAGS   - no Explorer folder navigation on a fresh install
#   RECENTDOCS  - no documents opened
#   RECYCLEBIN  - nothing deleted
EXPECTED_EMPTY = {"FORENSIC_SRUM", "FORENSIC_SHELLBAGS", "FORENSIC_RECENTDOCS", "FORENSIC_RECYCLEBIN"}

ok = bad = 0
for t, yaml_text in items:
    rows, errors, na = run_one(t, yaml_text)
    good = not errors and (rows > 0 or t in EXPECTED_EMPTY)
    ok += good; bad += (not good)
    tag = "ERR:" + str(errors)[:160] if errors else ("(empty ok on a clean image)" if rows == 0 and t in EXPECTED_EMPTY else ("NA" if na else ""))
    print(f"{'PASS' if good else 'FAIL'}  {t:26} rows={rows:<7} {tag}", flush=True)
print(f"{ok} passed, {bad} failed")
