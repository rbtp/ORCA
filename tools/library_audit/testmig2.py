"""Test migrations/repair_library_queries_2.sql on a throwaway postgres:15 loaded with schema + seed data:
round 1 then round 2 must give exactly the shipped library (manual/fixed2/library.json), a re-run changes
nothing, an analyst-edited row is kept, and the not-observable note is added once.
usage: python testmig2.py QUALITY_DIR REPO_DIR"""
import hashlib, json, os, subprocess, sys, time
QD, REPO = sys.argv[1], sys.argv[2]
CT = "orca-migtest2"
CR = chr(13)
ok = bad = 0


def check(name, cond, extra=""):
    global ok, bad
    ok += bool(cond); bad += (not cond)
    print(("PASS " if cond else "FAIL ") + name + (f"  [{str(extra)[:300]}]" if extra and not cond else ""), flush=True)


def psql(args, stdin=None):
    # bytes, not text: a Windows text-mode pipe turns every LF into CRLF inside the loaded SQL
    r = subprocess.run(["docker", "exec", "-i", CT, "psql", "-U", "postgres", "-d", "orca_db"] + args,
                       input=stdin.encode("utf-8") if stdin is not None else None, capture_output=True)
    r.stdout, r.stderr = r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace")
    return r


def run_file(path):
    r = psql(["-v", "ON_ERROR_STOP=1"], open(path, encoding="utf-8").read())
    ups = [l for l in r.stdout.splitlines() if l.startswith("UPDATE")]
    return r.returncode, r.stderr[-300:], sum(int(l.split()[1]) for l in ups)


md5 = lambda s: hashlib.md5((s or "").replace(CR, "").encode("utf-8")).hexdigest()
subprocess.run(["docker", "rm", "-f", CT], capture_output=True)
subprocess.run(["docker", "run", "-d", "--name", CT, "-e", "POSTGRES_PASSWORD=x", "-e", "POSTGRES_DB=orca_db", "postgres:15"], check=True, capture_output=True)
try:
    for _ in range(60):
        if psql(["-c", "select 1"]).returncode == 0: break
        time.sleep(1)
    r = psql([], open(os.path.join(REPO, "backend", "schema.sql"), encoding="utf-8").read())
    seed = os.path.join(REPO, "seed_data", "ref_artifact_library.sql")
    r = psql([], open(seed, encoding="utf-8").read())
    n = psql(["-tAc", "select count(*) from ref_artifact_library"]).stdout.strip()
    check("seed library loaded", n not in ("", "0"), n)
    # an analyst edit made after round 1, before round 2 (T1134.002 is hand-repaired in round 2)
    run_file(os.path.join(REPO, "migrations", "fix_broken_library_techniques.sql"))   # runs before these on every install
    rc, err, n1 = run_file(os.path.join(REPO, "migrations", "repair_library_queries.sql"))
    check("round 1 applies", rc == 0, err)
    psql(["-c", "update ref_artifact_library set custom_vql = 'SELECT 1 AS analyst_edit FROM scope()' where t_code = 'T1134.002'"])
    rc, err, n2 = run_file(os.path.join(REPO, "migrations", "repair_library_queries_2.sql"))
    check("round 2 applies", rc == 0, err)
    print(f"      rows updated: round 1 {n1}, round 2 {n2}")
    rc, err, n3 = run_file(os.path.join(REPO, "migrations", "repair_library_queries_2.sql"))
    check("round 2 re-run changes nothing", rc == 0 and n3 == 0, n3)
    want = {r["t"]: r for r in json.load(open(os.path.join(QD, "manual", "fixed2", "library.json"), encoding="utf-8"))}
    q = "select t_code||'|'||md5(replace(coalesce(surgical_yaml,''),chr(13),''))||'|'||md5(replace(coalesce(custom_vql,''),chr(13),'')) from ref_artifact_library"
    got = {l.split("|")[0]: l.split("|")[1:] for l in psql(["-tAc", q]).stdout.splitlines() if l}
    mism = [t for t, f in want.items() if t != "T1134.002" and got.get(t) != [md5(f["y"]), md5(f["v"])]]
    check(f"library equals the shipped library ({len(want)} techniques)", not mism, mism[:10])
    v = psql(["-tAc", "select custom_vql from ref_artifact_library where t_code='T1134.002'"]).stdout.strip()
    y = psql(["-tAc", "select md5(replace(coalesce(surgical_yaml,''),chr(13),'')) from ref_artifact_library where t_code='T1134.002'"]).stdout.strip()
    check("analyst-edited column kept, other column of that row still repaired", "analyst_edit" in v and y == md5(want["T1134.002"]["y"]), (v[:80], y))
    hand = json.load(open(os.path.join(QD, "manual", "changed.json"), encoding="utf-8"))
    no = hand["not_observable"]
    c = psql(["-tAc", "select count(*) from ref_artifact_library where analysis_steps like 'NOT OBSERVABLE ON THE HOST%' and t_code in (" + ",".join(f"'{t}'" for t in no) + ")"]).stdout.strip()
    d = psql(["-tAc", "select count(*) from ref_artifact_library where analysis_steps like '%NOT OBSERVABLE ON THE HOST%NOT OBSERVABLE ON THE HOST%'"]).stdout.strip()
    check(f"not-observable note on all {len(no)}, once", c == str(len(no)) and d == "0", (c, d))
finally:
    subprocess.run(["docker", "rm", "-f", CT], capture_output=True)
print(f"{ok} passed, {bad} failed")
