"""Adds the Atomic Red Team results to docs/LIBRARY_QUALITY.md (replaces the 'Next step: attack simulation'
section written by report.py) and per-technique columns to docs/library_scorecard.csv.
usage: python report_atomics.py QUALITY_DIR REPO ATOMIC_RUNS_JSONL ATOMIC_SCORES_JSON
(scores from `score_atomics.py score RUNS OUT original fixed fixed2`)"""
import csv, json, os, sys
QD, REPO, RUNS, SCORES = sys.argv[1:5]
runs = {}
for l in open(RUNS, encoding="utf-8-sig", errors="replace"):
    if l.strip():
        r = json.loads(l); runs[r["t"]] = r
sc = json.load(open(SCORES, encoding="utf-8"))
names = {r["t_code"]: r["attack_name"] for r in json.load(open(os.path.join(QD, "findings.json"), encoding="utf-8"))["rows"]}
VERS = [("original", "original library"), ("fixed", "automatic repair"), ("fixed2", "hand repair (shipped)")]


def by(v):
    return {k.split("|")[0]: r for k, r in sc.items() if k.endswith("|" + v) and "fires" in r}


S = {v: by(v) for v, _ in VERS}
both = sorted(set.intersection(*(set(S[v]) for v, _ in VERS)))
executed = [t for t, r in runs.items() if r.get("tests", 0) > 0]
ok_exit = [t for t in executed if any(x == "0" for x in (runs[t].get("exit_codes") or "").split(","))]
win = {v: {t for t in both if S[v][t]["in_window"] > 0} for v, _ in VERS}
fires = {v: {t for t in both if S[v][t]["fires"]} for v, _ in VERS}
fb = {v: sum(1 for t in both if S[v][t]["fallback"]) for v, _ in VERS}
gained = sorted(win["fixed2"] - win["original"])
lost = sorted(win["original"] - win["fixed2"])
missed = sorted(t for t in both if t not in win["fixed2"])
ps_lost = sorted(t for t in missed if S["fixed2"][t].get("ps_log_lost"))

L = []
w = L.append
w("## Attack simulation (Atomic Red Team)")
w("")
w("Ground truth: the Windows Atomic Red Team tests were run technique by technique on an isolated Windows 11 Enterprise VM "
  "(no network during the tests; Sysmon with the sysmon-modular config, full audit policy incl. command lines, PowerShell "
  "script-block logging), logging each technique's start and end time. Windows Defender stayed on (Tamper Protection can't be "
  "switched off unattended; only the test folders were excluded), so some tests were blocked part-way, as they would be on a "
  "protected target. Tests that wreck the lab (shutdown, disk wipe, encryption, account lock-out, service stop, DoS) were skipped. "
  f"The run covered {len(runs)} techniques in alphabetical order before the VM restarted itself; the remaining ones, mostly log "
  "clearing and defence evasion (deliberately ordered last so they couldn't wipe the earlier evidence), were not run.")
w("")
w("The VM's disk before and after the attacks was mounted on the analyst workstation and each technique's queries (original, "
  "after the automatic repair, after the hand repair) were run through the ORCA agent against both, exactly the disk-image "
  "path an analyst uses. A technique *detects* its test when its query returns a row on the attacked disk that isn't on the "
  "clean disk, timestamped inside that technique's own test window (start - 30 s to end + 2 min).")
w("")
w(f"- Techniques run: {len(runs)}; with at least one test executed: {len(executed)}; at least one test exited 0: {len(ok_exit)}")
w(f"- Scored (technique has a library query): {len(both)}")
w("")
w("| | " + " | ".join(lbl for _, lbl in VERS) + " |")
w("|---|" + "---:|" * len(VERS))
w("| **detects its own test** (new row inside the test window) | " + " | ".join(f"**{len(win[v])}**" for v, _ in VERS) + " |")
w("| returns new rows after the attacks (looser; another test's activity can trigger it) | " + " | ".join(str(len(fires[v])) for v, _ in VERS) + " |")
w("| only fallback rows (the agent's broad event dump, not a detection) | " + " | ".join(str(fb[v]) for v, _ in VERS) + " |")
w("")
w(f"**Detected only after the repairs ({len(gained)})**: " + ", ".join(gained))
w("")
if lost:
    w(f"**Detected before, not after ({len(lost)})** (check these): " + ", ".join(lost))
    w("")
w(f"**Not detected ({len(missed)})**: the test ran but no query row falls in its window. Common reasons: Defender blocked the test, "
  "a prerequisite needed the internet, the test only works on a domain/server, or the query looks for a different variant of "
  "the technique than the Atomic test performs. "
  f"{len(ps_lost)} of them ran before 00:17 UTC, the earliest event the VM's PowerShell logs still held (the 1 GB "
  "PowerShell logs filled up during the run), so PowerShell-based detection can't show for those. Per technique: "
  "`library_scorecard.csv` (`atomic_*` columns).")
w("")
w(", ".join(f"{t}{'*' if t in ps_lost else ''}" for t in missed))
w("")
w("(* = test ran before the PowerShell logs' earliest event)")
w("")
w("How the disks were read: the two disks are clones (same disk signature), so they were mounted with a fake signature and a "
  "throwaway write overlay (`tools/library_audit/mount_overlay.ps1`; the .vmdk files are never written). To keep 400+ "
  "collections practical, the big event logs on the overlays were cut to the attack window (attacked disk: 23:18-02:00 UTC; "
  "clean disk: emptied, so any log row on the attacked disk in the window counts as new). File, registry and other "
  "non-log evidence is compared between the two full disks.")
w("")

md = os.path.join(REPO, "docs", "LIBRARY_QUALITY.md")
s = open(md, encoding="utf-8").read()
start = s.index("## Next step: attack simulation") if "## Next step: attack simulation" in s else s.index("## Attack simulation (Atomic Red Team)")
end = s.index("## Rules for writing library queries")
s = s[:start] + "\n".join(L) + "\n" + s[end:]
open(md, "w", encoding="utf-8", newline="\n").write(s)

cp = os.path.join(REPO, "docs", "library_scorecard.csv")
rows = list(csv.DictReader(open(cp, encoding="utf-8")))
for r in rows:
    t = r["t_code"]
    r["atomic_tests_run"] = runs.get(t, {}).get("tests", "")
    for v, _ in VERS:
        r[f"atomic_detects_{v}"] = (S[v][t]["in_window"] > 0) if t in S[v] else ""
    r["atomic_new_rows_shipped"] = S["fixed2"][t]["new_rows"] if t in S["fixed2"] else ""
with open(cp, "w", newline="", encoding="utf-8") as fh:
    wr = csv.DictWriter(fh, fieldnames=list(rows[0].keys())); wr.writeheader(); wr.writerows(rows)
print(f"executed {len(executed)}, scored {len(both)}; detects " + ", ".join(f"{v} {len(win[v])}" for v, _ in VERS)
      + f"; gained {len(gained)}, lost {len(lost)} {lost}, not detected {len(missed)} (ps log lost {len(ps_lost)})")
