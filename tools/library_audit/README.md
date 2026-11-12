# Artifact library audit tools

Re-runnable audit of the detection queries in `ref_artifact_library` (see `docs/LIBRARY_QUALITY.md` for the
results and the Velociraptor rules the checks are based on). Windows host with Python 3.9+, PyYAML, Docker
(for the ORCA database) and a `velociraptor.exe` (0.77; the agent's `bin\velociraptor.exe` works).

All scripts take a work folder (`WORK`) for their data; nothing is written to the repo except by
`report.py` (docs) and `mkmigration.py` (migration).

| step | command | output |
|---|---|---|
| 1. event schemas from this machine's logs (admin; Sysmon installed) | `python schemas.py VR.exe WORK\schemas.json` | real field names + value types per log/event ID |
| 2. event schemas from Windows provider manifests | `powershell -File manifests.ps1 -Out WORK\manifests.json` | field names for events that never happened here |
| 3. export the library | `docker exec orca-postgres psql -U postgres -d orca_db -tAc "select json_agg(json_build_object('t',t_code,'name',name,'os',os,'priority',priority,'v',coalesce(custom_vql,''),'y',coalesce(surgical_yaml,'')) order by t_code) from ref_artifact_library" > WORK\library.json` | |
| 4. static analysis | `python analyze.py WORK REPO VR.exe` | `WORK\findings.json`, `WORK\scorecard.csv` (per technique: severity, ATT&CK alignment, issues) |
| 5. run every Windows query part on this machine | `python runall.py WORK REPO VR.exe 8` (needs `WORK\logs\Security.evtx`, e.g. `wevtutil epl Security WORK\logs\Security.evtx "/q:*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]"`) | `WORK\run_results.json` (resumable) |
| 6. static flags vs live rows | `python compare.py WORK` | |
| 7. automatic repair | `python fixlib.py WORK REPO VR.exe` | `WORK\fixed_library.json` (new text + change list per technique) |
| 8. re-check the repaired library | `python mkfixed.py WORK`, then steps 4-6 with `WORK\fixed` | |
| 9. report | `python report.py WORK REPO` | `docs/LIBRARY_QUALITY.md`, `docs/library_scorecard.csv` |
| 10. migration | `python mkmigration.py WORK REPO`, test with `python testmig.py WORK REPO <postgres container with the library loaded>` | `migrations/<name>.sql` (md5-guarded per column) |

`unit_intent.py` tests the regex-intent logic (how a regex written in a VQL string was meant to read).

Notes:
- Queries are run from files (`velociraptor query -f`): Windows Defender blocks a velociraptor command line
  that contains indicator strings such as `invoke-mimikatz`.
- `artifacts verify` stops at the first failing file and prints `[ERROR]` lines on stdout: `analyze.py` verifies
  one file at a time (results cached in `WORK\verify_cache.json`).
- A migration generated from a later audit must have a new file name (migrations run once each).
