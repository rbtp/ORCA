"""Builds docs/LIBRARY_QUALITY.md + docs/library_scorecard.csv from the audit data.
usage: python report.py QUALITY_DIR REPO_DIR"""
import collections, csv, json, os, re, sys
QD, REPO = sys.argv[1], sys.argv[2]
FD = os.path.join(QD, "fixed")
J = lambda *p: json.load(open(os.path.join(*p), encoding="utf-8")) if os.path.exists(os.path.join(*p)) else None
before = {r["t_code"]: r for r in J(QD, "findings.json")["rows"]}
after = {r["t_code"]: r for r in (J(FD, "findings.json") or {"rows": []})["rows"]}
run_b = J(QD, "run_results.json") or {}
run_a = J(FD, "run_results.json") or {}
fixes = J(QD, "fixed_library.json") or {}
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from holdback import held_back
HB = held_back(QD)
fixes = {t: f for t, f in fixes.items() if t not in HB}   # held-back repairs don't ship
WIN = [t for t, r in before.items() if r["platform"] == "windows"]

def sev_counts(rows):
    c = collections.Counter(r["severity"] for r in rows)
    return {k: c.get(k, 0) for k in ("broken", "blind", "partly_blind", "partial", "noisy", "output", "info", "ok")}
def code_counts(rows):
    c = collections.Counter()
    for r in rows:
        for code in set(r["issue_codes"].split()): c[code] += 1
    return c
def run_summary(run, techs):
    srcs = {k: v for k, v in run.items() if k.split("|")[0] in techs}
    tech_rows = collections.defaultdict(int)
    for k, v in srcs.items(): tech_rows[k.split("|")[0]] += v.get("rows", 0)
    return {"sources": len(srcs), "sources_with_rows": sum(1 for v in srcs.values() if v.get("rows", 0) > 0),
            "techniques_with_rows": sum(1 for t in techs if tech_rows.get(t, 0) > 0),
            "capped": sum(1 for v in srcs.values() if v.get("capped")),
            "errors": sum(1 for v in srcs.values() if v.get("errors")),
            "timeouts": sum(1 for v in srcs.values() if v.get("timeout"))}

b_rows = [before[t] for t in WIN]
a_rows = [after[t] for t in WIN if t in after]
sb, sa = sev_counts(b_rows), sev_counts(a_rows)
cb, ca = code_counts(b_rows), code_counts(a_rows)
rb, ra = run_summary(run_b, set(WIN)), run_summary(run_a, set(WIN))
al_b = collections.Counter(r["alignment"] for r in b_rows)
al_a = collections.Counter(r["alignment"] for r in a_rows)
al_int = collections.Counter(r["alignment_if_logs_fixed"] for r in b_rows)
manual = [(t, c) for t, f in fixes.items() for c in f["changes"] if "MANUAL" in c]
changed = [t for t, f in fixes.items() if any("MANUAL" not in c for c in f["changes"])]

CODE_TEXT = {
    "WRONG_LOG_FOR_EVENT": ("Looks for an event in a log where it never occurs",
        "e.g. Sysmon event 1 (process creation) or PowerShell 4104 searched for in Security.evtx. Event numbers are per log: Security event 1 doesn't exist."),
    "EVENTID_WITHOUT_VALUE": ("Compares `System.EventID` to a number",
        "`System.EventID` is a structure `{Value: N}`; `System.EventID = 4688` is always false. It must be `System.EventID.Value`."),
    "UNDEFINED_IN_FILTER": ("Filters on a name that doesn't exist in the row",
        "e.g. `WHERE CommandLine =~ ...` instead of `EventData.CommandLine`, or a field renamed in SELECT then filtered by its old name. The name is empty, so the condition is never true."),
    "REGEX_NEVER_MATCHES": ("Regular expression mangled by VQL string escaping",
        "In VQL quoted strings a backslash escapes the next character: `'.*\\\\CurrentVersion\\\\Run'` reaches the regex engine as `.*\\CurrentVersion\\Run` (`\\C`, `\\R` are not a backslash) and never matches a registry path; `'\\s+'` becomes `s+`. Checked by running every regex in Velociraptor against a string it was meant to match."),
    "FIELD_NOT_IN_EVENT": ("Uses a field the event doesn't have",
        "e.g. `EventData.ProcessName` / `EventData.Image` on Security 4688 (the field is `NewProcessName`), `TargetProcessName` on Sysmon 10 (it's `TargetImage`)."),
    "TYPE_MISMATCH": ("Compares a number to text",
        "VQL never treats `3` and `'3'` as equal. `GrantedAccess`, `LogonType`, `DestinationPort`, event IDs are numbers; `GrantedAccess IN ('0x1410')` is always false."),
    "FIELD_WRONG_CASE": ("Field name in the wrong case", "Field names are case-sensitive; `EventData.targetimage` is always empty."),
    "REGEX_UNSUPPORTED": ("Regex uses lookahead/lookbehind", "Velociraptor's regex engine (Go RE2) doesn't support `(?=`, `(?!`, `(?<=`: the pattern never matches."),
    "BLANK_COLUMN": ("Output column that is always blank",
        "`SELECT EventTime, Computer, ...` on raw events: those aren't fields of an event row (they're `System.TimeCreated.SystemTime`, `System.Computer`), so every result row had no time and no computer name."),
    "EVENT_ID_ONLY": ("Returns every event of a type, with no content filter", "e.g. every 4688 process creation. Not an indicator; analysts must sift everything."),
    "NO_EVENT_ID_FILTER": ("Reads a whole log with no event-type filter", "Slow and noisy."),
    "VERIFY_ERROR": ("Velociraptor refuses to load the artifact", "Invalid artifact name (a part starting with a digit), YAML syntax errors, `ORDER BY a, b` (VQL allows one column), unknown functions."),
    "LITERAL_BACKSLASH_LOST": ("Path text loses its backslashes", "`'C:\\Windows'` is `C:Windows` to VQL."),
    "CASE_SENSITIVE_PATH": ("Exact, case-sensitive path comparison", "`=` is case-sensitive; Windows paths vary in case. `=~` is case-insensitive."),
    "LIVE_ONLY_PLUGIN": ("Needs a running computer", "process list / network connections etc.: not applicable to a disk image."),
    "SERVER_ONLY_SOURCE": ("Reads results stored on a Velociraptor server", "Nothing to read in a standalone collection."),
}
SEV_TEXT = {"broken": "won't run at all", "blind": "every query part has a defect that stops it matching",
            "partly_blind": "some query parts have such a defect", "partial": "minor defect in a filter",
            "noisy": "runs, but returns events with no real filter", "output": "works, but some output columns are blank",
            "info": "notes only", "ok": "no defect found"}

L = []
w = L.append
w("# Artifact library quality audit")
w("")
w("Audit of the detection queries in ORCA's artifact library (`ref_artifact_library`: `surgical_yaml` and `custom_vql`), "
  "for Windows targets, against what Velociraptor 0.77 actually does and against MITRE ATT&CK v19.2's detection analytics. "
  "Generated by the audit scripts; numbers are per technique unless stated.")
w("")
w("## How it was tested")
w("")
w("1. **Velociraptor's behaviour was measured, not assumed**: string escaping, regex engine, number/text comparison, case rules, "
  "the shape of parsed event rows (see *Rules for writing library queries* below). Every check is based on those measurements.")
w("2. **Real event schemas**: the field names and value types of every event were read from this machine's logs (Sysmon, Security, "
  "PowerShell, System, ...) and from the Windows event provider manifests (Security-Auditing: 421 events, Sysmon: 30, ...).")
w("3. **Static analysis of every query** (exactly what the agent runs, after its own rewrites): which log and event IDs it reads, "
  "whether those events exist in that log, whether every field exists in those events, every regex run through Velociraptor "
  "against a string it was meant to match, number/text comparisons, and Velociraptor's own `artifacts verify`.")
w("4. **Alignment with ATT&CK**: each technique's event sources compared with the log sources and event codes of ATT&CK v19.2's "
  "Windows detection analytics for that technique.")
w("5. **Live run**: every query part run on a Windows 10 workstation with Sysmon (Security log: last 24 h; Sysmon: 67 MB), "
  "counting rows, errors and queries that return thousands of rows on a normal machine.")
w("")
w("Note: Windows Defender on the workstation blocks a velociraptor *command line* that contains indicator strings "
  "(`invoke-mimikatz`, `lsadump::secrets`, ...). The ORCA agent is not affected: it passes each query in a file (`query -f`).")
w("")
w(f"Scope: {len(WIN)} Windows techniques. {sum(1 for r in before.values() if r['platform'] != 'windows')} library queries for Linux/macOS "
  "were left out (a Windows agent can't run them).")
w("")
w("## Results")
w("")
w("| | before | after automatic repair |")
w("|---|---:|---:|")
for k in ("broken", "blind", "partly_blind", "partial", "noisy", "output", "ok"):
    w(f"| {k.replace('_', ' ')} ({SEV_TEXT[k]}) | {sb[k]} | {sa[k] if a_rows else '-'} |")
if rb["sources"]:
    w(f"| query parts run on a live workstation | {rb['sources']} | {ra['sources'] or '-'} |")
    w(f"| ... returning rows | {rb['sources_with_rows']} | {ra['sources_with_rows'] or '-'} |")
    w(f"| techniques returning anything | {rb['techniques_with_rows']} | {ra['techniques_with_rows'] or '-'} |")
    w(f"| ... runtime errors | {rb['errors']} | {ra['errors'] or '-'} |")
w("")
w("A *blind* query is not a weak query: whatever happened on the computer, it cannot return a row. "
  "A workstation with no attack activity returns few rows either way; the live run mainly proves queries run and shows noise. "
  "Whether each query catches the technique needs attack simulation (next step below).")
w("")
w("### Defects found (techniques affected)")
w("")
w("| defect | before | after | what it means |")
w("|---|---:|---:|---|")
for code, n in cb.most_common():
    if code in ("HAS_PARAMETERS", "REGEX_CHANGED"): continue
    t, d = CODE_TEXT.get(code, (code, ""))
    w(f"| {t} | {n} | {ca.get(code, 0) if a_rows else '-'} | {d} |")
w("")
w("### Alignment with MITRE ATT&CK (v19.2 detection analytics)")
w("")
w("| | as written | if the wrong-log errors are fixed | after repair |")
w("|---|---:|---:|---:|")
for k in ("ALIGNED", "ALIGNED_NON_LOG", "SAME_LOG_OTHER_EVENTS", "MISALIGNED", "NOT_A_WINDOWS_TECHNIQUE", "ATTACK_NEEDS_NON_HOST_TELEMETRY", "ORCA_COLLECTION_ITEM"):
    w(f"| {k.replace('_', ' ').lower()} | {al_b.get(k, 0)} | {al_int.get(k, 0)} | {al_a.get(k, 0) if a_rows else '-'} |")
w("")
w("*Aligned*: the query reads at least one event ATT&CK's analytics use for that technique (same log, same event code). "
  "*Not a Windows technique*: ATT&CK lists the technique only for cloud/SaaS/network platforms (e.g. cloud accounts); "
  "ORCA's queries for those are host-side approximations. *ORCA collection item*: raw collections (AMCACHE, browser history, ...), not techniques. "
  "Most mismatches came from the wrong-log defect: the queries *meant* the right events.")
w("")
vb = json.load(open(os.path.join(QD, "verify_cache.json"), encoding="utf-8"))
y_fail = sum(1 for t in WIN if before[t]["runs"] == "vql" and before[t].get("other_part_severity") == "broken")
w("### Artifacts that never loaded")
w("")
w(f"{sum(1 for m in vb.values() if m)} of {len(vb)} YAML artifacts / VQL queries are rejected by Velociraptor's own `artifacts verify` "
  "(mostly artifact names with a part starting with a digit, e.g. `...T1003.001`, and YAML syntax errors). When the YAML fails, "
  f"the agent silently runs the technique's shorter VQL instead: for {y_fail} Windows techniques the multi-source YAML had never run. "
  "Earlier health checks (\"0 failures\") couldn't see this because the fallback hid it.")
w("")
noisy = sorted(((v.get("rows", 0), k) for k, v in run_a.items() if v.get("capped")), reverse=True)
if noisy:
    w("### Noisy on a normal workstation")
    w("")
    w(f"{len(noisy)} query parts returned 5000+ rows (the cap) on a workstation with no attack activity. "
      "They read the right events but have no real filter, so an analyst gets every event of that type:")
    w("")
    for n, k in noisy[:30]:
        t, _, src = k.partition("|")
        w(f"- {t} ({before.get(t, {}).get('attack_name', '')}) - {src}")
    w("")
w("## What the automatic repair changed")
w("")
w(f"{len(changed)} techniques changed. Every change is one of the defects above with an unambiguous fix; each technique's list of changes is in "
  "`library_scorecard.csv` and in the migration. Individual edits, by kind (a technique usually has several):")
w("")
kinds = collections.Counter()
for t, f in fixes.items():
    for c in f["changes"]:
        if "MANUAL" in c: continue
        c2 = c.split(": ", 1)[-1]; c2 = re.sub(r"^\[[^\]]*\] ", "", c2)
        for pat, label in [(r"^regex", "regex rewritten so Velociraptor sees the pattern the author wrote (raw '''...''' string)"),
                           (r"read from .* where they never occur", "event read from the log it actually occurs in"),
                           (r"^System\.EventID ->", "`System.EventID` -> `System.EventID.Value`"),
                           (r"^SELECT .* \(always blank\)", "blank output column -> the real field (time, computer, event ID, EventData.X)"),
                           (r"^WHERE .*not a column", "filter on an undefined name -> the real field (EventData.X, System.Channel, ...)"),
                           (r"^FullPath", "`FullPath` (removed in Velociraptor 0.7) -> `OSPath` on file/registry rows"),
                           (r"^EventData\.\w+ \(not a field", "field that doesn't exist in the event -> the event's real field"),
                           (r"text .* -> numbers|-> \d|-> 0x", "text compared to a number field -> number"),
                           (r"regex now runs on its hex form", "regex on a numeric access mask -> run on its hex form"),
                           (r"time window relative to now", "time window relative to now() removed (see below)"),
                           (r"artifact name", "invalid artifact name fixed (the YAML never loaded)"),
                           (r"ORDER BY", "`ORDER BY a, b` (parse error) -> one column"),
                           (r"single backslashes", "path text backslashes doubled")]:
            if re.search(pat, c2): kinds[label] += 1; break
        else:
            kinds["other"] += 1
for k, n in kinds.most_common(): w(f"- {k}: {n}")
w("")
tw_n = sum(1 for f in fixes.values() for c in f["changes"] if "time window relative to now" in c)
tw_t = sum(1 for f in fixes.values() if any("time window relative to now" in c for c in f["changes"]))
w(f"**Time windows**: {tw_n} filters in {tw_t} techniques only looked at events from the last N days *before the collection ran* (`EventTime > now() - 604800`). "
  "The name they used was undefined, so they returned nothing at all; and for a disk image examined after the fact a window relative to "
  "*now* is wrong anyway. They were removed: the query covers the whole log. Some of these techniques now return every event "
  "of their type (they show as *noisy*): they were silent before, so they still need a real content filter.")
w("")
w("The repair is applied by a migration that only replaces a row whose text is still exactly the shipped version, so a query an analyst "
  "edited in the Artifact Library Editor is left alone.")
w("")
if HB:
    w("### Repairs held back: too broad once they run")
    w("")
    w(f"For {len(HB)} techniques the repaired query works, but returns thousands of rows on a normal workstation with no attack "
      "activity (2000+ from one query part, Security log limited to 24 h): the detection logic itself is too loose (e.g. *any* process "
      "opening lsass, every file under a user profile). Shipping those would mark every host *Evidence Found*, so they keep their "
      "previous text and need a real content filter first:")
    w("")
    for t, d in sorted(HB.items(), key=lambda x: -x[1]["rows_after"]):
        w(f"- {t} ({before.get(t, {}).get('attack_name', '')}): {d['rows_before']} -> {d['rows_after']}{'+' if d['rows_after'] >= 5000 else ''} rows")
    w("")
w("## Still needs a person")
w("")
def mcat(c):
    c = c.split("MANUAL: ")[1]
    if c.startswith("event IDs"): return "one query reads event IDs that belong to different logs (needs splitting into one query per log)"
    if "compile" in c: return "regular expression that is invalid in every reading (needs rewriting)"
    if c.startswith("YAML"): return "YAML syntax error: the artifact never loaded and the shorter VQL runs instead"
    if "lookaround" in c: return "regex lookahead/lookbehind (unsupported by Velociraptor)"
    return c[:80]
mk = collections.Counter(mcat(c) for _, c in manual)
w(f"{len(manual)} items in {len({t for t, _ in manual})} techniques the repair didn't touch, because the right fix needs judgement:")
w("")
for k, n in mk.most_common(): w(f"- {n} x {k}")
w("")
w("Plus the defects left in the *after* column above, and detection *logic* (a query that runs but is too broad or too narrow), "
  "which only attack simulation can measure.")
w("")
w("## Next step: attack simulation")
w("")
w("Run Atomic Red Team tests for each technique on an isolated Windows VM (Sysmon + full audit policy, Defender off on that VM only), "
  "collect with ORCA, and check each technique's query returns the rows the test produced. That turns *runs correctly* into *detects the technique*.")
w("")
w("## Rules for writing library queries (Velociraptor 0.77, verified)")
w("")
w("- **Backslashes in strings**: in `'...'` and `\"...\"`, `\\\\` becomes one backslash, `\\n \\t \\' \\\"` are escapes, and any other backslash is "
  "**dropped** (`'C:\\Users'` is `C:Users`, `'\\d'` is `d`). For regexes use triple quotes, which keep text as written: "
  "`=~ '''.*\\\\CurrentVersion\\\\Run'''` (regex `\\\\` = one literal backslash).")
w("- **Event rows** from `parse_evtx()` have only `System`, `EventData` (or `UserData`) and `Message`. Use `System.EventID.Value` "
  "(not `System.EventID`), `System.TimeCreated.SystemTime`, `System.Computer`, `System.Channel`, `EventData.<Field>`. "
  "Bare `EventTime`, `Computer`, `CommandLine` are empty.")
w("- **Event numbers are per log**: Sysmon 1 is in `Microsoft-Windows-Sysmon%4Operational.evtx`, not `Security.evtx`.")
w("- **Field names** are case-sensitive and differ per event (Security 4688: `NewProcessName`, `ParentProcessName`, `CommandLine`; "
  "Sysmon 1: `Image`, `ParentImage`, `CommandLine`; Sysmon 10: `SourceImage`, `TargetImage`, `GrantedAccess`, `SourceProcessGUID`).")
w("- **Numbers vs text**: `=` and `IN` never convert. `GrantedAccess` (2097151 = 0x1FFFFF), `LogonType`, `DestinationPort`, event IDs are numbers: "
  "`GrantedAccess IN (0x1410, 0x1010)`, not `('0x1410')`.")
w("- `=~` is case-insensitive; `=` and `IN` are case-sensitive. Regex engine is Go RE2: no lookahead/lookbehind.")
w("- A SELECT alias can be used in WHERE; the original name after renaming can't.")
w("- `ORDER BY` takes one column. Artifact names: dot-separated parts that don't start with a digit.")
w("- Check a new query with `velociraptor artifacts verify <file.yaml>` (one file at a time).")
w("")
open(os.path.join(REPO, "docs", "LIBRARY_QUALITY.md"), "w", encoding="utf-8", newline="\n").write("\n".join(L))

with open(os.path.join(REPO, "docs", "library_scorecard.csv"), "w", newline="", encoding="utf-8") as f:
    cols = ["t_code", "attack_name", "tactics", "severity_before", "severity_after", "blind_sources_before",
            "alignment_before", "alignment_after", "attack_events", "logs_after", "events_after",
            "rows_on_workstation_before", "rows_on_workstation_after", "changes", "manual", "remaining_issues"]
    wr = csv.DictWriter(f, fieldnames=cols); wr.writeheader()
    for t in sorted(WIN):
        b, a = before[t], after.get(t, {})
        rows_b = sum(v.get("rows", 0) for k, v in run_b.items() if k.split("|")[0] == t)
        rows_a = sum(v.get("rows", 0) for k, v in run_a.items() if k.split("|")[0] == t)
        ch = (fixes.get(t) or (J(QD, "fixed_library.json") or {}).get(t, {})).get("changes", [])
        wr.writerow({"t_code": t, "attack_name": b["attack_name"], "tactics": b["tactics"],
                     "severity_before": b["severity"], "severity_after": a.get("severity", ""),
                     "blind_sources_before": b.get("blind_sources", ""),
                     "alignment_before": b["alignment"], "alignment_after": a.get("alignment", ""),
                     "attack_events": b["attack_events"], "logs_after": a.get("logs", ""), "events_after": a.get("events", ""),
                     "rows_on_workstation_before": rows_b if run_b else "", "rows_on_workstation_after": rows_a if run_a else "",
                     "changes": ("HELD BACK (repaired query too broad); proposed: " if t in HB else "") + " | ".join(c for c in ch if "MANUAL" not in c)[:4000],
                     "manual": " | ".join(c for c in ch if "MANUAL" in c)[:1000],
                     "remaining_issues": a.get("issues", "")[:2000]})
print("report written; windows techniques:", len(WIN), "before:", sb, "after:", sa)
