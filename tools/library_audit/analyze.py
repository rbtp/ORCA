"""Static quality audit of the ORCA artifact library against Velociraptor 0.77
import warnings; warnings.filterwarnings("ignore")
semantics (verified empirically on this host) and MITRE ATT&CK v19 analytics.

usage: python analyze.py QUALITY_DIR REPO_DIR VELOCIRAPTOR_EXE
reads  QUALITY_DIR/library.json, schemas.json, manifests.json
writes QUALITY_DIR/findings.json, scorecard.csv
"""
import collections, csv, importlib.util, json, os, re, sre_constants, subprocess, sys, tempfile
try:
    import sre_parse
except ImportError:  # py3.11+
    import re._parser as sre_parse

QD, REPO, VR = sys.argv[1], sys.argv[2], sys.argv[3]
J = lambda f: json.load(open(os.path.join(QD, f), encoding="utf-8-sig"))
LIB, OBS, MAN = J("library.json"), J("schemas.json"), J("manifests.json")
ATTACK = json.load(open(os.path.join(REPO, "backend", "data", "mitre-attack.json"), encoding="utf-8"))

spec = importlib.util.spec_from_file_location("orca_agent", os.path.join(REPO, "agent", "orca_agent.py"))
agent = importlib.util.module_from_spec(spec); spec.loader.exec_module(agent)
Agent = agent.OrcaAgent
CONVERT = Agent._convert_source_to_parse_evtx          # what the agent does to every query before running it
LIVE_ONLY = set(Agent._LIVE_ONLY_PLUGINS)

# ── event schemas: channel -> id -> {fields, types} (real events first, manifests second) ──────────
OBS_CHANNEL = {
    "Sysmon": "Microsoft-Windows-Sysmon/Operational", "Security": "Security",
    "PowerShellOperational": "Microsoft-Windows-PowerShell/Operational", "WindowsPowerShell": "Windows PowerShell",
    "System": "System", "Application": "Application", "TaskScheduler": "Microsoft-Windows-TaskScheduler/Operational",
    "WMIActivity": "Microsoft-Windows-WMI-Activity/Operational", "Defender": "Microsoft-Windows-Windows Defender/Operational",
    "RDPCoreTS": "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
    "TSLocalSession": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "BITS": "Microsoft-Windows-Bits-Client/Operational", "CodeIntegrity": "Microsoft-Windows-CodeIntegrity/Operational",
    "Firewall": "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
}
SCHEMA = collections.defaultdict(lambda: collections.defaultdict(lambda: {"fields": set(), "types": {}, "observed": False}))
for short, ids in OBS.items():
    ch = OBS_CHANNEL[short]
    for i, d in ids.items():
        e = SCHEMA[ch.lower()][int(i)]
        e["fields"].update(d["eventdata"]); e["observed"] = True
        for f, t in d.get("types", {}).items():
            e["types"][f] = set(t)
for prov, ids in MAN.items():
    for i, d in (ids or {}).items():
        for ch in (d.get("logs") or []):
            e = SCHEMA[ch.lower()][int(i)]
            if not e["observed"]:              # manifests are sometimes wrong (Sysmon 10 GUID case); real data wins
                e["fields"].update(d.get("fields") or [])
# "System" log has events from hundreds of providers: only a partial schema, so don't call unknown IDs wrong there.
COMPLETE_CHANNELS = {"security", "microsoft-windows-sysmon/operational", "microsoft-windows-powershell/operational",
                     "microsoft-windows-taskscheduler/operational", "microsoft-windows-wmi-activity/operational",
                     "microsoft-windows-windows defender/operational", "microsoft-windows-bits-client/operational",
                     "microsoft-windows-terminalservices-localsessionmanager/operational",
                     "microsoft-windows-terminalservices-remoteconnectionmanager/operational",
                     "microsoft-windows-codeintegrity/operational", "microsoft-windows-applocker/exe and dll"}
SYSMON = "microsoft-windows-sysmon/operational"

PSOP = "microsoft-windows-powershell/operational"
def intended_log(log, eid):
    """(log, id) as the author evidently meant it: an ID that can't occur in the log it was looked for in
    is re-assigned to the log where that number means what the query's fields expect."""
    sch = SCHEMA.get(log)
    if sch is not None and eid in sch or log not in COMPLETE_CHANNELS:
        return log
    if eid < 30 and eid in SCHEMA.get(SYSMON, {}):
        return SYSMON
    for lg in (PSOP, "windows powershell", "microsoft-windows-taskscheduler/operational",
               "microsoft-windows-windows defender/operational", "microsoft-windows-wmi-activity/operational",
               "microsoft-windows-bits-client/operational", "security", "system",
               "microsoft-windows-terminalservices-remoteconnectionmanager/operational",
               "microsoft-windows-terminalservices-localsessionmanager/operational",
               "microsoft-windows-dns-client/operational", "microsoft-windows-codeintegrity/operational"):
        if eid in SCHEMA.get(lg, {}) and lg != log:
            return lg
    return log

def channel_of(filename):
    base = filename.replace("\\", "/").split("/")[-1]
    if base.lower().endswith(".evtx"):
        base = base[:-5]
    return base.replace("%4", "/")

# ── VQL tokenizer + string semantics (verified: '\\'->'\', \n \t \r \' \" escapes, other \X -> X; '''raw''') ──
def vql_unescape(body):
    out, i = [], 0
    while i < len(body):
        c = body[i]
        if c == "\\" and i + 1 < len(body):
            n = body[i + 1]
            out.append({"n": "\n", "t": "\t", "r": "\r"}.get(n, n)); i += 2
        else:
            out.append(c); i += 1
    return "".join(out)

TOK = re.compile(r"""
  (?P<comment>--[^\n]*|//[^\n]*|/\*.*?\*/)
 |(?P<triple>'''.*?''')
 |(?P<sq>'(?:\\.|[^'\\])*')
 |(?P<dq>"(?:\\.|[^"\\])*")
 |(?P<num>0x[0-9a-fA-F]+|\d+(?:\.\d+)?)
 |(?P<ident>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)
 |(?P<op>=~|!=|<=|>=|=>|=|<|>|\+|-|\*|/|\|\||&&)
 |(?P<punct>[(){}\[\],.:])
 |(?P<ws>\s+)
""", re.S | re.X)

class T:
    __slots__ = ("k", "v", "raw", "kind", "pos", "end")
    def __init__(s, k, v, raw=None, kind=None, pos=0, end=0): s.k, s.v, s.raw, s.kind, s.pos, s.end = k, v, raw, kind, pos, end
    def __repr__(s): return f"{s.k}:{s.v!r}"

def tokenize(q):
    toks, pos = [], 0
    while pos < len(q):
        m = TOK.match(q, pos)
        if not m:
            toks.append(T("other", q[pos])); pos += 1; continue
        start = pos; pos = m.end(); k = m.lastgroup; s = m.group()
        if k in ("ws", "comment"):
            continue
        if k == "triple":
            toks.append(T("str", s[3:-3], s[3:-3], "triple", start, pos))
        elif k in ("sq", "dq"):
            toks.append(T("str", vql_unescape(s[1:-1]), s[1:-1], k, start, pos))
        elif k == "num":
            toks.append(T("num", int(s, 16) if s.lower().startswith("0x") else float(s) if "." in s else int(s), s, None, start, pos))
        else:
            toks.append(T(k, s, s, None, start, pos))
    return toks

KW = {"select", "from", "where", "and", "or", "not", "in", "as", "limit", "order", "by", "group", "desc", "asc",
      "let", "true", "false", "null", "explain", "if"}

def split_statements(toks):
    """Top-level statements: split at LET / SELECT at bracket depth 0 (a LET's SELECT stays with it)."""
    stmts, cur, depth = [], [], 0
    for i, t in enumerate(toks):
        if t.k == "punct" and t.v in "({[": depth += 1
        if t.k == "punct" and t.v in ")}]": depth -= 1
        lv = t.v.lower() if t.k == "ident" else None
        if depth == 0 and lv in ("let", "select") and cur:
            prev_is_let = any(x.k == "ident" and x.v.lower() == "let" for x in cur[:1])
            # "LET x = SELECT ..." -> the SELECT belongs to the LET
            if lv == "select" and prev_is_let and not any(x.k == "ident" and x.v.lower() == "select" for x in cur):
                cur.append(t); continue
            stmts.append(cur); cur = []
        cur.append(t)
    if cur: stmts.append(cur)
    return stmts

def clauses(stmt):
    """Indices of top-level SELECT/FROM/WHERE/GROUP/ORDER/LIMIT in a statement (depth 0 relative to its SELECT)."""
    out, depth = {}, 0
    for i, t in enumerate(stmt):
        if t.k == "punct" and t.v in "({[": depth += 1
        if t.k == "punct" and t.v in ")}]": depth -= 1
        if depth == 0 and t.k == "ident" and t.v.lower() in ("select", "from", "where", "group", "order", "limit") \
                and t.v.lower() not in out:
            out[t.v.lower()] = i
    return out

def section(stmt, cl, name, ends=("from", "where", "group", "order", "limit")):
    if name not in cl: return []
    s = cl[name] + 1
    e = min([cl[x] for x in ends if x in cl and cl[x] > cl[name]] + [len(stmt)])
    return stmt[s:e]

EID_NAMES = {"system.eventid.value", "system.eventid", "eventid", "eventdata.eventid"}

# ── regex: sample string from the author's intended regex, to test what VQL really does with it ─────
def sample_from_regex(pattern):
    try:
        tree = sre_parse.parse(pattern, re.I)
    except Exception:
        return None
    def gen(items):
        out = []
        for op, av in items:
            name = str(op).split(".")[-1].upper()
            if name == "LITERAL": out.append(chr(av))
            elif name == "NOT_LITERAL": out.append("a" if av != ord("a") else "b")
            elif name == "ANY": out.append("x")
            elif name == "IN":
                ch = None
                for o2, a2 in av:
                    n2 = str(o2).split(".")[-1].upper()
                    if n2 == "LITERAL": ch = chr(a2); break
                    if n2 == "RANGE": ch = chr(a2[0]); break
                    if n2 == "CATEGORY":
                        ch = {"CATEGORY_DIGIT": "1", "CATEGORY_WORD": "a", "CATEGORY_SPACE": " ",
                              "CATEGORY_NOT_DIGIT": "a", "CATEGORY_NOT_WORD": "-", "CATEGORY_NOT_SPACE": "a"}.get(str(a2).split(".")[-1].upper(), "a"); break
                    if n2 == "NEGATE": ch = None
                out.append(ch or "a")
            elif name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
                lo, hi, sub = av
                out.append(gen(sub) * max(lo, 0 if lo == 0 else lo))
                if lo == 0 and sub and str(sub[0][0]).split(".")[-1].upper() == "LITERAL":
                    pass
            elif name == "SUBPATTERN":
                out.append(gen(av[-1]))
            elif name == "BRANCH":
                out.append(gen(av[1][0]))
            elif name == "CATEGORY":
                out.append({"CATEGORY_DIGIT": "1", "CATEGORY_WORD": "a", "CATEGORY_SPACE": " ",
                            "CATEGORY_NOT_DIGIT": "a", "CATEGORY_NOT_WORD": "-", "CATEGORY_NOT_SPACE": "a"}.get(str(av).split(".")[-1].upper(), "a"))
            elif name in ("AT", "ASSERT", "ASSERT_NOT", "GROUPREF"):
                if name == "ASSERT_NOT": continue
                if name == "ASSERT": continue
            else:
                return None
        return "".join(x for x in out if x is not None)
    try:
        s = gen(tree)
    except Exception:
        return None
    try:
        if s is not None and re.search(pattern, s, re.I): return s
    except Exception:
        return None
    return None

# ── ATT&CK v19: technique -> Windows analytics (log source, event codes, data components) ─────────
objs = {o["id"]: o for o in ATTACK["objects"]}
tech = {}
for o in ATTACK["objects"]:
    if o["type"] == "attack-pattern":
        tid = next((r["external_id"] for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if tid:
            tech[tid] = o
strat_for = collections.defaultdict(list)
for o in ATTACK["objects"]:
    if o["type"] == "relationship" and o.get("relationship_type") == "detects" and o["source_ref"].startswith("x-mitre-detection-strategy"):
        strat_for[o["target_ref"]].append(objs.get(o["source_ref"]))
ATT_LOG = {"wineventlog:sysmon": SYSMON, "wineventlog:security": "security",
           "wineventlog:system": "system", "wineventlog:application": "application",
           "wineventlog:taskscheduler": "microsoft-windows-taskscheduler/operational",
           "wineventlog:wmi": "microsoft-windows-wmi-activity/operational",
           "wineventlog:windows defender": "microsoft-windows-windows defender/operational"}
def attack_expectations(t_code):
    o = tech.get(t_code)
    if not o:
        return None
    exp = {"events": set(), "logs": set(), "components": set(), "other_sources": set(), "analytics": 0}
    for ds in strat_for.get(o["id"], []):
        if not ds: continue
        for aref in ds.get("x_mitre_analytic_refs", []):
            a = objs.get(aref)
            if not a or "Windows" not in a.get("x_mitre_platforms", []) or a.get("x_mitre_deprecated"): continue
            exp["analytics"] += 1
            for ls in a.get("x_mitre_log_source_references", []):
                comp = objs.get(ls.get("x_mitre_data_component_ref"), {}).get("name")
                if comp: exp["components"].add(comp)
                name = ls.get("name", ""); nl = name.lower()
                if nl.startswith("wineventlog:"):
                    if nl == "wineventlog:powershell":
                        logs = ["microsoft-windows-powershell/operational", "windows powershell"]
                    else:
                        logs = [ATT_LOG.get(nl.replace("winEventLog", "wineventlog"), ATT_LOG.get(nl, nl.split(":", 1)[1]))]
                    ids = [int(x) for x in re.findall(r"\d+", ls.get("channel", "")) if "eventcode" in ls.get("channel", "").lower()]
                    for lg in logs:
                        exp["logs"].add(lg)
                        for i in ids: exp["events"].add((lg, i))
                else:
                    exp["other_sources"].add(name)
    return exp

def has_lone_backslash(raw):
    """A backslash VQL will drop: a single one before anything but \\ n t r ' "."""
    i = 0
    while i < len(raw):
        if raw[i] == "\\":
            if i + 1 < len(raw) and raw[i + 1] in "\\nrt'\"":
                i += 2; continue
            return True
        i += 1
    return False

def intended_regex(raw):
    """What the author meant, read from the VQL source text, occurrence by occurrence:
      \\\\\\\\      -> a literal backslash (author knew VQL halves backslashes)
      \\\\X  where X starts a regex class/escape and is not the start of a word (\\\\s+ \\\\d{ \\\\w* \\\\b \\\\.exe)
             -> the regex escape \\X (author knew)
      \\\\X  otherwise (\\\\System32, \\\\SAM, \\\\Run) -> a literal backslash followed by X (path separator)
      \\X    (single) -> the regex escape \\X the author wrote (VQL drops the backslash)"""
    out, i = [], 0
    while i < len(raw):
        if raw.startswith("\\\\\\\\", i):
            out.append("\\\\"); i += 4; continue
        if raw.startswith("\\\\", i) and i + 2 < len(raw):
            x = raw[i + 2]; nxt = raw[i + 3] if i + 3 < len(raw) else ""
            if x in "sdwSDWbB" and not nxt.isalpha():
                out.append("\\" + x); i += 3; continue
            if x == "." and nxt not in "*+?":
                out.append("\\."); i += 3; continue
            if x in ")]{}|+?*^$":     # \\( and \\[ are a path backslash before a group/class
                out.append("\\" + x); i += 3; continue
            out.append("\\\\"); i += 2; continue
        if raw.startswith("\\\\", i):
            out.append("\\\\"); i += 2; continue
        if raw[i] == "\\" and i + 1 < len(raw):
            out.append(raw[i:i + 2]); i += 2; continue
        out.append(raw[i]); i += 1
    return "".join(out)

def query_platform(text):
    t = text.lower()
    if re.search(r"linux\.|/var/log|/etc/|/proc/|\bjournal|bash_history|/home/", t): return "linux"
    if re.search(r"macos\.|/library/|/users/[^/]+/library|unifiedlogs|/system/library", t): return "macos"
    return "windows"

# ── per-query analysis ─────────────────────────────────────────────────────────────────────────────
REGEX_ARGS = {"regex", "re", "pattern", "ignore", "require"}
def analyze_query(vql, origin):
    """Returns dict with statements' logs/ids/fields and a list of issues (code, severity, detail)."""
    issues, regex_tests = [], []
    toks = tokenize(vql)
    info = {"logs": set(), "events": set(), "plugins": set(), "has_time": False, "select_star": False,
            "content_filter": False, "reads_registry": False, "reads_files": False}
    lets = {toks[i + 1].v for i, t in enumerate(toks[:-1]) if t.k == "ident" and t.v.lower() == "let" and toks[i + 1].k == "ident"}
    for i, t in enumerate(toks):
        if t.k == "ident" and i + 1 < len(toks) and toks[i + 1].v == "(":
            info["plugins"].add(t.v.split(".")[-1] if not t.v.startswith("Artifact.") else t.v)
    pl = {p.lower() for p in info["plugins"]}
    info["reads_registry"] = bool(re.search(r"registry|hklm|hkey_|read_reg_key|ntuser", vql, re.I))
    info["reads_files"] = "glob" in pl or "read_file" in pl or "parse_mft" in pl or "hash" in pl
    if any(p in LIVE_ONLY for p in pl):
        issues.append(("LIVE_ONLY_PLUGIN", "info", "uses " + ", ".join(sorted(p for p in pl if p in LIVE_ONLY)) + ": not applicable to a disk image"))
    if "source" in pl:
        issues.append(("SERVER_ONLY_SOURCE", "broken", "source() still present after the agent's conversion: reads nothing in a standalone collection"))

    for stmt in split_statements(toks):
        cl = clauses(stmt)
        frm = section(stmt, cl, "from", ("where", "group", "order", "limit"))
        sel = section(stmt, cl, "select")
        whr = section(stmt, cl, "where", ("group", "order", "limit"))
        # logs read by this statement
        logs = set(); dynamic_log = False
        for j, t in enumerate(stmt):
            if t.k == "ident" and t.v.lower() == "parse_evtx":
                fn = None
                for k in range(j + 1, min(j + 8, len(stmt))):
                    if stmt[k].k == "ident" and stmt[k].v.lower() == "filename" and k + 2 < len(stmt) and stmt[k + 1].v == "=":
                        fn = stmt[k + 2]; break
                if fn is not None and fn.k == "str":
                    logs.add(channel_of(fn.v))
                else:
                    dynamic_log = True
        direct_evtx = any(t.k == "ident" and t.v.lower() == "parse_evtx" for t in frm)
        logs_l = {l.lower() for l in logs}
        info["logs"] |= logs
        # aliases in this statement
        aliases, alias_expr = set(), {}
        for j, t in enumerate(sel):
            if t.k == "ident" and t.v.lower() == "as" and j + 1 < len(sel) and sel[j + 1].k == "ident":
                aliases.add(sel[j + 1].v)
                # expression = tokens back to previous top-level comma
                k, depth = j - 1, 0
                while k >= 0:
                    if sel[k].v in (")", "}", "]"): depth += 1
                    elif sel[k].v in ("(", "{", "["): depth -= 1
                    elif sel[k].v == "," and depth == 0: break
                    k -= 1
                alias_expr[sel[j + 1].v] = sel[k + 1:j]
        def resolve_field(name):
            """EventData field behind an identifier (directly or via a SELECT alias)."""
            if name.startswith("EventData."):
                return name.split(".")[1]
            ex = alias_expr.get(name)
            if ex and len(ex) == 1 and ex[0].k == "ident" and ex[0].v.startswith("EventData."):
                return ex[0].v.split(".")[1]
            return None
        def is_eid(name):
            if name.lower() in EID_NAMES: return True
            ex = alias_expr.get(name)
            return bool(ex and len(ex) == 1 and ex[0].k == "ident" and ex[0].v.lower() in EID_NAMES)
        # event IDs constrained in WHERE
        ids, id_only = set(), True
        j = 0
        cond_tokens = 0
        while j < len(whr):
            t = whr[j]
            if t.k == "ident" and is_eid(t.v) and j + 1 < len(whr):
                op = whr[j + 1]
                under = t.v if t.v.lower() in EID_NAMES else alias_expr[t.v][0].v
                if under.lower() == "system.eventid" and op.v in ("=", "!=", "=~") or \
                        (under.lower() == "system.eventid" and op.k == "ident" and op.v.lower() == "in"):
                    # verified: System.EventID is {"Value": N}; comparing it to a number is always false
                    issues.append(("EVENTID_WITHOUT_VALUE", "blind",
                                   f"'{t.v}' is System.EventID, a structure {{Value: N}}: comparing it to a number is always false (use System.EventID.Value)"))
                if op.v == "=" and j + 2 < len(whr) and whr[j + 2].k == "num":
                    ids.add(int(whr[j + 2].v)); j += 3; continue
                if op.k == "ident" and op.v.lower() == "in" and j + 2 < len(whr) and whr[j + 2].v in ("(", "["):
                    k = j + 3
                    while k < len(whr) and whr[k].v not in (")", "]"):
                        if whr[k].k == "num": ids.add(int(whr[k].v))
                        elif whr[k].k == "str" and whr[k].v.isdigit():
                            ids.add(int(whr[k].v))
                            issues.append(("TYPE_MISMATCH", "blind", f"event ID compared as text '{whr[k].v}' (IDs are numbers: never equal)"))
                        k += 1
                    j = k + 1; continue
                if op.v == "=~" and j + 2 < len(whr) and whr[j + 2].k == "str":
                    ids |= {int(x) for x in re.findall(r"\d+", whr[j + 2].v)}; j += 3; continue
                if op.v == "=" and j + 2 < len(whr) and whr[j + 2].k == "str":
                    issues.append(("TYPE_MISMATCH", "blind", f"event ID compared as text '{whr[j + 2].v}' (never equal)"))
                    j += 3; continue
            if t.k in ("ident", "str") and not (t.k == "ident" and t.v.lower() in KW):
                cond_tokens += 1
            j += 1
        has_content = any(
            (t.k == "ident" and not is_eid(t.v) and t.v.lower() not in KW and t.v.lower() not in ("system.eventid.value",)
             and not (j + 1 < len(whr) and whr[j + 1].v == "("))
            for j, t in enumerate(whr))
        if logs and direct_evtx:
            for lg in logs_l:
                for i in ids: info["events"].add((lg, i))
            if not ids:
                issues.append(("NO_EVENT_ID_FILTER", "noisy", f"reads every event in {', '.join(sorted(logs))}" + ("" if has_content else " with no filter at all")))
            elif not has_content:
                issues.append(("EVENT_ID_ONLY", "noisy", f"returns every {', '.join(map(str, sorted(ids)))} event from {', '.join(sorted(logs))} (no content filter)"))
            if has_content:
                info["content_filter"] = True
            # event IDs that don't exist in that log
            for lg in logs_l:
                sch = SCHEMA.get(lg)
                if not sch or lg not in COMPLETE_CHANNELS: continue
                bad = sorted(i for i in ids if i not in sch)
                if bad:
                    sev = "blind" if len(bad) == len(ids) else "partial"
                    hint = ""
                    if lg == "security" and any(i < 100 for i in bad): hint = " (these are Sysmon event numbers)"
                    if lg == SYSMON and any(i > 1000 for i in bad): hint = " (these are Security log event numbers)"
                    issues.append(("WRONG_LOG_FOR_EVENT", sev, f"{lg}: event ID(s) {bad} never occur in this log{hint}"))
        elif logs and not direct_evtx:
            for lg in logs_l:
                for i in ids: info["events"].add((lg, i))
            if ids or has_content: info["content_filter"] = True
        else:
            if whr: info["content_filter"] = True
        # EventData fields: exist for (log, ids)?
        if logs_l and (direct_evtx or ids):
            known = [SCHEMA[lg] for lg in logs_l if lg in SCHEMA]
            if known:
                cand = set(); types = {}
                for sch in known:
                    for i, d in sch.items():
                        if not ids or i in ids:
                            cand |= d["fields"]
                            for f, ty in d["types"].items(): types.setdefault(f, set()).update(ty)
                complete = all(lg in COMPLETE_CHANNELS for lg in logs_l)
                if cand:
                    for part, label in ((whr, "filter"), (sel, "output")):
                        for t in part:
                            if t.k == "ident" and t.v.startswith("EventData."):
                                f = t.v.split(".")[1]
                                if f in cand: continue
                                ci = next((c for c in cand if c.lower() == f.lower()), None)
                                if ci:
                                    issues.append(("FIELD_WRONG_CASE", "blind" if label == "filter" else "output",
                                                   f"EventData.{f} should be EventData.{ci} (field names are case-sensitive: always empty)"))
                                elif complete:
                                    issues.append(("FIELD_NOT_IN_EVENT", "blind" if label == "filter" else "output",
                                                   f"EventData.{f} does not exist in {'/'.join(sorted(logs))} event(s) {sorted(ids) or 'any'} (always empty)"))
                # int fields compared to text
                for j, t in enumerate(whr):
                    if t.k != "ident": continue
                    f = resolve_field(t.v)
                    if not f or types.get(f) != {"int"}: continue
                    if j + 2 < len(whr) and whr[j + 1].v in ("=", "!=") and whr[j + 2].k == "str":
                        issues.append(("TYPE_MISMATCH", "blind", f"{t.v} is a number but compared to text '{whr[j + 2].v}' (never equal; e.g. GrantedAccess is 2097151, not '0x1fffff')"))
                    if j + 2 < len(whr) and whr[j + 1].k == "ident" and whr[j + 1].v.lower() == "in":
                        strs = []
                        k = j + 3
                        while k < len(whr) and whr[k].v not in (")", "]"):
                            if whr[k].k == "str": strs.append(whr[k].v)
                            k += 1
                        if strs:
                            issues.append(("TYPE_MISMATCH", "blind", f"{t.v} is a number but compared to text {strs[:4]} (never equal)"))
                    if j + 2 < len(whr) and whr[j + 1].v == "=~" and whr[j + 2].k == "str" and re.search(r"0x", whr[j + 2].v, re.I):
                        issues.append(("TYPE_MISMATCH", "blind", f"{t.v} is a number: regex '{whr[j + 2].v}' on its decimal form can't match hex"))
        # bare symbols that resolve to nothing (only where the row columns are known: FROM parse_evtx)
        if direct_evtx:
            known_roots = {"System", "EventData", "UserData", "Message"} | aliases | lets
            paren = []
            for j, t in enumerate(whr):
                if t.v in ("(", "{", "["):
                    paren.append(j > 0 and whr[j - 1].k == "ident"); continue
                if t.v in (")", "}", "]"):
                    if paren: paren.pop()
                    continue
                if t.k != "ident" or t.v.lower() in KW: continue
                if j + 1 < len(whr) and whr[j + 1].v == "(": continue                       # function
                if paren and paren[-1] and j + 1 < len(whr) and whr[j + 1].v == "=": continue  # arg name
                root = t.v.split(".")[0]
                if root in known_roots or root.startswith("$") or root.startswith("_"): continue
                if root.lower() == "eventid":                                                 # agent rewrites this
                    continue
                issues.append(("UNDEFINED_IN_FILTER", "blind", f"'{t.v}' in WHERE is not a column of parse_evtx rows (System/EventData/Message) or an alias: always empty"))
            for item in [x for x in sel if x.k == "ident"]:
                pass
            # bare SELECT columns that are not real
            items, cur, depth = [], [], 0
            for t in sel:
                if t.v in ("(", "{", "["): depth += 1
                if t.v in (")", "}", "]"): depth -= 1
                if t.v == "," and depth == 0: items.append(cur); cur = []; continue
                cur.append(t)
            if cur: items.append(cur)
            for it in items:
                if not it: continue
                if it[0].v == "*": info["select_star"] = True; continue
                expr = it[:-2] if len(it) >= 3 and it[-2].k == "ident" and it[-2].v.lower() == "as" else it
                if len(expr) == 1 and expr[0].k == "ident" and "." not in expr[0].v and expr[0].v not in lets \
                        and expr[0].v not in ("System", "EventData", "UserData", "Message"):
                    issues.append(("BLANK_COLUMN", "output", f"SELECT {expr[0].v}: not a field of parse_evtx rows (always empty; use System.TimeCreated.SystemTime / System.Computer / EventData.X)"))
        # time column present? (bare EventTime/TimeCreated are blank, so they don't count)
        for t in sel:
            if t.v == "*":
                info["has_time"] = True
            elif t.k == "ident":
                lv = t.v.lower()
                if lv.startswith("system.timecreated") or lv == "timestamp" or (not direct_evtx and (
                        lv.split(".")[-1] in ("mtime", "btime", "ctime", "atime", "modtime", "lastwritetime", "lastmodified", "timestamp", "time"))):
                    info["has_time"] = True
        # regex literals: what VQL does vs what the author wrote
        for j, t in enumerate(stmt):
            if t.k != "str": continue
            is_re = (j > 0 and stmt[j - 1].v == "=~") or \
                    (j > 1 and stmt[j - 1].v == "=" and stmt[j - 2].k == "ident" and stmt[j - 2].v.lower() in REGEX_ARGS)
            if is_re:
                actual = t.v
                if re.search(r"\(\?<?[=!]", actual):
                    issues.append(("REGEX_UNSUPPORTED", "blind", f"regex '{t.raw[:80]}' uses a lookahead/lookbehind: Go RE2 can't compile it, never matches"))
                    continue
                if t.kind == "triple" or "\\" not in t.raw:
                    cands = [t.v]
                else:   # what the author may have meant: per-occurrence reading, or the whole text as a raw regex
                    cands = list(dict.fromkeys([intended_regex(t.raw), t.raw]))
                samples = [x for x in (sample_from_regex(c) for c in cands) if x is not None]
                if samples:
                    gid = id(t)
                    for smp in dict.fromkeys(samples):
                        regex_tests.append({"g": gid, "actual": actual, "sample": smp, "raw": t.raw})
                elif actual not in cands:
                    issues.append(("REGEX_CHANGED", "partial", f"regex '{t.raw[:80]}' becomes '{actual[:80]}' in VQL (backslashes consumed); not machine-checked"))
            elif t.kind in ("sq", "dq") and has_lone_backslash(t.raw) and j > 0 and stmt[j - 1].v in ("=", "!=", ",", "(") \
                    and not any(str(x.v).lower() == "glob" for x in stmt[max(0, j - 6):j]):
                issues.append(("LITERAL_BACKSLASH_LOST", "partial", f"'{t.raw[:80]}' becomes '{t.v[:80]}' (single backslashes are dropped in VQL strings)"))
        # case-sensitive exact path comparisons
        for j, t in enumerate(whr):
            if t.k == "ident" and j + 2 < len(whr) and whr[j + 1].v == "=" and whr[j + 2].k == "str" and re.search(r"[\\/]", whr[j + 2].v) \
                    and re.search(r"image|path|name|file|command", t.v, re.I):
                issues.append(("CASE_SENSITIVE_PATH", "partial", f"{t.v} = '{whr[j + 2].v[:60]}' is an exact, case-sensitive match (Windows paths vary in case; use =~)"))
    return info, issues, regex_tests

def yaml_sources(text):
    import yaml
    try:
        d = yaml.safe_load(text)
    except Exception as e:
        return None, f"YAML does not parse: {str(e)[:120]}"
    if not isinstance(d, dict):
        return None, "YAML is not an artifact definition"
    qs = []
    for s in d.get("sources") or []:
        if isinstance(s, dict) and s.get("query"):
            qs.append((s.get("name") or "source", s["query"]))
    if d.get("export"): qs.insert(0, ("export", d["export"]))
    if not qs:
        return None, "YAML has no source queries"
    return {"name": d.get("name"), "queries": qs, "params": d.get("parameters") or []}, None

def main():
    # ── run ──────────────────────────────────────────────────────────────────────────────────────────
    results, all_regex = [], []
    for row in LIB:
        v, y = (row["v"] or "").strip(), (row["y"] or "").strip()
        if not v and not y:
            continue
        rec = {"t_code": row["t"], "name": row.get("name") or "", "parts": []}
        if y:
            conv = CONVERT(y.replace("\r\n", "\n"))
            src, err = yaml_sources(conv)
            part = {"origin": "yaml", "issues": [], "info": None, "text": conv}
            if err:
                part["issues"].append(("YAML_INVALID", "broken", err))
            else:
                part["artifact"] = src["name"]
                part["sources"] = [n for n, _ in src["queries"]]
                if src["params"]:
                    part["issues"].append(("HAS_PARAMETERS", "info", f"{len(src['params'])} parameter(s): defaults not checked"))
                agg = None
                for sname, q in src["queries"]:
                    info, iss, rts = analyze_query(q, "yaml:" + sname)
                    part["issues"] += [(c, s_, f"[{sname}] {d}") for c, s_, d in iss]
                    for r in rts: r.update(t=row["t"], where=f"yaml:{sname}")
                    all_regex.extend(rts)
                    if agg is None: agg = info
                    else:
                        for k in ("logs", "events", "plugins"): agg[k] |= info[k]
                        for k in ("has_time", "select_star", "content_filter", "reads_registry", "reads_files"): agg[k] = agg[k] or info[k]
                part["info"] = agg
            rec["parts"].append(part)
        if v:
            conv = CONVERT(v)
            info, iss, rts = analyze_query(conv, "vql")
            for r in rts: r.update(t=row["t"], where="vql")
            all_regex.extend(rts)
            rec["parts"].append({"origin": "vql", "issues": iss, "info": info, "text": conv, "sources": ["vql"]})
        results.append(rec)

    # ── batch-check every regex with Velociraptor itself (actual pattern vs a string the author meant to match) ──
    tmp = os.path.join(QD, "regex_tests.json")
    json.dump([{"i": i, "re": r["actual"], "s": r["sample"]} for i, r in enumerate(all_regex)], open(tmp, "w", encoding="utf-8"))
    vq = ("SELECT i, s =~ re AS ok FROM foreach(row=parse_json_array(data=read_file(filename=%s)))" %
          json.dumps(tmp).replace("\\\\", "/"))
    p = subprocess.run([VR, "query", "--format", "jsonl", vq], capture_output=True, text=True, encoding="utf-8", errors="replace")
    ok = {}
    for line in p.stdout.splitlines():
        try:
            d = json.loads(line); ok[d["i"]] = bool(d["ok"])
        except Exception:
            pass
    if len(ok) != len(all_regex):
        print("WARNING: regex batch returned", len(ok), "of", len(all_regex), p.stderr[-300:])
    by_t = collections.defaultdict(list)
    groups = collections.defaultdict(list)
    for i, r in enumerate(all_regex):
        r["ok"] = ok.get(i)
        groups[(r["t"], r["where"], r["g"])].append(r)
    for (t_, where, g), rs in groups.items():
        if all(r["ok"] is False for r in rs):   # fails under every plausible reading of what the author meant
            by_t[(t_, where.split(":")[0])].append(rs[0])
    for rec in results:
        for part in rec["parts"]:
            for r in by_t.get((rec["t_code"], part["origin"]), []):
                if r["ok"] is False:
                    part["issues"].append(("REGEX_NEVER_MATCHES", "blind",
                        f"[{r['where'].split(':',1)[-1]}] regex '{r['raw'][:90]}' is '{r['actual'][:90]}' to Velociraptor and does not match '{r['sample'][:70]}'"))

    # ── verify syntax with velociraptor (YAML as written after conversion; VQL wrapped in an artifact) ──
    vdir = os.path.join(QD, "verify_all"); os.makedirs(vdir, exist_ok=True)
    for f in os.listdir(vdir): os.remove(os.path.join(vdir, f))
    paths = {}
    for rec in results:
        for k, part in enumerate(rec["parts"]):
            fn = os.path.join(vdir, f"{rec['t_code'].replace('.', '_')}_{part['origin']}.yaml")
            if part["origin"] == "yaml":
                txt = part["text"]
            else:
                import yaml as _y
                txt = _y.safe_dump({"name": f"Orca.Check.{rec['t_code'].replace('.', '_')}", "sources": [{"query": part["text"]}]}, sort_keys=False)
            open(fn, "w", encoding="utf-8").write(txt)
            paths[fn] = part
    files = list(paths)
    VCACHE = os.path.join(QD, "verify_cache.json")
    vcache = json.load(open(VCACHE, encoding="utf-8")) if os.path.exists(VCACHE) else {}
    def verify_one(fn):
        """One file per run: 'artifacts verify' stops at the first failing file. [ERROR] lines go to stdout."""
        txt = open(fn, encoding="utf-8").read()
        if txt in vcache:
            return fn, vcache[txt]
        p = subprocess.run([VR, "artifacts", "verify", fn], capture_output=True, text=True, encoding="utf-8", errors="replace")
        msgs = []
        for line in (p.stdout + "\n" + p.stderr).splitlines():
            m = re.search(r"\[ERROR\].*?\.yaml: (.*)", line)
            if m and "required_permissions" not in m.group(1):
                msgs.append(m.group(1).strip()[:200])
        return fn, msgs
    import concurrent.futures as _cf
    with _cf.ThreadPoolExecutor(8) as ex:
        for fn, msgs in ex.map(verify_one, files):
            vcache[open(fn, encoding="utf-8").read()] = msgs
            for msg in msgs[:1]:
                paths[fn]["issues"].append(("VERIFY_ERROR", "broken", msg))
    json.dump(vcache, open(VCACHE, "w", encoding="utf-8"))

    # ── score ────────────────────────────────────────────────────────────────────────────────────────
    SEV = ["broken", "blind", "partly_blind", "partial", "noisy", "output", "info"]
    def worst(issues):
        s = {x[1] for x in issues}
        return next((x for x in SEV if x in s), "ok")
    rows = []
    for rec in results:
        parts = {p["origin"]: p for p in rec["parts"]}
        y, v = parts.get("yaml"), parts.get("vql")
        eff = y if (y and worst(y["issues"]) != "broken") else (v or y)
        rec["effective"] = eff["origin"]
        exp = attack_expectations(rec["t_code"])
        o = tech.get(rec["t_code"])
        info = eff.get("info") or {"logs": set(), "events": set(), "reads_registry": False, "reads_files": False, "has_time": False, "select_star": False}
        q_events = {(l.lower(), i) for l, i in info["events"]}
        q_events_int = {(intended_log(l, i), i) for l, i in q_events}
        q_logs = {l.lower() for l in info["logs"]}
        if o is None:
            align = "NOT_IN_ATTACK"
        elif o.get("revoked") or o.get("x_mitre_deprecated"):
            align = "DEPRECATED_IN_ATTACK"
        elif "Windows" not in o.get("x_mitre_platforms", []):
            align = "NOT_A_WINDOWS_TECHNIQUE"
        elif not exp or not exp["analytics"]:
            align = "NO_ATTACK_WINDOWS_GUIDANCE"
        else:
            ev_hit = q_events & exp["events"]
            comps = " ".join(exp["components"]).lower()
            if ev_hit:
                align = "ALIGNED"
            elif q_logs & exp["logs"]:
                align = "SAME_LOG_OTHER_EVENTS"
            elif (info["reads_registry"] and "registry" in comps) or (info["reads_files"] and "file" in comps):
                align = "ALIGNED_NON_LOG"
            elif not exp["events"] and not exp["logs"]:
                align = "ATTACK_NEEDS_NON_HOST_TELEMETRY"
            else:
                align = "MISALIGNED"
        align_int = align
        if align in ("MISALIGNED", "SAME_LOG_OTHER_EVENTS") and exp:
            if q_events_int & exp["events"]:
                align_int = "ALIGNED"
            elif {l for l, _ in q_events_int} & exp["logs"]:
                align_int = "SAME_LOG_OTHER_EVENTS"
        if align == "NOT_IN_ATTACK":
            align = align_int = "ORCA_COLLECTION_ITEM" if not re.match(r"^T\d{4}", rec["t_code"]) else "NOT_IN_ATTACK"
        sysmon_only = bool(q_logs) and q_logs <= {SYSMON}
        all_issues = eff["issues"]
        # per source: a technique is BLIND only if every source is; PARTLY_BLIND if some are
        srcs = eff.get("sources") or ["vql"]
        per = collections.defaultdict(list)
        for c_, s_, d_ in all_issues:
            m_ = re.match(r"\[([^\]]+)\] ", d_)
            per[m_.group(1) if m_ else "*"].append((c_, s_, d_))
        if any(s_ == "broken" for _, s_, _ in all_issues):
            sev = "broken"
        else:
            blind_srcs = [n for n in srcs if any(s_ == "blind" for _, s_, _ in per.get(n, []) + per.get("*", []))]
            if blind_srcs and len(blind_srcs) == len(srcs):
                sev = "blind"
            elif blind_srcs:
                sev = "partly_blind"
            else:
                sev = worst([x for x in all_issues if x[1] != "blind"])
        blind_count = f"{len(blind_srcs)}/{len(srcs)}" if sev in ("blind", "partly_blind") else ""
        if align == "MISALIGNED" and sev in ("ok", "info", "output", "noisy"):
            sev_label = sev
        rows.append({
            "t_code": rec["t_code"], "name": rec["name"], "platform": query_platform(eff.get("text") or ""),
            "attack_name": (o or {}).get("name", ""),
            "tactics": ",".join(p["phase_name"] for p in (o or {}).get("kill_chain_phases", [])),
            "runs": eff["origin"],
            "severity": sev,
            "blind_sources": blind_count,
            "alignment": align,
            "alignment_if_logs_fixed": align_int,
            "event_coverage_if_logs_fixed": (f"{len(q_events_int & exp['events'])}/{len(exp['events'])}" if exp and exp["events"] else ""),
            "logs": "; ".join(sorted(info["logs"])),
            "events": " ".join(f"{l.split('/')[0].replace('Microsoft-Windows-','')}:{i}" for l, i in sorted(info["events"])),
            "attack_events": " ".join(f"{l.split('/')[0].replace('microsoft-windows-','')}:{i}" for l, i in sorted(exp["events"])) if exp else "",
            "attack_other_sources": "; ".join(sorted(exp["other_sources"])) if exp else "",
            "attack_components": "; ".join(sorted(exp["components"])) if exp else "",
            "event_coverage": (f"{len(q_events & exp['events'])}/{len(exp['events'])}" if exp and exp["events"] else ""),
            "sysmon_only": sysmon_only,
            "has_time_column": bool(info.get("has_time") or info.get("select_star")),
            "issue_codes": " ".join(sorted({c for c, _, _ in all_issues})),
            "issues": " || ".join(f"{c}: {d}" for c, s, d in all_issues if s != "info")[:3000],
            "other_part": ("vql" if eff["origin"] == "yaml" else "yaml") if len(parts) > 1 else "",
            "other_part_severity": worst(parts["vql" if eff["origin"] == "yaml" else "yaml"]["issues"]) if len(parts) > 1 else "",
        })

    with open(os.path.join(QD, "scorecard.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    json.dump({"rows": rows, "regex_tests": len(all_regex), "regex_failed": sum(len(v) for v in by_t.values())},
              open(os.path.join(QD, "findings.json"), "w", encoding="utf-8"), indent=1, default=list)
    print("platform:", dict(collections.Counter(r["platform"] for r in rows)))
    rows = [r for r in rows if r["platform"] == "windows"]
    c = collections.Counter(r["severity"] for r in rows); a = collections.Counter(r["alignment"] for r in rows)
    print("alignment if logs fixed:", dict(collections.Counter(r["alignment_if_logs_fixed"] for r in rows)))
    codes = collections.Counter(code for r in rows for code in r["issue_codes"].split())
    print("WINDOWS techniques:", len(rows)); print("severity:", dict(c)); print("alignment:", dict(a))
    print("issue codes (techniques affected):", dict(codes.most_common()))
    print("regex literals checked:", len(groups), "never match:", sum(len(v) for v in by_t.values()))

if __name__ == "__main__":
    main()
