"""Mechanical repair of the ORCA artifact library (Windows queries only).
usage: python fixlib.py QUALITY_DIR REPO_DIR VELOCIRAPTOR_EXE
reads library.json, writes fixed_library.json ({t_code: {y, v, changes}}) and fix_report.json.
Every change is one of the bug classes verified against Velociraptor 0.77 on this host."""
import collections, json, os, re, sys
QD, REPO, VR = sys.argv[1], sys.argv[2], sys.argv[3]
sys.argv = [sys.argv[0], QD, REPO, VR]
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import analyze as A                                   # tokenizer, schemas, intended_regex/log (main() not run)
import yaml

LIB = json.load(open(os.path.join(QD, "library.json"), encoding="utf-8"))

# canonical log names (case) for building file names
CANON = {}
for ch in A.OBS_CHANNEL.values():
    CANON[ch.lower()] = ch
for prov, ids in A.MAN.items():
    for d in (ids or {}).values():
        for lg in d.get("logs") or []:
            CANON.setdefault(lg.lower(), lg)
def log_file(log_lower):
    return CANON.get(log_lower, log_lower).replace("/", "%4") + ".evtx"

# field names people used that don't exist in that event -> the real field (only applied if it exists there)
RENAME = {
    "security": {"ProcessName": "NewProcessName", "Image": "NewProcessName", "ParentImage": "ParentProcessName",
                 "ProcessCommandLine": "CommandLine", "CreatorProcessName": "ParentProcessName",
                 "CreatorProcessId": "ProcessId", "ParentProcessId": "ProcessId", "User": "SubjectUserName",
                 "ImagePath": "ServiceFileName", "AccountName": "ServiceAccount", "PrivilegeName": "PrivilegeList",
                 "FailureCode": "Status", "DestinationPort": "DestPort", "DestinationIp": "DestAddress",
                 "SourceIp": "SourceAddress", "ObjectName": "RelativeTargetName",
                 "Author": "TaskContent", "Command": "TaskContent", "UserContext": "TaskContent", "Arguments": "TaskContent",
                 "IpAddress": "DestAddress", "ProcessPath": "Application", "LogonId": "TargetLogonId",
                 "TokenElevationType": "ElevatedToken"},
    "microsoft-windows-sysmon/operational": {
                 "ProcessName": "Image", "ProcessImage": "Image", "ParentProcessName": "ParentImage",
                 "NewProcessName": "Image", "TargetProcessName": "TargetImage", "SourceProcessName": "SourceImage",
                 "ProcessCommandLine": "CommandLine", "DestinationAddress": "DestinationIp", "SourceAddress": "SourceIp",
                 "TargetFileName": "TargetFilename", "Destination": "DestinationIp",
                 "NewValue": "Details", "DestinationHostname": "QueryName"},
    "microsoft-windows-powershell/operational": {"UserId": "ContextInfo", "HostApplication": "ContextInfo",
                 "CommandLine": "ContextInfo", "ScriptBlock": "ScriptBlockText"},
}
# Sysmon 10 has no "Image": the accessing process is SourceImage
RENAME_BY_EVENT = {("microsoft-windows-sysmon/operational", 10): {"ProcessName": "SourceImage", "Image": "SourceImage"}}
TIME_NAMES = {"eventtime", "timestamp", "timegenerated", "timecreated", "time", "eventtimestamp"}
HOST_NAMES = {"computer", "hostname", "computername"}

def stmt_logs_ids(stmt):
    cl = A.clauses(stmt)
    frm = A.section(stmt, cl, "from", ("where", "group", "order", "limit"))
    whr = A.section(stmt, cl, "where", ("group", "order", "limit"))
    fn_tok = None
    for j, t in enumerate(frm):
        if t.k == "ident" and t.v.lower() == "parse_evtx":
            for k in range(j + 1, min(j + 8, len(frm))):
                if frm[k].k == "ident" and frm[k].v.lower() == "filename" and k + 2 < len(frm) and frm[k + 1].v == "=" and frm[k + 2].k == "str":
                    fn_tok = frm[k + 2]; break
    ids = set(); channel_hint = None
    for j, t in enumerate(whr):
        if t.k == "ident" and t.v.lower() in A.EID_NAMES and j + 2 < len(whr):
            if whr[j + 1].v == "=" and whr[j + 2].k == "num": ids.add(int(whr[j + 2].v))
            elif whr[j + 1].k == "ident" and whr[j + 1].v.lower() == "in":
                k = j + 2
                while k < len(whr) and whr[k].v != ")":
                    if whr[k].k == "num": ids.add(int(whr[k].v))
                    elif whr[k].k == "str" and whr[k].v.isdigit(): ids.add(int(whr[k].v))
                    k += 1
            elif whr[j + 1].v == "=" and whr[j + 2].k == "str" and whr[j + 2].v.isdigit(): ids.add(int(whr[j + 2].v))
        if t.k == "ident" and t.v.lower() in ("channel", "system.channel") and j + 2 < len(whr) and whr[j + 1].v == "=" and whr[j + 2].k == "str":
            channel_hint = whr[j + 2].v.lower()
    return fn_tok, ids, channel_hint, cl, whr

def apply_edits(q, edits):
    for s, e, rep in sorted(set(edits), key=lambda x: -x[0]):
        q = q[:s] + rep + q[e:]
    return q

def schema_for(log, ids):
    sch = A.SCHEMA.get(log) or {}
    fields, types = set(), {}
    for i, d in sch.items():
        if not ids or i in ids:
            fields |= d["fields"]
            for f, ty in d["types"].items(): types.setdefault(f, set()).update(ty)
    return fields, types

def rename_target(log, ids, f, fields):
    for i in ids or [None]:
        t = RENAME_BY_EVENT.get((log, i), {}).get(f)
        if t and t in fields: return t
    t = RENAME.get(log, {}).get(f)
    if t and t in fields: return t
    ci = next((c for c in fields if c.lower() == f.lower()), None)
    return ci

def fix_query(q, changes):
    # pass 1: textual, unambiguous
    q2 = re.sub(r"(?<![.\w])System\.EventID(?![.\w])", "System.EventID.Value", q)
    if q2 != q: changes.append("System.EventID -> System.EventID.Value (System.EventID is {Value: N}; comparing it to a number was always false)")
    q = q2
    q2 = re.sub(r"(?i)(\bORDER\s+BY\s+[\w.]+(?:\s+(?:DESC|ASC))?)\s*,\s*[\w.]+(?:\s+(?:DESC|ASC))?", r"\1", q)
    if q2 != q: changes.append("ORDER BY with several columns (a VQL parse error) -> first column only")
    q = q2
    # glob()/registry rows have OSPath since Velociraptor 0.7; FullPath is "Symbol not found" (verified in the live run)
    if re.search(r"\bglob\s*\(|Artifact\.Windows\.|read_reg_key|accessor\s*=", q):
        q2 = re.sub(r"(?<![.\w])FullPath(?!\w)", "OSPath", q)
        q2 = re.sub(r"(?<=\.)FullPath(?!\w)", "OSPath", q2)
        if q2 != q: changes.append("FullPath (removed in Velociraptor 0.7: 'Symbol FullPath not found') -> OSPath")
        q = q2

    # pass 2: wrong log
    toks = A.tokenize(q); edits = []
    for stmt in A.split_statements(toks):
        fn_tok, ids, hint, cl, whr = stmt_logs_ids(stmt)
        if not fn_tok: continue
        log = A.channel_of(fn_tok.v).lower()
        sch = A.SCHEMA.get(log)
        if log not in A.COMPLETE_CHANNELS or not ids or sch is None: continue
        bad = {i for i in ids if i not in sch}
        if not bad: continue
        targets = {A.intended_log(log, i) for i in ids}
        if hint and hint in A.SCHEMA and all(i in A.SCHEMA[hint] for i in ids):
            targets = {hint}
        if len(targets) == 1 and (new := targets.pop()) != log and all(i in A.SCHEMA.get(new, {}) for i in ids):
            prefix = fn_tok.v[: len(fn_tok.v) - len(fn_tok.v.replace("\\", "/").split("/")[-1])]
            quote = "'''" if fn_tok.kind == "triple" else ("'" if fn_tok.kind == "sq" else '"')
            edits.append((fn_tok.pos, fn_tok.end, f"{quote}{prefix}{log_file(new)}{quote}"))
            changes.append(f"event(s) {sorted(ids)} read from {CANON.get(log, log)} where they never occur -> {CANON.get(new, new)}")
        else:
            changes.append(f"MANUAL: event IDs {sorted(ids)} read from {CANON.get(log, log)} belong to different logs ({sorted(targets)}); not changed")
    q = apply_edits(q, edits)

    # pass 3a: time windows relative to now()
    toks = A.tokenize(q); edits = []
    for stmt in A.split_statements(toks):
        cl = A.clauses(stmt)
        whr = A.section(stmt, cl, "where", ("group", "order", "limit"))
        if not whr: continue
        conj, cur, depth, has_or = [], [], 0, False
        for t in whr:
            if t.v in ("(", "{", "["): depth += 1
            if t.v in (")", "}", "]"): depth -= 1
            if depth == 0 and t.k == "ident" and t.v.lower() == "or": has_or = True
            if depth == 0 and t.k == "ident" and t.v.lower() == "and":
                conj.append(cur); cur = []; continue
            cur.append(t)
        conj.append(cur)
        def is_time_window(c):
            return c and c[0].k == "ident" and (c[0].v.lower() in TIME_NAMES or c[0].v.lower().startswith("system.timecreated")) \
                   and len(c) > 1 and c[1].v in (">", ">=") and any(x.k == "ident" and x.v.lower() == "now" for x in c)
        tw = [c for c in conj if is_time_window(c)]
        if not tw or has_or: continue
        keep = [c for c in conj if not is_time_window(c)]
        if keep:
            edits.append((whr[0].pos, whr[-1].end, " AND ".join(q[c[0].pos:c[-1].end] for c in keep)))
        else:
            edits.append((stmt[cl["where"]].pos, whr[-1].end, ""))
        changes.append("removed a time window relative to now() (" + q[tw[0][0].pos:tw[0][-1].end][:60] +
                       "): a disk image is examined after the fact, and the name it used was undefined anyway")
    q = apply_edits(q, edits)

    # pass 3: fields, bare names, blank SELECT columns
    toks = A.tokenize(q); edits = []
    for stmt in A.split_statements(toks):
        fn_tok, ids, hint, cl, whr = stmt_logs_ids(stmt)
        frm = A.section(stmt, cl, "from", ("where", "group", "order", "limit"))
        direct = any(t.k == "ident" and t.v.lower() == "parse_evtx" for t in frm)
        if not fn_tok or not direct: continue
        log = A.channel_of(fn_tok.v).lower()
        fields, types = schema_for(log, ids)
        sel = A.section(stmt, cl, "select")
        aliases = {sel[j + 1].v for j, t in enumerate(sel[:-1]) if t.k == "ident" and t.v.lower() == "as" and sel[j + 1].k == "ident"}
        lets = {toks[i + 1].v for i, t in enumerate(toks[:-1]) if t.k == "ident" and t.v.lower() == "let"}
        # EventData.X that don't exist in this event
        for part in (sel, whr):
            for t in part:
                if t.k == "ident" and t.v.startswith("EventData.") and fields:
                    f = t.v.split(".")[1]
                    if f in fields: continue
                    new = rename_target(log, ids, f, fields)
                    if new:
                        edits.append((t.pos, t.pos + len("EventData.") + len(f), "EventData." + new))
                        changes.append(f"EventData.{f} (not a field of {CANON.get(log, log)} {sorted(ids) or ''}) -> EventData.{new}")
        # WHERE: undefined bare names
        if whr:
            continue_where = True
            if continue_where:
                paren = []
                for j, t in enumerate(whr):
                    if t.v in ("(", "{", "["): paren.append(j > 0 and whr[j - 1].k == "ident"); continue
                    if t.v in (")", "}", "]"):
                        if paren: paren.pop()
                        continue
                    if t.k != "ident" or t.v.lower() in A.KW: continue
                    if j + 1 < len(whr) and whr[j + 1].v == "(": continue
                    if paren and paren[-1] and j + 1 < len(whr) and whr[j + 1].v == "=": continue
                    root = t.v.split(".")[0]
                    if root in ("System", "EventData", "UserData", "Message") or root in aliases or root in lets or root.startswith(("$", "_")): continue
                    if root.lower() == "eventid": continue
                    lv = t.v.lower()
                    rep = None
                    if lv in TIME_NAMES: rep = "System.TimeCreated.SystemTime"
                    elif lv == "channel": rep = "System.Channel"
                    elif lv in HOST_NAMES: rep = "System.Computer"
                    elif "." not in t.v and t.v in fields: rep = "EventData." + t.v
                    elif "." not in t.v and fields and (nf := rename_target(log, ids, t.v, fields)): rep = "EventData." + nf
                    if rep:
                        edits.append((t.pos, t.end, rep))
                        changes.append(f"WHERE {t.v} (not a column of the event row: always empty) -> {rep}")
        # SELECT: bare names that are always blank
        items, cur, depth = [], [], 0
        for t in sel:
            if t.v in ("(", "{", "["): depth += 1
            if t.v in (")", "}", "]"): depth -= 1
            if t.v == "," and depth == 0: items.append(cur); cur = []; continue
            cur.append(t)
        if cur: items.append(cur)
        for it in items:
            if not it or it[0].v == "*": continue
            has_as = len(it) >= 3 and it[-2].k == "ident" and it[-2].v.lower() == "as"
            expr = it[:-2] if has_as else it
            if len(expr) != 1 or expr[0].k != "ident" or "." in expr[0].v or expr[0].v in lets: continue
            name = expr[0].v; lv = name.lower(); alias = it[-1].v if has_as else name
            rep = None
            if lv in TIME_NAMES: rep = "timestamp(epoch=System.TimeCreated.SystemTime)"
            elif lv in HOST_NAMES: rep = "System.Computer"
            elif lv == "eventid": rep = "System.EventID.Value"
            elif lv == "channel": rep = "System.Channel"
            elif lv in ("eventrecordid", "recordid"): rep = "System.EventRecordID"
            elif name in fields: rep = "EventData." + name
            elif fields and (nf := rename_target(log, ids, name, fields)): rep = "EventData." + nf
            if rep:
                edits.append((expr[0].pos, expr[0].end, rep if has_as else f"{rep} AS {alias}"))
                changes.append(f"SELECT {name} (always blank) -> {rep}")
    q = apply_edits(q, edits)

    # pass 4: numbers compared to text
    toks = A.tokenize(q); edits = []
    for stmt in A.split_statements(toks):
        fn_tok, ids, hint, cl, whr = stmt_logs_ids(stmt)
        if not fn_tok: continue
        log = A.channel_of(fn_tok.v).lower()
        fields, types = schema_for(log, ids)
        sel = A.section(stmt, cl, "select")
        alias_field = {}
        for j, t in enumerate(sel[:-2]):
            if t.k == "ident" and t.v.startswith("EventData.") and sel[j + 1].k == "ident" and sel[j + 1].v.lower() == "as":
                alias_field[sel[j + 2].v] = t.v.split(".")[1]
        def int_field(name):
            if name.lower() in A.EID_NAMES or name.lower() == "system.eventid.value": return True
            f = name.split(".")[1] if name.startswith("EventData.") else alias_field.get(name)
            return bool(f and types.get(f) == {"int"})
        def num_lit(s):
            s = s.strip()
            if re.fullmatch(r"0[xX][0-9a-fA-F]+|\d+", s): return s.lower() if s.lower().startswith("0x") else s
            return None
        for j, t in enumerate(whr):
            if t.k != "ident" or not int_field(t.v) or j + 2 >= len(whr): continue
            op = whr[j + 1]
            if op.v in ("=", "!=") and whr[j + 2].k == "str" and (n := num_lit(whr[j + 2].v)):
                edits.append((whr[j + 2].pos, whr[j + 2].end, n))
                changes.append(f"{t.v} {op.v} '{whr[j + 2].v}' -> {n} (the field is a number; number vs text is never equal)")
            elif op.k == "ident" and op.v.lower() == "in":
                k = j + 2; conv = []
                while k < len(whr) and whr[k].v not in (")", "]"):
                    if whr[k].k == "str" and (n := num_lit(whr[k].v)):
                        edits.append((whr[k].pos, whr[k].end, n)); conv.append(n)
                    k += 1
                if conv:
                    changes.append(f"{t.v} IN (...): text {conv[:4]} -> numbers (the field is a number; number vs text is never equal)")
            elif op.v == "=~" and whr[j + 2].k == "str" and re.search(r"0x", whr[j + 2].v, re.I) and not t.v.lower().startswith("system."):
                edits.append((t.pos, t.end, f"format(format='0x%x', args={t.v})"))
                changes.append(f"{t.v} =~ '{whr[j + 2].v}': the field is a number, regex now runs on its hex form")
    q = apply_edits(q, edits)

    # pass 5: regex literals VQL mangles -> raw triple-quoted strings holding what the author meant
    toks = A.tokenize(q); edits = []
    for j, t in enumerate(toks):
        if t.k != "str" or t.kind == "triple": continue
        is_re = (j > 0 and toks[j - 1].v == "=~") or \
                (j > 1 and toks[j - 1].v == "=" and toks[j - 2].k == "ident" and toks[j - 2].v.lower() in A.REGEX_ARGS)
        if is_re and "\\" in t.raw and "'''" not in t.raw:
            intended = A.intended_regex(t.raw)
            if intended != t.v and not re.search(r"\(\?<?[=!]", intended):
                try:
                    re.compile(intended)
                except re.error:
                    changes.append(f"MANUAL: regex '{t.raw[:60]}' doesn't compile in any reading"); continue
                edits.append((t.pos, t.end, "'''" + intended + "'''"))
                changes.append(f"regex '{t.raw[:70]}' was '{t.v[:70]}' to Velociraptor -> '''{intended[:70]}'''")
        elif is_re and re.search(r"\(\?<?[=!]", t.v):
            changes.append(f"MANUAL: regex '{t.raw[:60]}' uses a lookaround (unsupported by Go RE2, never matches)")
        elif not is_re and t.kind in ("sq", "dq") and A.has_lone_backslash(t.raw) and j > 0 and toks[j - 1].v in ("=", "!=", ",", "(") \
                and not any(str(x.v).lower() == "glob" for x in toks[max(0, j - 6):j]):
            fixed = re.sub(r"\\(?![\\nrt'\"])", r"\\\\", t.raw)
            quote = "'" if t.kind == "sq" else '"'
            edits.append((t.pos, t.end, quote + fixed + quote))
            changes.append(f"'{t.raw[:60]}': single backslashes were dropped by VQL -> doubled")
    q = apply_edits(q, edits)
    return q

class Lit(str): pass
def _lit(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|" if "\n" in data else None)
yaml.add_representer(Lit, _lit, Dumper=yaml.SafeDumper)

def fix_name(name, changes):
    parts = [p for p in re.split(r"\.", name or "") if p != ""]
    out = []
    for p in parts:
        p2 = re.sub(r"[^A-Za-z0-9_]", "_", p)
        if p2[:1].isdigit():
            if out: out[-1] = out[-1] + "_" + p2; continue
            p2 = "_" + p2
        out.append(p2)
    new = ".".join(out)
    if new != name: changes.append(f"artifact name '{name}' (rejected by Velociraptor, so the YAML never ran) -> '{new}'")
    return new

CONVERT = A.CONVERT
fixed, report = {}, collections.Counter()
for row in LIB:
    t = row["t"]; y = (row["y"] or "").strip(); v = (row["v"] or "").strip()
    rec = {"y": row["y"], "v": row["v"], "changes": []}
    if y and A.query_platform(y) == "windows":
        try:
            d = yaml.safe_load(CONVERT(y.replace("\r\n", "\n")))
        except Exception as e:
            d = None; rec["changes"].append(f"MANUAL: YAML does not parse ({str(e)[:100]})")
        if isinstance(d, dict):
            ch = []
            d["name"] = fix_name(d.get("name"), ch)
            for s in d.get("sources") or []:
                if isinstance(s, dict) and isinstance(s.get("query"), str):
                    before = s["query"]
                    sc = []
                    s["query"] = Lit(fix_query(before, sc).rstrip() + "\n")
                    ch += [f"[{s.get('name') or 'source'}] {c}" for c in sc]
            for k, val in list(d.items()):
                if isinstance(val, str) and "\n" in val: d[k] = Lit(val)
            if ch:
                rec["y"] = yaml.safe_dump(d, sort_keys=False, allow_unicode=True, width=1000)
                rec["changes"] += ["yaml: " + c for c in ch]
    if v and A.query_platform(v) == "windows":
        ch = []
        nv = fix_query(CONVERT(v), ch)
        if ch:
            rec["v"] = nv; rec["changes"] += ["vql: " + c for c in ch]
    for c in rec["changes"]:
        report[re.sub(r"\[[^\]]*\] |'[^']*'|\d+|\([^)]*\)", "", c.split(":", 1)[-1])[:70].strip()] += 1
    fixed[t] = rec
json.dump(fixed, open(os.path.join(QD, "fixed_library.json"), "w", encoding="utf-8"), indent=1)
print("techniques changed:", sum(1 for r in fixed.values() if any(not c.split(": ", 1)[-1].startswith("MANUAL") for c in r["changes"])))
print("manual items:", sum(1 for r in fixed.values() for c in r["changes"] if "MANUAL" in c))
for k, n in report.most_common(30): print(f"{n:5d}  {k}")
