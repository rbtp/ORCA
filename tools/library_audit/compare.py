"""Static findings vs what each source actually returned on this host.
usage: python compare.py QUALITY_DIR"""
import collections, json, os, re, sys
QD = sys.argv[1]
F = json.load(open(os.path.join(QD, "findings.json"), encoding="utf-8"))["rows"]
RUN = json.load(open(os.path.join(QD, "run_results.json"), encoding="utf-8"))

def src_issues(row):
    per = collections.defaultdict(list)
    for part in (row["issues"] or "").split(" || "):
        if not part.strip(): continue
        code, _, rest = part.partition(": ")
        m = re.match(r"\[([^\]]+)\] ", rest)
        per[m.group(1) if m else "*"].append(code)
    return per

BLIND = {"WRONG_LOG_FOR_EVENT", "EVENTID_WITHOUT_VALUE", "UNDEFINED_IN_FILTER", "REGEX_NEVER_MATCHES", "FIELD_NOT_IN_EVENT",
         "TYPE_MISMATCH", "REGEX_UNSUPPORTED", "FIELD_WRONG_CASE"}
table = collections.Counter(); fp = []; noisy = []; errs = []; zero_ok = 0
for r in F:
    if r["platform"] != "windows": continue
    per = src_issues(r)
    for key, res in RUN.items():
        t, _, src = key.partition("|")
        if t != r["t_code"]: continue
        codes = set(per.get(src, [])) | set(per.get("*", []))
        if r["runs"] == "vql": codes |= set(per.get("vql", []))
        blind = bool(codes & BLIND)
        got = res.get("rows", 0) > 0
        table[(blind, got)] += 1
        if blind and got: fp.append((key, sorted(codes & BLIND), res.get("rows"), (res.get("first") or "")[:200]))
        if res.get("capped"): noisy.append((key, r["severity"]))
        if res.get("errors"): errs.append((key, res["errors"][0][-200:]))
print("sources:", sum(table.values()))
print(f"  flagged blind, returned nothing:   {table[(True, False)]}")
print(f"  flagged blind, returned rows:      {table[(True, True)]}  <- inspect")
print(f"  not flagged,   returned rows:      {table[(False, True)]}")
print(f"  not flagged,   returned nothing:   {table[(False, False)]}")
print(f"  hit the 5000-row cap on this workstation (noisy): {len(noisy)}")
print(f"  runtime errors: {len(errs)}")
json.dump({"blind_but_rows": fp, "noisy": noisy, "errors": errs}, open(os.path.join(QD, "compare.json"), "w", encoding="utf-8"), indent=1)
for x in fp[:40]: print("  BLIND-BUT-ROWS", x[0], x[1], x[2], "|", x[3][:140])
ec = collections.Counter(re.sub(r"\d+", "N", e[1].split("]")[-1])[:90] for e in errs)
for k, v in ec.most_common(12): print("  ERR", v, k)
