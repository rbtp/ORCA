import re, os
src = open(os.path.join(os.path.dirname(__file__), "analyze.py"), encoding="utf-8").read()
start = src.index("def has_lone_backslash"); end = src.index("# ── per-query analysis")
ns = {"re": re}; exec(src[start:end], ns)
I, L = ns["intended_regex"], ns["has_lone_backslash"]
B = "\\"
cases = [  # (raw VQL source text inside quotes, intended regex)
    ("(?i)reg" + B*2 + "s+save",                  "(?i)reg" + B + "s+save"),             # \\s+ = whitespace class
    ("(?i)HKLM" + B*2 + "SAM" + B*2 + "SAM",       "(?i)HKLM" + B*2 + "SAM" + B*2 + "SAM"), # \\SAM = path backslash
    ("lsass" + B + ".exe$",                       "lsass" + B + ".exe$"),                # single \. = escaped dot
    ("lsass" + B*2 + ".exe",                      "lsass" + B + ".exe"),                 # \\.exe = escaped dot
    (".*" + B*2 + "CurrentVersion" + B*2 + "Run.*", ".*" + B*2 + "CurrentVersion" + B*2 + "Run.*"),
    ("C:" + B*4 + "Users",                        "C:" + B*2 + "Users"),                 # \\\\ = literal backslash
    ("C:" + B*2 + "Windows" + B*2 + ".*",          "C:" + B*2 + "Windows" + B*2 + ".*"),  # \\.* = backslash then .*
    (B*2 + "d{4}",                                B + "d{4}"),
    (B*2 + "System32",                            B*2 + "System32"),
    ("hklm" + B*2 + "(sam|system)",               "hklm" + B*2 + "(sam|system)"),       # \\( = backslash then group
    (".*" + B*2 + "(net|ping)" + B + ".exe$",      ".*" + B*2 + "(net|ping)" + B + ".exe$"),
]
ok = True
for raw, want in cases:
    got = I(raw)
    good = got == want
    ok &= good
    print("PASS" if good else "FAIL", repr(raw), "->", repr(got), "" if good else f"(want {want!r})")
for raw, want in [("%SystemRoot%" + B*2 + "System32", False), ("C:" + B + "Windows", True), ("a" + B + "nb", False)]:
    good = L(raw) == want; ok &= good
    print("PASS" if good else "FAIL", "lone backslash", repr(raw), L(raw))
print("ALL OK" if ok else "SOME FAILED")
