"""Builds migrations/add_forensic_deaddisk_collections.sql from the authored forensic YAMLs.
Each forensic collection becomes a ref_artifact_library row with applies_live=false (dead-disk only),
applies_dead=true, its query in surgical_yaml. Inserted ON CONFLICT DO NOTHING so operator edits survive.
usage: python mk_forensic_migration.py FORENSIC_DIR REPO_DIR"""
import glob, os, sys, yaml
FD, REPO = sys.argv[1], sys.argv[2]
TAG = "$orcaforensic$"
rows = []
for y in sorted(glob.glob(os.path.join(FD, "*.yaml"))):
    name = os.path.basename(y)[:-5]
    if name.upper() == "SPEC":
        continue
    text = open(y, encoding="utf-8").read().replace("\r\n", "\n").strip() + "\n"
    try:
        doc = yaml.safe_load(text)
        artifact_name = doc["name"]
        desc = (doc.get("description") or artifact_name).strip().split("\n")[0][:240]
    except Exception as e:
        raise SystemExit(f"{name}: YAML does not parse: {e}")
    assert TAG not in text, name
    rows.append((f"FORENSIC_{name}", desc, text))

out = ["-- Forensic dead-disk-only collections (see docs/LIBRARY_QUALITY.md): the artifacts a forensic",
       "-- analyst wants off a mounted image regardless of any ATT&CK technique mapping -- MFT, USN journal,",
       "-- Prefetch, Amcache, ShimCache, SRUM, WMI persistence, shellbags, LNK, recycle bin, scheduled tasks,",
       "-- services, autoruns, UserAssist, RecentDocs. applies_live=false so they run only for a DEAD_DISK",
       "-- asset; applies_dead=true. Inserted once; an operator's later edits in the Artifact Library Editor",
       "-- are kept (ON CONFLICT DO NOTHING).",
       ""]
out.append("-- Depends on add_live_dead_query_variants.sql; the column adds are repeated with IF NOT EXISTS")
out.append("-- so this migration works regardless of apply order.")
for _c, _t in (("applies_live","boolean NOT NULL DEFAULT true"),("applies_dead","boolean NOT NULL DEFAULT true"),("custom_vql_dead","text"),("surgical_yaml_dead","text")):
    out.append(f"ALTER TABLE ref_artifact_library ADD COLUMN IF NOT EXISTS {_c} {_t};")
out.append("")
for t, desc, text in rows:
    desc_sql = desc.replace("'", "''")
    out.append(f"INSERT INTO ref_artifact_library (t_code, name, os, priority, surgical_yaml, applies_live, applies_dead, updated_at)")
    out.append(f"VALUES ('{t}', '{desc_sql}', 'Windows', 'Forensic', {TAG}{text}{TAG}, false, true, NOW())")
    out.append(f"ON CONFLICT (t_code) DO NOTHING;")
    out.append("")
path = os.path.join(REPO, "migrations", "add_live_dead_query_variants_forensic_collections.sql")
open(path, "w", encoding="utf-8", newline="\n").write("\n".join(out))
print(f"{len(rows)} forensic collections -> {path}")
for t, desc, _ in rows:
    print(f"  {t}: {desc[:70]}")
