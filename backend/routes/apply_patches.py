"""
apply_patches.py — Patches mitre_routes.py with:
  1. /analytics/{t_code} endpoint
  2. deprecated/revoked columns added to mitre_techniques
  3. /techniques endpoint filters deprecated/revoked
  4. /threat-profile returns platforms + subtechnique fields
  5. DB schema columns for is_deprecated / is_revoked

Run from the ORCA backend directory (same level as mitre_routes.py):
    python apply_patches.py
"""

import subprocess, re, shutil
from pathlib import Path

ROUTES_FILE = Path("mitre_routes.py")

# ── DB helpers ───────────────────────────────────────────────────────────────

def run_sql(sql):
    cmd = ["docker", "exec", "-i", "orca-postgres",
           "psql", "-U", "postgres", "-d", "orca_db", "-c", sql]
    r = subprocess.run(cmd, capture_output=True)
    out = r.stdout.decode("utf-8", errors="replace")
    err = r.stderr.decode("utf-8", errors="replace")
    if r.returncode != 0:
        print(f"  [SQL ERROR] {err.strip()}")
        return False
    print(f"  {out.strip()[:80]}")
    return True

def run_sql_file(sql):
    cmd = ["docker", "exec", "-i", "orca-postgres",
           "psql", "-U", "postgres", "-d", "orca_db"]
    r = subprocess.run(cmd, input=sql.encode("utf-8"), capture_output=True)
    out = r.stdout.decode("utf-8", errors="replace")
    err = r.stderr.decode("utf-8", errors="replace")
    if r.returncode != 0:
        print(f"  [SQL ERROR] {err.strip()}")
        return False
    return True

# ── Patch helpers ────────────────────────────────────────────────────────────

def patch(content, old, new, label):
    if old not in content:
        print(f"  [SKIP] {label} — pattern not found (may already be applied)")
        return content
    result = content.replace(old, new, 1)
    print(f"  [OK]   {label}")
    return result

# ── Step 1: DB schema — add is_deprecated / is_revoked columns ───────────────

def apply_db_schema():
    print("\n[1/4] Applying DB schema...")
    run_sql("ALTER TABLE mitre_techniques ADD COLUMN IF NOT EXISTS is_deprecated BOOLEAN DEFAULT FALSE")
    run_sql("ALTER TABLE mitre_techniques ADD COLUMN IF NOT EXISTS is_revoked BOOLEAN DEFAULT FALSE")
    # Backfill from existing data — techniques without platforms are likely deprecated
    # The reparse script will set these properly; this seeds them from stix_id patterns
    run_sql_file("""
        UPDATE mitre_techniques SET is_deprecated = TRUE
        WHERE platforms IS NULL OR platforms = '[]'::jsonb OR platforms = 'null'::jsonb;
    """)
    print("  Schema done. Re-run mitre_reparse_v19.py to populate is_deprecated/is_revoked properly.")

# ── Step 2: Patch mitre_routes.py ────────────────────────────────────────────

def apply_routes_patches():
    print(f"\n[2/4] Reading {ROUTES_FILE}...")
    content = ROUTES_FILE.read_text(encoding="utf-8")

    # Backup
    backup = ROUTES_FILE.with_suffix(".py.bak")
    shutil.copy(ROUTES_FILE, backup)
    print(f"  Backup saved to {backup}")

    # ── Patch A: /techniques — exclude deprecated/revoked ──────────────────
    old_techniques = '''@router.get("/techniques")
def get_all_techniques(current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        results = session.execute(text(
            "SELECT t_code, name AS technique_name FROM public.mitre_techniques ORDER BY t_code ASC"
        )).mappings().all()
        return [dict(r) for r in results]
    except:
        return []
    finally:
        session.close()'''

    new_techniques = '''@router.get("/techniques")
def get_all_techniques(current_user: dict = Depends(get_current_user)):
    session = db.get_session()
    try:
        results = session.execute(text("""
            SELECT t_code, name AS technique_name
            FROM public.mitre_techniques
            WHERE NOT COALESCE(is_deprecated, FALSE)
              AND NOT COALESCE(is_revoked, FALSE)
            ORDER BY t_code ASC
        """)).mappings().all()
        return [dict(r) for r in results]
    except:
        return []
    finally:
        session.close()'''

    content = patch(content, old_techniques, new_techniques, "/techniques deprecated filter")

    # ── Patch B: /threat-profile — add platforms/subtechnique to SELECT ───
    old_threat_select = '''            SELECT mt.t_code, mt.name AS technique_name,
                string_agg(DISTINCT ta.group_name, ', ') as associated_actors,
                ref.live_analysis, ref.dead_disk_analysis, ref.collection_strategy AS bluf_text,
                COALESCE(ar.verdict, 'Undetermined') as verdict,
                COALESCE(ar.evidence_imported, False) as evidence_imported
            FROM threat_attribution ta
            JOIN mitre_actors ma ON ta.group_name = ma.name
            JOIN mitre_relationships ma_rel ON ma.stix_id = ma_rel.source_ref
            JOIN mitre_techniques mt ON ma_rel.target_ref = mt.stix_id
            JOIN ref_artifact_library ref ON mt.t_code = ref.t_code
            LEFT JOIN artifact_results ar ON (mt.t_code = ar.t_code AND ar.asset_id = :asset_id)
            WHERE UPPER(ta.attribution) = :country AND ma_rel.relationship_type = 'uses'
            GROUP BY mt.t_code, mt.name, ref.live_analysis, ref.dead_disk_analysis,
                ref.collection_strategy, ar.verdict, ar.evidence_imported
            ORDER BY mt.t_code ASC'''

    new_threat_select = '''            SELECT mt.t_code, mt.name AS technique_name,
                string_agg(DISTINCT ta.group_name, ', ') as associated_actors,
                ref.live_analysis, ref.dead_disk_analysis, ref.collection_strategy AS bluf_text,
                COALESCE(ar.verdict, 'Undetermined') as verdict,
                COALESCE(ar.evidence_imported, False) as evidence_imported,
                mt.platforms,
                mt.parent_t_code,
                COALESCE(mt.is_subtechnique, FALSE) as is_subtechnique
            FROM threat_attribution ta
            JOIN mitre_actors ma ON ta.group_name = ma.name
            JOIN mitre_relationships ma_rel ON ma.stix_id = ma_rel.source_ref
            JOIN mitre_techniques mt ON ma_rel.target_ref = mt.stix_id
            JOIN ref_artifact_library ref ON mt.t_code = ref.t_code
            LEFT JOIN artifact_results ar ON (mt.t_code = ar.t_code AND ar.asset_id = :asset_id)
            WHERE UPPER(ta.attribution) = :country
              AND ma_rel.relationship_type = 'uses'
              AND NOT COALESCE(mt.is_deprecated, FALSE)
              AND NOT COALESCE(mt.is_revoked, FALSE)
            GROUP BY mt.t_code, mt.name, ref.live_analysis, ref.dead_disk_analysis,
                ref.collection_strategy, ar.verdict, ar.evidence_imported,
                mt.platforms, mt.parent_t_code, mt.is_subtechnique
            ORDER BY mt.t_code ASC'''

    content = patch(content, old_threat_select, new_threat_select, "/threat-profile deprecated filter + platforms")

    # ── Patch C: Insert /analytics/{t_code} endpoint after library GET ────
    analytics_endpoint = '''

@router.get("/analytics/{t_code}")
async def get_technique_analytics(t_code: str, current_user: dict = Depends(get_current_user)):
    """
    Returns MITRE v19 detection analytics for a technique, grouped by platform.
    Includes detection narrative, log sources, and tunable parameters per analytic.
    """
    session = db.get_session()
    try:
        rows = session.execute(text("""
            SELECT
                ds.det_code,
                ds.name                 AS strategy_name,
                a.analytic_code,
                a.platforms,
                a.description           AS detection_narrative,
                a.log_source_refs,
                a.mutable_elements
            FROM mitre_detection_strategies ds
            JOIN mitre_analytics a        ON a.det_code = ds.det_code
            JOIN mitre_techniques mt      ON mt.t_code  = ds.t_code
            WHERE ds.t_code = :t_code
              AND NOT COALESCE(mt.is_deprecated, FALSE)
              AND NOT COALESCE(mt.is_revoked, FALSE)
            ORDER BY a.analytic_code ASC
        """), {"t_code": t_code.strip()}).mappings().all()

        if not rows:
            return {"t_code": t_code, "strategy_name": None, "analytics_by_platform": {}, "platforms": []}

        strategy_name = rows[0]["strategy_name"]
        det_code      = rows[0]["det_code"]

        by_platform = {}
        for row in rows:
            # platforms stored as jsonb array or text[]
            raw_plat = row["platforms"] or []
            if isinstance(raw_plat, str):
                raw_plat = json.loads(raw_plat) if raw_plat.startswith("[") else \
                           [p.strip() for p in raw_plat.strip("{}").split(",") if p.strip()]

            log_refs = row["log_source_refs"]
            if isinstance(log_refs, str):
                try:    log_refs = json.loads(log_refs)
                except: log_refs = []

            mutable = row["mutable_elements"]
            if isinstance(mutable, str):
                try:    mutable = json.loads(mutable)
                except: mutable = []

            entry = {
                "analytic_code":       row["analytic_code"],
                "detection_narrative": row["detection_narrative"] or "",
                "log_sources": [
                    {"name": ls.get("name", ""), "channel": ls.get("channel", "")}
                    for ls in (log_refs or [])
                ],
                "tuning_parameters": [
                    {"field": m.get("field", ""), "description": m.get("description", "")}
                    for m in (mutable or [])
                ],
            }

            for plat in raw_plat:
                plat = plat.strip()
                if not plat:
                    continue
                by_platform.setdefault(plat, []).append(entry)

        return {
            "t_code":               t_code,
            "det_code":             det_code,
            "strategy_name":        strategy_name,
            "platforms":            list(by_platform.keys()),
            "analytics_by_platform": by_platform,
        }
    finally:
        session.close()

'''

    insert_after = '''        return dict(row) if row else {"t_code": t_code, "technique_name": "", "live_analysis": "",
                                       "dead_disk_analysis": "", "collection_strategy": "", "custom_vql": "", "surgical_yaml": ""}
    finally:
        session.close()

@router.post("/library/{t_code}/update")'''

    new_insert_after = '''        return dict(row) if row else {"t_code": t_code, "technique_name": "", "live_analysis": "",
                                       "dead_disk_analysis": "", "collection_strategy": "", "custom_vql": "", "surgical_yaml": ""}
    finally:
        session.close()
''' + analytics_endpoint + '''@router.post("/library/{t_code}/update")'''

    content = patch(content, insert_after, new_insert_after, "/analytics/{t_code} endpoint inserted")

    ROUTES_FILE.write_text(content, encoding="utf-8")
    print(f"\n  {ROUTES_FILE} written.")

# ── Step 3: Update reparse script to populate is_deprecated/is_revoked ──────

def patch_reparse():
    print("\n[3/4] Patching mitre_reparse_v19.py to populate is_deprecated/is_revoked...")
    reparse = Path("mitre_reparse_v19.py")
    if not reparse.exists():
        print("  mitre_reparse_v19.py not found — skipping")
        return

    content = reparse.read_text(encoding="utf-8")

    old_upsert = '''        deprecated = tech.get("x_mitre_deprecated", False)
        revoked = tech.get("revoked", False)

        platforms = tech.get("x_mitre_platforms", [])'''

    new_upsert = '''        deprecated = bool(tech.get("x_mitre_deprecated", False))
        revoked    = bool(tech.get("revoked", False))

        platforms = tech.get("x_mitre_platforms", [])'''

    old_insert = '''        statements.append(
            "INSERT INTO mitre_techniques "
            "(t_code, name, tactic, description, stix_id, platforms, detection_notes, is_subtechnique, parent_t_code) "
            f"VALUES ({e(t_code)}, {e(tech.get('name',''))}, {e(tactic)}, {e(tech.get('description',''))}, "
            f"{e(tech['id'])}, {e_array(platforms)}, {e(detection_notes)}, {e_bool(is_sub)}, {parent_val}) "
            "ON CONFLICT (t_code) DO UPDATE SET "
            "name = EXCLUDED.name, tactic = EXCLUDED.tactic, description = EXCLUDED.description, "
            "stix_id = EXCLUDED.stix_id, platforms = EXCLUDED.platforms, "
            f"is_subtechnique = EXCLUDED.is_subtechnique, parent_t_code = EXCLUDED.parent_t_code{detect_col};"
        )'''

    new_insert = '''        statements.append(
            "INSERT INTO mitre_techniques "
            "(t_code, name, tactic, description, stix_id, platforms, detection_notes, is_subtechnique, parent_t_code, is_deprecated, is_revoked) "
            f"VALUES ({e(t_code)}, {e(tech.get('name',''))}, {e(tactic)}, {e(tech.get('description',''))}, "
            f"{e(tech['id'])}, {e_array(platforms)}, {e(detection_notes)}, {e_bool(is_sub)}, {parent_val}, "
            f"{e_bool(deprecated)}, {e_bool(revoked)}) "
            "ON CONFLICT (t_code) DO UPDATE SET "
            "name = EXCLUDED.name, tactic = EXCLUDED.tactic, description = EXCLUDED.description, "
            "stix_id = EXCLUDED.stix_id, platforms = EXCLUDED.platforms, "
            "is_subtechnique = EXCLUDED.is_subtechnique, parent_t_code = EXCLUDED.parent_t_code, "
            f"is_deprecated = EXCLUDED.is_deprecated, is_revoked = EXCLUDED.is_revoked{detect_col};"
        )'''

    content = content.replace(old_upsert, new_upsert, 1)
    content = content.replace(old_insert, new_insert, 1)
    reparse.write_text(content, encoding="utf-8")
    print("  mitre_reparse_v19.py patched.")

# ── Step 4: Validate endpoint exists in routes ───────────────────────────────

def validate():
    print("\n[4/4] Validating patches...")
    content = ROUTES_FILE.read_text(encoding="utf-8")
    checks = [
        ("/analytics/{t_code} endpoint",  '@router.get("/analytics/{t_code}")'),
        ("deprecated filter on techniques", "COALESCE(is_deprecated, FALSE)"),
        ("threat-profile platforms field",  "mt.platforms"),
        ("threat-profile deprecated filter", "NOT COALESCE(mt.is_deprecated, FALSE)"),
    ]
    all_ok = True
    for label, pattern in checks:
        found = pattern in content
        print(f"  {'[OK]' if found else '[MISSING]'} {label}")
        if not found:
            all_ok = False

    if all_ok:
        print("\n  All patches applied. Next steps:")
        print("  1. Run: python mitre_reparse_v19.py  (populates is_deprecated/is_revoked)")
        print("  2. Restart FastAPI server")
        print("  3. Apply EvidenceWindow.jsx patch")
    else:
        print("\n  Some patches failed — check mitre_routes.py manually.")

# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not ROUTES_FILE.exists():
        print(f"ERROR: {ROUTES_FILE} not found. Run from the backend directory.")
        exit(1)

    apply_db_schema()
    apply_routes_patches()
    patch_reparse()
    validate()