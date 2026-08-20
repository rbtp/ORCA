import logging
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy import text
from core.database_manager import db
from auth_utils import get_current_user
from collections import defaultdict

router = APIRouter(prefix="/api/coverage", tags=["coverage"])
logger = logging.getLogger(__name__)


def _covered(vql):
    return bool(vql and vql.strip())


def _partial(vql, yaml):
    return not _covered(vql) and bool(yaml and yaml.strip())


def _build_entry(name, kind, rows, tcode_key="t_code", name_key="technique_name"):
    tcodes = []
    for r in rows:
        tc = r[tcode_key]
        if tc is None:
            continue
        vql = r.get("custom_vql")
        yaml = r.get("surgical_yaml")
        updated = r.get("updated_at")
        tcodes.append({
            "t_code": tc,
            "name": r.get(name_key) or "",
            "has_vql": _covered(vql),
            "has_yaml": bool(yaml and yaml.strip()),
            "updated_at": updated.isoformat() if updated else None,
        })
    total = len(tcodes)
    covered = sum(1 for t in tcodes if t["has_vql"])
    partial = sum(1 for t in tcodes if not t["has_vql"] and t["has_yaml"])
    return {
        "type": kind,
        "name": name,
        "total": total,
        "covered": covered,
        "partial": partial,
        "coverage_pct": round(covered / total * 100, 1) if total else 0,
        "tcodes": tcodes,
    }


@router.get("")
async def get_coverage(current_user: dict = Depends(get_current_user)):
    try:
        with db.engine.connect() as conn:
            # --- Countries: country attribution → MITRE chain → ref_artifact_library ---
            country_rows = conn.execute(text("""
                SELECT DISTINCT
                    ta.attribution AS country,
                    mt.t_code,
                    COALESCE(mt.name, '') AS technique_name,
                    ref.custom_vql,
                    ref.surgical_yaml,
                    ref.updated_at
                FROM threat_attribution ta
                JOIN mitre_actors ma ON ta.group_name = ma.name
                JOIN mitre_relationships ma_rel
                    ON ma.stix_id = ma_rel.source_ref
                    AND ma_rel.relationship_type = 'uses'
                JOIN mitre_techniques mt
                    ON ma_rel.target_ref = mt.stix_id
                    AND NOT COALESCE(mt.is_deprecated, FALSE)
                    AND NOT COALESCE(mt.is_revoked, FALSE)
                JOIN ref_artifact_library ref ON mt.t_code = ref.t_code
                WHERE ta.attribution IS NOT NULL AND ta.attribution != ''
                ORDER BY ta.attribution, mt.t_code
            """)).mappings().all()

            # --- Profiles: direct T-code list from investigation_profiles ---
            profile_rows = conn.execute(text("""
                SELECT
                    ip.id           AS profile_id,
                    ip.name         AS profile_name,
                    t.tcode         AS t_code,
                    COALESCE(mt.name, ref.name, '') AS technique_name,
                    ref.custom_vql,
                    ref.surgical_yaml,
                    ref.updated_at
                FROM investigation_profiles ip
                CROSS JOIN LATERAL UNNEST(ip.tcodes) AS t(tcode)
                LEFT JOIN ref_artifact_library ref ON ref.t_code = t.tcode
                LEFT JOIN mitre_techniques mt ON mt.t_code = t.tcode
                ORDER BY ip.name, t.tcode
            """)).mappings().all()

        # Aggregate countries
        country_map = defaultdict(list)
        for r in country_rows:
            country_map[r["country"]].append(r)

        countries = [
            _build_entry(name, "country", rows)
            for name, rows in sorted(country_map.items())
        ]

        # Aggregate profiles
        profile_map = defaultdict(lambda: {"name": "", "rows": []})
        for r in profile_rows:
            pid = r["profile_id"]
            profile_map[pid]["name"] = r["profile_name"]
            profile_map[pid]["rows"].append(r)

        profiles = [
            _build_entry(data["name"], "profile", data["rows"])
            for data in profile_map.values()
        ]
        profiles.sort(key=lambda x: x["name"])

        return countries + profiles

    except Exception as e:
        logger.error("coverage lookup failed: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to load coverage data")
