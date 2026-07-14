"""
report_routes.py — ORCA Reporting Module
"""

import json as _json

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy import text
from typing import Optional
from datetime import datetime

from core.database_manager import db
from auth_utils import get_current_user

router = APIRouter(prefix="/api/reports")


@router.get("/{case_name}")
async def get_case_report(
    case_name: str,
    asset_id: Optional[int] = None,
    current_user: dict = Depends(get_current_user)
):
    session = db.get_session()
    try:
        # ── Case metadata ──────────────────────────────────────────────────────
        case_row = session.execute(
            text("SELECT name, focus_country, selected_groups, map_data FROM cases WHERE name = :n"),
            {"n": case_name}
        ).mappings().first()

        if not case_row:
            raise HTTPException(status_code=404, detail=f"Case '{case_name}' not found")

        focus_country   = case_row["focus_country"]
        raw_groups = case_row["selected_groups"] or ""
        selected_groups = [g.strip() for g in raw_groups.split(",") if g.strip()] if raw_groups else []

        raw_map = case_row["map_data"]
        if isinstance(raw_map, dict):
            map_data = raw_map
        elif isinstance(raw_map, str) and raw_map:
            try:
                map_data = _json.loads(raw_map)
            except Exception:
                map_data = {"nodes": [], "links": []}
        else:
            map_data = {"nodes": [], "links": []}

        # ── Assets ────────────────────────────────────────────────────────────
        assets = session.execute(text("""
            SELECT id, hostname, os, asset_type, analysis_mode
            FROM assets
            WHERE case_name = :cn
            ORDER BY hostname
        """), {"cn": case_name}).mappings().all()
        assets_list = [dict(a) for a in assets]

        if asset_id:
            scoped_asset_ids = [asset_id]
        else:
            scoped_asset_ids = [a["id"] for a in assets_list]

        # ── Technique results ─────────────────────────────────────────────────
        # Support both country-based and group-based investigations
        if focus_country:
            tech_rows = session.execute(text("""
                SELECT
                    mt.t_code,
                    mt.name            AS technique_name,
                    mt.description     AS technique_description,
                    string_agg(DISTINCT ta.group_name, ', ') AS associated_actors,
                    CASE
                        WHEN bool_or(ar.verdict = 'MALICIOUS')       THEN 'MALICIOUS'
                        WHEN bool_or(ar.verdict = 'NON-MALICIOUS')   THEN 'NON-MALICIOUS'
                        WHEN bool_or(ar.verdict = 'Evidence Found')  THEN 'Evidence Found'
                        WHEN bool_or(ar.verdict = 'NO_ARTIFACTS')    THEN 'NO_ARTIFACTS'
                        ELSE 'Undetermined'
                    END AS verdict,
                    CASE
                        WHEN bool_or(ar.technique_status = 'CLOSED')          THEN 'CLOSED'
                        WHEN bool_or(ar.technique_status = 'PENDING_REVIEW')  THEN 'PENDING_REVIEW'
                        WHEN bool_or(ar.technique_status = 'IN_PROGRESS')     THEN 'IN_PROGRESS'
                        ELSE 'UNCLAIMED'
                    END AS technique_status,
                    bool_or(COALESCE(ar.evidence_imported, FALSE)) AS evidence_imported,
                    MAX(ar.closed_at)  AS closed_at
                FROM threat_attribution ta
                JOIN mitre_actors ma        ON ta.group_name = ma.name
                JOIN mitre_relationships mr ON ma.stix_id = mr.source_ref
                JOIN mitre_techniques mt    ON mr.target_ref = mt.stix_id
                JOIN ref_artifact_library ref ON mt.t_code = ref.t_code
                LEFT JOIN artifact_results ar ON (
                    ar.t_code = mt.t_code
                    AND ar.asset_id = ANY(:asset_ids)
                )
                WHERE UPPER(ta.attribution) = UPPER(:country)
                  AND mr.relationship_type = 'uses'
                  AND NOT COALESCE(mt.is_deprecated, FALSE)
                  AND NOT COALESCE(mt.is_revoked, FALSE)
                GROUP BY mt.t_code, mt.name, mt.description
                ORDER BY mt.t_code
            """), {"country": focus_country, "asset_ids": scoped_asset_ids}).mappings().all()

        else:
            # Group-name fallback (no country set)
            tech_rows = session.execute(text("""
                SELECT
                    mt.t_code,
                    mt.name            AS technique_name,
                    mt.description     AS technique_description,
                    string_agg(DISTINCT ta.group_name, ', ') AS associated_actors,
                    CASE
                        WHEN bool_or(ar.verdict = 'MALICIOUS')       THEN 'MALICIOUS'
                        WHEN bool_or(ar.verdict = 'NON-MALICIOUS')   THEN 'NON-MALICIOUS'
                        WHEN bool_or(ar.verdict = 'Evidence Found')  THEN 'Evidence Found'
                        WHEN bool_or(ar.verdict = 'NO_ARTIFACTS')    THEN 'NO_ARTIFACTS'
                        ELSE 'Undetermined'
                    END AS verdict,
                    CASE
                        WHEN bool_or(ar.technique_status = 'CLOSED')          THEN 'CLOSED'
                        WHEN bool_or(ar.technique_status = 'PENDING_REVIEW')  THEN 'PENDING_REVIEW'
                        WHEN bool_or(ar.technique_status = 'IN_PROGRESS')     THEN 'IN_PROGRESS'
                        ELSE 'UNCLAIMED'
                    END AS technique_status,
                    bool_or(COALESCE(ar.evidence_imported, FALSE)) AS evidence_imported,
                    MAX(ar.closed_at) AS closed_at
                FROM threat_attribution ta
                JOIN mitre_actors ma        ON ta.group_name = ma.name
                JOIN mitre_relationships mr ON ma.stix_id = mr.source_ref
                JOIN mitre_techniques mt    ON mr.target_ref = mt.stix_id
                JOIN ref_artifact_library ref ON mt.t_code = ref.t_code
                LEFT JOIN artifact_results ar ON (
                    ar.t_code = mt.t_code
                    AND ar.asset_id = ANY(:asset_ids)
                )
                WHERE ta.group_name = ANY(:groups)
                  AND mr.relationship_type = 'uses'
                  AND NOT COALESCE(mt.is_deprecated, FALSE)
                  AND NOT COALESCE(mt.is_revoked, FALSE)
                GROUP BY mt.t_code, mt.name, mt.description
                ORDER BY mt.t_code
            """), {"groups": selected_groups, "asset_ids": scoped_asset_ids}).mappings().all()

        tech_list = [dict(t) for t in tech_rows]

        # ── Per-asset technique breakdown ─────────────────────────────────────
        # Full threat-profile technique list per asset, LEFT JOIN so untouched
        # techniques still appear (blank verdict/status) — usable as a checklist.
        per_asset_techniques = {}
        if scoped_asset_ids and tech_list:
            all_t_codes = [t["t_code"] for t in tech_list]
            for aid in scoped_asset_ids:
                if focus_country:
                    rows = session.execute(text("""
                        SELECT
                            :asset_id                AS asset_id,
                            mt.t_code,
                            mt.name                  AS technique_name,
                            mt.description           AS technique_description,
                            string_agg(DISTINCT ta.group_name, ', ') AS associated_actors,
                            ar.verdict,
                            ar.technique_status,
                            ar.evidence_imported,
                            ar.closed_at
                        FROM threat_attribution ta
                        JOIN mitre_actors ma        ON ta.group_name = ma.name
                        JOIN mitre_relationships mr ON ma.stix_id = mr.source_ref
                        JOIN mitre_techniques mt    ON mr.target_ref = mt.stix_id
                        JOIN ref_artifact_library ref ON mt.t_code = ref.t_code
                        LEFT JOIN artifact_results ar ON (
                            ar.t_code = mt.t_code AND ar.asset_id = :asset_id
                        )
                        WHERE UPPER(ta.attribution) = UPPER(:country)
                          AND mr.relationship_type = 'uses'
                          AND NOT COALESCE(mt.is_deprecated, FALSE)
                          AND NOT COALESCE(mt.is_revoked, FALSE)
                        GROUP BY mt.t_code, mt.name, mt.description,
                                 ar.verdict, ar.technique_status,
                                 ar.evidence_imported, ar.closed_at
                        ORDER BY mt.t_code
                    """), {"asset_id": aid, "country": focus_country}).mappings().all()
                else:
                    rows = session.execute(text("""
                        SELECT
                            :asset_id                AS asset_id,
                            mt.t_code,
                            mt.name                  AS technique_name,
                            mt.description           AS technique_description,
                            string_agg(DISTINCT ta.group_name, ', ') AS associated_actors,
                            ar.verdict,
                            ar.technique_status,
                            ar.evidence_imported,
                            ar.closed_at
                        FROM threat_attribution ta
                        JOIN mitre_actors ma        ON ta.group_name = ma.name
                        JOIN mitre_relationships mr ON ma.stix_id = mr.source_ref
                        JOIN mitre_techniques mt    ON mr.target_ref = mt.stix_id
                        JOIN ref_artifact_library ref ON mt.t_code = ref.t_code
                        LEFT JOIN artifact_results ar ON (
                            ar.t_code = mt.t_code AND ar.asset_id = :asset_id
                        )
                        WHERE ta.group_name = ANY(:groups)
                          AND mr.relationship_type = 'uses'
                          AND NOT COALESCE(mt.is_deprecated, FALSE)
                          AND NOT COALESCE(mt.is_revoked, FALSE)
                        GROUP BY mt.t_code, mt.name, mt.description,
                                 ar.verdict, ar.technique_status,
                                 ar.evidence_imported, ar.closed_at
                        ORDER BY mt.t_code
                    """), {"asset_id": aid, "groups": selected_groups}).mappings().all()

                per_asset_techniques[aid] = [dict(r) for r in rows]

        # ── Summary counts ────────────────────────────────────────────────────
        total         = len(tech_list)
        closed        = sum(1 for t in tech_list if (t["verdict"] or "").upper() in ("MALICIOUS", "NON-MALICIOUS"))
        with_evidence = sum(1 for t in tech_list if t["evidence_imported"])
        no_artifacts  = sum(1 for t in tech_list if (t["verdict"] or "").upper() == "NO_ARTIFACTS")
        pending       = total - with_evidence - no_artifacts
        malicious     = sum(1 for t in tech_list if (t["verdict"] or "").upper() == "MALICIOUS")
        non_malicious = sum(1 for t in tech_list if (t["verdict"] or "").upper() == "NON-MALICIOUS")
        evidence_found = sum(1 for t in tech_list if (t["verdict"] or "").upper() == "EVIDENCE FOUND")
        undetermined  = sum(1 for t in tech_list if (t["verdict"] or "") in ("", "Undetermined"))
        completion_pct = round((closed / total * 100), 1) if total > 0 else 0.0

        # ── BLUF notes (case-level) ────────────────────────────────────────────
        bluf_notes = session.execute(text("""
            SELECT n.note_text AS text, u.username AS author, n.created_at
            FROM case_notes n
            LEFT JOIN users u ON n.author_id = u.id
            WHERE n.case_name = :cn
              AND n.note_type = 'BLUF'
            ORDER BY n.created_at DESC
        """), {"cn": case_name}).mappings().all()

        # ── Timeline (tcode notes across scoped assets) ───────────────────────
        timeline = session.execute(text("""
            SELECT
                n.t_code,
                n.note_text        AS text,
                n.note_type,
                n.author_initials  AS initials,
                u.username         AS author,
                n.created_at,
                n.asset_id
            FROM tcode_notes n
            LEFT JOIN users u ON n.author_id = u.id
            WHERE n.asset_id = ANY(:asset_ids)
            ORDER BY n.created_at ASC
        """), {"asset_ids": scoped_asset_ids}).mappings().all()

        return {
            "case_name":     case_name,
            "focus_country": focus_country,
            "generated_at":  datetime.utcnow().isoformat(),
            "summary": {
                "total_techniques": total,
                "closed":           closed,
                "with_evidence":    with_evidence,
                "no_artifacts":     no_artifacts,
                "pending":          pending,
                "completion_pct":   completion_pct,
                "malicious":        malicious,
                "non_malicious":    non_malicious,
                "evidence_found":   evidence_found,
                "undetermined":     undetermined,
            },
            "bluf_notes":           [dict(n) for n in bluf_notes],
            "timeline":             [dict(t) for t in timeline],
            "techniques":           tech_list,
            "assets":               assets_list,
            "per_asset_techniques": per_asset_techniques,
            "map_data":             map_data,
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

import subprocess, tempfile, os, io, shutil
from fastapi.responses import StreamingResponse
from fastapi import Query

@router.post("/{case_name}/export")
async def export_report(
    case_name: str,
    format: str = Query("docx"),
    sections: list = None,
    range_from: Optional[str] = None,
    range_to: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    import json
    report_data = await get_case_report(case_name, current_user=current_user)

    default_sections = [
        {"id": "summary",  "detail": False},
        {"id": "network",  "detail": False},
        {"id": "assets",   "detail": False},
        {"id": "bluf",     "detail": False},
        {"id": "timeline", "detail": False},
        {"id": "verdicts", "detail": False},
    ]

    payload = {
        "report":     report_data,
        "sections":   sections or default_sections,
        "range_from": range_from,
        "range_to":   range_to,
    }

    safe_name = case_name.replace(" ", "_")
    tmp_dir   = tempfile.mkdtemp()
    try:
        json_path = os.path.join(tmp_dir, "payload.json")
        docx_path = os.path.join(tmp_dir, "report.docx")

        with open(json_path, "w") as f:
            json.dump(payload, f, default=str)

        script_path = os.path.join(os.path.dirname(__file__), "report_gen.js")
        result = subprocess.run(
            ["node", script_path, json_path, docx_path],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0 or not os.path.exists(docx_path):
            raise HTTPException(status_code=500, detail=f"report_gen.js error: {result.stderr}")

        if format == "pdf":
            pdf_path = os.path.join(tmp_dir, "report.pdf")
            result = subprocess.run(
                ["soffice", "--headless", "--convert-to", "pdf", "--outdir", tmp_dir, docx_path],
                capture_output=True, text=True, timeout=120,
                env={**os.environ, "HOME": tmp_dir},
            )
            if result.returncode != 0 or not os.path.exists(pdf_path):
                raise HTTPException(status_code=500, detail=f"PDF conversion failed: {result.stderr.strip()}")
            with open(pdf_path, "rb") as f:
                content = f.read()
            return StreamingResponse(
                io.BytesIO(content),
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="{safe_name}_report.pdf"'},
            )

        with open(docx_path, "rb") as f:
            content = f.read()
        return StreamingResponse(
            io.BytesIO(content),
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": f'attachment; filename="{safe_name}_report.docx"'},
        )
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)