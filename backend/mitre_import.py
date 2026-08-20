"""
mitre_import.py — loads a MITRE ATT&CK STIX 2.1 bundle (e.g.
enterprise-attack.json from https://github.com/mitre-attack/attack-stix-data)
into mitre_groups / mitre_software / mitre_mitigations / mitre_techniques /
mitre_tactics / mitre_relationships.

Deliberately does NOT touch ref_artifact_library (ORCA's own analyst-curated
collection-strategy mapping, keyed by t_code but populated separately) or
mitre_techniques.detection_notes/kape_targets (analyst-editable fields with
no equivalent in raw STIX data) -- those columns are only ever set on first
INSERT for a technique, never overwritten by a re-import.

Usable two ways:
  - Imported and called by main.py's startup hook (auto-import on first boot
    if the MITRE tables are empty).
  - Run standalone to (re-)import an updated bundle:
        python mitre_import.py [path/to/enterprise-attack.json]
    (defaults to cfg.MITRE_ATTACK_JSON if no path given)
"""

import json
import logging
import sys
from datetime import datetime
from pathlib import Path

from sqlalchemy import text

logger = logging.getLogger(__name__)


def _parse_ts(raw):
    """STIX timestamps are ISO8601 with a trailing 'Z' -- Python's
    datetime.fromisoformat() on 3.9 doesn't accept 'Z' directly."""
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).replace(tzinfo=None)
    except (ValueError, AttributeError):
        return None


def _external_id(obj, source_name="mitre-attack"):
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") == source_name and ref.get("external_id"):
            return ref["external_id"], ref.get("url")
    return None, None


def _version(obj):
    raw = obj.get("x_mitre_version")
    if raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def _domain(obj):
    domains = obj.get("x_mitre_domains") or []
    return domains[0] if domains else None


def parse_stix_bundle(bundle: dict) -> dict:
    """Pure function: STIX bundle dict -> {table_name: [row_dict, ...]}.
    No DB access, easy to unit test independently of the import step."""
    objects = bundle.get("objects") or []

    tactics_by_shortname = {}
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic":
            shortname = obj.get("x_mitre_shortname")
            if shortname:
                tactics_by_shortname[shortname] = obj.get("name", "")

    groups, software, mitigations, techniques, tactics, relationships = [], [], [], [], [], []
    skipped = {"groups": 0, "software": 0, "mitigations": 0, "techniques": 0, "tactics": 0}

    for obj in objects:
        otype = obj.get("type")

        if otype == "intrusion-set":
            g_id, url = _external_id(obj)
            if not g_id:
                skipped["groups"] += 1
                continue
            groups.append({
                "id": g_id,
                "stix_id": obj.get("id"),
                "name": obj.get("name"),
                "description": obj.get("description"),
                "url": url,
                "created": obj.get("created"),
                "last_modified": obj.get("modified"),
                "domain": _domain(obj),
                "version": _version(obj),
                "contributors": "; ".join(obj.get("x_mitre_contributors") or []) or None,
                "aliases": obj.get("aliases") or [],
            })

        elif otype in ("malware", "tool"):
            s_id, _url = _external_id(obj)
            software.append({
                "stix_id": obj.get("id"),
                "s_code": s_id,
                "name": obj.get("name"),
                "description": obj.get("description"),
                "software_type": otype,
                "platforms": json.dumps(obj.get("x_mitre_platforms") or []),
                "modified_at": _parse_ts(obj.get("modified")),
            })
            if not s_id:
                skipped["software"] += 1

        elif otype == "course-of-action":
            m_id, _url = _external_id(obj)
            mitigations.append({
                "stix_id": obj.get("id"),
                "m_code": m_id,
                "name": obj.get("name"),
                "description": obj.get("description"),
            })
            if not m_id:
                skipped["mitigations"] += 1

        elif otype == "attack-pattern":
            t_id, _url = _external_id(obj)
            if not t_id:
                skipped["techniques"] += 1
                continue
            phase_names = [
                tactics_by_shortname.get(kcp.get("phase_name"), kcp.get("phase_name"))
                for kcp in (obj.get("kill_chain_phases") or [])
                if kcp.get("kill_chain_name") == "mitre-attack" and kcp.get("phase_name")
            ]
            techniques.append({
                "stix_id": obj.get("id"),
                "t_code": t_id,
                "name": obj.get("name"),
                "description": obj.get("description"),
                "platforms": json.dumps(obj.get("x_mitre_platforms") or []),
                "tactic": ", ".join(phase_names) or None,
                "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", False)),
                "modified_at": _parse_ts(obj.get("modified")),
                "parent_t_code": t_id.split(".")[0] if "." in t_id else None,
                "is_deprecated": bool(obj.get("x_mitre_deprecated", False)),
                "is_revoked": bool(obj.get("revoked", False)),
            })

        elif otype == "x-mitre-tactic":
            ta_id, url = _external_id(obj)
            if not ta_id:
                skipped["tactics"] += 1
                continue
            tactics.append({
                "id": ta_id,
                "stix_id": obj.get("id"),
                "name": obj.get("name"),
                "description": obj.get("description"),
                "url": url,
                "created": obj.get("created"),
                "last_modified": obj.get("modified"),
                "domain": _domain(obj),
                "version": _version(obj),
                "shortname": obj.get("x_mitre_shortname"),
            })

        elif otype == "relationship":
            relationships.append({
                "stix_id": obj.get("id"),
                "source_ref": obj.get("source_ref"),
                "target_ref": obj.get("target_ref"),
                "relationship_type": obj.get("relationship_type"),
                "modified_at": _parse_ts(obj.get("modified")),
                "description": obj.get("description"),
            })

    if any(skipped.values()):
        logger.warning("mitre_import: skipped objects with no mitre-attack external_id: %s", skipped)

    return {
        "groups": groups, "software": software, "mitigations": mitigations,
        "techniques": techniques, "tactics": tactics, "relationships": relationships,
    }


def _upsert_many(conn, sql, rows):
    for row in rows:
        conn.execute(text(sql), row)


def import_into_db(parsed: dict, conn) -> dict:
    """Upserts parsed STIX data into the DB. `conn` is an open SQLAlchemy
    connection/session with an active transaction the caller controls
    (commits itself -- this function doesn't call commit())."""

    _upsert_many(conn, """
        INSERT INTO public.mitre_groups
            (id, stix_id, name, description, url, created, last_modified, domain, version, contributors, aliases)
        VALUES
            (:id, :stix_id, :name, :description, :url, :created, :last_modified, :domain, :version, :contributors, :aliases)
        ON CONFLICT (id) DO UPDATE SET
            stix_id = EXCLUDED.stix_id, name = EXCLUDED.name, description = EXCLUDED.description,
            url = EXCLUDED.url, created = EXCLUDED.created, last_modified = EXCLUDED.last_modified,
            domain = EXCLUDED.domain, version = EXCLUDED.version, contributors = EXCLUDED.contributors,
            aliases = EXCLUDED.aliases
    """, parsed["groups"])

    _upsert_many(conn, """
        INSERT INTO public.mitre_mitigations (stix_id, m_code, name, description)
        VALUES (:stix_id, :m_code, :name, :description)
        ON CONFLICT (stix_id) DO UPDATE SET
            m_code = EXCLUDED.m_code, name = EXCLUDED.name, description = EXCLUDED.description
    """, parsed["mitigations"])

    _upsert_many(conn, """
        INSERT INTO public.mitre_software (stix_id, s_code, name, description, software_type, platforms, modified_at)
        VALUES (:stix_id, :s_code, :name, :description, :software_type, CAST(:platforms AS jsonb), :modified_at)
        ON CONFLICT (stix_id) DO UPDATE SET
            s_code = EXCLUDED.s_code, name = EXCLUDED.name, description = EXCLUDED.description,
            software_type = EXCLUDED.software_type, platforms = EXCLUDED.platforms, modified_at = EXCLUDED.modified_at
    """, parsed["software"])

    _upsert_many(conn, """
        INSERT INTO public.mitre_tactics
            (id, stix_id, name, description, url, created, last_modified, domain, version, shortname)
        VALUES
            (:id, :stix_id, :name, :description, :url, :created, :last_modified, :domain, :version, :shortname)
        ON CONFLICT (id) DO UPDATE SET
            stix_id = EXCLUDED.stix_id, name = EXCLUDED.name, description = EXCLUDED.description,
            url = EXCLUDED.url, created = EXCLUDED.created, last_modified = EXCLUDED.last_modified,
            domain = EXCLUDED.domain, version = EXCLUDED.version, shortname = EXCLUDED.shortname
    """, parsed["tactics"])

    # detection_notes / kape_targets deliberately excluded from DO UPDATE SET
    # -- only ever populated on first INSERT (defaults to NULL there too,
    # since raw STIX has no equivalent field), never clobbered by a re-import
    # after an analyst has filled them in some other way.
    _upsert_many(conn, """
        INSERT INTO public.mitre_techniques
            (stix_id, t_code, name, description, platforms, tactic, is_subtechnique,
             modified_at, parent_t_code, is_deprecated, is_revoked)
        VALUES
            (:stix_id, :t_code, :name, :description, CAST(:platforms AS jsonb), :tactic, :is_subtechnique,
             :modified_at, :parent_t_code, :is_deprecated, :is_revoked)
        ON CONFLICT (stix_id) DO UPDATE SET
            t_code = EXCLUDED.t_code, name = EXCLUDED.name, description = EXCLUDED.description,
            platforms = EXCLUDED.platforms, tactic = EXCLUDED.tactic,
            is_subtechnique = EXCLUDED.is_subtechnique, modified_at = EXCLUDED.modified_at,
            parent_t_code = EXCLUDED.parent_t_code, is_deprecated = EXCLUDED.is_deprecated,
            is_revoked = EXCLUDED.is_revoked
    """, parsed["techniques"])

    # Relationships reference other objects by stix_id, so must load after
    # every table above so nothing (foreign-key-less, but logically
    # dependent) references a row that doesn't exist yet.
    _upsert_many(conn, """
        INSERT INTO public.mitre_relationships
            (stix_id, source_ref, target_ref, relationship_type, modified_at, description)
        VALUES
            (:stix_id, :source_ref, :target_ref, :relationship_type, :modified_at, :description)
        ON CONFLICT (stix_id) DO UPDATE SET
            source_ref = EXCLUDED.source_ref, target_ref = EXCLUDED.target_ref,
            relationship_type = EXCLUDED.relationship_type, modified_at = EXCLUDED.modified_at,
            description = EXCLUDED.description
    """, parsed["relationships"])

    return {k: len(v) for k, v in parsed.items()}


def import_mitre_attack_json(filepath, conn) -> dict:
    """Load and import a single STIX bundle file. Caller commits."""
    with open(filepath, "r", encoding="utf-8") as f:
        bundle = json.load(f)
    parsed = parse_stix_bundle(bundle)
    counts = import_into_db(parsed, conn)
    logger.info("mitre_import: imported from %s -> %s", filepath, counts)
    return counts


def mitre_tables_are_empty(conn) -> bool:
    row = conn.execute(text("SELECT COUNT(*) FROM public.mitre_techniques")).fetchone()
    return not row or row[0] == 0


def auto_import_if_empty(engine, filepath):
    """Startup-hook entry point: import filepath into the MITRE tables only
    if they're currently empty. Never raises -- a missing/bad file or a
    parse error is logged and the app continues booting without MITRE
    data rather than crashing the whole backend over it."""
    # This codebase has no root logging configuration anywhere, so the
    # default level is WARNING -- logger.info() calls are silently
    # swallowed. Both of these are one-time, operator-relevant startup
    # signals (empty air-gapped install with no data loaded yet / a fresh
    # successful import), so they're logged at WARNING to actually be seen
    # without requiring a separate logging-config change.
    if not filepath or not Path(filepath).exists():
        logger.warning("mitre_import: no MITRE ATT&CK JSON at %s -- skipping auto-import "
                        "(MITRE Navigator/threat-profile features will be empty until one is provided)", filepath)
        return
    try:
        with engine.connect() as conn:
            if not mitre_tables_are_empty(conn):
                logger.info("mitre_import: mitre_techniques already populated -- skipping auto-import "
                             "(re-run `python mitre_import.py` manually to refresh)")
                return
            counts = import_mitre_attack_json(filepath, conn)
            conn.commit()
            logger.warning("mitre_import: auto-import complete -- %s", counts)
    except Exception as e:
        logger.error("mitre_import: auto-import from %s failed: %s", filepath, e, exc_info=True)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    from core.database_manager import db
    from config import cfg

    path = sys.argv[1] if len(sys.argv) > 1 else cfg.MITRE_ATTACK_JSON
    if not Path(path).exists():
        print(f"ERROR: {path} not found.")
        sys.exit(1)

    with db.engine.connect() as conn:
        counts = import_mitre_attack_json(path, conn)
        conn.commit()
    print(f"Import complete: {counts}")
