from sqlalchemy import asc, text, or_
from core.database_manager import db

# Define aliases
MitreGroup = db.MitreGroup
MitreSoftware = db.MitreSoftware
MitreTechnique = db.MitreTechnique
MitreTactic = db.MitreTactic
MitreMitigation = db.MitreMitigation
MitreRelationship = db.MitreRelationship
ThreatAttribution = db.ThreatAttribution

class MitreIntelService:
    @staticmethod
    def get_all_geopolitical_groups(session):
        """NEW: Direct flat-list fetch for InvestigationWorkspace."""
        sql = text("""
            SELECT 
                g.id, 
                g.name, 
                COALESCE(t.attribution, 'Global/Unknown') as country
            FROM mitre_groups g
            LEFT JOIN threat_attribution t ON g.name = t.group_name
            ORDER BY g.name ASC
        """)
        try:
            results = session.execute(sql).mappings().all()
            return [dict(row) for row in results]
        except Exception as e:
            print(f"GEO_FETCH_FAILURE: {e}")
            return []

    @staticmethod
    def get_sidebar_structure(session):
        """Categorize groups by country using verified SQL Join."""
        group_sql = text("""
            SELECT 
                g.id, 
                g.name, 
                g.stix_id, 
                COALESCE(t.attribution, 'Global/Unknown') as country
            FROM mitre_groups g
            LEFT JOIN threat_attribution t ON g.name = t.group_name
            ORDER BY country ASC, g.name ASC
        """)
        
        try:
            raw_groups = session.execute(group_sql).mappings().all()
            country_data = {}
            standalone_groups = []
            
            for g in raw_groups:
                country = g['country']
                if country not in country_data:
                    country_data[country] = []
                
                group_obj = {"stix_id": g['stix_id'], "name": g['name'], "id": g['id']}
                country_data[country].append(group_obj)
                standalone_groups.append(group_obj)

            software = [
                {"stix_id": s.stix_id, "name": s.name, "id": s.s_code, "type": s.software_type} 
                for s in session.query(MitreSoftware).order_by(asc(MitreSoftware.name)).all()
            ]

            mitigations = [
                {"stix_id": m.stix_id, "name": m.name, "id": m.m_code} 
                for m in session.query(MitreMitigation).order_by(asc(MitreMitigation.name)).all()
            ]

            return {
                "geopolitical": [
                    {"country_name": k, "associated_groups": v} 
                    for k, v in country_data.items()
                ],
                "groups": standalone_groups,
                "software": software,
                "mitigations": mitigations
            }
        except Exception as e:
            print(f"SIDEBAR_STRUCTURE_FAILURE: {e}")
            return {"geopolitical": [], "groups": [], "software": [], "mitigations": []}

    @staticmethod
    def get_group_details(session, identifier):
        query = text("SELECT * FROM mitre_groups WHERE id = :id OR stix_id = :id")
        result = session.execute(query, {"id": identifier}).mappings().first()
        if not result: return None
        
        data = dict(result)
        stix_id = data.get("stix_id")

        tech_sql = text("""
            SELECT t.t_code, t.name, t.tactic, t.description, t.stix_id
            FROM mitre_techniques t
            JOIN mitre_relationships r ON t.stix_id = r.target_ref
            WHERE r.source_ref = :sid AND r.relationship_type = 'uses'
        """)
        techniques = session.execute(tech_sql, {"sid": stix_id}).mappings().all()

        soft_sql = text("""
            SELECT s.s_code as id, s.name, s.description, s.stix_id
            FROM mitre_software s
            JOIN mitre_relationships r ON s.stix_id = r.target_ref
            WHERE r.source_ref = :sid AND r.relationship_type = 'uses'
        """)
        software = session.execute(soft_sql, {"sid": stix_id}).mappings().all()

        return {
            "id": data.get("id"),
            "stix_id": stix_id,
            "name": data.get("name"),
            "description": data.get("description"),
            "associated_groups": data.get("associated_groups", ""),
            "url": data.get("url", ""),
            "techniques": [dict(t) for t in techniques],
            "software": [dict(s) for s in software]
        }

    @staticmethod
    def get_software_details(session, identifier):
        query = text("SELECT * FROM mitre_software WHERE s_code = :id OR stix_id = :id")
        result = session.execute(query, {"id": identifier}).mappings().first()
        return dict(result) if result else None

    @staticmethod
    def get_mitigation_details(session, identifier):
        query = text("SELECT * FROM mitre_mitigations WHERE m_code = :id OR stix_id = :id")
        result = session.execute(query, {"id": identifier}).mappings().first()
        return dict(result) if result else None

    @staticmethod
    def get_aggregate_techniques(session, stix_ids):
        if not stix_ids: return []
        if isinstance(stix_ids, str): stix_ids = [stix_ids]
        
        query = text("""
            SELECT DISTINCT t.t_code 
            FROM mitre_techniques t
            JOIN mitre_relationships r ON t.stix_id = r.target_ref
            WHERE r.relationship_type = 'uses' AND (
                r.source_ref IN :ids OR 
                r.source_ref IN (
                    SELECT target_ref FROM mitre_relationships 
                    WHERE source_ref IN :ids AND relationship_type = 'uses'
                )
            )
        """)
        try:
            res = session.execute(query, {"ids": tuple(stix_ids)}).fetchall()
            return [r[0] for r in res if r[0]]
        except Exception as e:
            print(f"Aggregation SQL Error: {e}")
            return []

    @staticmethod
    def get_matrix_layout(session):
        try:
            t_sql = text("SELECT name FROM mitre_tactics ORDER BY id ASC")
            tactics_results = session.execute(t_sql).mappings().all()
            tactics = [row['name'] for row in tactics_results]
            
            tech_sql = text("SELECT t_code, name, tactic FROM mitre_techniques")
            all_techs = session.execute(tech_sql).mappings().all()
            
            layout = []
            for t_name in tactics:
                matched = [
                    {"id": tech['t_code'], "name": tech['name']}
                    for tech in all_techs
                    if tech['tactic'] and t_name.lower() in tech['tactic'].lower()
                ]
                layout.append({
                    "tactic": t_name,
                    "techniques": matched
                })
            return layout
        except Exception as e:
            print(f"MATRIX_BUILD_ERROR: {e}")
            return []