from sqlalchemy.orm import Session
from sqlalchemy import func
from core.models import MitreGroup, MitreTechnique, MitreRelationship, RefArtifact, ThreatAttribution

class CoverageService:
    @staticmethod
    def get_group_coverage(session: Session, group_stix_id: str):
        """
        Emulates DetectionCoverage.py: Performs Gap Analysis for a specific group.
        Logic: Group -> Relationships -> Techniques -> RefArtifact Join.
        """
        # 1. Get all technique IDs used by this group
        rel_subquery = session.query(MitreRelationship.target_ref).filter(
            MitreRelationship.source_ref == group_stix_id,
            MitreRelationship.relationship_type == 'uses'
        ).subquery()

        # 2. Join Techniques with RefArtifact to find the "Gaps"
        # This mirrors the ✅ vs ❌ logic in the standalone table
        results = session.query(
            MitreTechnique.t_code,
            MitreTechnique.name,
            RefArtifact.name.label("artifact_name"),
            RefArtifact.priority
        ).join(
            rel_subquery, MitreTechnique.stix_id == rel_subquery.c.target_ref
        ).outerjoin(
            RefArtifact, MitreTechnique.t_code == RefArtifact.t_code
        ).all()

        techniques_list = []
        covered_count = 0

        for row in results:
            is_covered = row.artifact_name is not None
            if is_covered:
                covered_count += 1

            techniques_list.append({
                "t_code": row.t_code,
                "name": row.name,
                "covered": is_covered,
                "artifact": row.artifact_name or "MISSING",
                "priority": row.priority or "N/A",
                # UI Hint: Standalone used Cyan for covered, Zinc-Red for gaps
                "status_color": "#00bcd4" if is_covered else "#f44336"
            })

        # 3. Calculate Coverage Percentage for the themed ProgressBar
        total_techs = len(techniques_list)
        coverage_pct = (covered_count / total_techs * 100) if total_techs > 0 else 0

        return {
            "coverage_pct": round(coverage_pct, 2),
            "total_techniques": total_techs,
            "covered_techniques": covered_count,
            "techniques": techniques_list
        }

    @staticmethod
    def get_country_nesting(session: Session, country_name: str):
        """
        Toolbar Aspect: Detection Coverage Sidebar
        Logic: Country -> Threat Groups (with coverage summary)
        """
        # Standalone Logic: Use the ThreatAttribution table for precise mapping
        groups = session.query(MitreGroup).join(
            ThreatAttribution, MitreGroup.name == ThreatAttribution.group_name
        ).filter(
            ThreatAttribution.attribution.ilike(f"%{country_name}%")
        ).all()

        nesting = []
        for group in groups:
            # We provide a summary so the UI can show "Group Name (64%)"
            stats = CoverageService.get_group_coverage(session, group.stix_id)
            
            nesting.append({
                "group_name": group.name,
                "group_id": group.stix_id,
                "coverage_pct": stats["coverage_pct"],
                "technique_count": stats["total_techniques"]
            })
            
        return nesting