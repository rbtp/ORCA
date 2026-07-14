from sqlalchemy.orm import Session
from sqlalchemy.dialects.postgresql import insert
from core.models import RefArtifact

class LibraryService:
    @staticmethod
    def get_all_artifacts(session: Session):
        """Returns all artifacts, ordered by Priority for the UI Grid."""
        return session.query(RefArtifact).order_by(RefArtifact.priority.desc()).all()

    @staticmethod
    def upsert_artifact(session: Session, artifact_data: dict):
        """
        Emulates Standalone 'Save to Postgres' Logic:
        If the T-Code exists, update it. If not, create it.
        This ensures the Detection Coverage ✅ status updates immediately.
        """
        t_code = artifact_data.get('t_code')
        if not t_code:
            return None

        # Standardizing multi-line text blocks from the Web UI to Postgres strings
        # Mirrors the formatted_steps = "\n".join(new_data['dead_disk_analysis']) logic
        for field in ['dead_disk_analysis', 'live_analysis', 'analysis_steps']:
            if field in artifact_data and isinstance(artifact_data[field], list):
                artifact_data[field] = "\n".join(artifact_data[field])

        # SQLAlchemy Core Upsert (PostgreSQL On Conflict)
        stmt = insert(RefArtifact).values(**artifact_data)
        
        # We update everything except the primary key and the t_code itself
        update_cols = {c.name: c for c in stmt.excluded if c.name not in ['id', 't_code']}
        
        upsert_stmt = stmt.on_conflict_do_update(
            index_elements=['t_code'],
            set_=update_cols
        )

        session.execute(upsert_stmt)
        session.commit()
        
        return session.query(RefArtifact).filter_by(t_code=t_code).first()

    @staticmethod
    def get_artifact_by_tcode(session: Session, t_code: str):
        """Fetches a single artifact for the 'Right-Drawer' editor in the UI."""
        return session.query(RefArtifact).filter_by(t_code=t_code).first()

    @staticmethod
    def delete_artifact(session: Session, t_code: str):
        """Removes an artifact from the library (Step 0 of the Standalone Wizard)."""
        artifact = session.query(RefArtifact).filter_by(t_code=t_code).first()
        if artifact:
            session.delete(artifact)
            session.commit()
            return True
        return False