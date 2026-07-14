from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import Session as SASession
from sqlalchemy.ext.automap import automap_base

from config import cfg


class _DB:
    def __init__(self):
        self.engine = create_engine(cfg.DB_URL)
        self._SessionFactory = sessionmaker(bind=self.engine)

        Base = automap_base()
        Base.prepare(self.engine, reflect=True)

        classes = Base.classes
        self.MitreGroup = classes.mitre_groups
        self.MitreSoftware = classes.mitre_software
        self.MitreTechnique = classes.mitre_techniques
        self.MitreTactic = classes.mitre_tactics
        self.MitreMitigation = classes.mitre_mitigations
        self.MitreRelationship = classes.mitre_relationships
        self.ThreatAttribution = classes.threat_attribution

    def get_session(self) -> SASession:
        return self._SessionFactory()

    def Session(self) -> SASession:
        return self._SessionFactory()


db = _DB()


def get_db():
    session = db._SessionFactory()
    try:
        yield session
    finally:
        session.close()
