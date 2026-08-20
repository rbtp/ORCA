import logging
import time

from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import Session as SASession
from sqlalchemy.ext.automap import automap_base

from config import cfg

logger = logging.getLogger(__name__)

_REFLECT_RETRIES = 10
_REFLECT_RETRY_DELAY = 3.0  # seconds


class _DB:
    def __init__(self):
        self.engine = create_engine(cfg.DB_URL)
        self._SessionFactory = sessionmaker(bind=self.engine)

        Base = automap_base()
        for attempt in range(1, _REFLECT_RETRIES + 1):
            try:
                Base.prepare(self.engine, reflect=True)
                break
            except OperationalError:
                if attempt == _REFLECT_RETRIES:
                    raise
                logger.warning(
                    "Database not ready for schema reflection yet (attempt %d/%d) — retrying in %.0fs",
                    attempt, _REFLECT_RETRIES, _REFLECT_RETRY_DELAY,
                )
                time.sleep(_REFLECT_RETRY_DELAY)

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
