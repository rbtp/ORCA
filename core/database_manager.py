from sqlalchemy import create_engine, MetaData, Table
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.automap import automap_base

class DatabaseManager:
    def __init__(self):
        # Ensure your DB URL is correct and the DB is up
        self.db_url = "postgresql://postgres:password@localhost/orca_db"
        
        self.engine = create_engine(
            self.db_url,
            pool_size=10,
            max_overflow=5,
            pool_pre_ping=True
        )
        
        self.Session = sessionmaker(bind=self.engine)
        self.metadata = MetaData()
        
        try:
            # Reflect the database
            self.metadata.reflect(bind=self.engine)
            self.Base = automap_base(metadata=self.metadata)
            self.Base.prepare()
            
            classes = self.Base.classes

            def get_model(table_name):
                # 1. Try Automap Class (PascalCase usually)
                for c_name in dir(classes):
                    if c_name.lower() == table_name.replace('_', '').lower() or c_name.lower() == table_name.lower():
                        return getattr(classes, c_name)
                # 2. Try Raw Table Object
                if table_name in self.metadata.tables:
                    return self.metadata.tables[table_name]
                return None

            # --- Mapping ---
            self.MitreGroup = get_model('mitre_groups')
            self.MitreSoftware = get_model('mitre_software')
            self.MitreTechnique = get_model('mitre_techniques')
            self.MitreTactic = get_model('mitre_tactics')
            self.MitreMitigation = get_model('mitre_mitigations')
            self.MitreRelationship = get_model('mitre_relationships')
            self.ThreatAttribution = get_model('threat_attribution')

            self.Case = get_model('cases')
            self.Asset = get_model('assets')
            self.Evidence = get_model('evidence')
            self.ArtifactResult = get_model('artifact_results')
            self.DiscoveredIOC = get_model('discovered_iocs')

            print("\n--- DATABASE_REFLECTION_REPORT ---")
            for attr in ['MitreGroup', 'MitreTechnique', 'MitreTactic', 'Evidence', 'Case']:
                status = "[OK]" if getattr(self, attr) is not None else "[NOT_FOUND]"
                print(f"{attr.ljust(18)}: {status}")
            print("-----------------------------------\n")

        except Exception as e:
            print(f"CRITICAL: Database reflection failed: {e}")

    def get_session(self):
        return self.Session()

db = DatabaseManager()

def get_db():
    session = db.get_session()
    try:
        yield session
    finally:
        session.close()