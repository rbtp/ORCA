from sqlalchemy import Column, String, Text, Integer, JSON, ForeignKey, DateTime, Boolean, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func

Base = declarative_base()

# --- MITRE ATT&CK KNOWLEDGE BASE ---
class MitreGroup(Base):
    __tablename__ = 'mitre_groups'
    id = Column(String, primary_key=True)
    stix_id = Column(String, unique=True)
    name = Column(String)
    description = Column(Text)
    url = Column(String)
    associated_groups = Column(Text)

class MitreTactic(Base):
    __tablename__ = 'mitre_tactics'
    id = Column(String, primary_key=True)
    stix_id = Column(String, unique=True)
    name = Column(String)
    description = Column(Text)
    url = Column(String)

class MitreTechnique(Base):
    __tablename__ = 'mitre_techniques'
    t_code = Column(String, primary_key=True)
    stix_id = Column(String, unique=True)
    name = Column(String)
    description = Column(Text)
    tactics = Column(String)
    platforms = Column(JSON)

# --- INVESTIGATION METADATA ---
class Case(Base):
    __tablename__ = 'cases'
    name = Column(String, primary_key=True) # Used as the join key in ioc.py
    description = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Asset(Base):
    __tablename__ = 'assets'
    id = Column(Integer, primary_key=True)
    hostname = Column(String)
    case_name = Column(String, ForeignKey('cases.name'))

# --- FORENSIC DATA & IOCS ---
class Evidence(Base):
    __tablename__ = 'evidence'
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey('assets.id'))
    t_code = Column(String)
    raw_data = Column(JSON) # Searched via ILIKE in ioc.py
    file_name = Column(String)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

class DiscoveredIOC(Base):
    __tablename__ = 'discovered_iocs'
    id = Column(Integer, primary_key=True)
    ioc_value = Column(String, nullable=False)
    ioc_type = Column(String)
    case_name = Column(String)
    t_code = Column(String)
    note = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    __table_args__ = (UniqueConstraint('ioc_value', 'case_name', name='_value_case_uc'),)