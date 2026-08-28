from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from backend.app.database import Base

class Repository(Base):
    __tablename__ = "repositories"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    path = Column(String, unique=True, index=True)
    branch = Column(String, default="main")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    scans = relationship("Scan", back_populates="repository", cascade="all, delete-orphan")

class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    repository_id = Column(Integer, ForeignKey("repositories.id", ondelete="CASCADE"))
    status = Column(String, default="PENDING") # PENDING, RUNNING, COMPLETED, FAILED
    started_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    commits_scanned = Column(Integer, default=0)
    files_scanned = Column(Integer, default=0)
    candidates_found = Column(Integer, default=0)
    duration_sec = Column(Float, default=0.0)
    error_message = Column(Text, nullable=True)
    
    repository = relationship("Repository", back_populates="scans")
    commits = relationship("Commit", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

class Commit(Base):
    __tablename__ = "commits"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"))
    hash = Column(String, index=True)
    parent_hash = Column(String, nullable=True)
    author = Column(String)
    email = Column(String)
    timestamp = Column(Integer)
    message = Column(Text)
    
    scan = relationship("Scan", back_populates="commits")

class Finding(Base):
    __tablename__ = "findings"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"))
    fingerprint = Column(String, index=True)
    provider = Column(String, index=True)
    type = Column(String)
    masked_value = Column(String)
    classification = Column(String, index=True) # REAL_SECRET, PLACEHOLDER, TEST_FIXTURE, DOCUMENTATION_EXAMPLE, RANDOM_VALUE, UNKNOWN
    confidence = Column(Float, default=0.5)
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String, index=True) # INFO, LOW, MEDIUM, HIGH, CRITICAL
    rationale = Column(Text) # JSON serialized array of strings
    status = Column(String, default="ACTIVE") # ACTIVE, DELETED, FALSE_POSITIVE, ACCEPTED_RISK, TEST_FIXTURE, DOCUMENTATION, RESOLVED
    validation_status = Column(String, default="NOT_CHECKED") # VALID, INVALID, EXPIRED, REVOKED, UNKNOWN, NOT_SUPPORTED
    validation_checked_at = Column(DateTime, nullable=True)
    
    scan = relationship("Scan", back_populates="findings")
    occurrences = relationship("SecretOccurrence", back_populates="finding", cascade="all, delete-orphan")

class SecretOccurrence(Base):
    __tablename__ = "secret_occurrences"
    
    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id", ondelete="CASCADE"))
    commit_hash = Column(String, index=True)
    file_path = Column(String, index=True)
    line_number = Column(Integer)
    change_type = Column(String) # ADDED, DELETED
    line_content = Column(Text)
    context_before = Column(Text) # JSON serialized list of strings
    context_after = Column(Text) # JSON serialized list of strings
    
    finding = relationship("Finding", back_populates="occurrences")
