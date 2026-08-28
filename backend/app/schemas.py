from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

# Repository Schemas
class RepositoryCreate(BaseModel):
    name: str = Field(..., description="Name of the repository")
    path: str = Field(..., description="Local folder path or git URL")
    branch: Optional[str] = Field("main", description="Target branch to scan")

class RepositoryOut(BaseModel):
    id: int
    name: str
    path: str
    branch: str
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

# Scan Schemas
class ScanStartRequest(BaseModel):
    repository_path: str = Field(..., description="Local git path or remote git URL")
    history_mode: str = Field("full", description="current, full, deep") # current, full, deep
    validate_secrets: bool = Field(False, description="Whether to run active credential checks")

class ScanOut(BaseModel):
    id: int
    repository_id: int
    status: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    commits_scanned: int
    files_scanned: int
    candidates_found: int
    duration_sec: float
    error_message: Optional[str] = None
    
    class Config:
        from_attributes = True

# Occurrence Schemas
class SecretOccurrenceOut(BaseModel):
    id: int
    commit_hash: str
    file_path: str
    line_number: int
    change_type: str
    line_content: str
    context_before: List[str]
    context_after: List[str]
    
    class Config:
        from_attributes = True

# Finding Schemas
class FindingOut(BaseModel):
    id: int
    scan_id: int
    fingerprint: str
    provider: str
    type: str
    masked_value: str
    classification: str
    confidence: float
    risk_score: float
    risk_level: str
    status: str
    validation_status: str
    validation_checked_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True

class FindingDetailsOut(FindingOut):
    rationale: List[str]
    occurrences: List[SecretOccurrenceOut]
    
    class Config:
        from_attributes = True

class FindingStatusUpdate(BaseModel):
    status: str = Field(..., description="ACTIVE, DELETED, FALSE_POSITIVE, ACCEPTED_RISK, TEST_FIXTURE, DOCUMENTATION, RESOLVED")

# Statistics Schemas
class StatisticsOut(BaseModel):
    repositories_scanned: int
    total_findings: int
    critical_findings: int
    high_findings: int
    historical_secrets: int  # count of DELETED status findings
    false_positive_rate: float
    validation_coverage: float

# Health Schema
class HealthOut(BaseModel):
    status: str
    timestamp: datetime
    database: str
