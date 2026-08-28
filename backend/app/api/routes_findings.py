from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
import json

from backend.app.database import get_db
from backend.app.models import Finding, SecretOccurrence
from backend.app.schemas import FindingOut, FindingDetailsOut, FindingStatusUpdate, SecretOccurrenceOut

router = APIRouter(prefix="/api/findings", tags=["Findings"])

@router.get("", response_model=List[FindingOut])
def get_findings(
    scan_id: Optional[int] = None,
    risk_level: Optional[str] = None,
    status: Optional[str] = None,
    classification: Optional[str] = None,
    provider: Optional[str] = None,
    validation_status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(Finding)
    
    if scan_id is not None:
        query = query.filter(Finding.scan_id == scan_id)
    if risk_level is not None:
        query = query.filter(Finding.risk_level == risk_level)
    if status is not None:
        query = query.filter(Finding.status == status)
    if classification is not None:
        query = query.filter(Finding.classification == classification)
    if provider is not None:
        query = query.filter(Finding.provider == provider)
    if validation_status is not None:
        query = query.filter(Finding.validation_status == validation_status)
        
    return query.order_by(Finding.risk_score.desc()).all()

@router.get("/{finding_id}", response_model=FindingDetailsOut)
def get_finding_details(finding_id: int, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding with ID {finding_id} not found."
        )
        
    # Deserialize JSON fields for response mapping
    rationale_list = json.loads(finding.rationale) if finding.rationale else []
    
    # Load and map occurrences
    occurrences_list = []
    for occ in finding.occurrences:
        occurrences_list.append(SecretOccurrenceOut(
            id=occ.id,
            commit_hash=occ.commit_hash,
            file_path=occ.file_path,
            line_number=occ.line_number,
            change_type=occ.change_type,
            line_content=occ.line_content,
            context_before=json.loads(occ.context_before) if occ.context_before else [],
            context_after=json.loads(occ.context_after) if occ.context_after else []
        ))
        
    return FindingDetailsOut(
        id=finding.id,
        scan_id=finding.scan_id,
        fingerprint=finding.fingerprint,
        provider=finding.provider,
        type=finding.type,
        masked_value=finding.masked_value,
        classification=finding.classification,
        confidence=finding.confidence,
        risk_score=finding.risk_score,
        risk_level=finding.risk_level,
        status=finding.status,
        validation_status=finding.validation_status,
        validation_checked_at=finding.validation_checked_at,
        rationale=rationale_list,
        occurrences=occurrences_list
    )

@router.put("/{finding_id}/status", response_model=FindingOut)
def update_finding_status(
    finding_id: int,
    payload: FindingStatusUpdate,
    db: Session = Depends(get_db)
):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding with ID {finding_id} not found."
        )
        
    valid_statuses = ["ACTIVE", "DELETED", "FALSE_POSITIVE", "ACCEPTED_RISK", "TEST_FIXTURE", "DOCUMENTATION", "RESOLVED"]
    if payload.status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status '{payload.status}'. Allowed statuses: {', '.join(valid_statuses)}"
        )
        
    finding.status = payload.status
    db.commit()
    db.refresh(finding)
    
    return finding
