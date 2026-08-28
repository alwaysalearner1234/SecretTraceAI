from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime
import json
import os

from backend.app.database import get_db
from backend.app.models import Finding, Repository
from scanner.history.git_walker import GitWalker
from scanner.detector.candidate_extractor import CandidateExtractor
from scanner.validation.credential_validator import CredentialValidator
from scanner.classifier.model import LocalClassifier

router = APIRouter(prefix="/api/findings", tags=["Validation"])

@router.post("/{finding_id}/validate")
def validate_finding(finding_id: int, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding with ID {finding_id} not found."
        )
        
    # Get the repository associated with this scan
    repo = db.query(Repository).filter(Repository.id == finding.scan.repository_id).first()
    if not repo or not os.path.exists(repo.path):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Local repository files are no longer available on disk to extract raw secret."
        )
        
    # Retrieve the latest addition occurrence to locate the secret
    occurrences = [occ for occ in finding.occurrences if occ.change_type == "ADDED"]
    if not occurrences:
        occurrences = list(finding.occurrences)
    if not occurrences:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No occurrences found to resolve secret."
        )
        
    occ = occurrences[-1] # Latest occurrence
    
    # Read the secret value dynamically from Git/Filesystem
    walker = GitWalker(repo.path)
    extractor = CandidateExtractor(walker)
    
    plaintext_secret = None
    
    try:
        if occ.commit_hash == "WORKING_TREE":
            full_path = os.path.join(repo.path, occ.file_path)
            if os.path.isfile(full_path):
                with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
                    if 0 <= occ.line_number - 1 < len(lines):
                        line_content = lines[occ.line_number - 1]
        else:
            # Read from Git object at commit
            line_content = walker._run_git(["show", f"{occ.commit_hash}:{occ.file_path}"])
            if not line_content:
                # Fallback to parent
                line_content = walker._run_git(["show", f"{occ.commit_hash}~1:{occ.file_path}"])
                
            if line_content:
                lines = line_content.splitlines()
                if 0 <= occ.line_number - 1 < len(lines):
                    line_content = lines[occ.line_number - 1]
                    
        # Extract secret from line_content
        # Let's search candidates in this single line
        mock_occ = occ # Use same occurrence
        candidates = extractor.extract_candidates([mock_occ])
        
        # Match fingerprint to find the correct one if multiple candidates exist in the line
        for cand in candidates:
            if cand.fingerprint == finding.fingerprint:
                plaintext_secret = cand.value
                break
                
        # If not found directly, try generic extraction matching raw regexes on the line
        if not plaintext_secret and candidates:
            plaintext_secret = candidates[0].value
            
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to extract secret value from history: {str(e)}"
        )
        
    if not plaintext_secret:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Could not locate matching secret token in the repository diff content."
        )
        
    # Validate the secret
    validator = CredentialValidator()
    val_status = validator.validate(finding.provider, finding.type, plaintext_secret)
    
    # Update the finding
    finding.validation_status = val_status
    finding.validation_checked_at = datetime.utcnow()
    
    # Recalculate risk score based on validation result
    classifier = LocalClassifier()
    # Reconstruct candidate to pass to classifier
    from scanner.detector.candidate_extractor import Candidate as ExtractorCandidate
    # Parse context lines
    before_lines = json.loads(occ.context_before) if occ.context_before else []
    after_lines = json.loads(occ.context_after) if occ.context_after else []
    
    from scanner.history.git_walker import GitOccurrence as WalkerOccurrence
    walker_occ = WalkerOccurrence(occ.commit_hash, occ.file_path, occ.line_number, occ.change_type, occ.line_content)
    
    cand = ExtractorCandidate(
        value=plaintext_secret,
        provider=finding.provider,
        credential_type=finding.type,
        occurrence=walker_occ,
        context_before=before_lines,
        context_after=after_lines,
        variable_name=extractor.get_variable_name(occ.line_content)
    )
    
    res = classifier.classify_and_score(cand, val_status)
    finding.risk_score = res.risk_score
    finding.risk_level = res.risk_level
    finding.classification = res.classification
    finding.confidence = res.confidence
    finding.rationale = json.dumps(res.rationale)
    
    db.commit()
    db.refresh(finding)
    
    return {
        "finding_id": finding.id,
        "validation_status": val_status,
        "risk_score": finding.risk_score,
        "risk_level": finding.risk_level,
        "classification": finding.classification
    }
