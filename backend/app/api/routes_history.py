from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Dict, Any

from backend.app.database import get_db
from backend.app.models import Finding, Commit

router = APIRouter(prefix="/api/findings", tags=["Provenance"])

@router.get("/{finding_id}/provenance")
def get_finding_provenance(finding_id: int, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding with ID {finding_id} not found."
        )
        
    # Get all commits in the scan to build metadata map
    commits = db.query(Commit).filter(Commit.scan_id == finding.scan_id).all()
    commits_map = {c.hash: c for c in commits}
    
    # Sort occurrences by commit timestamp
    occurrences = finding.occurrences
    
    def get_timestamp(occ):
        c = commits_map.get(occ.commit_hash)
        return c.timestamp if c else 0
        
    sorted_occs = sorted(occurrences, key=get_timestamp)
    
    timeline = []
    active_instances = set()
    
    for idx, occ in enumerate(sorted_occs):
        commit = commits_map.get(occ.commit_hash)
        msg = commit.message if commit else "Working Tree"
        author = commit.author if commit else "Developer"
        timestamp = commit.timestamp if commit else 0
        
        # Tag event type
        if idx == 0:
            if occ.change_type == "DELETED":
                event_type = "DELETED"
            else:
                event_type = "INTRODUCED"
                active_instances.add(occ.file_path)
        else:
            if occ.change_type == "ADDED":
                if occ.file_path in active_instances:
                    event_type = "MODIFIED"
                else:
                    event_type = "COPIED"
                    active_instances.add(occ.file_path)
            else: # DELETED
                event_type = "DELETED"
                if occ.file_path in active_instances:
                    active_instances.remove(occ.file_path)
                    
        timeline.append({
            "commit_hash": occ.commit_hash,
            "commit_message": msg,
            "author": author,
            "timestamp": timestamp,
            "file_path": occ.file_path,
            "line_number": occ.line_number,
            "change_type": occ.change_type,
            "event_type": event_type
        })
        
    return {
        "finding_id": finding.id,
        "fingerprint": finding.fingerprint,
        "provider": finding.provider,
        "type": finding.type,
        "status": finding.status,
        "timeline": timeline
    }
