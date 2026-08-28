from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
import os

from backend.app.database import get_db
from backend.app.models import Repository, Scan, Finding
from backend.app.schemas import ScanStartRequest, ScanOut, StatisticsOut
from backend.app.services.git_scanner import run_scan_pipeline

router = APIRouter(prefix="/api", tags=["Scans"])

@router.post("/scans", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
def start_scan(
    request: ScanStartRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    # Verify path exists if it is local
    is_remote = request.repository_path.startswith(("http://", "https://", "git@"))
    if not is_remote and not os.path.exists(request.repository_path):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Local path '{request.repository_path}' does not exist on server."
        )

    # Extract repository name from path or url
    repo_name = request.repository_path.replace("\\", "/").rstrip("/").split("/")[-1]
    if repo_name.endswith(".git"):
        repo_name = repo_name[:-4]
    if not repo_name:
        repo_name = "unnamed_repo"
        
    # Check if Repository already exists
    repo = db.query(Repository).filter(Repository.path == request.repository_path).first()
    if not repo:
        repo = Repository(
            name=repo_name,
            path=request.repository_path,
            branch="main"
        )
        db.add(repo)
        db.commit()
        db.refresh(repo)
        
    # Create Scan record
    scan = Scan(
        repository_id=repo.id,
        status="PENDING",
        commits_scanned=0,
        files_scanned=0,
        candidates_found=0,
        duration_sec=0.0
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    # Run pipeline in background
    background_tasks.add_task(
        run_scan_pipeline,
        db=db,
        scan_id=scan.id,
        repo_path=request.repository_path,
        history_mode=request.history_mode,
        validate=request.validate_secrets
    )
    
    return scan

@router.get("/scans", response_model=List[ScanOut])
def get_all_scans(db: Session = Depends(get_db)):
    return db.query(Scan).order_by(Scan.started_at.desc()).all()

@router.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan_details(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID {scan_id} not found."
        )
    return scan

@router.get("/statistics", response_model=StatisticsOut)
def get_statistics(db: Session = Depends(get_db)):
    repo_count = db.query(Repository).count()
    total_findings = db.query(Finding).count()
    critical_findings = db.query(Finding).filter(Finding.risk_level == "CRITICAL").count()
    high_findings = db.query(Finding).filter(Finding.risk_level == "HIGH").count()
    
    # Historical findings (detected in commit history but deleted now)
    historical_secrets = db.query(Finding).filter(
        Finding.status == "DELETED"
    ).count()
    
    # False positive rate: suppressed false positives / total findings
    suppressed_fps = db.query(Finding).filter(
        Finding.status == "FALSE_POSITIVE"
    ).count()
    
    fp_rate = 0.0
    if total_findings > 0:
        fp_rate = suppressed_fps / total_findings
        
    # Validation coverage: validated / total findings
    validated_findings = db.query(Finding).filter(
        Finding.validation_status != "NOT_CHECKED"
    ).count()
    
    val_coverage = 0.0
    if total_findings > 0:
        val_coverage = validated_findings / total_findings

    return {
        "repositories_scanned": repo_count,
        "total_findings": total_findings,
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "historical_secrets": historical_secrets,
        "false_positive_rate": fp_rate,
        "validation_coverage": val_coverage
    }
