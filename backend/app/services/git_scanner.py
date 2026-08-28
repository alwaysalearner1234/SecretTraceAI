import os
import shutil
import time
import json
from datetime import datetime
from sqlalchemy.orm import Session
import subprocess
import urllib.parse

from backend.app.models import Repository, Scan, Commit, Finding, SecretOccurrence
from scanner.history.git_walker import GitWalker
from scanner.detector.candidate_extractor import CandidateExtractor
from scanner.classifier.model import LocalClassifier
from scanner.validation.credential_validator import CredentialValidator
from scanner.provenance.timeline import ProvenanceEngine

def clean_git_url(url: str) -> str:
    """Sanitize remote repository URLs to prevent shell injections and SSRF."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ["http", "https", "git"]:
        raise ValueError("Invalid URL scheme. Only HTTP, HTTPS, and git are allowed.")
    return url

def run_scan_pipeline(db: Session, scan_id: int, repo_path: str, history_mode: str, validate: bool):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return
        
    scan.status = "RUNNING"
    db.commit()
    
    local_path = repo_path
    is_remote = repo_path.startswith(("http://", "https://", "git@"))
    temp_dir = None
    
    start_time = time.time()
    
    try:
        if is_remote:
            clean_url = clean_git_url(repo_path)
            # Create unique folder in scratch
            repo_name = clean_url.split("/")[-1].replace(".git", "")
            temp_dir = os.path.join("scratch", f"{repo_name}_{scan_id}")
            os.makedirs(temp_dir, exist_ok=True)
            
            # Run git clone
            subprocess.run(
                ["git", "clone", "--depth", "100" if history_mode == "current" else "1000", clean_url, "."],
                cwd=temp_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                timeout=120 # 2 minute limit on clone
            )
            local_path = temp_dir
            
        walker = GitWalker(local_path)
        if not walker.is_git_repo():
            raise ValueError(f"Directory {local_path} is not a valid Git repository.")
            
        # 1. Walk Commits
        if history_mode == "current":
            commits = []
            occurrences = walker.get_current_working_tree_occurrences()
        else:
            deep = (history_mode == "deep")
            commits = walker.get_commits(deep_history=deep)
            occurrences = []
            for c in commits:
                occurrences.extend(walker.get_commit_diff_occurrences(c.hash))
                
        # Save commit history to DB
        db_commits = []
        for c in commits:
            db_commits.append(Commit(
                scan_id=scan.id,
                hash=c.hash,
                parent_hash=" ".join(c.parents),
                author=c.author,
                email=c.email,
                timestamp=c.timestamp,
                message=c.message
            ))
        db.bulk_save_objects(db_commits)
        db.commit()
        
        # 2. Extract Candidates
        extractor = CandidateExtractor(walker)
        candidates = extractor.extract_candidates(occurrences)
        
        # 3. Provenance Timeline Deduplication
        findings = ProvenanceEngine.process_candidates(candidates, commits)
        
        # 4. Classify & Score & Validate
        classifier = LocalClassifier()
        validator = CredentialValidator()
        
        candidates_count = len(candidates)
        files_scanned = len(set(o.file_path for o in occurrences))
        
        for f in findings:
            c = f.candidates[-1]
            val_status = "NOT_CHECKED"
            if validate:
                val_status = validator.validate(f.provider, f.type, c.value)
                
            res = classifier.classify_and_score(c, val_status)
            
            # Save Finding to DB
            db_finding = Finding(
                scan_id=scan.id,
                fingerprint=f.fingerprint,
                provider=f.provider,
                type=f.type,
                masked_value=f.masked_value,
                classification=res.classification,
                confidence=res.confidence,
                risk_score=res.risk_score,
                risk_level=res.risk_level,
                rationale=json.dumps(res.rationale),
                status=f.status,
                validation_status=val_status,
                validation_checked_at=datetime.utcnow() if validate else None
            )
            db.add(db_finding)
            db.commit()
            
            # Save Occurrences
            db_occs = []
            for occ in f.candidates:
                db_occs.append(SecretOccurrence(
                    finding_id=db_finding.id,
                    commit_hash=occ.commit_hash,
                    file_path=occ.file_path,
                    line_number=occ.line_number,
                    change_type=occ.change_type,
                    line_content=occ.line_content,
                    context_before=json.dumps(occ.context_before),
                    context_after=json.dumps(occ.context_after)
                ))
            db.bulk_save_objects(db_occs)
            db.commit()
            
        # Complete scan
        scan.status = "COMPLETED"
        scan.finished_at = datetime.utcnow()
        scan.commits_scanned = len(commits) if history_mode != "current" else 1
        scan.files_scanned = files_scanned
        scan.candidates_found = candidates_count
        scan.duration_sec = time.time() - start_time
        db.commit()
        
    except Exception as e:
        scan.status = "FAILED"
        scan.finished_at = datetime.utcnow()
        scan.error_message = str(e)
        db.commit()
        
    finally:
        # Clean up cloned temp directory
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
            except Exception:
                pass
