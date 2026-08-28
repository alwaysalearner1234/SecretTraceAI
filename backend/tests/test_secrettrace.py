import pytest
from fastapi.testclient import TestClient
import json

from scanner.detector.patterns import calculate_entropy, is_highly_entropy_string
from scanner.classifier.model import LocalClassifier
from scanner.detector.candidate_extractor import Candidate
from scanner.history.git_walker import GitOccurrence
from scanner.provenance.timeline import ProvenanceEngine, Finding
from backend.app.main import app

client = TestClient(app)

def test_entropy_calculation():
    # Base case
    assert calculate_entropy("") == 0.0
    
    # Low entropy repeat character
    low_ent = calculate_entropy("AAAAAA")
    assert low_ent == 0.0
    
    # High entropy string
    high_ent = calculate_entropy("g9X#m2P$L&k9@qW")
    assert high_ent > 3.0
    assert is_highly_entropy_string("g9X#m2P$L&k9@qW", 3.0) is True

def test_local_classifier_heuristics():
    classifier = LocalClassifier()
    
    # Mock occurrence representing a real-looking AWS Secret committed to config
    occ_real = GitOccurrence(
        commit_hash="abc123commit",
        file_path="config/production.py",
        line_number=12,
        change_type="ADDED",
        line_content="AWS_SECRET_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'"
    )
    cand_real = Candidate(
        value="AKIAIOSFODNN7EXAMPLE",
        provider="AWS",
        credential_type="Access Key ID",
        occurrence=occ_real,
        context_before=["import os"],
        context_after=["print('Loaded S3')"],
        variable_name="AWS_SECRET_ACCESS_KEY"
    )
    
    res_real = classifier.classify_and_score(cand_real)
    assert res_real.classification == "REAL_SECRET"
    assert res_real.risk_score >= 60
    
    # Mock occurrence representing a placeholder
    occ_placeholder = GitOccurrence(
        commit_hash="abc123commit",
        file_path="config.py",
        line_number=5,
        change_type="ADDED",
        line_content="AWS_ACCESS_KEY_ID = 'YOUR-AWS-ACCESS-KEY-HERE'"
    )
    cand_placeholder = Candidate(
        value="YOUR-AWS-ACCESS-KEY-HERE",
        provider="AWS",
        credential_type="Access Key ID",
        occurrence=occ_placeholder,
        context_before=["# Setup config"],
        context_after=[],
        variable_name="AWS_ACCESS_KEY_ID"
    )
    res_placeholder = classifier.classify_and_score(cand_placeholder)
    assert res_placeholder.classification == "PLACEHOLDER"
    assert res_placeholder.risk_score < 40

def test_provenance_timeline_deduplication():
    # Create two candidates with the same secret value (same fingerprint)
    # representing introduced in commit 1 and deleted in commit 2.
    mock_key = "sk_live_" + "51N2xabcdefghijklmnopqrstuvw"
    occ1 = GitOccurrence(
        commit_hash="commit_hash_1",
        file_path="app.py",
        line_number=2,
        change_type="ADDED",
        line_content=mock_key
    )
    cand1 = Candidate(
        value=mock_key,
        provider="Stripe",
        credential_type="Secret Key",
        occurrence=occ1
    )
    
    occ2 = GitOccurrence(
        commit_hash="commit_hash_2",
        file_path="app.py",
        line_number=2,
        change_type="DELETED",
        line_content=mock_key
    )
    cand2 = Candidate(
        value=mock_key,
        provider="Stripe",
        credential_type="Secret Key",
        occurrence=occ2
    )
    
    from scanner.history.git_walker import GitCommit
    commit1 = GitCommit("commit_hash_1", [], "Dev A", "dev@st.ai", 1700000000, "Add stripe key")
    commit2 = GitCommit("commit_hash_2", ["commit_hash_1"], "Dev A", "dev@st.ai", 1700010000, "Delete stripe key")
    
    findings = ProvenanceEngine.process_candidates([cand1, cand2], [commit1, commit2])
    
    assert len(findings) == 1
    finding = findings[0]
    assert finding.status == "DELETED" # Chronologically deleted!
    assert len(finding.timeline) == 2
    assert finding.timeline[0].event_type == "INTRODUCED"
    assert finding.timeline[1].event_type == "DELETED"

def test_api_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    assert "database" in data
