import argparse
import sys
import json
import time
import os
from typing import List, Dict, Any

from scanner.history.git_walker import GitWalker
from scanner.detector.candidate_extractor import CandidateExtractor
from scanner.classifier.model import LocalClassifier
from scanner.validation.credential_validator import CredentialValidator
from scanner.provenance.timeline import ProvenanceEngine, Finding

def build_sarif(findings: List[Finding], classifier: LocalClassifier) -> Dict[str, Any]:
    """Generate a standard SARIF JSON representation of findings."""
    rules = {}
    results = []
    
    for f in findings:
        # Determine rule details
        rule_id = f"ST-{f.provider.upper()}-{f.type.upper().replace(' ', '_')}"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f"{f.provider} {f.type} Leak",
                "shortDescription": {
                    "text": f"Leaked {f.provider} {f.type} detected in Git history."
                },
                "helpUri": "https://github.com/alwaysalearner1234/Hallucination_hunter"
            }
            
        # Get the latest addition occurrence for location info
        latest_occurrences = [c for c in f.candidates if c.change_type == "ADDED"]
        loc_candidate = latest_occurrences[-1] if latest_occurrences else f.candidates[-1]
        
        # Scoring classification
        class_res = classifier.classify_and_score(loc_candidate)
        
        level = "warning"
        if class_res.risk_level in ["CRITICAL", "HIGH"]:
            level = "error"
        elif class_res.risk_level == "MEDIUM":
            level = "warning"
        else:
            level = "note"

        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": f"SecretTrace AI detected {f.provider} {f.type} ({f.status}). Classification: {class_res.classification} ({class_res.risk_level}, score: {class_res.risk_score}). Fingerprint: {f.fingerprint}."
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": loc_candidate.file_path
                        },
                        "region": {
                            "startLine": loc_candidate.line_number
                        }
                    }
                }
            ],
            "properties": {
                "status": f.status,
                "risk_score": class_res.risk_score,
                "classification": class_res.classification,
                "masked_value": f.masked_value
            }
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecretTrace AI",
                        "semanticVersion": "1.0.0",
                        "rules": list(rules.values())
                    }
                },
                "results": results
            }
        ]
    }

def print_text_report(findings: List[Finding], classifier: LocalClassifier):
    """Print a beautiful console summary report."""
    print("=" * 80)
    print(" SECRETTRACE AI — SCAN SUMMARY REPORT")
    print(" Tagline: \"Find the secrets Git forgot.\"")
    print("=" * 80)
    
    if not findings:
        print("\n[+] SUCCESS: No credentials detected!")
        print("=" * 80)
        return

    print(f"\nDetected {len(findings)} unique credentials in Git history:\n")
    
    # Sort findings by score
    scored_findings = []
    for f in findings:
        # Get latest candidate for scoring
        c = f.candidates[-1]
        score_res = classifier.classify_and_score(c)
        scored_findings.append((f, score_res))
        
    scored_findings.sort(key=lambda x: x[1].risk_score, reverse=True)
    
    for f, res in scored_findings:
        color_tag = f"[{res.risk_level}]"
        print(f" {color_tag:<10} | {f.provider:<12} | {f.type:<22} | Status: {f.status:<8}")
        print(f" Masked Value: {f.masked_value}")
        print(f" Fingerprint:  {f.fingerprint}")
        print(f" Classification: {res.classification} (Confidence: {res.confidence * 100:.0f}%)")
        print(f" Risk Score:    {res.risk_score}/100")
        print(" Evidence/Rationale:")
        for rat in res.rationale:
            print(f"   * {rat}")
            
        print(" Provenance Timeline:")
        for idx, event in enumerate(f.timeline):
            action = "Introduced" if event.event_type == "INTRODUCED" else (
                "Removed" if event.event_type == "DELETED" else "Modified"
            )
            print(f"   [{idx+1}] Commit {event.commit_hash[:8]} by {event.author} ({action} in {event.file_path}:L{event.line_number})")
        print("-" * 80)
    print("=" * 80)

def main():
    parser = argparse.ArgumentParser(
        description="SecretTrace AI: Low-Noise Git Secret Detection & Provenance Platform"
    )
    parser.add_argument("path", help="Path to the local Git repository to scan", default=".", nargs="?")
    parser.add_argument("--history", action="store_true", help="Scan entire commit history")
    parser.add_argument("--deep-history", action="store_true", help="Include unreachable commits and reflogs")
    parser.add_argument("--validate", action="store_true", help="Enable online credential validation checks")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--sarif", action="store_true", help="Output results in SARIF format")
    parser.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical"], 
                        default=None, help="Fail (exit code 1) if finding exists at or above this risk level")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.path):
        print(f"[-] Error: Path '{args.path}' does not exist.", file=sys.stderr)
        sys.exit(2)
        
    walker = GitWalker(args.path)
    if not walker.is_git_repo():
        print(f"[-] Error: Path '{args.path}' is not a valid Git repository.", file=sys.stderr)
        sys.exit(2)
        
    # Phase: Commit Traversal
    start_time = time.time()
    
    try:
        if args.history or args.deep_history:
            commits = walker.get_commits(deep_history=args.deep_history)
            occurrences = []
            for c in commits:
                occurrences.extend(walker.get_commit_diff_occurrences(c.hash))
        else:
            # Current working tree scan only
            commits = []
            occurrences = walker.get_current_working_tree_occurrences()
    except Exception as e:
        print(f"[-] Git extraction failed: {str(e)}", file=sys.stderr)
        sys.exit(2)
        
    # Phase: Candidate Extraction
    extractor = CandidateExtractor(walker)
    candidates = extractor.extract_candidates(occurrences)
    
    # Phase: Provenance Engine (Deduplication)
    findings = ProvenanceEngine.process_candidates(candidates, commits)
    
    # Phase: Credential Validation
    classifier = LocalClassifier()
    validator = CredentialValidator()
    
    max_risk_level = 0
    severity_map = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    risk_level_to_severity = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    
    # Track metrics
    scan_time = time.time() - start_time
    commits_count = len(commits) if (args.history or args.deep_history) else 1
    
    # Format and Output Results
    if args.json:
        findings_json = []
        for f in findings:
            c = f.candidates[-1]
            val_status = "NOT_CHECKED"
            if args.validate:
                val_status = validator.validate(f.provider, f.type, c.value)
            
            res = classifier.classify_and_score(c, val_status)
            finding_data = f.to_dict()
            finding_data["risk_assessment"] = res.to_dict()
            finding_data["validation_status"] = val_status
            findings_json.append(finding_data)
            
            # Keep track of max risk level
            sev = risk_level_to_severity.get(res.risk_level, 0)
            if sev > max_risk_level:
                max_risk_level = sev
                
        metrics = {
            "scan_duration_sec": scan_time,
            "commits_scanned": commits_count,
            "candidates_found": len(candidates),
            "unique_findings": len(findings)
        }
        
        print(json.dumps({"findings": findings_json, "metrics": metrics}, indent=2))
        
    elif args.sarif:
        # Run validations first if enabled
        for f in findings:
            c = f.candidates[-1]
            val_status = "NOT_CHECKED"
            if args.validate:
                val_status = validator.validate(f.provider, f.type, c.value)
            
            res = classifier.classify_and_score(c, val_status)
            sev = risk_level_to_severity.get(res.risk_level, 0)
            if sev > max_risk_level:
                max_risk_level = sev
                
        sarif_data = build_sarif(findings, classifier)
        print(json.dumps(sarif_data, indent=2))
        
    else:
        # Human readable CLI report
        validated_findings = []
        for f in findings:
            c = f.candidates[-1]
            val_status = "NOT_CHECKED"
            if args.validate:
                print(f"[~] Validating {f.provider} {f.type} ({f.masked_value})...")
                val_status = validator.validate(f.provider, f.type, c.value)
                
            res = classifier.classify_and_score(c, val_status)
            sev = risk_level_to_severity.get(res.risk_level, 0)
            if sev > max_risk_level:
                max_risk_level = sev
                
        print_text_report(findings, classifier)
        
        # Summary stats
        print(f"Scan Duration:   {scan_time:.2f} seconds")
        print(f"Commits Scanned: {commits_count}")
        print(f"Files Analyzed:  {len(set(o.file_path for o in occurrences))}")
        print(f"Candidates:      {len(candidates)}")
        print("=" * 80)
        
    # Check exit code based on fail-on severity threshold
    if args.fail-on:
        threshold_sev = severity_map.get(args.fail_on, 0)
        if max_risk_level >= threshold_sev and len(findings) > 0:
            sys.exit(1)
            
    sys.exit(0)

if __name__ == "__main__":
    main()
