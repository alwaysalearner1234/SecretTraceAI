import time
import json
import os
import random
import string
from typing import Dict, Any, List

# Import scanner parts
from scanner.detector.patterns import COMPILED_PATTERNS
from scanner.history.git_walker import GitOccurrence
from scanner.detector.candidate_extractor import Candidate
from scanner.classifier.model import LocalClassifier

def generate_random_string(length: int, chars: str = string.ascii_letters + string.digits) -> str:
    return ''.join(random.choice(chars) for _ in range(length))

def build_benchmark_dataset() -> List[Dict[str, Any]]:
    dataset = []
    
    random.seed(42) # Set seed for reproducibility
    
    # 1. 100 Real Secrets
    providers = ["Stripe", "GitHub", "AWS_ACCESS", "AWS_SECRET", "OpenAI", "Google"]
    for i in range(100):
        prov = random.choice(providers)
        if prov == "Stripe":
            val = f"sk_live_{generate_random_string(24)}"
            var = "stripe_secret"
            path = "config/production.json"
            typ = "Secret Key"
        elif prov == "GitHub":
            val = f"ghp_{generate_random_string(36)}"
            var = "GITHUB_TOKEN"
            path = "src/main.py"
            typ = "Personal Access Token"
        elif prov == "AWS_ACCESS":
            val = f"AKIA{generate_random_string(16, string.ascii_uppercase + string.digits)}"
            var = "AWS_ACCESS_KEY_ID"
            path = "deploy/s3_uploader.py"
            typ = "Access Key ID"
        elif prov == "AWS_SECRET":
            val = generate_random_string(40, string.ascii_letters + string.digits + "/+=")
            var = "AWS_SECRET_ACCESS_KEY"
            path = "deploy/s3_uploader.py"
            typ = "Secret Access Key"
        elif prov == "OpenAI":
            val = f"sk-{generate_random_string(48)}"
            var = "OPENAI_API_KEY"
            path = "app/ai_client.py"
            typ = "API Key"
        else: # Google
            val = f"AIzaSy{generate_random_string(33)}"
            var = "GOOGLE_MAPS_KEY"
            path = "public/index.html"
            typ = "API Key"
            
        dataset.append({
            "id": f"real-{i}",
            "value": val,
            "variable_name": var,
            "file_path": path,
            "line_content": f"{var} = '{val}'",
            "provider": prov.split("_")[0],
            "type": typ,
            "is_real": True
        })
        
    # 2. 100 Placeholders
    placeholders = [
        "your-api-key-here", "YOUR_ACCESS_KEY_ID", "your-stripe-secret-key",
        "sk_live_YOUR_KEY_HERE", "ghp_YOUR_TOKEN_HERE", "sk-proj-ENTER_KEY_HERE",
        "insert_token_here", "changeme", "change-me", "dummy_password_value"
    ]
    for i in range(100):
        val = random.choice(placeholders)
        var = random.choice(["API_KEY", "STRIPE_KEY", "AWS_SECRET", "TOKEN", "PASSWORD"])
        dataset.append({
            "id": f"placeholder-{i}",
            "value": val,
            "variable_name": var,
            "file_path": "config.example.py",
            "line_content": f"{var} = '{val}'",
            "provider": "Generic",
            "type": "Password/Key",
            "is_real": False
        })
        
    # 3. 100 Test Fixtures
    for i in range(100):
        prov = random.choice(providers)
        if prov == "Stripe":
            val = f"sk_test_{generate_random_string(24)}"
            var = "test_stripe_key"
            typ = "Test Secret Key"
        elif prov == "GitHub":
            val = f"ghp_{generate_random_string(36)}"
            var = "mock_github_token"
            typ = "Personal Access Token"
        else:
            val = f"sk-{generate_random_string(48)}"
            var = "dummy_openai_key"
            typ = "API Key"
            
        dataset.append({
            "id": f"fixture-{i}",
            "value": val,
            "variable_name": var,
            "file_path": f"tests/fixtures/mock_credentials.json",
            "line_content": f'"{var}": "{val}"',
            "provider": prov.split("_")[0],
            "type": typ,
            "is_real": False
        })
        
    # 4. 100 Documentation Examples
    for i in range(100):
        val = f"sk_live_example{generate_random_string(16)}"
        var = "STRIPE_SECRET_KEY"
        dataset.append({
            "id": f"doc-{i}",
            "value": val,
            "variable_name": var,
            "file_path": "docs/setup.md",
            "line_content": f"export STRIPE_SECRET_KEY=\"{val}\"",
            "provider": "Stripe",
            "type": "Secret Key",
            "is_real": False
        })
        
    # 5. 100 Random High-Entropy strings
    for i in range(100):
        val = generate_random_string(32, string.ascii_letters + string.digits) # High entropy random string
        var = random.choice(["session_id", "csrf_token", "hash_salt", "cache_key", "uuid"])
        dataset.append({
            "id": f"random-{i}",
            "value": val,
            "variable_name": var,
            "file_path": "src/utils.py",
            "line_content": f"{var} = '{val}'",
            "provider": "Generic",
            "type": "Password/Key",
            "is_real": False
        })
        
    return dataset

def run_benchmark():
    dataset = build_benchmark_dataset()
    classifier = LocalClassifier()
    
    # 1. Evaluate Baseline Regex Scanner
    # Regex scanner flags ANY value that matches a credential regex pattern.
    baseline_tp = 0
    baseline_fp = 0
    baseline_tn = 0
    baseline_fn = 0
    
    start_time = time.time()
    for item in dataset:
        # Check if value matches any regex pattern
        matched = False
        val = item["value"]
        
        # Test against COMPILED_PATTERNS
        for key, (pattern, _, _) in COMPILED_PATTERNS.items():
            if pattern.search(item["line_content"]):
                matched = True
                break
                
        # Classify match
        if matched:
            if item["is_real"]:
                baseline_tp += 1
            else:
                baseline_fp += 1
        else:
            if item["is_real"]:
                baseline_fn += 1
            else:
                baseline_tn += 1
                
    baseline_time = time.time() - start_time
    
    # 2. Evaluate SecretTrace AI Scanner
    # SecretTrace AI runs CandidateExtractor + LocalClassifier
    # It is flagged as REAL only if the classifier returns REAL_SECRET and risk >= 50
    st_tp = 0
    st_fp = 0
    st_tn = 0
    st_fn = 0
    
    start_time = time.time()
    for item in dataset:
        # Create a mock Candidate
        occ = GitOccurrence(
            commit_hash="BENCHMARK",
            file_path=item["file_path"],
            line_number=10,
            change_type="ADDED",
            line_content=item["line_content"]
        )
        
        # Split contexts to mock Git surroundings
        # E.g. test paths should triggers classifier test pathway
        before = ["# Some boilerplate code", "import sys"]
        after = ["print('Done')"]
        
        candidate = Candidate(
            value=item["value"],
            provider=item["provider"],
            credential_type=item["type"],
            occurrence=occ,
            context_before=before,
            context_after=after,
            variable_name=item["variable_name"]
        )
        
        # Run classifier
        res = classifier.classify_and_score(candidate)
        
        is_flagged = (res.classification == "REAL_SECRET" and res.risk_score >= 50)
        
        if is_flagged:
            if item["is_real"]:
                st_tp += 1
            else:
                st_fp += 1
        else:
            if item["is_real"]:
                st_fn += 1
            else:
                st_tn += 1
                
    st_time = time.time() - start_time
    
    # Compute Metrics Helper
    def calculate_metrics(tp, fp, tn, fn, duration):
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        fnr = fn / (tp + fn) if (tp + fn) > 0 else 0
        return {
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "false_positive_rate": fpr,
            "false_negative_rate": fnr,
            "duration_ms": duration * 1000
        }

    results = {
        "baseline": calculate_metrics(baseline_tp, baseline_fp, baseline_tn, baseline_fn, baseline_time),
        "secrettrace_ai": calculate_metrics(st_tp, st_fp, st_tn, st_fn, st_time),
        "dataset_size": len(dataset)
    }
    
    # Save results to evaluation directory
    os.makedirs("ml/evaluation", exist_ok=True)
    with open("ml/evaluation/benchmark_results.json", "w") as f:
        json.dump(results, f, indent=2)
        
    print("[+] Benchmark evaluation complete!")
    print(f"SecretTrace AI F1-Score: {results['secrettrace_ai']['f1_score']*100:.1f}% vs Baseline: {results['baseline']['f1_score']*100:.1f}%")
    print(f"SecretTrace AI False Positive Rate: {results['secrettrace_ai']['false_positive_rate']*100:.1f}% vs Baseline: {results['baseline']['false_positive_rate']*100:.1f}%")

if __name__ == "__main__":
    run_benchmark()
