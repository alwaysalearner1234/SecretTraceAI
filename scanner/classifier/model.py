import re
from typing import Dict, Any, List, Tuple
from scanner.detector.candidate_extractor import Candidate
from scanner.detector.patterns import calculate_entropy

class ClassifierResult:
    def __init__(self, classification: str, confidence: float, risk_score: float, risk_level: str, rationale: List[str]):
        self.classification = classification
        self.confidence = confidence
        self.risk_score = risk_score
        self.risk_level = risk_level
        self.rationale = rationale

    def to_dict(self) -> Dict[str, Any]:
        return {
            "classification": self.classification,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "rationale": self.rationale
        }

class LocalClassifier:
    def __init__(self):
        # Keywords suggesting a placeholder
        self.placeholder_val_keywords = [
            "your-api-key", "your-access-key", "your-secret", "your-token", "your-password",
            "insert-here", "enter-here", "paste-here", "example", "placeholder", "dummy",
            "changeme", "change-me", "my-secret", "some-token", "xxxx", "123456", "abcdef",
            "todo", "api_key_here", "token_here", "secret_here", "write-key", "<your", "[your",
            "your_api", "your_secret", "example_key", "test_key", "test_token", "your"
        ]
        
        self.placeholder_var_keywords = [
            "placeholder", "dummy", "example", "mock", "template", "fake", "sample",
            "your_", "my_", "test_", "demo_"
        ]

        # Config/Production indicators in file paths
        self.prod_path_keywords = [
            "prod", "production", "config", "settings", "env", "credentials", "auth",
            "secrets", "main", "deploy", "ci", "cd"
        ]

        # Test indicators in file paths
        self.test_path_keywords = [
            "test", "tests", "fixture", "fixtures", "spec", "specs", "mock", "mocks",
            "demo", "example", "examples", "docs", "documentation", "tutorial", "tutorials",
            "samples"
        ]

    def classify_and_score(self, candidate: Candidate, validation_status: str = "NOT_CHECKED") -> ClassifierResult:
        score = 0
        rationale = []
        
        # Base regex match
        score += 20
        rationale.append("+20: Matches known provider credential pattern format")

        # 1. Entropy Check
        entropy = calculate_entropy(candidate.value)
        if entropy > 4.2:
            score += 20
            rationale.append(f"+20: Extremely high Shannon entropy ({entropy:.2f})")
        elif entropy > 3.5:
            score += 15
            rationale.append(f"+15: High Shannon entropy ({entropy:.2f})")
        elif entropy > 2.8:
            score += 5
            rationale.append(f"+5: Moderate Shannon entropy ({entropy:.2f})")
        else:
            score -= 15
            rationale.append(f"-15: Very low Shannon entropy ({entropy:.2f})")

        # 2. Variable Name Semantics
        var_name = candidate.variable_name.lower()
        if var_name:
            # Check for strong secret variable names
            if any(k in var_name for k in ["secret", "private", "passwd", "password", "token", "auth"]):
                score += 15
                rationale.append(f"+15: Variable name suggests secret/credential ('{candidate.variable_name}')")
            elif any(k in var_name for k in ["key", "api"]):
                score += 10
                rationale.append(f"+10: Variable name suggests key/api ('{candidate.variable_name}')")
                
            # Check for placeholder variable names
            if any(k in var_name for k in self.placeholder_var_keywords):
                score -= 30
                rationale.append(f"-30: Variable name suggests placeholder/test ('{candidate.variable_name}')")

        # 3. Path Semantics
        path = candidate.file_path.lower()
        if any(k in path for k in self.test_path_keywords):
            score -= 25
            rationale.append(f"-25: File located in a test, fixture, or docs path ('{candidate.file_path}')")
        elif any(k in path for k in self.prod_path_keywords):
            score += 10
            rationale.append(f"+10: File located in a production/config path ('{candidate.file_path}')")

        # 4. Value Semantics (Placeholder keywords with standalone word check)
        val = candidate.value.lower()
        has_placeholder_keyword = False
        for kw in self.placeholder_val_keywords:
            start = 0
            while True:
                idx = val.find(kw, start)
                if idx == -1:
                    break
                
                # Check if this match is standalone (not part of an alphanumeric word)
                left_char = val[idx - 1] if idx > 0 else None
                right_char = val[idx + len(kw)] if idx + len(kw) < len(val) else None
                
                left_ok = (left_char is None or not left_char.isalnum())
                right_ok = (right_char is None or not right_char.isalnum())
                
                if left_ok and right_ok:
                    has_placeholder_keyword = True
                    score -= 30
                    rationale.append(f"-30: Value contains placeholder keyword/pattern ('{kw}')")
                    break
                start = idx + 1
            if has_placeholder_keyword:
                break

        # Check for repetitive strings or dummy values (e.g. AAAAAAAA, 12345678)
        if len(set(val)) <= 3 and len(val) > 8:
            score -= 25
            rationale.append("-25: Value consists of highly repetitive characters (low diversity)")

        # 5. Format Confidence (Exact matches)
        if candidate.provider == "Stripe":
            if candidate.type == "Secret Key":
                score += 15
                rationale.append("+15: Valid Stripe live secret key format (sk_live_)")
            elif candidate.type == "Test Secret Key":
                score -= 25
                rationale.append("-25: Stripe test secret key format (sk_test_)")
        elif candidate.provider == "GitHub":
            score += 15
            rationale.append("+15: Valid GitHub Personal Access Token format")
        elif candidate.provider == "AWS":
            if candidate.type == "Access Key ID":
                # Check for exact 20 chars
                if len(candidate.value) == 20:
                    score += 15
                    rationale.append("+15: Valid AWS Access Key ID format (20 characters)")
            elif candidate.type == "Secret Access Key":
                if len(candidate.value) == 40:
                    score += 15
                    rationale.append("+15: Valid AWS Secret Access Key format (40 characters)")

        # 6. Credential Validation Results
        if validation_status == "VALID":
            score += 25
            rationale.append("+25: Credential validated successfully against provider API")
        elif validation_status == "INVALID" or validation_status == "EXPIRED" or validation_status == "REVOKED":
            score -= 30
            rationale.append(f"-30: Provider API confirmed credential is {validation_status}")

        # Normalize score to 0 - 100
        score = max(0, min(100, score))

        # Classify the candidate
        classification = "UNKNOWN"
        confidence = 0.5
        
        # Heuristics for final classification
        if validation_status == "VALID":
            classification = "REAL_SECRET"
            confidence = 0.99
        elif validation_status in ["INVALID", "EXPIRED", "REVOKED"]:
            classification = "REAL_SECRET" # It was real, just no longer valid
            confidence = 0.95
        elif has_placeholder_keyword:
            classification = "PLACEHOLDER"
            confidence = 0.90
        elif any(k in path for k in ["test", "fixture", "spec"]):
            classification = "TEST_FIXTURE"
            confidence = 0.80
        elif any(k in path for k in ["doc", "example"]):
            classification = "DOCUMENTATION_EXAMPLE"
            confidence = 0.85
        else:
            # If score is high, it's likely a real secret
            if score >= 70:
                classification = "REAL_SECRET"
                confidence = 0.85
            elif score >= 40:
                classification = "REAL_SECRET"
                confidence = 0.65
            else:
                classification = "RANDOM_VALUE"
                confidence = 0.70

        # Determine risk level
        if score >= 85:
            risk_level = "CRITICAL"
        elif score >= 70:
            risk_level = "HIGH"
        elif score >= 50:
            risk_level = "MEDIUM"
        elif score >= 30:
            risk_level = "LOW"
        else:
            risk_level = "INFO"

        return ClassifierResult(
            classification=classification,
            confidence=confidence,
            risk_score=score,
            risk_level=risk_level,
            rationale=rationale
        )
