import re
import math
from typing import Dict, Any, List, Optional

# Extensible Provider Registry
# Patterns map to (regex_pattern_string, provider_name, type_name)
PROVIDER_PATTERNS = {
    "AWS_ACCESS_KEY": (r"\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|ASCA|ASIA)[A-Z0-9]{16}\b", "AWS", "Access Key ID"),
    "AWS_SECRET_KEY": (r"\b[A-Za-z0-9/+=]{40}\b", "AWS", "Secret Access Key"), # Combined with context check in extractor
    "GITHUB_PAT": (r"\bghp_[a-zA-Z0-9]{36}\b", "GitHub", "Personal Access Token"),
    "GITHUB_FINE_GRAINED": (r"\bgithub_pat_[a-zA-Z0-9]{82}\b", "GitHub", "Fine-grained PAT"),
    "STRIPE_SECRET": (r"\bsk_live_[0-9a-zA-Z]{24,32}\b", "Stripe", "Secret Key"),
    "STRIPE_TEST_SECRET": (r"\bsk_test_[0-9a-zA-Z]{24,32}\b", "Stripe", "Test Secret Key"),
    "OPENAI_KEY": (r"\bsk-[a-zA-Z0-9]{48}\b", "OpenAI", "API Key"),
    "SLACK_TOKEN": (r"\bxox[bapts]-[0-9a-zA-Z]{10,48}\b", "Slack", "Token"),
    "TWILIO_AUTH_TOKEN": (r"\b[a-f0-9]{32}\b", "Twilio", "Auth Token"), # Combined with context check in extractor
    "GOOGLE_API_KEY": (r"\bAIzaSy[A-Za-z0-9_-]{33}\b", "Google Cloud", "API Key"),
    "GENERIC_PASSWORD": (r"\b(?i)(?:password|passwd|secret|token|api_?key|apikey|private_?key|auth_?token|client_?secret)\s*[:=]\s*['\"]([^'\"]{10,128})['\"]", "Generic", "Password/Key"),
    "DATABASE_URL": (r"\b(?:postgres|postgresql|mongodb|mysql|redis):\/\/[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9.-]+:[0-9]+\/[a-zA-Z0-9_.-]+", "Database", "Connection String"),
    "PRIVATE_KEY": (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "SSH/SSL", "Private Key"),
}

# Compile patterns for efficiency
COMPILED_PATTERNS = {
    key: (re.compile(pat, re.MULTILINE) if key == "PRIVATE_KEY" else re.compile(pat), prov, typ)
    for key, (pat, prov, typ) in PROVIDER_PATTERNS.items()
}

def calculate_entropy(value: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not value:
        return 0.0
    freq = {}
    for char in value:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    total_len = len(value)
    for count in freq.values():
        p = count / total_len
        entropy -= p * math.log2(p)
    return entropy

def is_highly_entropy_string(value: str, threshold: float = 3.5) -> bool:
    """Determine if a string's entropy exceeds a threshold."""
    return calculate_entropy(value) >= threshold
