import re
import hashlib
from typing import List, Dict, Any, Tuple, Optional
from scanner.history.git_walker import GitOccurrence, GitWalker
from scanner.detector.patterns import COMPILED_PATTERNS, calculate_entropy

class Candidate:
    def __init__(self,
                 value: str,
                 provider: str,
                 credential_type: str,
                 occurrence: GitOccurrence,
                 context_before: List[str] = None,
                 context_after: List[str] = None,
                 variable_name: str = ""):
        self.value = value
        self.provider = provider
        self.type = credential_type
        self.commit_hash = occurrence.commit_hash
        self.file_path = occurrence.file_path
        self.line_number = occurrence.line_number
        self.change_type = occurrence.change_type
        self.line_content = occurrence.line_content
        self.context_before = context_before or []
        self.context_after = context_after or []
        self.variable_name = variable_name
        
        # Security properties
        self.fingerprint = hashlib.sha256(value.encode('utf-8')).hexdigest()
        self.masked_value = self._mask_value(value)

    def _mask_value(self, val: str) -> str:
        """Mask the secret value leaving only prefix/suffix for debuggability."""
        if len(val) <= 8:
            return "••••••••"
        elif len(val) <= 16:
            return f"{val[:3]}••••{val[-3:]}"
        else:
            return f"{val[:5]}••••••••{val[-5:]}"

class CandidateExtractor:
    def __init__(self, walker: GitWalker):
        self.walker = walker
        # Simple regex to extract variable name in lines like: API_KEY = "xyz"
        self.var_pattern = re.compile(r'\b([A-Za-z0-9_.-]+)\s*[:=]')

    def get_variable_name(self, line: str) -> str:
        """Extract variable name from the line content."""
        match = self.var_pattern.search(line)
        if match:
            return match.group(1)
        return ""

    def get_context(self, commit_hash: str, file_path: str, line_number: int, context_size: int = 3) -> Tuple[List[str], List[str]]:
        """Retrieve lines of context before and after the occurrence line from Git."""
        if commit_hash == "WORKING_TREE":
            # Read from local filesystem
            full_path = os.path.join(self.walker.repo_path, file_path)
            if not os.path.isfile(full_path):
                return [], []
            try:
                with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
            except Exception:
                return [], []
        else:
            # Read from Git object
            # If the line was deleted, look in the parent commit, otherwise in the commit itself
            # We try commit_hash first, if it fails (e.g. file deleted/unreachable), we fall back
            target_ref = commit_hash
            content = self.walker._run_git(["show", f"{target_ref}:{file_path}"])
            if not content:
                # Fallback to parent commit if deleted
                content = self.walker._run_git(["show", f"{target_ref}~1:{file_path}"])
            
            if not content:
                return [], []
            lines = content.splitlines(keepends=True)

        line_idx = line_number - 1 # 0-indexed
        
        before = []
        for i in range(max(0, line_idx - context_size), line_idx):
            if i < len(lines):
                before.append(lines[i].rstrip("\r\n"))
                
        after = []
        for i in range(line_idx + 1, min(len(lines), line_idx + 1 + context_size)):
            if i < len(lines):
                after.append(lines[i].rstrip("\r\n"))
                
        return before, after

    def extract_candidates(self, occurrences: List[GitOccurrence]) -> List[Candidate]:
        """Scan occurrences and return list of extracted secret candidates."""
        candidates = []
        
        for occ in occurrences:
            line = occ.line_content
            # Pre-filter: skip extremely long lines (minified JS/CSS) to prevent regex slowdown
            if len(line) > 1000:
                continue
                
            for key, (pattern, provider, typ) in COMPILED_PATTERNS.items():
                matches = pattern.findall(line)
                if not matches:
                    continue
                
                for match in matches:
                    # In some regexes with groups, match is a tuple or a string
                    val = match[0] if isinstance(match, tuple) else match
                    val = val.strip('\'"')
                    
                    if not val or len(val) < 8:
                        continue
                        
                    # Handle conditional matching for keys that are high-entropy but need context
                    var_name = self.get_variable_name(line)
                    lower_line = line.lower()
                    
                    if key == "AWS_SECRET_KEY":
                        # Validate that it's a true base64 string, entropy > 3.0, and context has 'aws'
                        if calculate_entropy(val) < 3.0:
                            continue
                        if not any(k in lower_line for k in ["aws", "secret", "access", "key"]):
                            continue
                            
                    elif key == "TWILIO_AUTH_TOKEN":
                        # Validate that context has 'twilio'
                        if not any(k in lower_line for k in ["twilio", "auth", "token"]):
                            continue
                            
                    # Extract context
                    # To speed up, we can fetch context on demand or fetch now
                    before, after = self.get_context(occ.commit_hash, occ.file_path, occ.line_number)
                    
                    candidates.append(Candidate(
                        value=val,
                        provider=provider,
                        credential_type=typ,
                        occurrence=occ,
                        context_before=before,
                        context_after=after,
                        variable_name=var_name
                    ))
                    
        return candidates

import os
