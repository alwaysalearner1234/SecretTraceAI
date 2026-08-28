import os
import json
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional
from scanner.detector.candidate_extractor import Candidate

class SemanticClassifier:
    def __init__(self):
        self.api_key = os.environ.get("GEMINI_API_KEY", "")

    def classify_with_llm(self, candidate: Candidate) -> Optional[Dict[str, Any]]:
        """
        Classifies a candidate using Google Gemini API.
        Masks the actual secret in the code context to ensure no data leaks.
        """
        if not self.api_key:
            return None

        # Mask the secret in the surrounding lines
        masked_val = f"<MASKED_SECRET_{candidate.provider}_{candidate.type[:4].upper()}>"
        
        # Prepare context strings
        context_before = "\n".join(candidate.context_before)
        context_after = "\n".join(candidate.context_after)
        
        # Mask target line
        target_line = candidate.line_content
        # Replace the real value with masked value in the target line
        if candidate.value in target_line:
            target_line = target_line.replace(candidate.value, masked_val)

        prompt = f"""
You are a security intelligence AI. Analyze the following code snippet containing a suspected leaked credential.
The actual secret has been masked to protect its confidentiality. Determine if this is a real active credential, a placeholder, a test fixture, or a documentation example.

FILE PATH: {candidate.file_path}
VARIABLE NAME: {candidate.variable_name}
PROVIDER: {candidate.provider}
TYPE: {candidate.type}

CODE CONTEXT:
```
{context_before}
{target_line}  <-- Suspected Credential (MASKED AS {masked_val})
{context_after}
```

Respond with a JSON object exactly in this format:
{{
  "classification": "REAL_SECRET" | "PLACEHOLDER" | "TEST_FIXTURE" | "DOCUMENTATION_EXAMPLE" | "UNKNOWN",
  "confidence": 0.0 to 1.0,
  "explanation": "Brief explanation of your classification based on the context, variable names, and file path."
}}
"""

        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={self.api_key}"
        data = {
            "contents": [
                {
                    "parts": [
                        {"text": prompt}
                    ]
                }
            ],
            "generationConfig": {
                "responseMimeType": "application/json"
            }
        }
        
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(data).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                res_body = response.read().decode("utf-8")
                res_json = json.loads(res_body)
                
                # Extract text response from Gemini format
                text_content = res_json['candidates'][0]['content']['parts'][0]['text']
                result = json.loads(text_content.strip())
                return result
        except Exception as e:
            # Silently fall back to rule-based classification in case of API issues/timeouts
            return None
