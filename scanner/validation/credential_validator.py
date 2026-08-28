import urllib.request
import urllib.error
import json
import base64
from typing import Dict, Any, Tuple

class CredentialValidator:
    def __init__(self):
        self.user_agent = "SecretTraceAI-Scanner/1.0"

    def validate(self, provider: str, credential_type: str, credential_value: str) -> str:
        """
        Validate a credential with its provider.
        Returns: 'VALID', 'INVALID', 'EXPIRED', 'REVOKED', 'UNKNOWN', 'NOT_SUPPORTED'
        """
        provider = provider.upper()
        
        # Guard against scanning obviously fake/test tokens or empty strings
        lower_val = credential_value.lower()
        if any(x in lower_val for x in ["placeholder", "your-", "dummy", "xxxx", "test_"]):
            return "INVALID"

        if provider == "GITHUB":
            return self._validate_github(credential_value)
        elif provider == "STRIPE":
            return self._validate_stripe(credential_type, credential_value)
        elif provider == "GOOGLE CLOUD":
            return self._validate_google_cloud(credential_value)
        else:
            return "NOT_SUPPORTED"

    def _validate_github(self, token: str) -> str:
        url = "https://api.github.com/user"
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"token {token}",
                "User-Agent": self.user_agent
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=3) as response:
                if response.status == 200:
                    return "VALID"
        except urllib.error.HTTPError as e:
            if e.code in [401, 403]:
                return "INVALID"
            return "UNKNOWN"
        except Exception:
            return "UNKNOWN"
        return "UNKNOWN"

    def _validate_stripe(self, cred_type: str, api_key: str) -> str:
        # Don't try to validate test keys online as they're not active prod secrets
        if "test" in cred_type.lower() or api_key.startswith("sk_test_"):
            return "VALID" # Stripe test keys are valid test credentials
            
        url = "https://api.stripe.com/v1/charges?limit=1"
        # Stripe auth uses key as username, password is empty
        auth_str = base64.b64encode(f"{api_key}:".encode("utf-8")).decode("utf-8")
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Basic {auth_str}",
                "User-Agent": self.user_agent
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=3) as response:
                if response.status == 200:
                    return "VALID"
        except urllib.error.HTTPError as e:
            if e.code in [401, 403]:
                return "INVALID"
            return "UNKNOWN"
        except Exception:
            return "UNKNOWN"
        return "UNKNOWN"

    def _validate_google_cloud(self, api_key: str) -> str:
        # Query Google Project Config API using the key
        url = f"https://www.googleapis.com/identitytoolkit/v3/retdb/getProjectConfig?key={api_key}"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": self.user_agent
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=3) as response:
                if response.status == 200:
                    return "VALID"
        except urllib.error.HTTPError as e:
            if e.code in [400, 401, 403]:
                return "INVALID"
            return "UNKNOWN"
        except Exception:
            return "UNKNOWN"
        return "UNKNOWN"
