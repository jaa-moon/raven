"""
tools/advisories.py
-------------------
Built-in advisory table: package -> versions below which it is affected.
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple


# Extended known vulnerability database with version ranges
_KNOWN_VULNS: Dict[str, List[Dict[str, str]]] = {
    # Python packages
    "flask": [
        {"max_version": "2.2.5", "cve_hint": "CVE-2023-30861: Session cookie handling allows session data leakage on redirect responses (< 2.2.5)"},
        {"max_version": "2.3.2", "cve_hint": "CVE-2023-30861: Session handling edge cases in debug mode (< 2.3.2)"},
    ],
    "django": [
        {"max_version": "4.2.7", "cve_hint": "CVE-2023-46695: Potential DoS via large number of uploaded files (< 4.2.7)"},
        {"max_version": "3.2.23", "cve_hint": "CVE-2023-46695: Potential DoS in file upload handler (< 3.2.23)"},
    ],
    "requests": [
        {"max_version": "2.31.0", "cve_hint": "CVE-2023-32681: Proxy-Authorization header leak on redirects to different schemes (< 2.31.0)"},
    ],
    "pyyaml": [
        {"max_version": "5.4", "cve_hint": "CVE-2020-14343: Arbitrary code execution via yaml.load() without SafeLoader (< 5.4)"},
    ],
    "jinja2": [
        {"max_version": "3.1.3", "cve_hint": "CVE-2024-22195: XSS via xmlattr filter with user-controlled keys (< 3.1.3)"},
    ],
    "werkzeug": [
        {"max_version": "3.0.3", "cve_hint": "CVE-2024-34069: Debugger PIN bypass allows arbitrary code execution (< 3.0.3)"},
    ],
    "cryptography": [
        {"max_version": "41.0.6", "cve_hint": "CVE-2023-49083: NULL pointer dereference in PKCS7/SMIME parsing (< 41.0.6)"},
    ],
    "sqlalchemy": [
        {"max_version": "2.0.0", "cve_hint": "Legacy SQLAlchemy versions may allow SQL injection via textual SQL or incorrect ORM usage"},
    ],
    "pillow": [
        {"max_version": "10.0.1", "cve_hint": "CVE-2023-44271: Uncontrolled resource consumption in image processing (< 10.0.1)"},
    ],
    "urllib3": [
        {"max_version": "2.0.7", "cve_hint": "CVE-2023-45803: Request body not stripped on redirect from 303 status (< 2.0.7)"},
    ],
    # Node packages
    "express": [
        {"max_version": "4.19.2", "cve_hint": "CVE-2024-29041: Open redirect via malformed URL in res.redirect() (< 4.19.2)"},
        {"max_version": "4.16.0", "cve_hint": "Query parser prototype pollution via qs module (< 4.16.0)"},
    ],
    "lodash": [
        {"max_version": "4.17.21", "cve_hint": "CVE-2021-23337: Prototype pollution via zipObjectDeep (< 4.17.21)"},
    ],
    "jsonwebtoken": [
        {"max_version": "9.0.0", "cve_hint": "CVE-2022-23529: Insecure key retrieval allows MITM attacks (< 9.0.0)"},
    ],
    "axios": [
        {"max_version": "1.6.0", "cve_hint": "CVE-2023-45857: CSRF token leakage via cross-site redirect (< 1.6.0)"},
    ],
    "minimist": [
        {"max_version": "1.2.6", "cve_hint": "CVE-2021-44906: Prototype pollution via constructor and __proto__ (< 1.2.6)"},
    ],
    "tar": [
        {"max_version": "6.1.9", "cve_hint": "CVE-2021-37701: Arbitrary file creation via symlink attack (< 6.1.9)"},
    ],
    "node-forge": [
        {"max_version": "1.3.0", "cve_hint": "CVE-2022-24771: Signature verification bypass in RSA PKCS#1 (< 1.3.0)"},
    ],
    "helmet": [],  # Known-safe when updated
    "cors": [
        {"max_version": "2.8.4", "cve_hint": "Older cors middleware versions may allow misconfigured origins"},
    ],
}


def _parse_version(version_str: str) -> Tuple[int, ...]:
    """Parse a version string like '2.3.1' into a comparable tuple."""
    try:
        return tuple(int(x) for x in re.findall(r'\d+', version_str)[:3])
    except (ValueError, IndexError):
        return (0, 0, 0)
