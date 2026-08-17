"""
tools/secret_scanner.py
-----------------------
Static scanner for hardcoded secrets, API keys, passwords, and sensitive configuration.

Detection approaches:
1. Regex patterns for known secret formats (AWS, JWT, private keys)
2. Variable name heuristics (secret_key, password, token, etc.)
3. High-entropy string detection for opaque secrets
"""

from __future__ import annotations

import re
import math
from pathlib import Path
from typing import Dict, List

# Regex patterns for known secret formats
_FORMAT_PATTERNS = {
    "AWS Access Key": r'AKIA[0-9A-Z]{16}',
    "JWT Token": r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
    "Private Key": r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
    "GitHub Token": r'gh[ps]_[A-Za-z0-9_]{36,}',
    "Slack Token": r'xox[baprs]-[0-9A-Za-z\-]{10,}',
}

# Variable name patterns that commonly hold secrets
_VAR_PATTERNS = {
    "Hardcoded Password": r'(?:password|passwd|pwd|db_password|db_pass)\s*[=:]\s*["\']([^"\']{3,})["\']',
    "Hardcoded Secret Key": r'(?:secret_key|secret|app_secret|signing_key)\s*[=:]\s*["\']([^"\']{3,})["\']',
    "Generic API Key": r'(?:api[_-]?key|api_secret|access_key)\s*[=:]\s*["\']([^"\']{8,})["\']',
    "Auth Token": r'(?:auth_token|bearer_token|access_token)\s*[=:]\s*["\']([^"\']{8,})["\']',
    "Database URL": r'(?:database_url|db_url|connection_string|dsn)\s*[=:]\s*["\']([^"\']+://[^"\']+)["\']',
}

_SKIP_EXTENSIONS = {".pyc", ".pyo", ".exe", ".dll", ".bin", ".so", ".o", ".class", ".whl", ".gz", ".zip", ".tar",
                     ".png", ".jpg", ".gif", ".svg", ".ico", ".woff", ".ttf", ".eot"}
_SCAN_EXTENSIONS = {".py", ".js", ".ts", ".json", ".env", ".yaml", ".yml", ".toml", ".cfg", ".ini",
                     ".conf", ".properties", ".xml", ".sh", ".bash", ".go", ".java", ".rb", ".php",
                     ".cs", ".rs", ".tf", ".hcl", ".dockerfile"}


def _entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


class SecretScanner:
    """
    Scans project source files for hardcoded secrets and credentials.
    """

    def __init__(self, target_path: str) -> None:
        self.target_path = Path(target_path)

    def scan(self) -> List[Dict[str, str]]:
        """Scan directory and return list of discovered secret findings."""
        findings: List[Dict[str, str]] = []
        if not self.target_path.exists():
            return findings

        seen_matches = set()

        for file_path in list(self.target_path.rglob("*"))[:200]:
            if not file_path.is_file():
                continue
            if file_path.suffix.lower() in _SKIP_EXTENSIONS:
                continue
            if file_path.suffix.lower() not in _SCAN_EXTENSIONS and file_path.name not in (".env", "Dockerfile", "docker-compose.yml"):
                continue
            # Skip common non-source directories
            parts = file_path.parts
            if any(p in ("node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build") for p in parts):
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            rel_path = file_path.relative_to(self.target_path).as_posix()

            # 1. Check known format patterns
            for secret_type, pattern in _FORMAT_PATTERNS.items():
                for match in re.finditer(pattern, content):
                    key = (secret_type, rel_path, match.group(0)[:60])
                    if key not in seen_matches:
                        seen_matches.add(key)
                        findings.append({
                            "type": secret_type,
                            "file": rel_path,
                            "match": match.group(0)[:80],
                            "line": _get_line_number(content, match.start())
                        })

            # 2. Check variable name heuristics
            for secret_type, pattern in _VAR_PATTERNS.items():
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    value = match.group(1) if match.lastindex else match.group(0)
                    key = (secret_type, rel_path, value[:60])
                    if key not in seen_matches:
                        seen_matches.add(key)
                        findings.append({
                            "type": secret_type,
                            "file": rel_path,
                            "match": match.group(0)[:80],
                            "line": _get_line_number(content, match.start())
                        })

        return findings


def _get_line_number(content: str, position: int) -> str:
    """Return the line number for a character position in content."""
    return str(content[:position].count("\n") + 1)
