"""
tools/config_scanner.py
-----------------------
Static configuration security scanner for Raven.

Analyzes configuration files (.env, yaml, json, toml, docker-compose, Dockerfile, etc.)
for debug mode exposure, insecure defaults, TLS validation disabling, and misconfigurations.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List


class ConfigScanner:
    """Scans project configurations for security misconfigurations and weak defaults."""

    CONFIG_NAMES = {
        ".env", ".env.example", ".env.local", ".env.production", ".env.stage",
        "config.yaml", "config.yml", "config.json", "settings.py", "local_settings.py",
        "docker-compose.yml", "docker-compose.yaml", "Dockerfile", "k8s.yaml",
        "application.properties", "application.yml", "appsettings.json",
        "nginx.conf", "httpd.conf",
    }

    PATTERNS: List[Dict[str, Any]] = [
        {
            "id": "CONF-001",
            "name": "Debug Mode Enabled",
            "pattern": r'(?i)\b(DEBUG|FLASK_DEBUG|DJANGO_DEBUG)\s*[:=]\s*(True|1|"true"|"1"|yes)',
            "severity": "HIGH",
            "description": "Debug mode enabled in configuration, which may expose stack traces, interactive debuggers, or internal variables.",
        },
        {
            "id": "CONF-002",
            "name": "TLS Certificate Verification Disabled",
            "pattern": r'(?i)(verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*["\']?0["\']?|ssl_verify\s*[:=]\s*false|insecure_skip_verify\s*[:=]\s*true)',
            "severity": "HIGH",
            "description": "TLS certificate validation explicitly disabled, making connections vulnerable to man-in-the-middle attacks.",
        },
        {
            "id": "CONF-003",
            "name": "Weak / Default Secret Key",
            "pattern": r'(?i)(SECRET_KEY|JWT_SECRET|APP_KEY)\s*[:=]\s*["\'](changeme|secret|default|password|123456|test|admin)["\']',
            "severity": "CRITICAL",
            "description": "Known default or trivial secret key in configuration file.",
        },
        {
            "id": "CONF-004",
            "name": "Permissive Wildcard CORS",
            "pattern": r'(?i)(allow_origins\s*[:=]\s*["\']\*["\']|Access-Control-Allow-Origin\s*[:=]\s*["\']\*["\'])',
            "severity": "MEDIUM",
            "description": "Wildcard Access-Control-Allow-Origin allows arbitrary cross-origin requests.",
        },
        {
            "id": "CONF-005",
            "name": "Privileged Container Mode",
            "pattern": r'(?i)\bprivileged\s*:\s*true\b',
            "severity": "HIGH",
            "description": "Container configured with privileged: true, bypassing host isolation boundaries.",
        },
        {
            "id": "CONF-006",
            "name": "Exposed Insecure Listening Address",
            "pattern": r'(?i)\b(HOST|BIND_ADDR|LISTEN_ADDRESS)\s*[:=]\s*["\']0\.0\.0\.0["\']',
            "severity": "LOW",
            "description": "Service binds to all network interfaces (0.0.0.0) by default.",
        },
    ]

    def __init__(self, target_path: str) -> None:
        self.target_path = Path(target_path).resolve()

    def scan(self) -> Dict[str, Any]:
        """Scan target directory or single config file."""
        files_to_scan: List[Path] = []
        issues: List[Dict[str, Any]] = []

        if self.target_path.is_file():
            files_to_scan.append(self.target_path)
        elif self.target_path.is_dir():
            for root, dirs, files in os.walk(self.target_path):
                # Skip heavy directories
                dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build")]
                for f in files:
                    p = Path(root) / f
                    if f.lower() in self.CONFIG_NAMES or p.suffix.lower() in (".env", ".conf", ".ini"):
                        files_to_scan.append(p)

        for file_path in files_to_scan:
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
                lines = content.splitlines()

                for line_no, line in enumerate(lines, start=1):
                    # Skip commented lines
                    stripped = line.strip()
                    if stripped.startswith("#") or stripped.startswith("//"):
                        continue

                    for check in self.PATTERNS:
                        if re.search(check["pattern"], line):
                            issues.append({
                                "check_id": check["id"],
                                "name": check["name"],
                                "severity": check["severity"],
                                "description": check["description"],
                                "file": str(file_path.relative_to(self.target_path) if self.target_path.is_dir() else file_path),
                                "line": line_no,
                                "line_content": stripped[:120],
                            })
            except Exception:
                continue

        return {
            "target_path": str(self.target_path),
            "files_scanned": len(files_to_scan),
            "issues_count": len(issues),
            "issues": issues,
            "vulnerable": len(issues) > 0,
        }


# ── Module-level wrapper for MCP gateway dispatch ────────────────────────────

async def scan(path: str = ".") -> Dict[str, Any]:
    """Gateway-callable wrapper for ConfigScanner."""
    scanner = ConfigScanner(target_path=path)
    return scanner.scan()
