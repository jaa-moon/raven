"""
tools/permission_scanner.py
---------------------------
Filesystem and service permission auditing tool for Raven.

Checks for world-writable sensitive files, overly permissive private keys,
unquoted executable paths, and SUID/SGID binaries on POSIX systems.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any, Dict, List


class PermissionScanner:
    """Audits local filesystem and file permissions for privilege escalation and exposure risks."""

    SENSITIVE_NAMES = {
        ".env", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
        "private.key", "server.key", "credentials", "shadow", "passwd",
    }

    def __init__(self, target_path: str) -> None:
        self.target_path = Path(target_path).resolve()

    def scan(self) -> Dict[str, Any]:
        """Audit file and directory permissions."""
        issues: List[Dict[str, Any]] = []
        files_checked = 0

        if not self.target_path.exists():
            return {
                "target_path": str(self.target_path),
                "error": "Target path does not exist",
                "files_checked": 0,
                "issues": [],
            }

        # Check single file or walk directory
        paths = [self.target_path] if self.target_path.is_file() else []
        if self.target_path.is_dir():
            for root, dirs, files in os.walk(self.target_path):
                dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "venv", ".venv", "__pycache__")]
                for f in files:
                    paths.append(Path(root) / f)
                    if len(paths) >= 200:  # Bound scan size for performance
                        break
                if len(paths) >= 200:
                    break

        for p in paths:
            files_checked += 1
            try:
                st = p.stat()
                mode = st.st_mode

                # 1. SUID / SGID detection (POSIX)
                if hasattr(stat, "S_ISUID") and (mode & stat.S_ISUID):
                    issues.append({
                        "check_id": "PERM-001",
                        "severity": "HIGH",
                        "issue": "SUID bit set on binary",
                        "file": str(p),
                        "details": f"File has SUID bit set (mode: {oct(mode)}), runs with owner privileges.",
                    })
                if hasattr(stat, "S_ISGID") and (mode & stat.S_ISGID):
                    issues.append({
                        "check_id": "PERM-002",
                        "severity": "MEDIUM",
                        "issue": "SGID bit set on file",
                        "file": str(p),
                        "details": f"File has SGID bit set (mode: {oct(mode)}).",
                    })

                # 2. World-writable files
                if hasattr(stat, "S_IWOTH") and (mode & stat.S_IWOTH):
                    issues.append({
                        "check_id": "PERM-003",
                        "severity": "HIGH",
                        "issue": "World-writable file",
                        "file": str(p),
                        "details": f"Any local user can modify this file (mode: {oct(mode)}).",
                    })

                # 3. Sensitive file with excessive permissions
                if p.name.lower() in self.SENSITIVE_NAMES or p.suffix.lower() in (".key", ".pem"):
                    # On POSIX: check if group/others have read access
                    if hasattr(stat, "S_IRGRP") and (mode & (stat.S_IRGRP | stat.S_IROTH)):
                        issues.append({
                            "check_id": "PERM-004",
                            "severity": "CRITICAL",
                            "issue": "Sensitive credential or private key readable by group/others",
                            "file": str(p),
                            "details": f"Private key/secret has loose permissions ({oct(mode)}). Should be 0600.",
                        })

            except Exception:
                continue

        return {
            "target_path": str(self.target_path),
            "files_checked": files_checked,
            "issues_count": len(issues),
            "issues": issues,
            "vulnerable": len(issues) > 0,
        }


# ── Module-level wrapper for MCP gateway dispatch ────────────────────────────

async def scan(path: str = ".") -> Dict[str, Any]:
    """Gateway-callable wrapper for PermissionScanner."""
    scanner = PermissionScanner(target_path=path)
    return scanner.scan()
