"""
tools/code_scanner.py
---------------------
Lightweight static analysis. Emits *issues* (pattern hits with file/line),
never verdicts: the validator independently re-reads each location.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".tox"}
EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".rb", ".go", ".java"}
MAX_FILES = 600
MAX_ISSUES = 300

# rule_id -> (regex, severity, cwe, description)
RULES: Dict[str, tuple] = {
    "code-eval": (r"(?<![\w.])eval\s*\(", "high", "CWE-95", "Dynamic evaluation via eval()"),
    "code-exec": (r"(?<![\w.])exec\s*\(", "high", "CWE-95", "Dynamic execution via exec()"),
    "cmd-shell-true": (r"shell\s*=\s*True", "high", "CWE-78", "Subprocess invoked with shell=True"),
    "cmd-os-system": (r"os\.system\s*\(", "high", "CWE-78", "os.system() call"),
    "deser-pickle": (r"pickle\.loads?\s*\(", "high", "CWE-502", "Untrusted deserialization via pickle"),
    "deser-yaml": (r"yaml\.load\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?Safe)", "medium", "CWE-502",
                   "yaml.load without SafeLoader"),
    "sql-fstring": (r"execute\s*\(\s*f[\"']", "high", "CWE-89", "SQL built with an f-string"),
    "sql-concat": (r"execute\s*\(\s*[\"'][^\"']*[\"']\s*(?:\+|%)", "high", "CWE-89",
                   "SQL built by concatenation/formatting"),
    "tls-verify-off": (r"verify\s*=\s*False", "medium", "CWE-295", "TLS certificate verification disabled"),
    "debug-enabled": (r"(?:app\.run\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True)", "medium", "CWE-489",
                      "Debug mode enabled"),
    "weak-hash": (r"hashlib\.(?:md5|sha1)\s*\(", "low", "CWE-328", "Weak hash function"),
    "js-innerhtml": (r"\.innerHTML\s*=", "medium", "CWE-79", "Assignment to innerHTML"),
    "js-child-process": (r"child_process\.exec\s*\(", "high", "CWE-78", "child_process.exec() call"),
}
_COMPILED = {k: (re.compile(v[0], re.M), *v[1:]) for k, v in RULES.items()}


def _is_comment(line: str) -> bool:
    s = line.lstrip()
    return s.startswith(("#", "//", "*", "/*"))


def scan(path: str) -> Dict[str, Any]:
    root = Path(path)
    issues: List[Dict[str, Any]] = []
    files = 0
    walker = [(str(root.parent), [], [root.name])] if root.is_file() else os.walk(root)
    for dirpath, dirs, names in walker:
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for name in names:
            if Path(name).suffix.lower() not in EXTS:
                continue
            files += 1
            if files > MAX_FILES:
                return {"files_scanned": MAX_FILES, "issues": issues, "truncated": True}
            fp = Path(dirpath) / name
            try:
                text = fp.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = fp.relative_to(root).as_posix() if root.is_dir() else fp.name
            for lineno, line in enumerate(text.splitlines(), 1):
                if _is_comment(line):
                    continue
                for rule_id, (rx, sev, cwe, desc) in _COMPILED.items():
                    if rx.search(line):
                        issues.append({
                            "rule": rule_id, "severity": sev, "cwe": cwe, "description": desc,
                            "file": rel, "line": lineno, "snippet": line.strip()[:160],
                        })
                        if len(issues) >= MAX_ISSUES:
                            return {"files_scanned": files, "issues": issues, "truncated": True}
    return {"files_scanned": files, "issues": issues, "truncated": False}
