"""
tools/dependency_audit.py
-------------------------
Reads a project's dependency manifests and checks the *declared* versions
against the built-in advisory table. It deliberately does not run pip-audit:
that would audit Raven's own environment, not the target's.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

from tools.advisories import _KNOWN_VULNS, _parse_version

_REQ_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:==|~=|>=|<=|>|<)?\s*([0-9][A-Za-z0-9_.\-]*)?")


def parse_requirements(text: str) -> List[Tuple[str, str]]:
    deps = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = _REQ_RE.match(line)
        if m:
            deps.append((m.group(1).lower(), m.group(2) or ""))
    return deps


def parse_package_json(text: str) -> List[Tuple[str, str]]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    deps = []
    for section in ("dependencies", "devDependencies"):
        for name, ver in (data.get(section) or {}).items():
            deps.append((name.lower(), re.sub(r"^[^0-9]*", "", str(ver))))
    return deps


def find_manifests(root: Path) -> List[Path]:
    if root.is_file():
        return [root]
    found = []
    for pat in ("requirements*.txt", "package.json"):
        found += [p for p in root.rglob(pat)
                  if not any(part in ("node_modules", "venv", ".venv", ".git") for part in p.parts)]
    return sorted(found)[:20]


def audit_repository(path: str) -> Dict[str, Any]:
    root = Path(path)
    manifests = find_manifests(root)
    vulns: List[Dict[str, Any]] = []
    total = 0
    for mf in manifests:
        text = mf.read_text(encoding="utf-8", errors="ignore")
        deps = parse_package_json(text) if mf.name == "package.json" else parse_requirements(text)
        rel = mf.relative_to(root).as_posix() if root.is_dir() else mf.name
        for name, version in deps:
            total += 1
            for adv in _KNOWN_VULNS.get(name, []):
                max_v = adv.get("max_version")
                if version and max_v and _parse_version(version) < _parse_version(max_v):
                    vulns.append({
                        "package": name, "version": version, "manifest": rel,
                        "fixed_in": max_v, "advisory": adv.get("cve_hint", ""),
                    })
    return {"manifests": [m.name for m in manifests], "dependencies": total, "vulnerabilities": vulns}
