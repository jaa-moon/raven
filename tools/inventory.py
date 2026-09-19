"""
tools/inventory.py
------------------
Read-only inventory helpers used during target analysis.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List

from tools.dependency_audit import find_manifests, parse_package_json, parse_requirements

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".tox"}
CONFIG_NAMES = {".env", "docker-compose.yml", "docker-compose.yaml", "config.json", "settings.py",
                "application.properties", "application.yml", "web.config", "nginx.conf"}
CONFIG_EXTS = {".env", ".ini", ".cfg", ".toml", ".yaml", ".yml", ".conf", ".properties"}
MAX_FILES = 5000


def repo_inventory(path: str) -> Dict[str, Any]:
    root = Path(path)
    exts: Dict[str, int] = {}
    configs: List[str] = []
    dockerfiles: List[str] = []
    files = 0
    for dirpath, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".git")]
        for name in names:
            files += 1
            if files > MAX_FILES:
                break
            ext = Path(name).suffix.lower()
            exts[ext] = exts.get(ext, 0) + 1
            rel = (Path(dirpath) / name).relative_to(root).as_posix()
            if name.lower().startswith("dockerfile"):
                dockerfiles.append(rel)
            if name.lower() in CONFIG_NAMES or ext in CONFIG_EXTS:
                configs.append(rel)
        if files > MAX_FILES:
            break
    manifests = find_manifests(root)
    dep_names: List[str] = []
    for mf in manifests:
        text = mf.read_text(encoding="utf-8", errors="ignore")
        deps = parse_package_json(text) if mf.name == "package.json" else parse_requirements(text)
        dep_names += [n for n, _ in deps]
    return {
        "file_count": min(files, MAX_FILES), "extensions": exts,
        "manifests": [m.relative_to(root).as_posix() for m in manifests],
        "config_files": configs[:50], "dockerfiles": dockerfiles, "dependencies": sorted(set(dep_names)),
    }


_MAGIC = [(b"\x7fELF", "ELF"), (b"MZ", "PE"), (b"\xcf\xfa\xed\xfe", "Mach-O"), (b"\xca\xfe\xba\xbe", "Mach-O")]


def file_classify(path: str) -> Dict[str, Any]:
    p = Path(path)
    if not p.is_file():
        return {"exists": False}
    head = p.open("rb").read(8)
    for magic, fmt in _MAGIC:
        if head.startswith(magic):
            return {"exists": True, "size": p.stat().st_size, "format": fmt, "is_binary": True}
    binary = b"\x00" in head
    return {"exists": True, "size": p.stat().st_size, "format": "binary" if binary else "text", "is_binary": binary}
