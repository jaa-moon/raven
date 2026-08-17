"""
rag/memory_store.py
-------------------
Persists successful attack patterns discovered during pentests into the self-improving memory layer.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional
from reports.models import AgentFinding, AttackMemory, ProjectProfile

_MEMORY_DIR = Path(__file__).parent.parent / "knowledge" / "memory"


class MemoryStore:
    """
    Manages reading and writing attack pattern memories.
    """

    def __init__(self) -> None:
        _MEMORY_DIR.mkdir(parents=True, exist_ok=True)

    def _get_fingerprint(self, profile: ProjectProfile) -> str:
        lang = profile.language.lower()
        fw = profile.framework.lower()
        return f"{lang}+{fw}".replace(" ", "")

    def store_successful_pattern(self, finding: AgentFinding, profile: ProjectProfile) -> None:
        """Store or update a successful attack pattern for this target stack fingerprint."""
        fingerprint = self._get_fingerprint(profile)
        memory_file = _MEMORY_DIR / f"{fingerprint}.json"

        memories: List[dict] = []
        if memory_file.exists():
            try:
                memories = json.loads(memory_file.read_text(encoding="utf-8"))
            except Exception:
                memories = []

        # Check if technique already exists
        existing = None
        for m in memories:
            if m.get("technique") == finding.vulnerability_type and m.get("payload_template") == finding.payload_sent:
                existing = m
                break

        if existing:
            existing["confirmed_count"] += 1
            existing["scan_count"] += 1
            existing["success_rate"] = round(existing["confirmed_count"] / existing["scan_count"], 2)
        else:
            new_mem = AttackMemory(
                stack_fingerprint=fingerprint,
                technique=finding.vulnerability_type,
                payload_template=finding.payload_sent,
                success_rate=1.0,
                scan_count=1,
                confirmed_count=1
            )
            memories.append(new_mem.model_dump())

        memory_file.write_text(json.dumps(memories, indent=2), encoding="utf-8")

    def get_patterns_for_stack(self, profile: ProjectProfile) -> List[AttackMemory]:
        """Retrieve historical attack patterns for a stack."""
        fingerprint = self._get_fingerprint(profile)
        memory_file = _MEMORY_DIR / f"{fingerprint}.json"

        if not memory_file.exists():
            return []

        try:
            raw = json.loads(memory_file.read_text(encoding="utf-8"))
            return [AttackMemory(**item) for item in raw]
        except Exception:
            return []

    def deprioritize_failed_pattern(self, technique: str, profile: ProjectProfile) -> None:
        """Increment attempt count without confirmation, reducing success rate."""
        fingerprint = self._get_fingerprint(profile)
        memory_file = _MEMORY_DIR / f"{fingerprint}.json"

        if not memory_file.exists():
            return

        try:
            memories = json.loads(memory_file.read_text(encoding="utf-8"))
            updated = False
            for m in memories:
                if m.get("technique") == technique:
                    m["scan_count"] += 1
                    m["success_rate"] = round(m["confirmed_count"] / m["scan_count"], 2)
                    updated = True

            if updated:
                memory_file.write_text(json.dumps(memories, indent=2), encoding="utf-8")
        except Exception:
            pass
