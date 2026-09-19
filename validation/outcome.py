"""
validation/outcome.py
---------------------
The one place a Finding's verdict is written.
"""

from __future__ import annotations

from typing import List, Optional

from core.models import Confidence, Evidence, Finding, FindingStatus, now_iso


def conclude(f: Finding, status: FindingStatus, confidence: Confidence, note: str,
             validator: str, evidence: Optional[List[Evidence]] = None) -> Finding:
    f.status = status
    if status == FindingStatus.CONFIRMED and f.title.startswith("Possible "):
        f.title = f.title[len("Possible "):]
    f.confidence = confidence if status != FindingStatus.REJECTED else Confidence.NONE
    f.validator = validator
    f.validated_at = now_iso()
    f.validation_notes.append(note)
    f.evidence.extend(evidence or [])
    return f
