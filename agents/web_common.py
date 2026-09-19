"""
agents/web_common.py
--------------------
Shared helpers for web agents: the nonexistent-route baseline captured during
target analysis, and response classification against it.
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import urljoin

from core.profile import TargetProfile
from validation.baseline import SPAFallbackDetector
from validation.classifiers import ClassifiedResponse, classify_response


def base_url(profile: TargetProfile) -> str:
    return str(profile.attributes.get("base_url", "")).rstrip("/")


def url_for(profile: TargetProfile, path: str) -> str:
    return urljoin(base_url(profile) + "/", path.lstrip("/"))


def store_baseline(profile: TargetProfile, probe_path: str, data: Dict[str, Any]) -> None:
    profile.attributes["baseline"] = {
        "probe": probe_path,
        "status": data.get("status_code", 0),
        "headers": {"content-type": data.get("content_type", "")},
        "body": (data.get("body") or "")[:20000],
    }


def load_detector(profile: TargetProfile) -> Optional[SPAFallbackDetector]:
    b = profile.attributes.get("baseline")
    if not b:
        return None
    det = SPAFallbackDetector()
    det.load_baseline(b["probe"], b["status"], b["headers"], b["body"])
    return det


def classify(path: str, data: Dict[str, Any], det: Optional[SPAFallbackDetector]) -> ClassifiedResponse:
    return classify_response(path, data["status_code"], data["headers"], data["body"], det)
