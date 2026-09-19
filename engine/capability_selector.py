"""
engine/capability_selector.py
-----------------------------
Adaptive capability selection and priority ranking for Raven assessments.

Filters and prioritizes applicable capabilities based on:
1. Target architecture and attack surface
2. Operator preferences (--capabilities, --exclude)
3. Assessment depth preset (quick, standard, deep)
4. Budget and resource constraints
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from engine_models.capabilities import CapabilityManifest


@dataclass
class CapabilitySelectionResult:
    """Outcome of capability selection and ranking."""

    activated: List[CapabilityManifest] = field(default_factory=list)
    excluded: List[Tuple[str, str]] = field(default_factory=list)  # (capability_id, reason)

    @property
    def activated_ids(self) -> List[str]:
        return [c.capability_id for c in self.activated]


class CapabilitySelector:
    """
    Ranks and selects capabilities to activate for an assessment run.
    """

    # Priority score for execution ordering (higher runs earlier)
    PRIORITY_SCORES: Dict[str, int] = {
        "secrets_detection": 90,
        "source_code_analysis": 85,
        "dependency_analysis": 80,
        "network_assessment": 75,
        "auth_identity_assessment": 70,
        "web_api_assessment": 65,
        "configuration_assessment": 60,
        "container_assessment": 55,
        "kubernetes_assessment": 50,
        "cloud_assessment": 45,
        "database_assessment": 40,
        "binary_analysis": 35,
        "firmware_analysis": 30,
        "smart_contract_analysis": 25,
        "protocol_assessment": 20,
    }

    # Caps for depth presets
    DEPTH_ALLOWED_CAPABILITIES: Dict[str, Optional[Set[str]]] = {
        "quick": {
            "secrets_detection",
            "source_code_analysis",
            "dependency_analysis",
            "network_assessment",
            "web_api_assessment",
            "configuration_assessment",
        },
        "standard": None,  # All applicable allowed
        "deep": None,      # All applicable allowed
    }

    def __init__(
        self,
        explicit_include: Optional[List[str]] = None,
        explicit_exclude: Optional[List[str]] = None,
        depth: str = "standard",
    ) -> None:
        self.explicit_include = set(explicit_include or [])
        self.explicit_exclude = set(explicit_exclude or [])
        self.depth = depth.lower()

    def select(
        self,
        applicable_capabilities: List[CapabilityManifest],
    ) -> CapabilitySelectionResult:
        """
        Produce ordered list of capabilities to activate.
        """
        activated: List[CapabilityManifest] = []
        excluded: List[Tuple[str, str]] = []

        depth_filter = self.DEPTH_ALLOWED_CAPABILITIES.get(self.depth)

        for cap in applicable_capabilities:
            cap_id = cap.capability_id

            # 1. Operator explicit exclusion
            if cap_id in self.explicit_exclude:
                excluded.append((cap_id, "Explicitly excluded by operator (--exclude)"))
                continue

            # 2. Operator explicit inclusion overrides depth restrictions
            if self.explicit_include and cap_id not in self.explicit_include:
                excluded.append((cap_id, "Not included in explicit --capabilities selection"))
                continue

            # 3. Depth preset filtering
            if depth_filter is not None and cap_id not in depth_filter:
                excluded.append((cap_id, f"Deferred due to '{self.depth}' assessment depth preset"))
                continue

            activated.append(cap)

        # 4. Sort activated capabilities by priority score
        activated.sort(
            key=lambda c: self.PRIORITY_SCORES.get(c.capability_id, 50),
            reverse=True,
        )

        return CapabilitySelectionResult(
            activated=activated,
            excluded=excluded,
        )
