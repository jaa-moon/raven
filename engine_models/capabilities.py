"""
engine_models/capabilities.py
-----------------------------
Capability manifest model for Raven adaptive security assessment.

Each security capability (web scanning, source-code analysis, container
assessment, etc.) declares what it can assess, what tools it needs,
and under what conditions it should be activated.
"""

from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from engine_models.assets import AssetType
from engine_models.target import TargetType


class CapabilityManifest(BaseModel):
    """
    Declarative manifest for a security assessment capability.

    The capability registry discovers these manifests and uses them
    to determine which capabilities are applicable to a given target.
    New capabilities are added by creating a new manifest — no engine
    modification required.
    """

    capability_id: str = ""
    name: str = ""
    description: str = ""

    # What this capability can assess
    supported_target_types: List[TargetType] = Field(default_factory=list)
    supported_asset_types: List[AssetType] = Field(default_factory=list)

    # Tool requirements
    required_tools: List[str] = Field(default_factory=list)
    optional_tools: List[str] = Field(default_factory=list)

    # Agent interface
    agent_module: str = ""  # Python module path, e.g., "agents.specialized.web_api_agent"
    agent_class: str = ""   # Class name, e.g., "WebApiAssessmentAgent"

    # Input/output contracts
    required_inputs: List[str] = Field(default_factory=list)
    produces_assets: List[AssetType] = Field(default_factory=list)

    # Risk and mode
    risk_level: str = "low"  # low, moderate, high
    supports_passive_mode: bool = True
    supports_active_mode: bool = False
    supports_authenticated_mode: bool = False

    # Dependency ordering
    prerequisites: List[str] = Field(default_factory=list)  # capability_ids that must run first
    exclusions: List[str] = Field(default_factory=list)  # capability_ids incompatible with this one

    def is_applicable(
        self,
        target_type: TargetType,
        available_assets: List[AssetType] | None = None,
        allow_active: bool = False,
    ) -> bool:
        """
        Check if this capability is applicable to a given target type
        and assessment mode.
        """
        if target_type not in self.supported_target_types:
            return False

        # If capability requires active testing but scope doesn't allow it
        if not self.supports_passive_mode and not allow_active:
            return False

        return True
