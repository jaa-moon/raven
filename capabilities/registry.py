"""
capabilities/registry.py
------------------------
Dynamic capability registry for Raven adaptive security assessment.

Discovers, registers, and queries capability manifests.
Determines applicable capabilities based on target characteristics,
discovered assets, scope boundaries, and available toolsets.
"""

from __future__ import annotations

import importlib
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set

from capabilities.manifests import ALL_MANIFESTS
from engine_models.assets import AssetType, DiscoveredAsset
from engine_models.authorization import Authorization
from engine_models.capabilities import CapabilityManifest
from engine_models.scope import Scope
from engine_models.target import Target, TargetType

logger = logging.getLogger("raven.capabilities.registry")


class CapabilityRegistry:
    """
    Registry of all available security assessment capabilities.
    Supports auto-discovery, manual registration, and context-aware filtering.
    """

    def __init__(self, auto_discover: bool = True) -> None:
        self._manifests: Dict[str, CapabilityManifest] = {}
        if auto_discover:
            self._load_builtins()

    def _load_builtins(self) -> None:
        """Load all manifests registered in ALL_MANIFESTS."""
        for manifest in ALL_MANIFESTS:
            self.register(manifest)

    def register(self, manifest: CapabilityManifest) -> None:
        """Register a new capability manifest."""
        self._manifests[manifest.capability_id] = manifest
        logger.debug(f"Registered capability '{manifest.capability_id}' ({manifest.name})")

    def unregister(self, capability_id: str) -> Optional[CapabilityManifest]:
        """Remove a capability manifest by ID."""
        return self._manifests.pop(capability_id, None)

    def get_capability(self, capability_id: str) -> Optional[CapabilityManifest]:
        """Fetch a capability manifest by ID."""
        return self._manifests.get(capability_id)

    def list_capabilities(self) -> List[CapabilityManifest]:
        """Return all registered capabilities."""
        return list(self._manifests.values())

    def find_applicable_capabilities(
        self,
        target: Target,
        assets: Optional[List[DiscoveredAsset]] = None,
        scope: Optional[Scope] = None,
        authorization: Optional[Authorization] = None,
        available_tools: Optional[Set[str]] = None,
    ) -> List[CapabilityManifest]:
        """
        Identify capabilities applicable to the target system and current state.

        Considers:
        1. Target primary type and component types
        2. Discovered asset types
        3. Scope permissions (passive vs. active)
        4. Authorization credentials (if authenticated mode required)
        5. Required tool availability
        6. Exclusion lists and prerequisite resolution
        """
        applicable: List[CapabilityManifest] = []
        allow_active = scope.allow_active_testing if scope else False
        allow_auth = scope.allow_authenticated_testing if scope else False
        has_creds = authorization.has_credentials() if authorization else False

        # Determine all relevant target types (primary target + components)
        target_types = {target.target_type}
        for comp in target.components:
            if comp.target_type:
                target_types.add(comp.target_type)

        # Determine all available asset types
        discovered_types = {a.asset_type for a in (assets or [])}

        for manifest in self._manifests.values():
            # 1. Target type match
            target_type_match = any(tt in manifest.supported_target_types for tt in target_types)

            # If hybrid or target has matching asset types even if target_type is generic
            asset_type_match = bool(discovered_types.intersection(set(manifest.supported_asset_types)))

            if not target_type_match and not asset_type_match:
                continue

            # 2. Mode compatibility check
            if not manifest.supports_passive_mode and not allow_active:
                logger.debug(
                    f"Skipping capability '{manifest.capability_id}': requires active mode, "
                    "but active testing is disabled."
                )
                continue

            if not manifest.supports_passive_mode and not manifest.supports_active_mode and not (allow_auth and has_creds):
                continue

            # 3. Tool requirements check
            if available_tools is not None and manifest.required_tools:
                missing_tools = set(manifest.required_tools) - available_tools
                if missing_tools:
                    logger.debug(
                        f"Skipping capability '{manifest.capability_id}': missing required tools {missing_tools}."
                    )
                    continue

            applicable.append(manifest)

        # 4. Resolve exclusions: if capability A excludes B, remove B if A is higher priority
        final_list: List[CapabilityManifest] = []
        excluded_ids: Set[str] = set()
        for cap in applicable:
            excluded_ids.update(cap.exclusions)

        for cap in applicable:
            if cap.capability_id not in excluded_ids:
                final_list.append(cap)

        return self._sort_by_prerequisites(final_list)

    def _sort_by_prerequisites(self, capabilities: List[CapabilityManifest]) -> List[CapabilityManifest]:
        """
        Sort capabilities so prerequisites appear before dependents (topological order).
        """
        cap_map = {c.capability_id: c for c in capabilities}
        visited: Set[str] = set()
        result: List[CapabilityManifest] = []

        def visit(cap_id: str) -> None:
            if cap_id in visited or cap_id not in cap_map:
                return
            visited.add(cap_id)
            for prereq in cap_map[cap_id].prerequisites:
                if prereq in cap_map:
                    visit(prereq)
            result.append(cap_map[cap_id])

        for c in capabilities:
            visit(c.capability_id)

        return result
