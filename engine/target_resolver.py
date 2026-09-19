"""
engine/target_resolver.py
-------------------------
Target resolver and classifier for Raven adaptive security assessments.

Analyzes raw input string (URL, file path, IP address, CIDR, container image, etc.)
and delegates to specialized target adapters to instantiate the universal Target model.
"""

from __future__ import annotations

from typing import Optional

from adapters.target_adapters.binary_adapter import BinaryTargetAdapter
from adapters.target_adapters.container_adapter import ContainerTargetAdapter
from adapters.target_adapters.generic_adapter import GenericTargetAdapter
from adapters.target_adapters.network_adapter import NetworkTargetAdapter
from adapters.target_adapters.repository_adapter import RepositoryTargetAdapter
from adapters.target_adapters.url_adapter import UrlTargetAdapter
from engine_models.target import Target, TargetType


class TargetResolver:
    """
    Resolves raw target strings into structured Target instances using adapter chain.
    """

    ADAPTERS = [
        UrlTargetAdapter,
        RepositoryTargetAdapter,
        BinaryTargetAdapter,
        NetworkTargetAdapter,
        ContainerTargetAdapter,
    ]

    @classmethod
    def resolve(
        cls,
        raw_input: str,
        explicit_type: Optional[TargetType | str] = None,
    ) -> Target:
        """
        Analyze raw target input and return a fully instantiated Target model.
        """
        raw_input = raw_input.strip()

        # If explicit type provided, honor it
        if explicit_type:
            tt = TargetType(explicit_type) if isinstance(explicit_type, str) else explicit_type
            return Target(
                raw_input=raw_input,
                target_type=tt,
                entrypoints=[raw_input],
            )

        # Iterate through adapters in order
        for adapter in cls.ADAPTERS:
            if adapter.can_handle(raw_input):
                return adapter.adapt(raw_input)

        # Fallback adapter
        return GenericTargetAdapter.adapt(raw_input)
