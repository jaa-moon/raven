"""
adapters/target_adapters/generic_adapter.py
-------------------------------------------
Fallback target adapter for arbitrary or novel assessment targets.
"""

from __future__ import annotations

from engine_models.target import Target, TargetType


class GenericTargetAdapter:
    """Fallback adapter that classifies unknown target strings for reconnaissance profiling."""

    @classmethod
    def can_handle(cls, raw_input: str) -> bool:
        return True

    @classmethod
    def adapt(cls, raw_input: str) -> Target:
        return Target(
            raw_input=raw_input,
            target_type=TargetType.UNKNOWN,
            entrypoints=[raw_input],
            metadata={"notes": "Classified via fallback GenericTargetAdapter"},
        )
