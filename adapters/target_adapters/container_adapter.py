"""
adapters/target_adapters/container_adapter.py
---------------------------------------------
Target adapter for container images and archives.
"""

from __future__ import annotations

import os
from engine_models.target import Target, TargetType


class ContainerTargetAdapter:
    """Adapts container images and archives into Target models."""

    @classmethod
    def can_handle(cls, raw_input: str) -> bool:
        clean = raw_input.strip()
        if clean.endswith((".tar", ".tar.gz")):
            return True
        if ":" in clean and not "/" in clean and " " not in clean:
            return True
        return False

    @classmethod
    def adapt(cls, raw_input: str) -> Target:
        clean = raw_input.strip()
        return Target(
            raw_input=raw_input,
            target_type=TargetType.CONTAINER_IMAGE,
            entrypoints=[clean],
            metadata={"image_reference": clean},
        )
