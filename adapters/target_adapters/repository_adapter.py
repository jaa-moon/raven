"""
adapters/target_adapters/repository_adapter.py
----------------------------------------------
Target adapter for source code repositories and local projects.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List

from engine_models.target import Target, TargetComponent, TargetType


class RepositoryTargetAdapter:
    """Adapts local source code directories into Target models."""

    @classmethod
    def can_handle(cls, raw_input: str) -> bool:
        return os.path.exists(raw_input) and os.path.isdir(raw_input)

    @classmethod
    def adapt(cls, raw_input: str) -> Target:
        p = Path(raw_input).resolve()
        components: List[TargetComponent] = []

        # Check subcomponents
        if (p / "package.json").exists():
            components.append(
                TargetComponent(
                    name="javascript_subsystem",
                    component_type="source_code",
                    target_type=TargetType.SOURCE_REPOSITORY,
                    location=str(p / "package.json"),
                )
            )
        if (p / "requirements.txt").exists() or (p / "pyproject.toml").exists():
            components.append(
                TargetComponent(
                    name="python_subsystem",
                    component_type="source_code",
                    target_type=TargetType.SOURCE_REPOSITORY,
                    location=str(p),
                )
            )
        if (p / "Dockerfile").exists():
            components.append(
                TargetComponent(
                    name="container_runtime",
                    component_type="container",
                    target_type=TargetType.CONTAINER,
                    location=str(p / "Dockerfile"),
                )
            )

        return Target(
            raw_input=raw_input,
            target_type=TargetType.SOURCE_REPOSITORY,
            entrypoints=[str(p)],
            components=components,
            metadata={
                "absolute_path": str(p),
                "is_git": (p / ".git").exists(),
            },
        )
