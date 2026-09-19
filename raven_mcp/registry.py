"""
raven_mcp/registry.py
---------------------
Tool registry: the single source of truth for which tools exist and which
capabilities they provide. Capability -> tool resolution happens here, not
inside agents.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Set

from raven_mcp.models import ToolDefinition

_RISK = {"passive": 0, "low": 1, "moderate": 2, "high": 3}


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: Dict[str, ToolDefinition] = {}

    # -- registration -----------------------------------------------------------

    def register(self, tool: ToolDefinition) -> None:
        if not tool.name:
            raise ValueError("Tool must have a name.")
        if tool.handler is None:
            raise ValueError(f"Tool '{tool.name}' has no handler.")
        self._tools[tool.name] = tool

    def unregister(self, name: str) -> None:
        self._tools.pop(name, None)

    # -- discovery --------------------------------------------------------------

    def get(self, name: str) -> Optional[ToolDefinition]:
        return self._tools.get(name)

    def all(self) -> List[ToolDefinition]:
        return list(self._tools.values())

    def is_available(self, tool: ToolDefinition) -> bool:
        return not tool.missing_requirements()

    def capabilities(self, available_only: bool = True) -> Set[str]:
        caps: Set[str] = set()
        for t in self._tools.values():
            if not available_only or self.is_available(t):
                caps.update(t.capabilities)
        return caps

    def providers(
        self,
        capability: str,
        target_type: Optional[str] = None,
        exclude: Iterable[str] = (),
        available_only: bool = True,
    ) -> List[ToolDefinition]:
        """Tools providing *capability*, safest first, then by name (deterministic)."""
        excluded = set(exclude)
        out = []
        for t in self._tools.values():
            if capability not in t.capabilities or t.name in excluded:
                continue
            if target_type and t.target_types and target_type not in t.target_types:
                continue
            if available_only and not self.is_available(t):
                continue
            out.append(t)
        return sorted(out, key=lambda t: (_RISK.get(t.risk_level, 9), t.name))

    def missing_capability_reason(self, capability: str) -> str:
        """Why can't *capability* be provided? Used for honest limitations."""
        tools = [t for t in self._tools.values() if capability in t.capabilities]
        if not tools:
            return f"No tool provides capability '{capability}'."
        gaps = sorted({m for t in tools for m in t.missing_requirements()})
        return f"Tool(s) for '{capability}' unavailable; missing: {', '.join(gaps)}."

    def describe(self) -> List[Dict[str, object]]:
        return [t.summary() for t in self._tools.values()]
