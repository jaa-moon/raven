"""
engine/assessment_context.py
----------------------------
Runtime context container for Raven adaptive security assessment.

Carries immutable target specifications, scope rules, authorization,
budget tracking, tool gateway, and persistent state references
across all agent and engine executions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from engine.asset_graph import AssetGraph
from engine_models.authorization import Authorization
from engine_models.scope import Scope
from engine_models.state import AssessmentState
from engine_models.target import Target


@dataclass
class AssessmentContext:
    """
    Standard assessment context shared across orchestrator, planner, and specialized agents.
    """

    target: Target
    scope: Scope
    authorization: Authorization
    state: AssessmentState
    asset_graph: AssetGraph
    budget_manager: Any  # BudgetManager instance
    provider: Any = None  # LLM provider instance (e.g. OpenAIProvider, ClaudeProvider)
    gateway: Any = None   # Tool gateway (e.g. InternalGateway / MCPGateway)
    sandbox: Any = None   # Sandbox instance if launched
    config: Any = None    # Global RavenConfig

    @property
    def assessment_id(self) -> str:
        return self.state.assessment_id

    @property
    def is_active_permitted(self) -> bool:
        return self.scope.allow_active_testing

    @property
    def is_auth_permitted(self) -> bool:
        return self.scope.allow_authenticated_testing and self.authorization.has_credentials()
