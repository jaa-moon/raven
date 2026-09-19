"""
agents/base.py
--------------
An agent is specialized assessment behavior for one family of capabilities.

  * `applies(profile)`      - is this agent relevant to what we're looking at?
  * `propose_tasks(state)`  - given everything known *now*, what could be tested?
  * `run(task, ctx)`        - do one task, requesting capabilities via `ctx.call`

Agents never import tools and never name them; they ask for capabilities and
the MCP gateway resolves, scope-checks, budget-checks and executes.
"""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from core.models import (Finding, Observation, Severity, TestTask, ToolRequest, ToolResult)
from core.profile import TargetProfile
from core.state import AssessmentState
from recovery.controller import RecoveryController


class AgentResult(BaseModel):
    success: bool = True
    blocked: bool = False            # could not run for a known external reason
    summary: str = ""
    error: str = ""
    notes: List[str] = Field(default_factory=list)


class AgentContext:
    """Everything an agent may touch during one task."""

    def __init__(self, state: AssessmentState, recovery: RecoveryController,
                 task: TestTask, guidance: Optional[Dict[str, Any]] = None) -> None:
        self.state = state
        self.recovery = recovery
        self.task = task
        self.guidance = guidance or {}
        self.last_error: Optional[ToolResult] = None

    @property
    def profile(self) -> TargetProfile:
        return self.state.profile

    async def call(self, capability: str, arguments: Dict[str, Any], purpose: str = "") -> ToolResult:
        req = ToolRequest(capability=capability, arguments=arguments, purpose=purpose or self.task.title,
                          agent=self.task.agent, task_id=self.task.task_id)
        res = await self.recovery.execute(req)
        if not res.ok:
            self.last_error = res
        return res

    def observe(self, kind: str, surface: str, summary: str, **data: Any) -> Observation:
        obs = Observation(kind=kind, surface=surface, summary=summary, data=data,
                          source_task=self.task.task_id)
        self.state.observations.append(obs)
        return obs

    def candidate(self, *, title: str, category: str, severity: Severity, surface: str,
                  location: str, description: str, signal: Dict[str, Any],
                  impact: str = "", remediation: str = "",
                  reproduction: Optional[List[str]] = None) -> Optional[Finding]:
        """Register a CANDIDATE finding (deduplicated). Agents can never confirm."""
        sig = hashlib.sha1(json.dumps(signal, sort_keys=True, default=str).encode()).hexdigest()[:12]
        if any(f.signal.get("_sig") == sig for f in self.state.findings):
            return None
        f = Finding(title=title, category=category, severity=severity, surface=surface,
                    location=location, description=description, impact=impact,
                    remediation=remediation, reproduction=reproduction or [],
                    signal={**signal, "_sig": sig}, source_task=self.task.task_id)
        self.state.findings.append(f)
        return f


class Agent(ABC):
    name: str = ""
    description: str = ""
    capabilities: List[str] = []

    @abstractmethod
    def applies(self, profile: TargetProfile) -> bool: ...

    @abstractmethod
    def propose_tasks(self, state: AssessmentState) -> List[TestTask]: ...

    @abstractmethod
    async def run(self, task: TestTask, ctx: AgentContext) -> AgentResult: ...

    # -- helpers -------------------------------------------------------------------

    def task(self, key: str, capability: str, surface: str, title: str, *, priority: int = 50,
             cost: int = 1, rationale: str = "", **params: Any) -> TestTask:
        return TestTask(key=f"{self.name}.{key}", agent=self.name, capability=capability,
                        surface=surface, title=title, priority=priority, cost=cost,
                        rationale=rationale, params=params)
