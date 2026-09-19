"""
agents/registry.py
------------------
Agents register themselves; the planner asks which are applicable. Adding a
new capability agent is one class + one `register()` call: no core changes.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from agents.base import Agent
from core.profile import TargetProfile


class AgentRegistry:
    def __init__(self) -> None:
        self._agents: Dict[str, Agent] = {}

    def register(self, agent: Agent) -> None:
        if not agent.name:
            raise ValueError("Agent must have a name.")
        self._agents[agent.name] = agent

    def get(self, name: str) -> Optional[Agent]:
        return self._agents.get(name)

    def all(self) -> List[Agent]:
        return list(self._agents.values())

    def applicable(self, profile: TargetProfile) -> List[Agent]:
        return [a for a in self._agents.values() if a.applies(profile)]


def default_registry() -> AgentRegistry:
    from agents.network import NetworkReconAgent, ServiceAssessmentAgent
    from agents.source import SourceAssessmentAgent
    from agents.web_exposure import WebExposureAgent
    from agents.web_recon import WebReconAgent
    from agents.web_security import WebSecurityAgent

    reg = AgentRegistry()
    for agent in (WebReconAgent(), WebSecurityAgent(), WebExposureAgent(),
                  NetworkReconAgent(), ServiceAssessmentAgent(), SourceAssessmentAgent()):
        reg.register(agent)
    return reg
