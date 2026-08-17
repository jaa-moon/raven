"""
agents/base_agent.py
--------------------
Abstract base agent for Raven autonomous pentesting architecture.
Includes automatic finding deduplication and provider interactions.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set, Tuple
from orchestrator.findings_bus import FindingsBus
from providers.base import BaseProvider
from reports.models import AgentFinding, ProjectProfile, SandboxInfo


class BaseAgent(ABC):
    """
    Abstract contract for offensive AI agents.
    """

    def __init__(
        self,
        profile: ProjectProfile,
        sandbox: SandboxInfo,
        tool_plan: List[str],
        findings_bus: FindingsBus,
        provider: BaseProvider,
        rag_context: List[str] | None = None,
        prioritized_techniques: List[str] | None = None,
    ) -> None:
        self.profile = profile
        self.sandbox = sandbox
        self.tool_plan = tool_plan
        self.bus = findings_bus
        self.provider = provider
        self.findings: List[AgentFinding] = []
        self._seen_keys: Set[Tuple[str, str, str, str]] = set()
        self.current_action: str = "Initializing"
        self.rag_context: List[str] = rag_context or []
        self.prioritized_techniques: List[str] = prioritized_techniques or []

    @abstractmethod
    async def run(self) -> List[AgentFinding]:
        """Execute the agent's attack plan."""
        ...

    def publish_finding(self, finding: AgentFinding) -> None:
        """Publish confirmed finding to shared bus and local list with deduplication."""
        dedup_key = (finding.agent, finding.vulnerability_type, finding.target_url, finding.parameter)
        if dedup_key in self._seen_keys:
            return
        self._seen_keys.add(dedup_key)

        self.findings.append(finding)
        self.bus.publish(finding)

    async def ask_llm(self, system_prompt: str, user_message: str) -> str:
        """Helper to invoke configured LLM provider asynchronously."""
        # Inject RAG context into user message if available
        if self.rag_context:
            rag_block = "\n\n--- Security Knowledge Context ---\n" + "\n---\n".join(self.rag_context[:3])
            user_message = user_message + rag_block
        return await self.provider.analyze_async(system_prompt, user_message)
