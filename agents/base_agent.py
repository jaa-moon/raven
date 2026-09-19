"""
agents/base_agent.py
--------------------
Abstract base agent for Raven autonomous pentesting architecture.
Includes automatic finding deduplication, provider interactions,
and MCP gateway tool dispatch.
"""

from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set, Tuple
from orchestrator.findings_bus import FindingsBus
from providers.base import BaseProvider
from reports.models import AgentFinding, ProjectProfile, SandboxInfo


class BaseAgent(ABC):
    """
    Abstract contract for offensive AI agents.

    When mcp_gateway is provided, all tool access routes through
    self.call_tool(tool_name, **params) which dispatches via the
    InternalGateway. When mcp_gateway is None, subclasses fall back
    to direct tool instantiation (legacy path for `raven scan`).
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
        mcp_gateway: Any | None = None,
        source_context: List[str] | None = None,
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
        self.mcp_gateway = mcp_gateway
        self.source_context: List[str] = source_context or []

    @property
    def use_mcp(self) -> bool:
        """True when the agent should route tool calls through MCP gateway."""
        return self.mcp_gateway is not None

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
        # Inject AST-compressed source code context if available
        if self.source_context:
            src_block = "\n\n--- AST-Compressed Source Code Context ---\n" + "\n---\n".join(self.source_context[:5])
            user_message = user_message + src_block

        # Inject RAG context into user message if available
        if self.rag_context:
            rag_block = "\n\n--- Security Knowledge Context ---\n" + "\n---\n".join(self.rag_context[:3])
            user_message = user_message + rag_block
        return await self.provider.analyze_async(system_prompt, user_message)


    async def call_tool(self, tool_name: str, **params) -> dict | str:
        """
        Invoke a registered MCP tool by name.

        Returns the tool output as a dict on success, or a dict
        with an 'error' key on failure. Agents should always use
        this method when self.use_mcp is True.
        """
        if not self.mcp_gateway:
            return {"error": "MCP Gateway not configured."}

        result = await self.mcp_gateway.call(tool_name, **params)
        if result.success:
            return result.data
        else:
            return {"error": result.error}

    async def call_tool_retry(self, tool_name: str, **params) -> dict | str:
        """
        Invoke a tool with automatic retry on failure.
        """
        if not self.mcp_gateway:
            return {"error": "MCP Gateway not configured."}

        result = await self.mcp_gateway.call_with_retry(tool_name, **params)
        if result.success:
            return result.data
        else:
            return {"error": result.error}


# ── Universal v3 Agent Base ──────────────────────────────────────────────────

class BaseSpecializedAgent(ABC):
    """
    Universal agent base class for Raven v3.0 adaptive capabilities.

    Accepts AssessmentContext, interacts with ScopeValidator and BudgetManager,
    executes structured AgentActions through MCP gateway, and registers findings.
    """

    def __init__(self, context: Any, manifest: Optional[Any] = None) -> None:
        self.context = context
        self.manifest = manifest
        self.state = getattr(context, "state", None)
        self.agent_name = getattr(manifest, "name", self.__class__.__name__)
        self.capability_id = getattr(manifest, "capability_id", "")
        self.scope_validator = None
        if hasattr(context, "scope"):
            from engine.scope_validator import ScopeValidator
            self.scope_validator = ScopeValidator(context.scope)

    @abstractmethod
    async def execute(self, context: Optional[Any] = None) -> None:
        """Run the specialized assessment logic for this capability."""
        ...

    async def execute_action(self, action: Any) -> Any:
        """
        Execute an AgentAction through scope gate, budget check, gateway,
        and result normalization.
        """
        from engine.result_processor import ResultProcessor
        from engine_models.results import NormalizedToolResult
        processor = ResultProcessor()

        action.agent_name = self.agent_name
        action.capability_id = self.capability_id

        # 1. Scope Gate
        if self.scope_validator:
            check = self.scope_validator.validate_action(action)
            if not check.allowed:
                return NormalizedToolResult(
                    action_id=action.action_id,
                    tool_name=action.tool_name,
                    target=action.target,
                    status="out_of_scope",
                    errors=[f"Scope blocked: {check.reason}"],
                )

        # 2. Budget Gate
        budget = getattr(self.context, "budget_manager", None)
        if budget:
            if not budget.can_afford():
                return NormalizedToolResult(
                    action_id=action.action_id,
                    tool_name=action.tool_name,
                    target=action.target,
                    status="error",
                    errors=["Assessment budget exhausted."],
                )
            if hasattr(budget, "check_repeated_action"):
                action_key = f"{action.tool_name}:{action.target}"
                if not budget.check_repeated_action(action_key):
                    return NormalizedToolResult(
                        action_id=action.action_id,
                        tool_name=action.tool_name,
                        target=action.target,
                        status="error",
                        errors=["Repeated identical action limit reached for budget safety."],
                    )

        # 3. Tool Execution via Gateway
        start_t = time.time()
        gateway = getattr(self.context, "gateway", None)
        raw_result = None

        try:
            if gateway and hasattr(gateway, "call"):
                raw_result = await gateway.call(
                    action.tool_name,
                    timeout_seconds=action.timeout_seconds,
                    **action.parameters,
                )
            else:
                raw_result = {"status": "error", "error": "No tool gateway configured."}
        except Exception as e:
            raw_result = e

        duration_ms = round((time.time() - start_t) * 1000, 2)

        # 4. Budget Consumption
        if budget:
            req_inc = 1 if action.tool_name in ("send_http_request", "crawl_endpoints") else 0
            budget.consume(tool_calls=1, requests=req_inc)

        # 5. Result Normalization
        norm_result = processor.process(action, raw_result, duration_ms)

        # 6. Asset Discovery Incorporation
        graph = getattr(self.context, "asset_graph", None)
        if graph and norm_result.discovered_assets:
            from engine_models.assets import AssetType, DiscoveredAsset
            for ast_dict in norm_result.discovered_assets:
                try:
                    asset = DiscoveredAsset(
                        asset_type=AssetType(ast_dict.get("asset_type", "unknown")),
                        value=ast_dict.get("value", ""),
                        source=action.tool_name,
                        confidence=ast_dict.get("confidence", "Medium"),
                        metadata=ast_dict.get("metadata", {}),
                    )
                    graph.add_asset(asset)
                except Exception:
                    pass

        # 7. Audit Log & Persistent State Save
        if self.state:
            self.state.tested_actions.append(
                {
                    "action_id": action.action_id,
                    "agent": self.agent_name,
                    "tool": action.tool_name,
                    "target": action.target,
                    "status": norm_result.status,
                    "duration_ms": duration_ms,
                }
            )
            try:
                self.state.save()
            except Exception:
                pass

        return norm_result

    def can_start_hypothesis(self) -> bool:
        """Check if budget allows starting a new hypothesis (soft exhaustion check)."""
        budget = getattr(self.context, "budget_manager", None)
        if budget and hasattr(budget, "is_soft_exhausted") and budget.is_soft_exhausted():
            return False
        return True

    def subscribe_to_bus(self, bus: Any) -> None:
        """Subscribe to FindingsBus for inter-agent findings and alerts."""
        self.findings_bus = bus

    def publish_candidate_finding(self, finding: Any) -> None:
        """Add candidate finding to state for subsequent validation and broadcast to bus."""
        if self.state:
            self.state.candidate_findings.append(finding)
            try:
                self.state.save()
            except Exception:
                pass
        if hasattr(self, "findings_bus") and self.findings_bus:
            try:
                self.findings_bus.publish(finding)
            except Exception:
                pass

    async def ask_llm(self, prompt: str, system: Optional[str] = None) -> str:
        """Query LLM provider if available."""
        provider = getattr(self.context, "provider", None)
        if not provider:
            return ""
        system_p = system or f"You are Raven AI Security Assessment Agent: {self.agent_name}."
        try:
            if hasattr(provider, "analyze_async"):
                return await provider.analyze_async(system_p, prompt)
            elif hasattr(provider, "analyze"):
                return provider.analyze(system_p, prompt)
        except Exception:
            pass
        return ""
