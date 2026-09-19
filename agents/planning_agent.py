"""
agents/planning_agent.py
------------------------
LLM-driven adaptive planning agent for Raven security assessment.

Synthesizes reconnaissance intelligence, asset graph relationships, and scope rules
into testable security hypotheses and an adaptive execution plan.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from engine.assessment_context import AssessmentContext
from engine_models.capabilities import CapabilityManifest
from engine_models.hypotheses import Hypothesis

logger = logging.getLogger("raven.agents.planning")


TARGET_TYPE_AGENT_MAP: Dict[str, List[str]] = {
    "web_application": ["web_api_agent", "auth_identity_agent"],
    "rest_api": ["web_api_agent", "auth_identity_agent"],
    "graphql_api": ["web_api_agent", "auth_identity_agent"],
    "source_repository": ["source_code_agent", "secrets_agent", "dependency_agent", "configuration_agent"],
    "library": ["source_code_agent", "dependency_agent", "secrets_agent"],
    "native_binary": ["binary_agent", "configuration_agent"],
    "cli_application": ["binary_agent", "configuration_agent"],
    "network_service": ["network_agent", "auth_identity_agent"],
    "network_range": ["network_agent"],
    "container": ["configuration_agent", "dependency_agent"],
    "container_image": ["configuration_agent", "dependency_agent"],
}


class PlanningAgent:
    """
    Adaptive planning agent that formulates assessment hypotheses and schedules tasks.
    """

    def __init__(self, context: AssessmentContext) -> None:
        self.context = context

    def get_deterministic_plan(self, target_type_val: str) -> Dict[str, Any]:
        """Generate deterministic fallback plan when LLM is unavailable."""
        applicable_agents = TARGET_TYPE_AGENT_MAP.get(target_type_val, ["source_code_agent", "web_api_agent", "network_agent"])
        all_possible = ["web_api_agent", "network_agent", "auth_identity_agent", "source_code_agent", "secrets_agent", "dependency_agent", "configuration_agent", "binary_agent"]
        not_testing = [
            {"agent": a, "reason": f"Target type '{target_type_val}' does not match agent specialization"}
            for a in all_possible if a not in applicable_agents
        ]

        hypotheses = []
        for agent in applicable_agents:
            hypotheses.append({
                "capability_id": agent,
                "title": f"Assess attack surfaces via {agent}",
                "vulnerability_type": "surface_audit",
                "confirmation_criteria": "Reproducible evidence or configuration flaw found",
                "priority": 5,
            })

        return {
            "selected_agents": applicable_agents,
            "parallel_groups": [applicable_agents],
            "hypotheses": hypotheses,
            "not_testing": not_testing,
            "stopping_condition": "Budget soft limit reached or all candidate hypotheses verified",
        }

    async def plan(
        self,
        activated_capabilities: List[CapabilityManifest],
    ) -> Dict[str, Any]:
        """
        Formulate an assessment plan using LLM when available, or deterministic fallback.
        """
        target = self.context.target
        target_type_val = target.target_type.value if hasattr(target.target_type, "value") else str(target.target_type)
        provider = self.context.provider

        if not provider:
            fallback = self.get_deterministic_plan(target_type_val)
            self._save_plan_to_state(fallback)
            return fallback

        state = self.context.state
        tech = state.technology_profile
        attack_surfaces = state.attack_surfaces[:15]
        cap_names = [c.name for c in activated_capabilities]

        system_prompt = (
            "You are Raven's Strategic Security Planning Agent. "
            "Given reconnaissance findings, technology fingerprints, and activated capabilities, "
            "generate testable security hypotheses and execution priorities. "
            "Output valid JSON ONLY."
        )

        user_prompt = f"""
Target: {target.raw_input} ({target_type_val})
Discovered Technologies: {json.dumps(tech)}
Key Attack Surfaces: {json.dumps(attack_surfaces)}
Activated Capabilities: {json.dumps(cap_names)}
Agent Capability Map: {json.dumps(TARGET_TYPE_AGENT_MAP)}
Scope: active_allowed={self.context.is_active_permitted}, auth_allowed={self.context.is_auth_permitted}

Provide a JSON plan with:
{{
  "selected_agents": ["agent_name1", "agent_name2"],
  "hypotheses": [
    {{
      "capability_id": "string",
      "title": "string",
      "vulnerability_type": "string",
      "confirmation_criteria": "string",
      "priority": 1-10
    }}
  ],
  "not_testing": [
    {{"agent": "string", "reason": "string"}}
  ],
  "parallel_groups": [["agent1", "agent2"], ["agent3"]],
  "stopping_condition": "string"
}}
"""
        try:
            raw = ""
            if hasattr(provider, "analyze_async"):
                raw = await provider.analyze_async(system_prompt, user_prompt)
            elif hasattr(provider, "analyze"):
                raw = provider.analyze(system_prompt, user_prompt)

            cleaned = raw.strip()
            if cleaned.startswith("```json"):
                cleaned = cleaned[7:]
            if cleaned.startswith("```"):
                cleaned = cleaned[3:]
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3]

            data = json.loads(cleaned.strip())
            if not data.get("selected_agents"):
                data["selected_agents"] = TARGET_TYPE_AGENT_MAP.get(target_type_val, cap_names)
            if "not_testing" not in data:
                data["not_testing"] = []
            if "stopping_condition" not in data:
                data["stopping_condition"] = "Budget soft limit reached or all candidate hypotheses verified"

            self._save_plan_to_state(data)
            return data
        except Exception as e:
            logger.debug(f"LLM planning parsing failed or unavailable: {e}. Falling back to deterministic plan.")
            fallback = self.get_deterministic_plan(target_type_val)
            self._save_plan_to_state(fallback)
            return fallback

    def _save_plan_to_state(self, plan_data: Dict[str, Any]) -> None:
        """Save active agents and plans to persistent assessment state."""
        state = self.context.state
        if state:
            state.active_agents = plan_data.get("selected_agents", [])
            state.agent_plans = plan_data
            for nt in plan_data.get("not_testing", []):
                state.not_assessed.append(f"{nt.get('agent', '')}: {nt.get('reason', '')}")
            try:
                state.save()
            except Exception:
                pass
