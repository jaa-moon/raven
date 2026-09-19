"""
engine/planning_engine.py
-------------------------
Planning engine coordinating adaptive assessment strategy and hypothesis generation.

Integrates LLM-driven planning with deterministic fallback to ensure rigorous,
testable hypotheses for all activated capabilities under all operational conditions.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from agents.planning_agent import PlanningAgent
from engine.assessment_context import AssessmentContext
from engine.hypothesis_manager import HypothesisManager
from engine_models.capabilities import CapabilityManifest
from engine_models.hypotheses import Hypothesis

logger = logging.getLogger("raven.engine.planning")


class PlanningEngine:
    """
    Formulates, schedules, and registers assessment hypotheses and execution ordering.
    """

    def __init__(self, context: AssessmentContext) -> None:
        self.context = context
        self.hypothesis_manager = HypothesisManager(context.state)
        self.agent = PlanningAgent(context)

    async def create_plan(
        self,
        activated_capabilities: List[CapabilityManifest],
    ) -> Dict[str, Any]:
        """
        Synthesize assessment plan and register hypotheses.
        """
        # 1. Attempt LLM planning
        plan = await self.agent.plan(activated_capabilities)

        # 2. Check if LLM supplied valid hypotheses
        llm_hypotheses = plan.get("hypotheses", [])
        if llm_hypotheses and isinstance(llm_hypotheses, list):
            for h_dict in llm_hypotheses:
                try:
                    hyp = Hypothesis(
                        capability_id=h_dict.get("capability_id", ""),
                        title=h_dict.get("title", "Hypothesis"),
                        vulnerability_type=h_dict.get("vulnerability_type", "general"),
                        confirmation_criteria=h_dict.get("confirmation_criteria", ""),
                        priority=h_dict.get("priority", 50),
                    )
                    self.hypothesis_manager.add_hypothesis(hyp)
                except Exception:
                    pass

        # 3. If no hypotheses registered, generate deterministic baseline hypotheses
        if not self.context.state.hypotheses:
            self._generate_deterministic_hypotheses(activated_capabilities)

        # 4. Synchronize planned tests list
        planned_tests = []
        for h in self.context.state.hypotheses:
            planned_tests.append(f"[{h.capability_id}] {h.title}")
        self.context.state.planned_tests = planned_tests

        # 5. Define execution order / parallel groups if not provided
        if not plan.get("parallel_groups"):
            # Default parallel groups: passive analysis in group 1, active testing in group 2
            group1 = [c.capability_id for c in activated_capabilities if c.supports_passive_mode and not c.supports_active_mode]
            group2 = [c.capability_id for c in activated_capabilities if c.capability_id not in group1]
            groups = []
            if group1:
                groups.append(group1)
            if group2:
                groups.append(group2)
            plan["parallel_groups"] = groups

        return plan

    def _generate_deterministic_hypotheses(
        self,
        activated_capabilities: List[CapabilityManifest],
    ) -> None:
        """Create standard testable hypotheses per capability."""
        for cap in activated_capabilities:
            cid = cap.capability_id

            if cid == "secrets_detection":
                self.hypothesis_manager.add_hypothesis(
                    Hypothesis(
                        capability_id=cid,
                        title="Repository or configuration contains exposed API keys or private credentials",
                        vulnerability_type="hardcoded_secret",
                        confirmation_criteria="High-entropy secret token identified in repository or config",
                        priority=90,
                    )
                )

            elif cid == "dependency_analysis":
                self.hypothesis_manager.add_hypothesis(
                    Hypothesis(
                        capability_id=cid,
                        title="Third-party dependencies contain known exploitable CVEs",
                        vulnerability_type="vulnerable_dependency",
                        confirmation_criteria="Matched package version with published NVD / advisory CVE",
                        priority=85,
                    )
                )

            elif cid == "source_code_analysis":
                self.hypothesis_manager.add_hypothesis(
                    Hypothesis(
                        capability_id=cid,
                        title="Source code contains unsanitized sinks leading to command injection or path traversal",
                        vulnerability_type="code_injection",
                        confirmation_criteria="Unsanitized user-controlled input flows into system sink",
                        priority=80,
                    )
                )

            elif cid == "web_api_assessment":
                self.hypothesis_manager.add_hypothesis(
                    Hypothesis(
                        capability_id=cid,
                        title="Web application lacks essential security headers or exposes sensitive endpoints",
                        vulnerability_type="security_misconfiguration",
                        confirmation_criteria="Missing HSTS/CSP or unauthenticated administrative path discovered",
                        priority=75,
                    )
                )
                if self.context.is_active_permitted:
                    self.hypothesis_manager.add_hypothesis(
                        Hypothesis(
                            capability_id=cid,
                            title="Web application parameters are susceptible to injection flaws",
                            vulnerability_type="injection",
                            confirmation_criteria="Response alteration, error leakage, or time delay on test payload",
                            priority=85,
                        )
                    )

            elif cid == "auth_identity_assessment":
                self.hypothesis_manager.add_hypothesis(
                    Hypothesis(
                        capability_id=cid,
                        title="Authentication tokens or cookies lack secure flags or proper signature verification",
                        vulnerability_type="broken_authentication",
                        confirmation_criteria="Weak JWT algorithm or cookies without HttpOnly/Secure flags",
                        priority=70,
                    )
                )

            elif cid == "network_assessment":
                self.hypothesis_manager.add_hypothesis(
                    Hypothesis(
                        capability_id=cid,
                        title="Host exposes unexpected network services on non-standard ports",
                        vulnerability_type="exposed_service",
                        confirmation_criteria="Open TCP/UDP port with listening service identified",
                        priority=65,
                    )
                )

            elif cid == "configuration_assessment":
                self.hypothesis_manager.add_hypothesis(
                    Hypothesis(
                        capability_id=cid,
                        title="Configuration files deviate from security hardening best practices",
                        vulnerability_type="insecure_configuration",
                        confirmation_criteria="Insecure debug mode, permissive CORS, or default credentials",
                        priority=60,
                    )
                )
