"""
agents/risk_agent.py
--------------------
Risk correlation and multi-finding attack path identification agent for Raven.

Analyzes relationships between confirmed findings across components and the asset graph
to synthesize chained attack scenarios with evidence distinction (confirmed vs. plausible).
"""

from __future__ import annotations

import logging
from typing import List, Optional

from agents.base_agent import BaseSpecializedAgent
from engine.assessment_context import AssessmentContext
from engine_models.findings import Finding
from engine_models.risk import AttackPath, AttackPathStep

logger = logging.getLogger("raven.agents.risk")


class RiskAgent(BaseSpecializedAgent):
    """
    Identifies multi-step attack paths across confirmed findings.
    """

    def __init__(self, context: AssessmentContext) -> None:
        super().__init__(context)
        self.agent_name = "RiskCorrelationAgent"
        self.capability_id = "risk_correlation"

    async def execute(self, context: Optional[AssessmentContext] = None) -> None:
        await self.identify_attack_paths()

    async def identify_attack_paths(self) -> List[AttackPath]:
        """Correlate confirmed findings into multi-step attack paths."""
        ctx = self.context
        findings = ctx.state.confirmed_findings
        paths: List[AttackPath] = []

        # Find potential chains
        has_secret = [f for f in findings if f.vulnerability_type == "hardcoded_secret"]
        has_injection = [f for f in findings if "injection" in f.vulnerability_type]
        has_dep = [f for f in findings if f.vulnerability_type == "vulnerable_dependency"]
        has_config = [f for f in findings if f.vulnerability_type == "security_misconfiguration"]

        # Chain 1: Secret Exposure -> Account Takeover / Unauthorized API Access
        if has_secret:
            sec = has_secret[0]
            step1 = AttackPathStep(
                step_number=1,
                finding_id=sec.finding_id,
                description=f"Attacker extracts hardcoded credential from {sec.target_component}",
                technique="Credential Harvesting",
            )
            step2 = AttackPathStep(
                step_number=2,
                finding_id="",
                description="Attacker leverages extracted credential to authenticate to internal services",
                technique="Privilege Escalation / Unauthorized Access",
            )
            path = AttackPath(
                assessment_id=ctx.state.assessment_id,
                name="Credential Exposure Leading to Unauthorized Access",
                description="Hardcoded secrets in the repository allow unauthenticated attackers to pivot to backend services.",
                steps=[step1, step2],
                finding_ids=[sec.finding_id],
                severity="Critical" if sec.severity == "Critical" else "High",
                confidence="plausible",
                combined_impact="Full compromise of administrative or service credentials.",
            )
            paths.append(path)

        # Chain 2: Vulnerable Dependency + Command Injection -> Full System Compromise
        if has_dep and has_injection:
            dep = has_dep[0]
            inj = has_injection[0]
            step1 = AttackPathStep(
                step_number=1,
                finding_id=dep.finding_id,
                description=f"Attacker identifies vulnerable dependency {dep.target_component}",
                technique="Exploit Public-Facing Application",
            )
            step2 = AttackPathStep(
                step_number=2,
                finding_id=inj.finding_id,
                description=f"Attacker chains code injection in {inj.target_component} for arbitrary execution",
                technique="Command and Scripting Interpreter",
            )
            path = AttackPath(
                assessment_id=ctx.state.assessment_id,
                name="Vulnerable Library and Unsanitized Sink Chained to Remote Execution",
                description="Known CVE in third-party package combined with unsanitized sink grants full arbitrary execution.",
                steps=[step1, step2],
                finding_ids=[dep.finding_id, inj.finding_id],
                severity="Critical",
                confidence="confirmed",
                combined_impact="Remote code execution and host system compromise.",
            )
            paths.append(path)

        return paths
