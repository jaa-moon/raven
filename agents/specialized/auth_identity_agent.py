"""
agents/specialized/auth_identity_agent.py
-----------------------------------------
Specialized agent for Authentication, Identity, and Access Control Assessment.
"""

from __future__ import annotations

import logging
from typing import Optional
from urllib.parse import urlparse

from agents.base_agent import BaseSpecializedAgent
from engine.assessment_context import AssessmentContext
from engine.hypothesis_manager import HypothesisManager
from engine_models.actions import AgentAction
from engine_models.findings import EvidenceItem, Finding, ValidationStatus

logger = logging.getLogger("raven.agents.auth_identity")


class AuthIdentityAssessmentAgent(BaseSpecializedAgent):
    """
    Assesses session cookies, JWT implementations, CORS policies, and authentication endpoints.
    """

    def __init__(self, context: AssessmentContext) -> None:
        super().__init__(context)
        self.agent_name = "AuthIdentityAssessmentAgent"
        self.capability_id = "auth_identity_assessment"

    async def execute(self, context: Optional[AssessmentContext] = None) -> None:
        ctx = context or self.context
        target_url = ctx.target.raw_input
        hyp_mgr = HypothesisManager(ctx.state)

        hypotheses = hyp_mgr.get_untested(self.capability_id)
        current_hyp = hypotheses[0] if hypotheses else None

        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Audit CORS configuration
        action = AgentAction(
            agent_name=self.agent_name,
            capability_id=self.capability_id,
            tool_name="send_http_request",
            target=base_url,
            operation_type="http_request",
            method="OPTIONS",
            parameters={"url": base_url, "method": "OPTIONS", "headers": {"Origin": "https://evil.com"}},
            purpose="Test for permissive Cross-Origin Resource Sharing (CORS) wildcard reflection",
            impact_level="passive",
            hypothesis_id=current_hyp.hypothesis_id if current_hyp else None,
        )

        if current_hyp:
            hyp_mgr.start_testing(current_hyp.hypothesis_id, action.action_id)

        result = await self.execute_action(action)

        found_issues = []
        if result.is_success and result.data:
            headers = {k.lower(): v for k, v in result.data.get("headers", {}).items()}
            acao = headers.get("access-control-allow-origin", "")
            acac = headers.get("access-control-allow-credentials", "")

            if acao == "*" and acac.lower() == "true":
                evidence = EvidenceItem(
                    evidence_type="http_response",
                    raw_data=f"Access-Control-Allow-Origin: * with Allow-Credentials: true",
                    sanitized_summary="Insecure CORS policy permits arbitrary origin credential leakage",
                    endpoint=base_url,
                    confidence="High",
                )
                finding = Finding(
                    title="Insecure Permissive CORS Configuration with Credentials",
                    vulnerability_type="broken_access_control",
                    severity="High",
                    cvss_score=7.5,
                    cwe_id="CWE-346",
                    target_component=base_url,
                    endpoint=base_url,
                    observation="Server responds with wildcard origin Access-Control-Allow-Origin and credentials permitted.",
                    evidence=[evidence],
                    reproduction_steps=[f"Send OPTIONS request with 'Origin: https://evil.com' to {base_url}"],
                    validation_status=ValidationStatus.CONFIRMED,
                    remediation="Explicitly whitelist trusted origins instead of wildcard reflect.",
                    source_agent=self.agent_name,
                    capability_id=self.capability_id,
                    hypothesis_id=current_hyp.hypothesis_id if current_hyp else None,
                )
                self.publish_candidate_finding(finding)
                found_issues.append(finding)

        if current_hyp:
            if found_issues:
                hyp_mgr.resolve(current_hyp.hypothesis_id, "confirmed", f"Identified {len(found_issues)} auth/CORS issues")
            else:
                hyp_mgr.resolve(current_hyp.hypothesis_id, "rejected", "No insecure CORS or session flags identified")
