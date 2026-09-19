"""
agents/specialized/secrets_agent.py
-----------------------------------
Specialized agent for detecting exposed secrets, API keys, and credentials.
"""

from __future__ import annotations

import logging
from typing import Optional

from agents.base_agent import BaseSpecializedAgent
from engine.assessment_context import AssessmentContext
from engine.hypothesis_manager import HypothesisManager
from engine_models.actions import AgentAction
from engine_models.findings import EvidenceItem, Finding, ValidationStatus

logger = logging.getLogger("raven.agents.secrets")


class SecretsAssessmentAgent(BaseSpecializedAgent):
    """
    Scans repositories, configuration files, and filesystems for hardcoded secrets.
    """

    def __init__(self, context: AssessmentContext) -> None:
        super().__init__(context)
        self.agent_name = "SecretsAssessmentAgent"
        self.capability_id = "secrets_detection"

    async def execute(self, context: Optional[AssessmentContext] = None) -> None:
        ctx = context or self.context
        target_path = ctx.target.raw_input
        hyp_mgr = HypothesisManager(ctx.state)

        # Retrieve relevant hypotheses
        hypotheses = hyp_mgr.get_untested(self.capability_id)
        current_hyp = hypotheses[0] if hypotheses else None

        action = AgentAction(
            agent_name=self.agent_name,
            capability_id=self.capability_id,
            tool_name="scan_secrets",
            target=target_path,
            operation_type="file_analysis",
            parameters={"repo_path": target_path},
            purpose="Scan repository for hardcoded secrets, private keys, and API tokens",
            impact_level="passive",
            hypothesis_id=current_hyp.hypothesis_id if current_hyp else None,
        )

        if current_hyp:
            hyp_mgr.start_testing(current_hyp.hypothesis_id, action.action_id)

        result = await self.execute_action(action)

        if result.is_success and result.data:
            findings_data = result.data.get("findings") or result.data.get("secrets") or []
            if isinstance(result.data, list):
                findings_data = result.data

            for item in findings_data:
                secret_type = item.get("type", "generic_secret") if isinstance(item, dict) else "secret"
                file_loc = item.get("file", target_path) if isinstance(item, dict) else target_path
                line_no = item.get("line", 1) if isinstance(item, dict) else 1
                snippet = item.get("match", "") if isinstance(item, dict) else str(item)

                evidence = EvidenceItem(
                    evidence_type="code_snippet",
                    raw_data=f"Found {secret_type} in {file_loc}:{line_no}",
                    sanitized_summary=f"High-entropy {secret_type} detected",
                    file_path=file_loc,
                    line_number=line_no,
                    confidence="High",
                )

                finding = Finding(
                    title=f"Hardcoded {secret_type.replace('_', ' ').title()} in {file_loc}",
                    vulnerability_type="hardcoded_secret",
                    severity="High",
                    cvss_score=7.5,
                    cwe_id="CWE-798",
                    target_component=file_loc,
                    endpoint=file_loc,
                    observation=f"Discovered {secret_type} in source code file {file_loc}",
                    evidence=[evidence],
                    reproduction_steps=[f"Inspect {file_loc} at line {line_no}"],
                    validation_status=ValidationStatus.CONFIRMED,
                    remediation="Revoke exposed credentials immediately and migrate to environment variables or secret vaults.",
                    source_agent=self.agent_name,
                    capability_id=self.capability_id,
                    hypothesis_id=current_hyp.hypothesis_id if current_hyp else None,
                )
                self.publish_candidate_finding(finding)

            if current_hyp:
                if findings_data:
                    hyp_mgr.resolve(current_hyp.hypothesis_id, "confirmed", f"Found {len(findings_data)} secrets")
                else:
                    hyp_mgr.resolve(current_hyp.hypothesis_id, "rejected", "No secrets identified")
