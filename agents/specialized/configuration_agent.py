"""
agents/specialized/configuration_agent.py
-----------------------------------------
Specialized agent for Security Configuration & Hardening Baseline Assessment.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from agents.base_agent import BaseSpecializedAgent
from engine.assessment_context import AssessmentContext
from engine.hypothesis_manager import HypothesisManager
from engine_models.actions import AgentAction
from engine_models.findings import EvidenceItem, Finding, ValidationStatus

logger = logging.getLogger("raven.agents.configuration")


class ConfigurationAssessmentAgent(BaseSpecializedAgent):
    """
    Audits application, container, and server configurations for security misconfigurations.
    """

    def __init__(self, context: AssessmentContext) -> None:
        super().__init__(context)
        self.agent_name = "ConfigurationAssessmentAgent"
        self.capability_id = "configuration_assessment"

    async def execute(self, context: Optional[AssessmentContext] = None) -> None:
        ctx = context or self.context
        target_path = ctx.target.raw_input
        hyp_mgr = HypothesisManager(ctx.state)

        hypotheses = hyp_mgr.get_untested(self.capability_id)
        current_hyp = hypotheses[0] if hypotheses else None

        p = Path(target_path)
        found_issues = []

        if p.exists():
            # 1. Automated Configuration Scan
            config_action = AgentAction(
                agent_name=self.agent_name,
                capability_id=self.capability_id,
                tool_name="config_scan",
                target=str(p),
                operation_type="config_scan",
                parameters={"path": str(p)},
                purpose="Scan configuration files for insecure settings, weak secrets, and debug flags",
                impact_level="passive",
                hypothesis_id=current_hyp.hypothesis_id if current_hyp else None,
            )
            config_res = await self.execute_action(config_action)
            if config_res.is_success and config_res.data and config_res.data.get("issues_count", 0) > 0:
                for issue in config_res.data.get("issues", []):
                    ev = EvidenceItem(
                        evidence_type="config_file",
                        raw_data=f"{issue.get('file')}:{issue.get('line')}: {issue.get('line_content')}",
                        sanitized_summary=issue.get("description", "Insecure configuration directive"),
                        file_path=issue.get("file"),
                        line_number=issue.get("line"),
                        confidence="High",
                    )
                    finding = Finding(
                        title=f"{issue.get('name', 'Configuration Issue')} in {issue.get('file')}",
                        vulnerability_type="security_misconfiguration",
                        severity=issue.get("severity", "Medium"),
                        cvss_score=7.5 if issue.get("severity") == "HIGH" else (9.0 if issue.get("severity") == "CRITICAL" else 5.0),
                        cwe_id="CWE-16",
                        target_component=issue.get("file", str(p)),
                        asset_description=issue.get("file", str(p)),
                        observation=f"{issue.get('description')} Found in {issue.get('file')} line {issue.get('line')}: {issue.get('line_content')}",
                        evidence=[ev],
                        reproduction_steps=[f"Check line {issue.get('line')} in {issue.get('file')}"],
                        validation_status=ValidationStatus.CONFIRMED,
                        remediation="Update configuration setting to use secure production defaults.",
                        source_agent=self.agent_name,
                        capability_id=self.capability_id,
                        hypothesis_id=current_hyp.hypothesis_id if current_hyp else None,
                    )
                    self.publish_candidate_finding(finding)
                    found_issues.append(finding)

            # 2. Automated File Permission Audit
            if self.can_start_hypothesis():
                perm_action = AgentAction(
                    agent_name=self.agent_name,
                    capability_id=self.capability_id,
                    tool_name="permission_scan",
                    target=str(p),
                    operation_type="permission_scan",
                    parameters={"path": str(p)},
                    purpose="Audit file and directory permissions for sensitive assets",
                    impact_level="passive",
                    hypothesis_id=current_hyp.hypothesis_id if current_hyp else None,
                )
                perm_res = await self.execute_action(perm_action)
                if perm_res.is_success and perm_res.data and perm_res.data.get("issues_count", 0) > 0:
                    for issue in perm_res.data.get("issues", []):
                        ev = EvidenceItem(
                            evidence_type="file_content",
                            raw_data=str(issue),
                            sanitized_summary=issue.get("issue", "Insecure file permissions"),
                            file_path=issue.get("file"),
                            confidence="High",
                        )
                        finding = Finding(
                            title=f"Insecure File Permission: {Path(issue.get('file', '')).name}",
                            vulnerability_type="insecure_permissions",
                            severity=issue.get("severity", "Medium"),
                            cvss_score=7.0 if issue.get("severity") == "HIGH" else 4.5,
                            cwe_id="CWE-732",
                            target_component=issue.get("file", str(p)),
                            asset_description=issue.get("file", str(p)),
                            observation=issue.get("details", "Insecure permission detected"),
                            evidence=[ev],
                            reproduction_steps=[f"Inspect permissions of {issue.get('file')}"],
                            validation_status=ValidationStatus.CONFIRMED,
                            remediation="Restrict file permissions to owner only (chmod 0600 / 0700).",
                            source_agent=self.agent_name,
                            capability_id=self.capability_id,
                            hypothesis_id=current_hyp.hypothesis_id if current_hyp else None,
                        )
                        self.publish_candidate_finding(finding)
                        found_issues.append(finding)

        if current_hyp:
            if found_issues:
                hyp_mgr.resolve(current_hyp.hypothesis_id, "confirmed", f"Discovered {len(found_issues)} configuration and permission issues")
            else:
                hyp_mgr.resolve(current_hyp.hypothesis_id, "rejected", "No significant configuration deviations found")


# Backward compatibility alias
InfraAssessmentAgent = ConfigurationAssessmentAgent
