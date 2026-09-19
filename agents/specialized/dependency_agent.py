"""
agents/specialized/dependency_agent.py
--------------------------------------
Specialized agent for Software Composition Analysis (SCA) & Vulnerable Dependencies.
"""

from __future__ import annotations

import logging
from typing import Optional

from agents.base_agent import BaseSpecializedAgent
from engine.assessment_context import AssessmentContext
from engine.hypothesis_manager import HypothesisManager
from engine_models.actions import AgentAction
from engine_models.findings import EvidenceItem, Finding, ValidationStatus

logger = logging.getLogger("raven.agents.dependency")


class DependencyAssessmentAgent(BaseSpecializedAgent):
    """
    Audits third-party dependencies and libraries for published CVEs.
    """

    def __init__(self, context: AssessmentContext) -> None:
        super().__init__(context)
        self.agent_name = "DependencyAssessmentAgent"
        self.capability_id = "dependency_analysis"

    async def execute(self, context: Optional[AssessmentContext] = None) -> None:
        ctx = context or self.context
        target_path = ctx.target.raw_input
        hyp_mgr = HypothesisManager(ctx.state)

        hypotheses = hyp_mgr.get_untested(self.capability_id)
        current_hyp = hypotheses[0] if hypotheses else None

        action = AgentAction(
            agent_name=self.agent_name,
            capability_id=self.capability_id,
            tool_name="audit_dependencies",
            target=target_path,
            operation_type="file_analysis",
            parameters={"repo_path": target_path},
            purpose="Audit project dependency manifests for known CVEs",
            impact_level="passive",
            hypothesis_id=current_hyp.hypothesis_id if current_hyp else None,
        )

        if current_hyp:
            hyp_mgr.start_testing(current_hyp.hypothesis_id, action.action_id)

        result = await self.execute_action(action)

        if result.is_success and result.data:
            vulns = result.data.get("vulnerabilities") or result.data.get("cves") or []
            if isinstance(result.data, list):
                vulns = result.data

            for item in vulns:
                pkg = item.get("package", "unknown") if isinstance(item, dict) else "pkg"
                version = item.get("installed_version", "") if isinstance(item, dict) else ""
                cve_id = item.get("cve_id", "CVE-UNKNOWN") if isinstance(item, dict) else "CVE"
                severity = item.get("severity", "Medium") if isinstance(item, dict) else "Medium"
                fixed_ver = item.get("fixed_version", "latest") if isinstance(item, dict) else "latest"

                evidence = EvidenceItem(
                    evidence_type="package_manifest",
                    raw_data=f"{pkg}=={version} vulnerable to {cve_id}",
                    sanitized_summary=f"Dependency {pkg} matches known vulnerability {cve_id}",
                    confidence="High",
                )

                finding = Finding(
                    title=f"Vulnerable Dependency: {pkg} ({cve_id})",
                    vulnerability_type="vulnerable_dependency",
                    severity=severity.capitalize(),
                    cvss_score=7.0 if severity.lower() == "high" else 5.0,
                    cwe_id="CWE-1395",
                    target_component=pkg,
                    observation=f"Installed package '{pkg}' version '{version}' is affected by {cve_id}",
                    evidence=[evidence],
                    reproduction_steps=[f"Check package manifest for {pkg}=={version}"],
                    validation_status=ValidationStatus.CONFIRMED,
                    remediation=f"Upgrade {pkg} to version {fixed_ver} or higher.",
                    source_agent=self.agent_name,
                    capability_id=self.capability_id,
                    hypothesis_id=current_hyp.hypothesis_id if current_hyp else None,
                )
                self.publish_candidate_finding(finding)

            if current_hyp:
                if vulns:
                    hyp_mgr.resolve(current_hyp.hypothesis_id, "confirmed", f"Discovered {len(vulns)} vulnerable dependencies")
                else:
                    hyp_mgr.resolve(current_hyp.hypothesis_id, "rejected", "No vulnerable dependencies discovered")
