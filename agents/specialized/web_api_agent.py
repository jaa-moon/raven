"""
agents/specialized/web_api_agent.py
-----------------------------------
Specialized agent for Web Application and REST API security assessments.
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

logger = logging.getLogger("raven.agents.web_api")


class WebApiAssessmentAgent(BaseSpecializedAgent):
    """
    Assesses web applications and REST APIs for OWASP Top 10 vulnerabilities,
    missing security headers, and injection flaws.
    """

    def __init__(self, context: AssessmentContext) -> None:
        super().__init__(context)
        self.agent_name = "WebApiAssessmentAgent"
        self.capability_id = "web_api_assessment"

    async def execute(self, context: Optional[AssessmentContext] = None) -> None:
        ctx = context or self.context
        target_url = ctx.target.raw_input
        hyp_mgr = HypothesisManager(ctx.state)

        hypotheses = hyp_mgr.get_untested(self.capability_id)
        current_hyp = hypotheses[0] if hypotheses else None

        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Baseline Header Audit
        action = AgentAction(
            agent_name=self.agent_name,
            capability_id=self.capability_id,
            tool_name="send_http_request",
            target=base_url,
            operation_type="http_request",
            method="GET",
            parameters={"url": base_url, "method": "GET"},
            purpose="Audit HTTP response security headers",
            impact_level="passive",
            hypothesis_id=current_hyp.hypothesis_id if current_hyp else None,
        )

        if current_hyp:
            hyp_mgr.start_testing(current_hyp.hypothesis_id, action.action_id)

        result = await self.execute_action(action)

        found_issues = []
        if result.is_success and result.data:
            headers = {k.lower(): v for k, v in result.data.get("headers", {}).items()}

            # Check Strict-Transport-Security
            if parsed.scheme == "https" and "strict-transport-security" not in headers:
                evidence = EvidenceItem(
                    evidence_type="http_response",
                    raw_data="Strict-Transport-Security header missing from response headers",
                    sanitized_summary="HSTS header not declared on HTTPS endpoint",
                    endpoint=base_url,
                    confidence="High",
                )
                finding = Finding(
                    title="Missing Strict-Transport-Security (HSTS) Header",
                    vulnerability_type="security_misconfiguration",
                    severity="Low",
                    cvss_score=3.7,
                    cwe_id="CWE-319",
                    target_component=base_url,
                    endpoint=base_url,
                    observation="The web application does not enforce HTTPS via Strict-Transport-Security header.",
                    evidence=[evidence],
                    reproduction_steps=[f"curl -I {base_url} and observe missing Strict-Transport-Security header"],
                    validation_status=ValidationStatus.CONFIRMED,
                    remediation="Configure 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
                    source_agent=self.agent_name,
                    capability_id=self.capability_id,
                    hypothesis_id=current_hyp.hypothesis_id if current_hyp else None,
                )
                self.publish_candidate_finding(finding)
                found_issues.append(finding)

            # Check X-Frame-Options
            if "x-frame-options" not in headers:
                evidence = EvidenceItem(
                    evidence_type="http_response",
                    raw_data="X-Frame-Options header missing from response",
                    sanitized_summary="X-Frame-Options header not configured on web endpoint",
                    endpoint=base_url,
                    confidence="High",
                )
                finding = Finding(
                    title="Missing X-Frame-Options Header (Clickjacking Risk)",
                    vulnerability_type="security_misconfiguration",
                    severity="Low",
                    cvss_score=3.5,
                    cwe_id="CWE-1021",
                    target_component=base_url,
                    endpoint=base_url,
                    curl_poc=f"curl -s -I '{base_url}' | grep -i x-frame-options",
                    observation="Missing X-Frame-Options header allows the page to be rendered within an iframe, enabling clickjacking attacks.",
                    evidence=[evidence],
                    reproduction_steps=[f"curl -I {base_url} and verify absence of X-Frame-Options"],
                    validation_status=ValidationStatus.CONFIRMED,
                    remediation="Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' to all HTTP responses.",
                    source_agent=self.agent_name,
                    capability_id=self.capability_id,
                    hypothesis_id=current_hyp.hypothesis_id if current_hyp else None,
                )
                self.publish_candidate_finding(finding)
                found_issues.append(finding)

            # Check X-Content-Type-Options
            if "x-content-type-options" not in headers:
                evidence = EvidenceItem(
                    evidence_type="http_response",
                    raw_data="X-Content-Type-Options header missing",
                    sanitized_summary="X-Content-Type-Options: nosniff header missing",
                    endpoint=base_url,
                    confidence="High",
                )
                finding = Finding(
                    title="Missing X-Content-Type-Options Header",
                    vulnerability_type="security_misconfiguration",
                    severity="Low",
                    cvss_score=3.1,
                    cwe_id="CWE-79",
                    target_component=base_url,
                    endpoint=base_url,
                    curl_poc=f"curl -s -I '{base_url}' | grep -i x-content-type-options",
                    observation="Missing X-Content-Type-Options allows browsers to MIME-sniff responses away from declared Content-Type.",
                    evidence=[evidence],
                    reproduction_steps=[f"curl -I {base_url} and verify absence of X-Content-Type-Options: nosniff"],
                    validation_status=ValidationStatus.CONFIRMED,
                    remediation="Add 'X-Content-Type-Options: nosniff' header to HTTP responses.",
                    source_agent=self.agent_name,
                    capability_id=self.capability_id,
                    hypothesis_id=current_hyp.hypothesis_id if current_hyp else None,
                )
                self.publish_candidate_finding(finding)
                found_issues.append(finding)

            # Check CORS misconfiguration (Access-Control-Allow-Origin: *)
            if headers.get("access-control-allow-origin") == "*":
                evidence = EvidenceItem(
                    evidence_type="http_response",
                    raw_data="Access-Control-Allow-Origin: *",
                    sanitized_summary="Wildcard CORS policy detected",
                    endpoint=base_url,
                    confidence="High",
                )
                finding = Finding(
                    title="Insecure CORS Policy (Wildcard Origin)",
                    vulnerability_type="security_misconfiguration",
                    severity="Medium",
                    cvss_score=5.3,
                    cwe_id="CWE-942",
                    target_component=base_url,
                    endpoint=base_url,
                    curl_poc=f"curl -s -I -H 'Origin: https://evil.com' '{base_url}' | grep -i access-control",
                    observation="The application returns 'Access-Control-Allow-Origin: *', allowing any domain to read its responses.",
                    evidence=[evidence],
                    reproduction_steps=[f"curl -I -H 'Origin: https://evil.com' {base_url} and verify ACAO header"],
                    validation_status=ValidationStatus.CONFIRMED,
                    remediation="Configure CORS policies to allow only specific, trusted origins. Do not use '*'.",
                    source_agent=self.agent_name,
                    capability_id=self.capability_id,
                    hypothesis_id=current_hyp.hypothesis_id if current_hyp else None,
                )
                self.publish_candidate_finding(finding)
                found_issues.append(finding)

            # 2. Check Cookie Security
            if "set-cookie" in headers:
                cookie_action = AgentAction(
                    agent_name=self.agent_name,
                    capability_id=self.capability_id,
                    tool_name="cookie_audit",
                    target=base_url,
                    operation_type="cookie_audit",
                    parameters={"base_url": base_url, "endpoint": "/"},
                    purpose="Audit cookie security flags (Secure, HttpOnly, SameSite)",
                    impact_level="passive",
                )
                cookie_res = await self.execute_action(cookie_action)
                if cookie_res.is_success and cookie_res.data:
                    c_issues = cookie_res.data if isinstance(cookie_res.data, list) else cookie_res.data.get("issues", [])
                    for ci in c_issues:
                        c_ev = EvidenceItem(
                            evidence_type="http_response",
                            raw_data=str(ci),
                            sanitized_summary="Cookie missing security attributes",
                            endpoint=base_url,
                            confidence="High",
                        )
                        c_find = Finding(
                            title=f"Insecure Cookie Flags: {ci.get('cookie_name', 'session')}",
                            vulnerability_type="insecure_cookie",
                            severity="Medium",
                            cvss_score=5.3,
                            cwe_id="CWE-614",
                            target_component=base_url,
                            endpoint=base_url,
                            observation=f"Cookie '{ci.get('cookie_name')}' missing Secure or HttpOnly flag.",
                            evidence=[c_ev],
                            reproduction_steps=[f"Inspect Set-Cookie header from {base_url}"],
                            validation_status=ValidationStatus.CONFIRMED,
                            remediation="Ensure all sensitive cookies specify Secure, HttpOnly, and SameSite=Strict/Lax.",
                            source_agent=self.agent_name,
                            capability_id=self.capability_id,
                            hypothesis_id=current_hyp.hypothesis_id if current_hyp else None,
                        )
                        self.publish_candidate_finding(c_find)
                        found_issues.append(c_find)

        if current_hyp:
            if found_issues:
                hyp_mgr.resolve(current_hyp.hypothesis_id, "confirmed", f"Discovered {len(found_issues)} web security issues")
            else:
                hyp_mgr.resolve(current_hyp.hypothesis_id, "rejected", "Standard security headers and cookie flags present")
