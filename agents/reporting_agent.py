"""
agents/reporting_agent.py
-------------------------
Executive and technical reporting agent for Raven adaptive security assessments.

Synthesizes findings, attack paths, coverage tracking, and limitations into
structured, executive-ready reports with actionable remediation advice.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from engine.assessment_context import AssessmentContext
from engine_models.report import PentestReport

logger = logging.getLogger("raven.agents.reporting")


class ReportingAgent:
    """
    Generates professional, evidence-backed security assessment narratives.
    """

    def __init__(self, context: AssessmentContext) -> None:
        self.context = context

    async def generate_narrative(self, report: PentestReport) -> None:
        """
        Produce executive summary, methodology documentation, and remediation priorities.
        """
        provider = self.context.provider
        target = self.context.target
        conf_count = len(report.confirmed_findings)
        inconc_count = len(report.inconclusive_findings)
        score = report.risk_score
        label = report.risk_label

        # Default deterministic narrative
        report.target_summary = (
            f"Target {target.raw_input} was assessed under {target.target_type.value} profile. "
            f"A total of {report.total_assets_discovered} assets were discovered across "
            f"{len(report.total_capabilities_used)} activated security capabilities."
        )

        report.methodology_summary = (
            "Assessment conducted using Raven v3.0 Adaptive Agentic Security Architecture. "
            "Reconnaissance established target architecture and attack surface graph. "
            "Hypotheses were autonomously generated and tested through MCP tool gateway. "
            "All confirmed findings were independently verified against evidence criteria; "
            "unverified observations are reported as inconclusive to ensure zero false-positive inflation."
        )

        report.executive_summary = (
            f"Raven conducted an autonomous security assessment against {target.raw_input}. "
            f"The overall target risk posture is evaluated at {score}/10.0 ({label}). "
            f"The assessment identified {conf_count} confirmed vulnerability findings and "
            f"{inconc_count} inconclusive observations requiring further investigation. "
            f"A total of {len(report.attack_paths)} chained attack paths were identified."
        )

        # Build prioritized remediation plan
        remediations = []
        for f in report.confirmed_findings:
            if f.remediation and f.remediation not in remediations:
                remediations.append(f"[{f.severity}] {f.title}: {f.remediation}")
        report.remediation_plan = remediations

        # If LLM available, enhance executive summary
        if provider:
            system_prompt = "You are a Chief Information Security Officer (CISO) executive report writer."
            user_prompt = f"""
Summarize this security pentest in 2 concise, executive paragraphs:
Target: {target.raw_input} ({target.target_type.value})
Risk Score: {score}/10.0 ({label})
Confirmed Findings: {conf_count}
Attack Paths: {len(report.attack_paths)}
Top Findings: {[f.title for f in report.confirmed_findings[:3]]}
Coverage: {report.coverage_percentage}% tested
"""
            try:
                if hasattr(provider, "analyze_async"):
                    summary = await provider.analyze_async(system_prompt, user_prompt)
                    if summary and len(summary) > 50:
                        report.executive_summary = summary.strip()
            except Exception as e:
                logger.debug(f"LLM narrative generation skipped: {e}")
