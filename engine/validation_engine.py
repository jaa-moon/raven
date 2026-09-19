"""
engine/validation_engine.py
---------------------------
Validation orchestrator for Raven adaptive security assessment.

Coordinates independent finding validation, deduplicates findings,
and enforces evidence integrity before findings enter the final report.
"""

from __future__ import annotations

import logging
from typing import List

from agents.validation_agent import ValidationAgent
from engine.assessment_context import AssessmentContext
from engine_models.findings import Finding, ValidationStatus
from engine_models.validation import ValidationResult

logger = logging.getLogger("raven.engine.validation")


class ValidationEngine:
    """
    Orchestrates finding verification, deduplication, and quality enforcement.
    """

    def __init__(self, context: AssessmentContext) -> None:
        self.context = context
        self.agent = ValidationAgent(context)

    async def validate_all(self) -> List[ValidationResult]:
        """
        Validate all candidate findings and enforce reportability constraints.
        """
        results = await self.agent.validate_all()

        # Enforce is_reportable() constraint: confirmed findings must have evidence
        confirmed_valid: List[Finding] = []
        for finding in self.context.state.confirmed_findings:
            if finding.is_reportable():
                # Deduplicate by (vulnerability_type, target_component, endpoint)
                if not any(
                    f.vulnerability_type == finding.vulnerability_type
                    and f.target_component == finding.target_component
                    and f.endpoint == finding.endpoint
                    for f in confirmed_valid
                ):
                    confirmed_valid.append(finding)
            else:
                logger.warning(
                    f"Finding '{finding.title}' was marked confirmed but lacks evidence. "
                    "Demoting to inconclusive."
                )
                finding.validation_status = ValidationStatus.INCONCLUSIVE
                self.context.state.inconclusive_findings.append(finding)

        self.context.state.confirmed_findings = confirmed_valid
        return results
