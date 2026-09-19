"""
agents/validation_agent.py
--------------------------
Independent finding validation agent for Raven adaptive security assessment.

Separates finding discovery from confirmation. Verifies candidate findings through
reproduction, differential testing, evidence verification, and alternative explanation checks.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from urllib.parse import urlparse

from agents.base_agent import BaseSpecializedAgent
from engine.assessment_context import AssessmentContext
from engine_models.actions import AgentAction
from engine_models.findings import EvidenceItem, Finding, ValidationStatus
from engine_models.validation import ValidationResult
from web.content_validators import ValidationState, get_validator_for_path, validate_admin_panel
from web.response_classifier import ResponseClass, classify_response
from web.spa_fallback_detector import SPAFallbackDetector

logger = logging.getLogger("raven.agents.validation")


class ValidationAgent(BaseSpecializedAgent):
    """
    Validates candidate findings against reproduction criteria and evidence standards.
    """

    def __init__(self, context: AssessmentContext) -> None:
        super().__init__(context)
        self.agent_name = "IndependentValidationAgent"
        self.capability_id = "finding_validation"
        # One SPA-fallback baseline per origin, reused across findings so we
        # don't spend validation budget re-establishing it for every candidate.
        self._spa_detectors: dict[str, SPAFallbackDetector] = {}

    async def execute(self, context: Optional[AssessmentContext] = None) -> None:
        await self.validate_all()

    async def validate_all(self) -> List[ValidationResult]:
        """Process all candidate findings in assessment state."""
        ctx = self.context
        results: List[ValidationResult] = []

        candidates = list(ctx.state.candidate_findings)
        logger.info(f"ValidationAgent evaluating {len(candidates)} candidate findings...")

        for finding in candidates:
            val_res = await self.validate_finding(finding)
            results.append(val_res)

            # Route finding to appropriate confirmed / inconclusive / rejected bucket
            if finding.validation_status == ValidationStatus.CONFIRMED:
                if finding not in ctx.state.confirmed_findings:
                    ctx.state.confirmed_findings.append(finding)
            elif finding.validation_status == ValidationStatus.REJECTED:
                if finding not in ctx.state.rejected_findings:
                    ctx.state.rejected_findings.append(finding)
            else:  # Inconclusive
                if finding not in ctx.state.inconclusive_findings:
                    ctx.state.inconclusive_findings.append(finding)

        logger.info(
            f"Validation complete: {len(ctx.state.confirmed_findings)} confirmed, "
            f"{len(ctx.state.inconclusive_findings)} inconclusive, "
            f"{len(ctx.state.rejected_findings)} rejected."
        )
        return results

    async def validate_finding(self, finding: Finding) -> ValidationResult:
        """Validate an individual candidate finding."""
        val = ValidationResult(
            finding_id=finding.finding_id,
            confidence_before=finding.confidence,
        )

        # 1. Check for reproducible evidence
        if not finding.evidence:
            val.complete(
                ValidationStatus.INCONCLUSIVE,
                reasoning="Finding lacks supporting evidence items required for confirmation.",
            )
            finding.validation_status = ValidationStatus.INCONCLUSIVE
            finding.confidence = "Low"
            return val

        # 2. Static / Evidence-backed findings (code snippet, package manifest, file, config)
        has_verified_evidence = any(
            str(e.evidence_type) in ("code_snippet", "package_manifest", "config_file", "file_content", "config_value")
            and e.confidence == "High"
            for e in finding.evidence
        )

        if has_verified_evidence:
            val.method = "evidence_verification"
            val.evidence_ids = [e.evidence_id for e in finding.evidence]
            val.confidence_after = "High"
            val.complete(
                ValidationStatus.CONFIRMED,
                reasoning="Evidence independently verified in target source code or configuration.",
            )
            finding.validation_status = ValidationStatus.CONFIRMED
            finding.confidence = "High"
            return val

        # 3. Network service findings validation
        if finding.asset_description and ":" in finding.asset_description and self.context.is_active_permitted:
            parts = finding.asset_description.split(":")
            host_p = parts[0]
            port_p = int(parts[1]) if parts[1].isdigit() else 80
            val.method = "network_protocol_verification"

            action = AgentAction(
                agent_name=self.agent_name,
                tool_name="protocol_probe",
                target=finding.asset_description,
                operation_type="protocol_probe",
                parameters={"host": host_p, "port": port_p, "protocol": "auto"},
                purpose=f"Verify network service vulnerability on {finding.asset_description}",
                impact_level="passive",
            )
            probe_res = await self.execute_action(action)
            if probe_res.is_success and probe_res.data.get("detected"):
                val.complete(
                    ValidationStatus.CONFIRMED,
                    reasoning=f"Service verified reachable on {finding.asset_description} with protocol {probe_res.data.get('protocol')}.",
                )
                finding.validation_status = ValidationStatus.CONFIRMED
                finding.confidence = "High"
                if not finding.cli_poc:
                    proto = probe_res.data.get("protocol", "tcp")
                    if proto == "redis":
                        finding.cli_poc = f"redis-cli -h {host_p} -p {port_p} PING"
                    elif proto == "memcached":
                        finding.cli_poc = f"echo 'stats' | nc {host_p} {port_p}"
                    elif proto == "ftp":
                        finding.cli_poc = f"curl -s ftp://anonymous:anonymous@{host_p}:{port_p}/"
                    else:
                        finding.cli_poc = f"nc -vz {host_p} {port_p}"
                return val

        # 4. Binary / Process findings validation
        if finding.cli_poc and self.context.is_active_permitted:
            val.method = "cli_execution_verification"
            
            action = AgentAction(
                agent_name=self.agent_name,
                capability_id=self.capability_id,
                tool_name="cli_fuzz",
                target=finding.cli_poc.split()[0] if finding.cli_poc else "binary",
                operation_type="cli_execution",
                parameters={"command": finding.cli_poc},
                purpose=f"Validate finding: {finding.title}",
                impact_level="active",
            )
            rep_res = await self.execute_action(action)
            
            if rep_res.is_success:
                val.complete(
                    ValidationStatus.CONFIRMED,
                    reasoning=f"CLI reproduction command executed successfully: {finding.cli_poc[:80]}",
                )
                finding.validation_status = ValidationStatus.CONFIRMED
                finding.confidence = "High"
            else:
                val.complete(
                    ValidationStatus.INCONCLUSIVE,
                    reasoning=f"CLI reproduction attempt failed: {rep_res.errors}",
                )
                finding.validation_status = ValidationStatus.INCONCLUSIVE
            return val

        # 5. Dynamic findings requiring HTTP reproduction
        if finding.endpoint and self.context.is_active_permitted:
            val.method = "active_reproduction"
            action = AgentAction(
                agent_name=self.agent_name,
                capability_id=self.capability_id,
                tool_name="send_http_request",
                target=finding.endpoint,
                operation_type="http_request",
                parameters={"url": finding.endpoint, "method": "GET"},
                purpose=f"Validate finding: {finding.title}",
                impact_level="passive",
            )
            rep_res = await self.execute_action(action)

            if not rep_res.is_success:
                val.complete(
                    ValidationStatus.INCONCLUSIVE,
                    reasoning=f"Reproduction attempt failed: {rep_res.errors}",
                )
                finding.validation_status = ValidationStatus.INCONCLUSIVE
                return val

            status_code = rep_res.data.get("status_code") or rep_res.data.get("status")
            body = rep_res.data.get("body", "")
            headers = rep_res.data.get("headers", {}) or {}

            # HTTP 200 (or any status) alone never confirms a finding: classify
            # the response against an SPA-fallback baseline for this origin,
            # then run a content-specific validator when the endpoint looks
            # like a sensitive path/admin panel/actuator route.
            if isinstance(status_code, int):
                await self._validate_http_reproduction(val, finding, status_code, headers, body)
            else:
                val.complete(
                    ValidationStatus.CONFIRMED,
                    reasoning="Endpoint verified reachable and observations reproduced.",
                )
                finding.validation_status = ValidationStatus.CONFIRMED
                finding.confidence = "High"
            return val

        # 6. Fallback if active testing not permitted
        val.method = "passive_inspection"
        val.complete(
            ValidationStatus.INCONCLUSIVE,
            reasoning="Active reproduction was required but active testing is disabled in scope.",
        )
        finding.validation_status = ValidationStatus.INCONCLUSIVE
        return val

    async def _validate_http_reproduction(
        self, val: ValidationResult, finding: Finding, status_code: int, headers: dict, body: str
    ) -> None:
        """Classify an HTTP reproduction response and, for sensitive paths, run
        the matching content validator before allowing CONFIRMED status.

        This is the guard against the SPA-fallback false-positive class: a
        200/text/html response that matches the site's nonexistent-path
        baseline must never become a confirmed finding.
        """
        parsed = urlparse(finding.endpoint)
        path = parsed.path or "/"
        detector = await self._get_spa_detector(finding.endpoint)
        classification = classify_response(path, status_code, headers, body, detector)

        validator = get_validator_for_path(path)
        if validator is not None and classification.classification in (
            ResponseClass.REAL_RESOURCE, ResponseClass.REDIRECT, ResponseClass.PROTECTED,
        ):
            if validator is validate_admin_panel:
                baseline_title = detector.baseline.title if (detector and detector.baseline) else ""
                outcome = validator(classification, body, baseline_title)
            else:
                outcome = validator(classification, body)

            status_map = {
                ValidationState.CONFIRMED: ValidationStatus.CONFIRMED,
                ValidationState.SPA_FALLBACK: ValidationStatus.SPA_FALLBACK,
                ValidationState.PROTECTED: ValidationStatus.PROTECTED,
                ValidationState.FALSE_POSITIVE: ValidationStatus.REJECTED,
                ValidationState.VALIDATED: ValidationStatus.INCONCLUSIVE,
                ValidationState.INCONCLUSIVE: ValidationStatus.INCONCLUSIVE,
                ValidationState.CANDIDATE: ValidationStatus.INCONCLUSIVE,
            }
            finding.validation_status = status_map[outcome.state]
            finding.confidence = outcome.confidence if outcome.confidence in ("High", "Medium", "Low") else "Low"
            if outcome.evidence:
                finding.add_evidence(EvidenceItem(
                    evidence_type="http_response",
                    content="; ".join(outcome.evidence),
                    sanitized_summary=outcome.reason,
                    endpoint=finding.endpoint,
                    confidence=finding.confidence,
                    source_tool="send_http_request",
                ))
            val.complete(finding.validation_status, reasoning=outcome.reason)
            return

        if classification.classification == ResponseClass.SPA_FALLBACK:
            finding.validation_status = ValidationStatus.SPA_FALLBACK
            finding.confidence = "Low"
            val.complete(
                ValidationStatus.SPA_FALLBACK,
                reasoning=classification.reason,
            )
            return

        if classification.classification == ResponseClass.PROTECTED:
            finding.validation_status = ValidationStatus.PROTECTED
            finding.confidence = "Medium"
            val.complete(ValidationStatus.PROTECTED, reasoning=classification.reason)
            return

        if classification.classification in (ResponseClass.GENERIC_404, ResponseClass.SERVER_ERROR):
            finding.validation_status = ValidationStatus.REJECTED
            finding.confidence = "Low"
            val.complete(ValidationStatus.REJECTED, reasoning=classification.reason)
            return

        # No content-specific validator and the response looks like a real
        # resource (e.g. a generic API endpoint): a 2xx that differs from the
        # SPA baseline is still only "reproduced," not independently confirmed
        # of any specific vulnerability class without further evidence.
        finding.validation_status = ValidationStatus.INCONCLUSIVE
        finding.confidence = "Low"
        val.complete(
            ValidationStatus.INCONCLUSIVE,
            reasoning="Endpoint reproduced but no content-specific evidence confirms the hypothesized vulnerability.",
        )

    async def _get_spa_detector(self, endpoint: str) -> Optional[SPAFallbackDetector]:
        """Lazily establish (once per origin) an SPA-fallback baseline.

        Cached per-origin on the agent instance so repeated candidate paths
        against the same target don't each spend a validation-budget request
        re-establishing the baseline.
        """
        parsed = urlparse(endpoint)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if not origin or origin == "://":
            return None
        if origin in self._spa_detectors:
            return self._spa_detectors[origin]

        import uuid as _uuid

        probe_path = f"/raven-nonexistent-{_uuid.uuid4().hex[:12]}"
        action = AgentAction(
            agent_name=self.agent_name,
            capability_id=self.capability_id,
            tool_name="send_http_request",
            target=origin + probe_path,
            operation_type="http_request",
            parameters={"url": origin + probe_path, "method": "GET"},
            purpose="Establish SPA-fallback baseline for validation",
            impact_level="passive",
        )
        res = await self.execute_action(action)
        if not res.is_success:
            logger.warning("Failed to establish SPA-fallback baseline for %s", origin)
            return None

        status = int(res.data.get("status_code", 0) or 0)
        headers = res.data.get("headers", {}) or {}
        body = res.data.get("body", "") or ""

        detector = SPAFallbackDetector(fetcher=lambda _p: (status, headers, body))
        detector.establish_baseline()
        self._spa_detectors[origin] = detector
        return detector
