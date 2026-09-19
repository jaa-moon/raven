"""
validation/validator.py
-----------------------
Independent finding validation. Agents only *suggest* candidates; this module
re-observes the target through the gateway (fresh requests / fresh file reads)
and decides CONFIRMED / INCONCLUSIVE / REJECTED from that new evidence.

    "HTTP 200" never confirms anything by itself.
"""

from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable, Dict, List, Optional, Protocol
from urllib.parse import urlparse

from core.models import Confidence, Finding, FindingStatus, ToolResult
from validation.baseline import SPAFallbackDetector
from validation.checks_net import NetChecks
from validation.checks_static import StaticChecks
from validation.checks_web import WebChecks
from validation.classifiers import classify_response
from validation.content import CONTENT_CHECKS, ValidationState, get_validator_for_path, validate_admin_panel
from validation.evidence import baseline_evidence, http_evidence
from validation.outcome import conclude

logger = logging.getLogger("raven.validation")


class ValidationContext(Protocol):
    async def call(self, capability: str, arguments: Dict[str, Any], purpose: str) -> ToolResult: ...
    def lookup(self, query: str, purpose: str) -> List[str]: ...


_STATE_TO_STATUS = {
    ValidationState.CONFIRMED: FindingStatus.CONFIRMED,
    ValidationState.SPA_FALLBACK: FindingStatus.REJECTED,
    ValidationState.FALSE_POSITIVE: FindingStatus.REJECTED,
    ValidationState.PROTECTED: FindingStatus.REJECTED,
    ValidationState.VALIDATED: FindingStatus.INCONCLUSIVE,
    ValidationState.INCONCLUSIVE: FindingStatus.INCONCLUSIVE,
    ValidationState.CANDIDATE: FindingStatus.INCONCLUSIVE,
}
_CONF = {"High": Confidence.HIGH, "Medium": Confidence.MEDIUM, "Low": Confidence.LOW}


class FindingValidator(WebChecks, StaticChecks, NetChecks):
    def __init__(self, ctx: ValidationContext) -> None:
        self.ctx = ctx
        self._baselines: Dict[str, SPAFallbackDetector] = {}

    async def validate(self, finding: Finding) -> Finding:
        kind = finding.signal.get("validator", "")
        handler: Optional[Callable[[Finding], Awaitable[Finding]]] = getattr(self, f"_v_{kind}", None)
        if handler is None:
            return conclude(finding, FindingStatus.INCONCLUSIVE, Confidence.LOW,
                            f"No validator exists for signal type '{kind or 'unspecified'}'; "
                            "the candidate could not be independently verified.", "none")
        try:
            return await handler(finding)
        except Exception as e:  # never let one bad finding stop the assessment
            logger.debug("Validator %s crashed", kind, exc_info=True)
            return conclude(finding, FindingStatus.INCONCLUSIVE, Confidence.LOW,
                            f"Validation raised {type(e).__name__}: {e}", kind)

    # -- shared helpers -----------------------------------------------------------

    async def _fetch(self, url: str, purpose: str, headers: Optional[Dict[str, str]] = None) -> Optional[Dict[str, Any]]:
        args: Dict[str, Any] = {"url": url}
        if headers:
            args["headers"] = headers
        res = await self.ctx.call("http_request", args, purpose)
        return res.data if res.ok else None

    async def _baseline(self, origin: str) -> Optional[SPAFallbackDetector]:
        if origin in self._baselines:
            return self._baselines[origin]
        probe = SPAFallbackDetector.new_probe_path()
        data = await self._fetch(origin + probe, "Establish nonexistent-route baseline")
        if data is None:
            return None
        det = SPAFallbackDetector()
        det.load_baseline(probe, data["status_code"], data["headers"], data["body"])
        self._baselines[origin] = det
        return det

    # -- HTTP: exposed paths ------------------------------------------------------

    async def _v_http_path_exposure(self, f: Finding) -> Finding:
        url = f.signal["url"]
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        notes = self.ctx.lookup(f"{parsed.path} exposure SPA fallback validation", "validate path exposure")
        det = await self._baseline(origin)
        data = await self._fetch(url, f"Reproduce candidate {parsed.path}")
        if data is None:
            return conclude(f, FindingStatus.INCONCLUSIVE, Confidence.LOW,
                            "Could not re-fetch the resource to reproduce the observation.", "http_path_exposure")
        cls = classify_response(parsed.path, data["status_code"], data["headers"], data["body"], det)
        validator = CONTENT_CHECKS.get(f.signal.get("content_check", "")) or get_validator_for_path(parsed.path)
        if validator is None:
            return conclude(f, FindingStatus.INCONCLUSIVE, Confidence.LOW,
                            "No content-specific validator for this path; existence alone is not a finding.",
                            "http_path_exposure", [http_evidence(url, data)])
        if validator is validate_admin_panel:
            outcome = validator(cls, data["body"], det.baseline.title if det and det.baseline else "")
        else:
            outcome = validator(cls, data["body"])
        ev = [baseline_evidence(cls.similarity_to_baseline, cls.classification.value, cls.reason),
              http_evidence(url, data, note="; ".join(outcome.evidence) or outcome.reason)]
        note = outcome.reason + (f" (context consulted: {'; '.join(notes)})" if notes else "")
        if outcome.vulnerability_type:
            f.category = outcome.vulnerability_type
        return conclude(f, _STATE_TO_STATUS[outcome.state], _CONF.get(outcome.confidence, Confidence.LOW),
                        note, "http_path_exposure", ev)

    _v_api_docs_exposure = _v_http_path_exposure
