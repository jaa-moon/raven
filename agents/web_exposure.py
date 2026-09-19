"""
agents/web_exposure.py
----------------------
Sensitive path discovery. Each candidate is fetched and classified against
the nonexistent-route baseline; only responses that are NOT the SPA shell (and
carry a plausible content signature) become candidate findings. Every
candidate path is recorded as an observation so the report can show
"discovered" separately from "validated".
"""

from __future__ import annotations

from typing import Dict, List

from agents.base import Agent, AgentContext, AgentResult
from agents.web_common import base_url, classify, load_detector, url_for
from core.models import Severity, TestTask
from core.profile import TargetProfile
from core.state import AssessmentState
from validation.classifiers import ResponseClass
from validation.content import ValidationState, get_validator_for_path, validate_admin_panel

GROUPS: Dict[str, List[str]] = {
    "vcs": ["/.git/HEAD", "/.git/config"],
    "env": ["/.env", "/.env.production", "/.env.local"],
    "admin": ["/admin", "/administrator", "/console", "/wp-admin", "/wp-login.php"],
    "debug": ["/actuator", "/actuator/env", "/actuator/health", "/debug", "/server-status", "/phpinfo.php"],
    "config": ["/wp-config.php", "/config.php", "/configuration.php", "/app/config/parameters.yml"],
}
_SEVERITY = {"SensitiveFileExposure": Severity.CRITICAL, "ActuatorExposure": Severity.HIGH,
             "AdminPanelExposed": Severity.HIGH}


class WebExposureAgent(Agent):
    name = "web_exposure"
    description = "Finds exposed sensitive files and interfaces, robust to SPA catch-all routing."
    capabilities = ["http_request"]

    def applies(self, profile: TargetProfile) -> bool:
        return profile.has_surface("web_application") and bool(base_url(profile))

    def propose_tasks(self, state: AssessmentState) -> List[TestTask]:
        return [
            self.task(f"paths::{group}", "http_request", "Exposed paths & files",
                      f"Probe {group} paths", priority=85 if group in ("env", "vcs") else 65,
                      cost=len(paths), paths=paths,
                      rationale="Common high-impact exposures; validated against a route baseline.")
            for group, paths in GROUPS.items()
        ]

    async def run(self, task: TestTask, ctx: AgentContext) -> AgentResult:
        det = load_detector(ctx.profile)
        if det is None:
            ctx.state.add_limitation("No route baseline could be established; path exposure results are less reliable.")
        title = det.baseline.title if det and det.baseline else ""
        raised = failures = 0
        for path in task.params["paths"]:
            url = url_for(ctx.profile, path)
            res = await ctx.call("http_request", {"url": url}, f"Probe {path}")
            if not res.ok:
                failures += 1
                if failures >= 3:
                    return AgentResult(success=False, error=res.error)
                continue
            cls = classify(path, res.data, det)
            ctx.observe("path.candidate", "Exposed paths & files", f"{path} -> {cls.classification.value}",
                        path=path, status=res.data["status_code"], content_type=cls.content_type,
                        classification=cls.classification.value, similarity=cls.similarity_to_baseline)
            if cls.classification not in (ResponseClass.REAL_RESOURCE, ResponseClass.REDIRECT):
                continue
            validator = get_validator_for_path(path)
            if validator is None:
                continue
            body = res.data["body"]
            outcome = validator(cls, body, title) if validator is validate_admin_panel else validator(cls, body)
            if outcome.state in (ValidationState.FALSE_POSITIVE, ValidationState.SPA_FALLBACK,
                                 ValidationState.PROTECTED):
                continue
            raised += 1
            ctx.candidate(
                title=f"Possible exposure at {path}", category=outcome.vulnerability_type or "PathExposure",
                severity=_SEVERITY.get(outcome.vulnerability_type, Severity.MEDIUM),
                surface="Exposed paths & files", location=url,
                description=f"{path} returned content that may be a real exposed resource.",
                impact="Depends on content; validated independently before reporting.",
                remediation="Deny access to this resource at the web server or remove it.",
                reproduction=[f"curl -s {url}"],
                signal={"validator": "http_path_exposure", "url": url, "path": path})
        return AgentResult(summary=f"{raised} candidate(s) from {len(task.params['paths'])} paths")
