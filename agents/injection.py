"""
agents/injection.py
--------------------
InjectionTestAgent: discovers input surface (forms and query parameters on
already-known endpoints), forms InjectionHypotheses, and requests the
`injection.*` capabilities -- it never touches httpx/requests/subprocess
itself and it never confirms anything. It only raises CANDIDATE findings;
`validation/checks_injection.py` independently re-derives the verdict.

Active probing only runs once the operator has raised scope beyond the
default 'low' risk ceiling (`assess --max-risk moderate`, still gated by
`authorized=True`). Below that ceiling the gap is recorded as an explicit
limitation -- it is never silently skipped -- and no active request is ever
attempted, so the existing scope guarantees (no out-of-scope tool call is
ever made) are not weakened by adding this agent.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qsl, urlsplit

from agents.base import Agent, AgentContext, AgentResult
from agents.web_common import base_url, url_for
from core.models import Confidence, InjectionHypothesis, InjectionType, Severity, TestTask
from core.profile import TargetProfile
from core.scope import RISK_ORDER
from core.state import AssessmentState

MIN_ACTIVE_RISK = "moderate"

_FORM_RE = re.compile(r"<form[^>]*action=[\"']([^\"']*)[\"'][^>]*>(.*?)</form>", re.I | re.S)
_FORM_METHOD_RE = re.compile(r'method=["\']post["\']', re.I)
_INPUT_RE = re.compile(r"<input[^>]*name=[\"']([^\"']+)[\"']", re.I)
_HREF_QS_RE = re.compile(r"""href=["']([^"']+\?[^"']+)["']""", re.I)
_API_HINT = re.compile(r"(?i)/(api|rest)(/|$)")
_URLLIKE_PARAM = re.compile(r"(?i)url|uri|link|redirect|return|dest|target|next|callback|src|host|fetch|proxy|webhook")

_TITLE = {
    InjectionType.SQL_INJECTION: "SQL Injection",
    InjectionType.XSS: "Cross-Site Scripting",
    InjectionType.SSRF: "Server-Side Request Forgery",
}
_CATEGORY = {
    InjectionType.SQL_INJECTION: "SQLInjection",
    InjectionType.XSS: "CrossSiteScripting",
    InjectionType.SSRF: "ServerSideRequestForgery",
}
_SEVERITY = {
    InjectionType.SQL_INJECTION: Severity.HIGH,
    InjectionType.XSS: Severity.MEDIUM,
    InjectionType.SSRF: Severity.HIGH,
}
_IMPACT = {
    InjectionType.SQL_INJECTION: "An attacker may read, and depending on privileges modify, backend database data.",
    InjectionType.XSS: "An attacker-controlled script could run in another user's browser session.",
    InjectionType.SSRF: "The application can be made to issue requests on the attacker's behalf, potentially "
                        "reaching internal-only services.",
}
_REMEDIATION = {
    InjectionType.SQL_INJECTION: "Use parameterized queries/prepared statements; never concatenate untrusted input into SQL.",
    InjectionType.XSS: "Contextually encode/escape all untrusted output; prefer a template engine with autoescaping.",
    InjectionType.SSRF: "Validate and allow-list destination hosts server-side; do not let user input choose the fetch target.",
}
_VALIDATOR = {
    InjectionType.SQL_INJECTION: "sql_injection",
    InjectionType.XSS: "reflected_xss",
    InjectionType.SSRF: "ssrf",
}
_CAPABILITY = {
    InjectionType.SQL_INJECTION: "injection.sql.detect",
    InjectionType.XSS: "injection.xss.reflect",
    InjectionType.SSRF: "injection.ssrf.detect",
}


def _looks_url_like(name: str) -> bool:
    return bool(_URLLIKE_PARAM.search(name))


def _interesting(kind: InjectionType, data: Dict[str, Any]) -> Tuple[bool, str]:
    """Cheap, agent-side triage: is this worth raising as a candidate at all?
    This is NOT a verdict -- the validator re-derives everything independently."""
    if kind == InjectionType.SQL_INJECTION:
        tests = data.get("tests", {})
        base, quote = tests.get("baseline", {}), tests.get("quote", {})
        true_r, false_r = tests.get("true", {}), tests.get("false", {})
        if quote.get("sql_error_signature"):
            return True, "A single quote in the parameter produced a database-error signature in the response."
        if true_r.get("sql_error_signature") or false_r.get("sql_error_signature"):
            return True, "A boolean SQL payload produced a database-error signature in the response."
        b_len, t_len, f_len = (len(base.get("body", "") or ""), len(true_r.get("body", "") or ""),
                               len(false_r.get("body", "") or ""))
        b_status, t_status, f_status = base.get("status_code"), true_r.get("status_code"), false_r.get("status_code")
        if t_status == b_status and abs(t_len - b_len) < max(20, b_len * 0.05) and (
                f_status != b_status or abs(f_len - b_len) > max(40, b_len * 0.1)):
            return True, ("The boolean-true payload matches the benign baseline while the boolean-false payload "
                         "changes the response, consistent with conditional query logic.")
        return False, "Baseline, quote and boolean payloads produced equivalent responses."
    if kind == InjectionType.XSS:
        if data.get("marker_reflected") and not data.get("escaped"):
            return True, f"An injected marker was reflected unescaped in {data.get('context', 'the response')}."
        if data.get("marker_reflected"):
            return False, "The injected marker was reflected but HTML-escaped."
        return False, "The injected marker was not reflected."
    if kind == InjectionType.SSRF:
        if data.get("callback_received"):
            return True, "The Raven callback canary received a connection after the parameter was set to its URL."
        if data.get("application_accepted"):
            return True, "The application accepted the supplied URL without an immediate rejection."
        return False, "The application rejected, or did not act on, the supplied URL."
    return False, "Unrecognized injection type."


class InjectionTestAgent(Agent):
    name = "injection_test"
    description = ("Investigates input-handling hypotheses (SQL injection, XSS, SSRF) on discovered forms "
                   "and query parameters. Creates candidates only; the validator decides.")
    capabilities = ["http_request", "injection.sql.detect", "injection.xss.reflect", "injection.ssrf.detect"]

    def applies(self, profile: TargetProfile) -> bool:
        return profile.has_surface("web_application") and bool(base_url(profile))

    # -- planning -----------------------------------------------------------------

    def propose_tasks(self, state: AssessmentState) -> List[TestTask]:
        p = state.profile
        tasks: List[TestTask] = []
        if "injection_surface" not in p.attributes:
            tasks.append(self.task(
                "discover_surface", "http_request", "HTTP",
                "Discover form and query-parameter input surface", priority=58,
                rationale="Active injection testing needs real discovered parameters, not guesses."))
        if not self._active_testing_permitted(state):
            return tasks
        for endpoint, info in sorted(p.attributes.get("injection_surface", {}).items()):
            method = info.get("method", "GET")
            for param in info.get("params", []):
                pname, location = param["name"], param.get("location", "query")
                tasks.append(self.task(
                    f"sql::{endpoint}::{location}::{pname}", "injection.sql.detect", "SQL Injection",
                    f"Test parameter '{pname}' on {endpoint} for SQL injection", priority=55, cost=4,
                    rationale=f"'{pname}' is an untrusted {location} input reaching {endpoint}.",
                    endpoint=endpoint, method=method, parameter=pname, location=location))
                tasks.append(self.task(
                    f"xss::{endpoint}::{location}::{pname}", "injection.xss.reflect", "XSS",
                    f"Test parameter '{pname}' on {endpoint} for reflected XSS", priority=55, cost=1,
                    rationale=f"'{pname}' is an untrusted {location} input that may be reflected in output.",
                    endpoint=endpoint, method=method, parameter=pname, location=location))
                if _looks_url_like(pname):
                    tasks.append(self.task(
                        f"ssrf::{endpoint}::{location}::{pname}", "injection.ssrf.detect", "SSRF",
                        f"Test parameter '{pname}' on {endpoint} for SSRF", priority=52, cost=2,
                        rationale=f"'{pname}' looks like a server-fetched URL/destination.",
                        endpoint=endpoint, method=method, parameter=pname, location=location))
        return tasks

    def _active_testing_permitted(self, state: AssessmentState) -> bool:
        allowed = RISK_ORDER.get(state.scope.max_risk, 0) >= RISK_ORDER.get(MIN_ACTIVE_RISK, 2)
        if not allowed and state.profile.attributes.get("injection_surface"):
            state.add_limitation(
                "Active injection testing (SQL injection/XSS/SSRF) was not performed: the current scope caps "
                f"risk at '{state.scope.max_risk}'. Re-run with --max-risk moderate (or higher) under explicit "
                "authorization to exercise it.")
        return allowed

    # -- execution ------------------------------------------------------------------

    async def run(self, task: TestTask, ctx: AgentContext) -> AgentResult:
        step = task.key.split(".", 1)[1]
        if step == "discover_surface":
            return await self._discover_surface(ctx)
        if step.startswith("sql::"):
            return await self._test(ctx, task, InjectionType.SQL_INJECTION)
        if step.startswith("xss::"):
            return await self._test(ctx, task, InjectionType.XSS)
        if step.startswith("ssrf::"):
            return await self._test(ctx, task, InjectionType.SSRF)
        return AgentResult(success=False, error=f"Unknown step {step}")

    async def _discover_surface(self, ctx: AgentContext) -> AgentResult:
        res = await ctx.call("http_request", {"url": base_url(ctx.profile) + "/"},
                             "GET / (discover input surface)")
        ctx.profile.attributes["injection_surface"] = {}   # attempted, whatever the outcome
        if not res.ok:
            return AgentResult(success=False, error=res.error)
        body = res.data.get("body", "") or ""
        surface: Dict[str, Dict[str, Any]] = {}

        for m in _FORM_RE.finditer(body):
            action, inner = m.group(1) or "", m.group(2)
            names = sorted(set(_INPUT_RE.findall(inner)))
            if not names:
                continue
            method = "POST" if _FORM_METHOD_RE.search(m.group(0)) else "GET"
            endpoint = action if action.startswith("/") else "/" + action.lstrip("/")
            entry = surface.setdefault(endpoint, {"method": method, "params": []})
            existing = {p["name"] for p in entry["params"]}
            entry["params"] += [{"name": n, "location": "query" if method == "GET" else "body"}
                                for n in names if n not in existing]
            ctx.profile.add_endpoint(endpoint)

        for m in _HREF_QS_RE.finditer(body):
            parts = urlsplit(m.group(1))
            path = parts.path or "/"
            names = sorted({k for k, _ in parse_qsl(parts.query)})
            if not names:
                continue
            entry = surface.setdefault(path, {"method": "GET", "params": []})
            existing = {p["name"] for p in entry["params"]}
            entry["params"] += [{"name": n, "location": "query"} for n in names if n not in existing]
            ctx.profile.add_endpoint(path)

        # Known REST-ish endpoints commonly take an 'id'; test it without guessing wildly.
        for ep in list(ctx.profile.endpoints):
            if _API_HINT.search(ep) and ep not in surface:
                surface[ep] = {"method": "GET", "params": [{"name": "id", "location": "query"}]}

        ctx.profile.attributes["injection_surface"] = surface
        n_params = sum(len(v["params"]) for v in surface.values())
        ctx.observe("injection.surface", "HTTP",
                    f"{len(surface)} endpoint(s) with {n_params} candidate parameter(s) for active testing.",
                    endpoints=list(surface))
        return AgentResult(summary=f"{len(surface)} endpoint(s), {n_params} parameter(s)")

    async def _test(self, ctx: AgentContext, task: TestTask, kind: InjectionType) -> AgentResult:
        params = task.params
        endpoint, method, parameter, location = (params["endpoint"], params["method"],
                                                  params["parameter"], params["location"])
        url = url_for(ctx.profile, endpoint)
        res = await ctx.call(task.capability,
                             {"url": url, "parameter": parameter, "method": method, "location": location},
                             f"Test '{parameter}' ({location}) on {endpoint} for {kind.value}")
        hyp = InjectionHypothesis(type=kind, target=base_url(ctx.profile), endpoint=endpoint, method=method,
                                  parameter=parameter, location=location, rationale=task.rationale)
        if not res.ok:
            hyp.recovery_notes.append(res.error)
            ctx.state.injection_hypotheses.append(hyp)
            return AgentResult(success=False, error=res.error)

        hyp.test_observations.append(res.data)
        interesting, why = _interesting(kind, res.data)
        ctx.observe(f"injection.{kind.value}.probe", task.surface,
                    f"{endpoint}::{parameter}: {'interesting behavior' if interesting else 'no signal'} ({why})",
                    endpoint=endpoint, parameter=parameter, location=location, interesting=interesting)
        if interesting:
            hyp.confidence = Confidence.LOW
            finding = ctx.candidate(
                title=f"Possible {_TITLE[kind]} via '{parameter}' on {endpoint}",
                category=_CATEGORY[kind], severity=_SEVERITY[kind], surface=task.surface,
                location=url, description=why, impact=_IMPACT[kind], remediation=_REMEDIATION[kind],
                reproduction=[f"{method} {url} with {location} parameter '{parameter}' varied (controlled payloads)"],
                signal={"validator": _VALIDATOR[kind], "url": url, "method": method,
                       "parameter": parameter, "location": location, "hint": res.data})
            if finding:
                hyp.finding_id = finding.finding_id
        ctx.state.injection_hypotheses.append(hyp)
        return AgentResult(summary=f"{kind.value} on {parameter}: {'candidate raised' if interesting else 'no signal'}")
