"""
agents/injection.py
--------------------
InjectionTestAgent: discovers input surface -- forms, query parameters, REST
path/id segments, cookies, and (when published) OpenAPI/Swagger operations --
on already-known endpoints, forms InjectionHypotheses, and requests the
`injection.*` capabilities -- it never touches httpx/requests/subprocess
itself and it never confirms anything. It only raises CANDIDATE findings;
`validation/checks_injection.py` independently re-derives the verdict.

Active probing only runs once the operator has raised scope beyond the
default 'low' risk ceiling (`assess --max-risk moderate`, still gated by
`authorized=True`). Below that ceiling the gap is recorded as an explicit
limitation -- it is never silently skipped -- and no active request is ever
attempted, so the existing scope guarantees (no out-of-scope tool call is
ever made) are not weakened by adding this agent.

Input-surface discovery v2: every discovered parameter carries an `evidence`
tag (spec / form / cookie / observed / guessed) recording *how* it was found,
never just a bare name. Task priority is derived from that evidence plus
whether the surface looks security-sensitive (login/auth/admin/...), rather
than a fixed per-injection-type constant -- so under a tight budget the
planner spends active-testing budget on the parameters most likely to matter
instead of treating every discovered 'id' the same. It's still not a full
crawler or fuzzer: discovery is bounded to what Raven actually observes on
the pages/specs it fetches (see `core/injection_signals.py` and the honest
gaps recorded in PROJECT_STATUS.md -- arbitrary/blind header fuzzing and
JSON bodies with no spec and no form are still out of scope).
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qsl, urlsplit

from agents.base import Agent, AgentContext, AgentResult
from agents.web_common import base_url, url_for
from core.injection_signals import redact_probe_data, sql_signals, ssrf_signals, xss_signals
from core.models import Confidence, InjectionHypothesis, InjectionType, Severity, TestTask
from core.profile import TargetProfile
from core.scope import RISK_ORDER
from core.state import AssessmentState

MIN_ACTIVE_RISK = "moderate"

_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
_ACTION_RE = re.compile(r"""\baction=["']([^"']*)["']""", re.I)
_FORM_METHOD_RE = re.compile(r'method=["\']post["\']', re.I)
_INPUT_RE = re.compile(r"<(?:input|textarea|select)\b[^>]*\bname=[\"']([^\"']+)[\"']", re.I)
_HREF_QS_RE = re.compile(r"""(?:href|action)=["']([^"']+\?[^"']+)["']""", re.I)
_HREF_PATH_RE = re.compile(r"""(?:href|action)=["'](/[^"'?\s]*)["']""", re.I)
_API_HINT = re.compile(r"(?i)/(api|rest)(/|$)")
_URLLIKE_PARAM = re.compile(r"(?i)url|uri|link|redirect|return|dest|target|next|callback|src|host|fetch|proxy|webhook")

# Path segments that look like a REST resource id (numeric, UUID, or a Mongo-
# style ObjectId) -- these are treated as a testable path *parameter*, keyed
# by their own literal value so `tools/injection_probe._place` can find and
# replace exactly that segment.
_PATH_ID_SEG = re.compile(r"^(?:[0-9]+|[0-9a-fA-F]{24}|[0-9a-fA-F-]{8,36})$")
_SPEC_ENDPOINTS = ("/openapi.json", "/swagger.json", "/api-docs", "/v2/api-docs")
_SPEC_PATH_PARAM = re.compile(r"\{[^{}]+\}")
_SYNTHETIC_PATH_ID = "1"          # placeholder substituted for a spec's `{param}` template

# Cookies that are third-party/analytics artifacts, not application input surface.
_NON_APP_COOKIE = re.compile(r"(?i)^(_ga|_gid|_gat|__cf_bm|__cfduid|_fbp|__utm[a-z])")

# Endpoint/parameter names that make a candidate worth testing first when the
# budget is tight -- authentication and account-management surfaces are where
# an injection bug is most consequential.
_SENSITIVE_HINT = re.compile(
    r"(?i)login|signin|password|passwd|reset|token|auth|admin|account|session|register|"
    r"api[-_]?key|secret|otp|2fa")

_BASE_PRIORITY = {InjectionType.SQL_INJECTION: 62, InjectionType.SSRF: 60, InjectionType.XSS: 56}
# How much confidence in the parameter's own existence contributes to priority:
# a spec is ground truth, a real <form> field is strong, an observed link/id
# is real but unconfirmed as attacker-reachable, a bare naming-convention
# guess is the weakest signal.
_EVIDENCE_WEIGHT = {"spec": 10, "form": 6, "cookie": 3, "observed": 2, "guessed": 0}

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


def _task_priority(kind: InjectionType, endpoint: str, parameter: str, evidence: str) -> int:
    """Evidence-aware priority, not a hardcoded per-endpoint list: a base
    score per injection class, adjusted by how strong the evidence for this
    specific parameter is (spec > form > cookie > observed > guessed) and
    whether the surface looks security-sensitive. This is what keeps active
    testing from being crowded out by low-value generic breadth tasks when
    the budget tightens, while still yielding to genuinely higher-value cheap
    checks (secrets, security headers, baseline) that stay at their own
    fixed, deliberately high priorities."""
    score = _BASE_PRIORITY[kind] + _EVIDENCE_WEIGHT.get(evidence, 0)
    if _SENSITIVE_HINT.search(endpoint) or _SENSITIVE_HINT.search(parameter):
        score += 12
    return min(score, 94)      # stay below LLM_IMMUNE_PRIORITY(95): the optional LLM may still nudge it


def _interesting(kind: InjectionType, data: Dict[str, Any]) -> Tuple[bool, str]:
    """Cheap, agent-side triage: is this worth raising as a candidate at all?
    This is NOT a verdict -- the validator re-runs its own probe and re-derives
    the outcome. Both sides share `core.injection_signals` so the threshold used
    to raise a candidate can never drift from the one used to confirm it."""
    if kind == InjectionType.SQL_INJECTION:
        s = sql_signals(data.get("tests", {}))
        return (s["error_based"] or s["boolean_based"]), s["why"]
    if kind == InjectionType.XSS:
        s = xss_signals(data)
        return s["executable"], s["why"]
    if kind == InjectionType.SSRF:
        s = ssrf_signals(data)
        # 'accepted but no callback' is still worth validating; 'mechanism
        # unavailable' and 'rejected' are not candidates.
        return s["state"] in ("callback_received", "accepted_no_callback"), s["why"]
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
                "Discover input surface: forms, query/path parameters, cookies, and any published "
                "OpenAPI/Swagger spec", priority=58, cost=2,
                rationale="Active injection testing needs real discovered parameters, not guesses."))
        if not self._active_testing_permitted(state):
            return tasks
        for endpoint, info in sorted(p.attributes.get("injection_surface", {}).items()):
            method = info.get("method", "GET")
            for param in info.get("params", []):
                pname, location = param["name"], param.get("location", "query")
                evidence = param.get("evidence", "guessed")
                ev_note = {"spec": "an OpenAPI/Swagger definition", "form": "a real HTML form field",
                          "cookie": "an observed Set-Cookie", "observed": "an observed link/endpoint",
                          "guessed": "the REST 'id' naming convention"}[evidence]
                tasks.append(self.task(
                    f"sql::{endpoint}::{location}::{pname}", "injection.sql.detect", "SQL Injection",
                    f"Test parameter '{pname}' on {endpoint} for SQL injection",
                    priority=_task_priority(InjectionType.SQL_INJECTION, endpoint, pname, evidence), cost=4,
                    rationale=f"'{pname}' is an untrusted {location} input reaching {endpoint} ({ev_note}).",
                    endpoint=endpoint, method=method, parameter=pname, location=location))
                tasks.append(self.task(
                    f"xss::{endpoint}::{location}::{pname}", "injection.xss.reflect", "XSS",
                    f"Test parameter '{pname}' on {endpoint} for reflected XSS",
                    priority=_task_priority(InjectionType.XSS, endpoint, pname, evidence), cost=1,
                    rationale=f"'{pname}' is an untrusted {location} input that may be reflected in output "
                              f"({ev_note}).",
                    endpoint=endpoint, method=method, parameter=pname, location=location))
                if location in ("query", "body") and _looks_url_like(pname):
                    tasks.append(self.task(
                        f"ssrf::{endpoint}::{location}::{pname}", "injection.ssrf.detect", "SSRF",
                        f"Test parameter '{pname}' on {endpoint} for SSRF",
                        priority=_task_priority(InjectionType.SSRF, endpoint, pname, evidence), cost=2,
                        rationale=f"'{pname}' looks like a server-fetched URL/destination ({ev_note}).",
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

        def _add(path: str, method: str, names: List[str], location: str, evidence: str) -> None:
            names = [n for n in dict.fromkeys(names) if n]      # dedupe, keep order
            if not names or not path:
                return
            entry = surface.setdefault(path, {"method": method, "params": []})
            existing = {p["name"] for p in entry["params"]}
            entry["params"] += [{"name": n, "location": location, "evidence": evidence}
                                for n in names if n not in existing]
            ctx.profile.add_endpoint(path)

        for m in _FORM_RE.finditer(body):
            attrs, inner = m.group(1) or "", m.group(2)
            names = sorted(set(_INPUT_RE.findall(inner)))
            am = _ACTION_RE.search(attrs)
            action = (am.group(1) if am else "") or "/"     # an action-less form posts to the current page
            method = "POST" if _FORM_METHOD_RE.search(attrs) else "GET"
            endpoint = action if action.startswith("/") else "/" + action.lstrip("/")
            _add(endpoint.split("?")[0], method, names, "query" if method == "GET" else "body", "form")

        # Query strings anywhere in the page (href/action), plus endpoints already
        # discovered by other agents that carry a query string -- no new crawl.
        seen_qs = list(_HREF_QS_RE.findall(body)) + [e for e in ctx.profile.endpoints if "?" in e]
        for raw in seen_qs:
            parts = urlsplit(raw)
            _add(parts.path or "/", "GET", [k for k, _ in parse_qsl(parts.query)], "query", "observed")

        # REST path/id segments: a trailing numeric/UUID/ObjectId-like segment on a
        # link on this same page, or on an endpoint already discovered by another
        # agent, is itself a testable path parameter -- keyed by its own literal
        # value (see tools/injection_probe._place, location="path"). This reads
        # links already on the fetched page; it never crawls to a new one.
        path_candidates = set(_HREF_PATH_RE.findall(body)) | {e.split("?")[0] for e in ctx.profile.endpoints}
        for base_ep in path_candidates:
            segments = base_ep.rstrip("/").split("/")
            if segments and segments[-1] and _PATH_ID_SEG.match(segments[-1]):
                _add(base_ep.rstrip("/"), "GET", [segments[-1]], "path", "observed")

        # Known REST-ish endpoints commonly take an 'id'; test it without guessing wildly.
        for ep in list(ctx.profile.endpoints):
            base_ep = ep.split("?")[0]
            if _API_HINT.search(base_ep) and base_ep not in surface:
                surface[base_ep] = {"method": "GET", "params": [{"name": "id", "location": "query",
                                                                 "evidence": "guessed"}]}

        # Cookies the target itself set are attacker-influenced input the same as any
        # query/body parameter (session/state cookies are a common injection vector).
        for raw_cookie in res.data.get("set_cookies", []) or []:
            name = raw_cookie.split("=", 1)[0].strip()
            if name and not _NON_APP_COOKIE.match(name):
                _add("/", "GET", [name], "cookie", "cookie")

        # A published OpenAPI/Swagger spec is ground truth for real parameter names --
        # far stronger evidence than sniffing HTML, and it is the only way Raven learns
        # about JSON request-body fields without executing client-side JavaScript.
        for spec_path in _SPEC_ENDPOINTS:
            if spec_path in ctx.profile.endpoints:
                await self._discover_from_spec(ctx, spec_path, _add)

        ctx.profile.attributes["injection_surface"] = surface
        n_params = sum(len(v["params"]) for v in surface.values())
        ctx.observe("injection.surface", "HTTP",
                    f"{len(surface)} endpoint(s) with {n_params} candidate parameter(s) for active testing.",
                    endpoints=list(surface))
        return AgentResult(summary=f"{len(surface)} endpoint(s), {n_params} parameter(s)")

    async def _discover_from_spec(self, ctx: AgentContext, spec_path: str, add) -> None:
        res = await ctx.call("http_request", {"url": base_url(ctx.profile) + spec_path},
                             f"GET {spec_path} (parse OpenAPI/Swagger spec for real parameters)")
        if not res.ok:
            return
        try:
            spec = json.loads(res.data.get("body", "") or "")
        except (ValueError, TypeError):
            return
        if not isinstance(spec, dict):
            return
        base_path = str(spec.get("basePath", "") or "")
        for path_tmpl, operations in (spec.get("paths") or {}).items():
            if not isinstance(operations, dict):
                continue
            # A generic synthetic id stands in for every `{param}` segment so the
            # resulting endpoint is concrete and directly testable via location="path".
            concrete = _SPEC_PATH_PARAM.sub(_SYNTHETIC_PATH_ID, str(path_tmpl))
            endpoint = (base_path.rstrip("/") + concrete) if base_path else concrete
            if not endpoint.startswith("/"):
                endpoint = "/" + endpoint
            for method, op in operations.items():
                if method.lower() not in ("get", "post", "put", "patch", "delete") or not isinstance(op, dict):
                    continue
                has_path_param = "{" in path_tmpl
                if has_path_param:
                    add(endpoint, method.upper(), [_SYNTHETIC_PATH_ID], "path", "spec")
                for param in op.get("parameters", []) or []:
                    if not isinstance(param, dict):
                        continue
                    where = param.get("in")
                    if where in ("query", "header") and param.get("name"):
                        add(endpoint, method.upper(), [param["name"]], where, "spec")
                    elif where == "body":                       # Swagger 2.0 body parameter
                        props = ((param.get("schema") or {}).get("properties") or {})
                        add(endpoint, method.upper(), list(props), "body", "spec")
                # OpenAPI 3.x request body
                body_schema = (((op.get("requestBody") or {}).get("content") or {})
                              .get("application/json", {}).get("schema") or {})
                if body_schema.get("properties"):
                    add(endpoint, method.upper(), list(body_schema["properties"]), "body", "spec")

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

        redacted = redact_probe_data(kind.value, res.data)      # never persist raw response bodies
        hyp.test_observations.append(redacted)
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
                       "parameter": parameter, "location": location, "hint": redacted})
            if finding:
                hyp.finding_id = finding.finding_id
        ctx.state.injection_hypotheses.append(hyp)
        return AgentResult(summary=f"{kind.value} on {parameter}: {'candidate raised' if interesting else 'no signal'}")
