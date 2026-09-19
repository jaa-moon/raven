"""
agents/web_security.py
----------------------
Passive HTTP security posture: headers, cookies, CORS, authentication surface.
Findings are candidates only; the validator re-fetches and decides.
"""

from __future__ import annotations

import re
from typing import List

from agents.base import Agent, AgentContext, AgentResult
from agents.web_common import base_url, classify, load_detector, url_for
from core.models import Severity, TestTask
from core.profile import TargetProfile
from core.state import AssessmentState
from validation.checks_web import _cookie_flags
from validation.classifiers import ResponseClass

# header -> (severity, why it matters, remediation)
HEADERS = {
    "content-security-policy": (Severity.LOW, "No CSP: injected script is not constrained.",
                                "Define a restrictive Content-Security-Policy."),
    "x-content-type-options": (Severity.LOW, "Browsers may MIME-sniff responses.",
                               "Send 'X-Content-Type-Options: nosniff'."),
    "x-frame-options": (Severity.LOW, "Pages can be framed (clickjacking).",
                        "Send X-Frame-Options or CSP frame-ancestors."),
    "referrer-policy": (Severity.INFO, "Full URLs may leak via Referer.", "Set a Referrer-Policy."),
}
HSTS = ("strict-transport-security", Severity.LOW, "HTTPS is not pinned by HSTS.",
        "Send Strict-Transport-Security with a long max-age.")
LOGIN_PATHS = ["/login", "/signin", "/api/login", "/rest/user/login", "/auth/login", "/users/login"]
_SESSION_COOKIE = re.compile(r"(?i)(sess|sid|token|jwt|auth)")


class WebSecurityAgent(Agent):
    name = "web_security"
    description = "Passive HTTP posture: security headers, cookies, CORS, authentication surface."
    capabilities = ["http_request"]

    def applies(self, profile: TargetProfile) -> bool:
        return profile.has_surface("web_application") and bool(base_url(profile))

    def propose_tasks(self, state: AssessmentState) -> List[TestTask]:
        return [
            self.task("headers", "http_request", "HTTP", "Audit HTTP security headers", priority=90),
            self.task("cookies", "http_request", "Session & cookies", "Audit cookie attributes", priority=75),
            self.task("cors", "http_request", "HTTP", "Test CORS origin handling", priority=60),
            self.task("auth_review", "http_request", "Authentication", "Passive authentication review",
                      priority=55, cost=len(LOGIN_PATHS),
                      rationale="Identify login mechanisms without credentials."),
        ]

    async def run(self, task: TestTask, ctx: AgentContext) -> AgentResult:
        step = task.key.split(".", 1)[1]
        return await getattr(self, f"_{step}")(ctx)

    async def _root(self, ctx: AgentContext, **kw):
        return await ctx.call("http_request", {"url": base_url(ctx.profile) + "/", **kw}, "GET /")

    async def _headers(self, ctx: AgentContext) -> AgentResult:
        res = await self._root(ctx)
        if not res.ok:
            return AgentResult(success=False, error=res.error)
        h, url = res.data["headers"], base_url(ctx.profile) + "/"
        wanted = dict(HEADERS)
        if url.startswith("https://"):
            wanted[HSTS[0]] = HSTS[1:]  # type: ignore[assignment]
        n = 0
        for header, (sev, why, fix) in wanted.items():
            if header in h:
                continue
            if header == "x-frame-options" and "frame-ancestors" in h.get("content-security-policy", ""):
                continue
            n += 1
            ctx.candidate(
                title=f"Missing {header} header", category="SecurityMisconfiguration", severity=sev,
                surface="HTTP", location=url, description=f"Response lacks '{header}'. {why}",
                impact=why, remediation=fix, reproduction=[f"curl -sI {url} | grep -i {header}"],
                signal={"validator": "missing_header", "url": url, "header": header})
        ctx.observe("http.headers", "HTTP", f"{n} expected header(s) missing.", server=h.get("server", ""))
        return AgentResult(summary=f"{n} missing header candidate(s)")

    async def _cookies(self, ctx: AgentContext) -> AgentResult:
        res = await self._root(ctx)
        if not res.ok:
            return AgentResult(success=False, error=res.error)
        url, n = base_url(ctx.profile) + "/", 0
        for raw in res.data.get("set_cookies", []):
            c = _cookie_flags(raw)
            if _SESSION_COOKIE.search(c["name"]):
                ctx.profile.authentication = True if ctx.profile.authentication is None else ctx.profile.authentication
            missing = [k for k in ("httponly", "secure", "samesite") if not c[k]]
            if missing:
                n += 1
                ctx.candidate(
                    title=f"Cookie '{c['name']}' lacks {', '.join(missing)}", category="InsecureCookie",
                    severity=Severity.LOW, surface="Session & cookies", location=url,
                    description=f"Cookie '{c['name']}' is set without: {', '.join(missing)}.",
                    remediation="Set HttpOnly, Secure (over TLS) and SameSite on session cookies.",
                    signal={"validator": "cookie_flags", "url": url, "cookie": c["name"], "missing": missing})
        ctx.observe("http.cookies", "Session & cookies", f"{len(res.data.get('set_cookies', []))} cookie(s) set.")
        return AgentResult(summary=f"{n} cookie candidate(s)")

    async def _cors(self, ctx: AgentContext) -> AgentResult:
        origin = "https://raven-probe.invalid"
        res = await self._root(ctx, headers={"Origin": origin})
        if not res.ok:
            return AgentResult(success=False, error=res.error)
        acao = res.data["headers"].get("access-control-allow-origin", "")
        if acao in ("*", origin):
            ctx.candidate(
                title="Permissive CORS policy", category="SecurityMisconfiguration", severity=Severity.MEDIUM,
                surface="HTTP", location=base_url(ctx.profile) + "/",
                description=f"Access-Control-Allow-Origin is {acao!r} for an arbitrary Origin.",
                remediation="Allow only explicit trusted origins.",
                signal={"validator": "cors_reflection", "url": base_url(ctx.profile) + "/", "origin": origin})
        return AgentResult(summary=f"ACAO={acao or 'absent'}")

    async def _auth_review(self, ctx: AgentContext) -> AgentResult:
        root = await self._root(ctx)
        if root.ok and "www-authenticate" in root.data["headers"]:
            ctx.profile.authentication = True
            ctx.observe("auth.challenge", "Authentication", "Root responds with WWW-Authenticate.")
        det, found = load_detector(ctx.profile), []
        for path in LOGIN_PATHS:
            res = await ctx.call("http_request", {"url": url_for(ctx.profile, path)}, f"GET {path}")
            if not res.ok:
                continue
            cls = classify(path, res.data, det)
            if cls.classification in (ResponseClass.REAL_RESOURCE, ResponseClass.PROTECTED) or (
                    cls.classification == ResponseClass.UNKNOWN and res.data["status_code"] == 405):
                found.append(path)
        if found:
            ctx.profile.authentication = True
        ctx.observe("auth.surface", "Authentication",
                    f"Login-like endpoints: {found or 'none found'} (no credentials, passive only).", paths=found)
        return AgentResult(summary=f"{len(found)} login-like endpoint(s)")
