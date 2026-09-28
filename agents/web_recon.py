"""
agents/web_recon.py
-------------------
Discovers web surfaces (robots.txt, API roots, GraphQL). Everything it learns
goes into the TargetProfile, which is what triggers re-planning.
"""

from __future__ import annotations

import json
import re
from typing import List

from agents.base import Agent, AgentContext, AgentResult
from agents.web_common import base_url, classify, load_detector, store_baseline, url_for
from core.graphql_schema import parse_introspection
from validation.baseline import SPAFallbackDetector
from core.models import Severity, TestTask
from core.profile import TargetProfile
from core.state import AssessmentState
from validation.classifiers import ResponseClass

_SCRIPT_SRC = re.compile(r"""(?:src|href)=["']([^"']+\.js(?:\?[^"']*)?)["']""", re.I)
_API_LITERAL = re.compile(r"""["'`](/(?:api|rest|graphql|v[0-9]+)(?:/[A-Za-z0-9_\-.]+)*/?)["'`?]""")
MAX_SCRIPTS = 14
_CHUNK_REF = re.compile(r"""["'](\./[A-Za-z0-9_.\-]+\.js)["']""")
MAX_ROUTES = 15

API_PATHS = ["/api", "/rest", "/api/v1", "/openapi.json", "/swagger.json", "/api-docs", "/v2/api-docs"]
_API_HINT = re.compile(r"(?i)(^|/)(api|rest|graphql|v[0-9]+)(/|$)")

# Bounded-depth (4 levels: a field/arg's own `type` plus up to 3 `ofType`
# unwraps) TypeRef fragment, shared by every `type` reference in the full
# introspection query below -- deep enough to resolve the common
# NonNull(List(NonNull(Scalar))) wrapper shapes real schemas use, without
# unbounded recursion into the schema itself. `core.graphql_schema.parse_introspection`
# is the only thing that interprets the response this produces.
_GRAPHQL_TYPE_REF = "kind name ofType{kind name ofType{kind name ofType{kind name}}}"
_FULL_GRAPHQL_INTROSPECTION_QUERY = (
    "{__schema{queryType{name}mutationType{name}types{kind name "
    "fields{name type{" + _GRAPHQL_TYPE_REF + "}args{name type{" + _GRAPHQL_TYPE_REF + "}}}"
    "inputFields{name type{" + _GRAPHQL_TYPE_REF + "}}}}}"
)


class WebReconAgent(Agent):
    name = "web_recon"
    description = "Discovers web application surfaces: robots.txt, API roots, GraphQL."
    capabilities = ["http_request"]

    def applies(self, profile: TargetProfile) -> bool:
        return profile.has_surface("web_application") and bool(base_url(profile))

    def propose_tasks(self, state: AssessmentState) -> List[TestTask]:
        p = state.profile
        tasks = []
        if "baseline" not in p.attributes:
            tasks.append(self.task(
                "baseline", "http_request", "HTTP", "Establish nonexistent-route baseline", priority=100,
                rationale="Required to tell real resources apart from catch-all (SPA) responses."))
        if p.attributes.get("spa") and "spa_routes" not in p.attributes:
            tasks.append(self.task(
                "spa_routes", "http_request", "HTTP", "Extract API routes from frontend bundles", priority=72,
                cost=MAX_SCRIPTS, rationale="Catch-all SPA: real API paths live in the JavaScript, not in guessable URLs."))
        tasks += [
            self.task("robots", "http_request", "HTTP", "Read robots.txt for disclosed paths",
                      priority=80, rationale="Cheap source of real application paths."),
            self.task("api_discovery", "http_request", "REST API", "Probe common API roots and specs",
                      priority=70, cost=len(API_PATHS),
                      rationale="Determine whether an API surface exists."),
            self.task("graphql", "http_request", "GraphQL", "Probe GraphQL endpoint",
                      priority=45, rationale="GraphQL introspection is a common exposure."),
        ]
        # New knowledge -> new work: probe API-looking endpoints learned from earlier tasks.
        for ep in p.endpoints:
            api = bool(_API_HINT.search(ep))
            tasks.append(self.task(f"endpoint::{ep}", "http_request", "REST API" if api else "Exposed paths & files",
                                   f"Inspect discovered endpoint {ep}", priority=48 if api else 68,
                                   rationale="Endpoint discovered during this assessment.", path=ep))
        return tasks

    async def run(self, task: TestTask, ctx: AgentContext) -> AgentResult:
        step = task.key.split(".", 1)[1]
        if step == "baseline":
            return await self._baseline(ctx)
        if step == "spa_routes":
            return await self._spa_routes(ctx)
        if step == "robots":
            return await self._robots(ctx)
        if step == "api_discovery":
            return await self._api(ctx)
        if step == "graphql":
            return await self._graphql(ctx)
        if step.startswith("endpoint::"):
            return await self._endpoint(ctx, task.params["path"])
        return AgentResult(success=False, error=f"Unknown step {step}")

    async def _get(self, ctx: AgentContext, path: str, **extra):
        return await ctx.call("http_request", {"url": url_for(ctx.profile, path), **extra}, f"GET {path}")

    async def _baseline(self, ctx: AgentContext) -> AgentResult:
        probe = SPAFallbackDetector.new_probe_path()
        res = await self._get(ctx, probe)
        if not res.ok:
            return AgentResult(success=False, error=res.error)
        store_baseline(ctx.profile, probe, res.data)
        catch_all = res.data["status_code"] == 200 and "html" in res.data["content_type"].lower()
        if catch_all:
            ctx.profile.attributes["spa"] = True
            ctx.profile.add_technology("SPA (catch-all routing)")
        ctx.observe("http.baseline", "HTTP",
                    f"Nonexistent route returns HTTP {res.data['status_code']} "
                    f"({res.data['content_type'] or 'no content-type'}); catch-all={catch_all}.",
                    status=res.data["status_code"], catch_all=catch_all)
        return AgentResult(summary=f"baseline HTTP {res.data['status_code']}, catch-all={catch_all}")

    async def _spa_routes(self, ctx: AgentContext) -> AgentResult:
        ctx.profile.attributes["spa_routes"] = True  # attempted, whatever the outcome
        root = await self._get(ctx, "/")
        if not root.ok:
            return AgentResult(success=False, error=root.error)
        queue: List[str] = []
        for m in _SCRIPT_SRC.finditer(root.data["body"]):
            src = m.group(1)
            if not src.startswith(("http://", "https://", "//")) and src not in queue:
                queue.append(src)
        queue.sort(key=lambda u: 0 if "main" in u else 1)   # main bundle first: it names the API
        routes: List[str] = []
        seen, fetched = set(), 0
        while queue and fetched < MAX_SCRIPTS:
            src = queue.pop(0)
            if src in seen:
                continue
            seen.add(src)
            res = await self._get(ctx, src)
            if not res.ok:
                continue
            fetched += 1
            for m in _API_LITERAL.finditer(res.data["body"]):
                path = m.group(1).rstrip("/")
                if path and "{" not in path and path not in routes:
                    routes.append(path)
            for m in _CHUNK_REF.finditer(res.data["body"]):
                ref = m.group(1)[2:]
                if ref not in seen and ref not in queue:
                    queue.append(ref)
        new = [r for r in routes[:MAX_ROUTES] if ctx.profile.add_endpoint(r)]
        ctx.observe("http.spa_routes", "HTTP", f"{fetched} bundle(s) scanned; {len(new)} API route(s) extracted.",
                    routes=new)
        return AgentResult(summary=f"{len(new)} route(s) from {fetched} bundle(s)")

    async def _robots(self, ctx: AgentContext) -> AgentResult:
        res = await self._get(ctx, "/robots.txt")
        if not res.ok:
            return AgentResult(success=False, error=res.error)
        cls = classify("/robots.txt", res.data, load_detector(ctx.profile))
        body = res.data["body"]
        real = (res.data["status_code"] == 200 and cls.classification != ResponseClass.SPA_FALLBACK
                and re.search(r"(?im)^\s*(user-agent|disallow|allow|sitemap)\s*:", body))
        if not real:
            ctx.observe("http.robots", "HTTP", "No real robots.txt (absent or SPA fallback).",
                        classification=cls.classification.value)
            return AgentResult(summary="no robots.txt")
        paths = [m.group(1).strip() for m in re.finditer(r"(?im)^\s*(?:dis)?allow\s*:\s*(\S+)", body)]
        new = [pth for pth in paths if pth not in ("/", "") and ctx.profile.add_endpoint(pth)]
        ctx.observe("http.robots", "HTTP", f"robots.txt discloses {len(new)} path(s).", paths=new[:20])
        return AgentResult(summary=f"{len(new)} new endpoint(s)")

    async def _api(self, ctx: AgentContext) -> AgentResult:
        det, found, failures = load_detector(ctx.profile), [], 0
        for path in API_PATHS:
            res = await self._get(ctx, path)
            if not res.ok:
                failures += 1
                if failures >= 3:
                    return AgentResult(success=False, error=res.error)
                continue
            cls = classify(path, res.data, det)
            ok = cls.classification == ResponseClass.REAL_RESOURCE and res.data["status_code"] == 200
            ctx.observe("path.candidate", "REST API", f"{path} -> {cls.classification.value}",
                        path=path, status=res.data["status_code"], classification=cls.classification.value,
                        content_type=cls.content_type, similarity=cls.similarity_to_baseline)
            if ok and (cls.is_json or path.endswith(("json", "docs"))):
                found.append(path)
                ctx.profile.add_endpoint(path)
                if path.endswith(("openapi.json", "swagger.json", "api-docs")):
                    ctx.candidate(
                        title=f"API specification exposed at {path}", category="APIDocumentationExposed",
                        severity=Severity.LOW, surface="REST API", location=url_for(ctx.profile, path),
                        description="A machine-readable API description appears to be publicly readable.",
                        signal={"validator": "api_docs_exposure", "url": url_for(ctx.profile, path)},
                        remediation="Restrict API documentation to authenticated/internal users.",
                        reproduction=[f"curl -s {url_for(ctx.profile, path)}"])
        if found:
            ctx.profile.api = True
            ctx.profile.add_surface("rest_api")
        return AgentResult(summary=f"{len(found)} API path(s) found")

    async def _endpoint(self, ctx: AgentContext, path: str) -> AgentResult:
        res = await self._get(ctx, path)
        if not res.ok:
            return AgentResult(success=False, error=res.error)
        cls = classify(path, res.data, load_detector(ctx.profile))
        ctx.observe("path.candidate", "REST API", f"{path} -> {cls.classification.value}", path=path,
                    status=res.data["status_code"], classification=cls.classification.value)
        if cls.classification in (ResponseClass.REAL_RESOURCE, ResponseClass.PROTECTED) and (
                cls.is_json or res.data["status_code"] in (401, 403)):
            ctx.profile.api = True
            ctx.profile.add_surface("rest_api")
            if res.data["status_code"] in (401, 403):
                ctx.profile.authentication = True
        if (cls.classification == ResponseClass.REAL_RESOURCE and res.data["status_code"] == 200
                and re.search(r"(?i)(listing directory|index of|parent directory)", res.data["body"][:2000])):
            url = url_for(ctx.profile, path)
            ctx.candidate(
                title=f"Directory listing enabled at {path}", category="DirectoryListing",
                severity=Severity.MEDIUM, surface="Exposed paths & files", location=url,
                description=f"{path} returns an auto-generated directory index.",
                impact="Lists files that may not be intended for public access.",
                remediation="Disable directory indexing; serve only intended files.",
                reproduction=[f"curl -s {url}"],
                signal={"validator": "http_path_exposure", "url": url, "path": path,
                        "content_check": "directory_listing"})
        return AgentResult(summary=f"{path}: {cls.classification.value}")

    async def _graphql(self, ctx: AgentContext) -> AgentResult:
        res = await self._get(ctx, "/graphql", params={"query": "{__schema{types{name}}}"})
        if not res.ok:
            return AgentResult(success=False, error=res.error)
        cls = classify("/graphql", res.data, load_detector(ctx.profile))
        if not (cls.is_json and cls.classification != ResponseClass.SPA_FALLBACK):
            ctx.observe("api.graphql", "GraphQL", "No GraphQL endpoint at /graphql.",
                        classification=cls.classification.value)
            return AgentResult(summary=f"graphql: {cls.classification.value}")

        ctx.profile.add_surface("graphql")
        ctx.profile.api = True
        ctx.observe("api.graphql", "GraphQL", "GraphQL endpoint responded with JSON.",
                    status=res.data["status_code"])
        if '"__schema"' in res.data["body"]:
            ctx.candidate(
                title="GraphQL introspection enabled", category="GraphQLIntrospectionEnabled",
                severity=Severity.LOW, surface="GraphQL", location=url_for(ctx.profile, "/graphql"),
                description="The GraphQL endpoint answered an introspection query.",
                signal={"validator": "api_docs_exposure",
                        "url": url_for(ctx.profile, "/graphql") + "?query=%7B__schema%7Btypes%7Bname%7D%7D%7D"},
                remediation="Disable introspection in production.")
            await self._graphql_schema(ctx)
        else:
            ctx.state.add_limitation(
                "GraphQL schema discovery for active injection testing was not possible: the endpoint at "
                "/graphql responded but introspection appears disabled (no '__schema' in the response). "
                "GraphQL query/mutation arguments could not be enumerated, so no GraphQL-specific SQL "
                "injection/SSRF testing was performed -- this is not evidence the underlying arguments "
                "are safe.")
        return AgentResult(summary=f"graphql: {cls.classification.value}")

    async def _graphql_schema(self, ctx: AgentContext) -> None:
        """Fetch the full introspection response (types/fields/args/inputFields,
        not just type names) and turn it into the bounded set of testable
        query-argument leaves `InjectionTestAgent` folds into its own
        `injection_surface` (see `core.graphql_schema.parse_introspection`).
        Degrades to an honest limitation -- never a crash, never a fabricated
        surface -- on any unreachable/unparsable/incomplete response."""
        res = await self._get(ctx, "/graphql", params={"query": _FULL_GRAPHQL_INTROSPECTION_QUERY})
        if not res.ok:
            ctx.state.add_limitation(
                f"Full GraphQL schema introspection failed ({res.error}); GraphQL arguments could not be "
                "enumerated for active injection testing.")
            return
        try:
            body = json.loads(res.data.get("body", "") or "")
        except (ValueError, TypeError):
            ctx.state.add_limitation(
                "The full GraphQL introspection response was not valid JSON; GraphQL arguments could not "
                "be enumerated for active injection testing.")
            return
        schema = (body.get("data") or {}).get("__schema") if isinstance(body, dict) else None
        if not isinstance(schema, dict):
            ctx.state.add_limitation(
                "The full GraphQL introspection response did not contain a usable '__schema'; GraphQL "
                "arguments could not be enumerated for active injection testing.")
            return
        if not isinstance(schema.get("types"), list):
            # A well-formed introspection response always has a `types` list
            # (even if the schema itself is tiny); its absence means the
            # response is incomplete/malformed, not merely a schema with no
            # testable fields -- record it honestly instead of silently
            # discovering nothing.
            ctx.state.add_limitation(
                "The full GraphQL introspection response was missing/incomplete '__schema.types' data; "
                "GraphQL arguments could not be enumerated for active injection testing.")
        parsed = parse_introspection(schema)
        operations = parsed["operations"]
        ctx.profile.attributes["graphql_operations"] = operations
        n_leaves = sum(len(op["testable_leaves"]) for op in operations)
        ctx.observe("api.graphql.schema", "GraphQL",
                    f"{len(operations)} GraphQL operation(s) with {n_leaves} testable scalar argument(s) "
                    f"discovered via introspection ({len(parsed['skipped'])} operation(s) skipped: an "
                    "argument type could not be safely defaulted).",
                    operations=[f"{op['operation_type']}.{op['field']}" for op in operations],
                    skipped=parsed["skipped"])
        if parsed["skipped"]:
            ctx.state.add_limitation(
                f"{len(parsed['skipped'])} GraphQL operation(s) were not added to active testing because "
                "at least one required argument's type could not be safely defaulted (a list, enum, or "
                f"unsupported/custom scalar): {', '.join(parsed['skipped'])}.")
