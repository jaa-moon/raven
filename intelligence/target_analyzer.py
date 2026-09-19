"""
intelligence/target_analyzer.py
-------------------------------
Answers "what exactly am I looking at?" and produces the TargetProfile.

All observation goes through the gateway (scope + budget apply); nothing here
decides what to *test*. Deeper discovery is done by agents, which update the
same profile and thereby trigger re-planning.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from core.models import ToolRequest, ToolResult
from core.state import AssessmentState
from core.target import InputKind, TargetInput
from intelligence.fingerprint import (canonical_technology, detect_web_technologies, frameworks_from_manifests,
                                      languages_from_extensions)
from intelligence.llm import LLM
from recovery.controller import RecoveryController

logger = logging.getLogger("raven.analyzer")


class TargetAnalyzer:
    def __init__(self, state: AssessmentState, recovery: RecoveryController, llm: Optional[LLM] = None) -> None:
        self.state = state
        self.recovery = recovery
        self.llm = llm or LLM(None)

    async def _call(self, capability: str, args: Dict[str, Any], purpose: str) -> ToolResult:
        return await self.recovery.execute(
            ToolRequest(capability=capability, arguments=args, purpose=purpose, agent="target_analyzer"))

    async def analyze(self, reachable_hint: bool = False) -> None:
        t = self.state.target
        assert t is not None, "state.target must be set by intake"
        p = self.state.profile
        p.target = t.normalized_target
        p.reachable = reachable_hint
        if t.input_type == InputKind.URL:
            await self._web(t.normalized_target)
        elif t.input_type in (InputKind.HOST, InputKind.IP):
            await self._host(t)
        elif t.input_type == InputKind.DIRECTORY:
            await self._directory(t)
        else:
            await self._file(t)
        await self._interpret_with_llm()

    # -- web ------------------------------------------------------------------------

    async def _web(self, url: str) -> None:
        p = self.state.profile
        parsed = urlparse(url)
        p.target_type = "web_application"
        p.add_surface("http")
        p.add_surface("web_application")
        p.attributes.update({"base_url": f"{parsed.scheme}://{parsed.netloc}", "entry_url": url,
                             "host": parsed.hostname, "port": parsed.port})
        res = await self._call("http_request", {"url": url}, "Fingerprint the web target")
        if not res.ok:
            p.reachable = False
            self.state.add_limitation(f"Target could not be reached during analysis: {res.error}")
            return
        d = res.data
        p.reachable = True
        for tech in detect_web_technologies(d["headers"], d["body"], d.get("set_cookies", [])):
            p.add_technology(tech)
        p.attributes.update({"server": d["headers"].get("server", ""), "root_status": d["status_code"],
                             "root_content_type": d["content_type"]})
        if "www-authenticate" in d["headers"]:
            p.authentication = True
        if "json" in d["content_type"].lower():
            p.api = True
            p.add_surface("rest_api")
        p.attributes["root_excerpt"] = d["body"][:1500]
        self.state.observations.append(self._obs("http.fingerprint", "HTTP",
            f"HTTP {d['status_code']} {d['content_type'] or 'no content-type'}; technologies: "
            f"{', '.join(p.technologies) or 'none identified'}."))

    # -- host / network -------------------------------------------------------------

    async def _host(self, t: TargetInput) -> None:
        p = self.state.profile
        p.attributes.update({"host": t.host, "port": t.port})
        if t.port:  # a specific port: does it speak HTTP?
            for scheme in ("http", "https"):
                res = await self._call("http_request", {"url": f"{scheme}://{t.host}:{t.port}/"},
                                       f"Check whether {t.host}:{t.port} speaks HTTP")
                if res.ok:
                    self.state.target = t.model_copy(update={"scheme": scheme})
                    await self._web(f"{scheme}://{t.host}:{t.port}")
                    return
        p.target_type = "network_service" if t.port else "host"
        p.add_surface("network")
        if t.port:
            p.add_service({"port": t.port, "protocol": None})
            p.add_surface(f"tcp:{t.port}")

    # -- source / file --------------------------------------------------------------

    async def _directory(self, t: TargetInput) -> None:
        p = self.state.profile
        res = await self._call("repository_inventory", {"path": t.path}, "Inventory the source tree")
        p.target_type = "source_repository"
        p.attributes["root"] = t.path
        p.reachable = True
        if not res.ok:
            self.state.add_limitation(f"Source tree could not be inventoried: {res.error}")
            return
        d = res.data
        p.source_available = d["file_count"] > 0
        p.add_surface("source_code")
        for lang in languages_from_extensions(d["extensions"]):
            p.languages.append(lang)
        for fw in frameworks_from_manifests(d["dependencies"]):
            p.add_technology(fw)
        for lang in p.languages[:2]:
            p.add_technology(lang)
        p.attributes.update({"manifests": d["manifests"], "config_files": d["config_files"],
                             "dockerfiles": d["dockerfiles"], "file_count": d["file_count"]})
        if d["manifests"]:
            p.add_surface("dependencies")
        if d["config_files"]:
            p.add_surface("configuration")
        if d["dockerfiles"]:
            p.add_technology("Docker")
        self.state.observations.append(self._obs("repo.inventory", "Source code",
            f"{d['file_count']} file(s); languages: {', '.join(p.languages) or 'none'}; "
            f"manifests: {d['manifests'] or 'none'}."))

    async def _file(self, t: TargetInput) -> None:
        p = self.state.profile
        res = await self._call("file_classification", {"path": t.path}, "Classify the target file")
        p.reachable = True
        p.attributes["root"] = t.path
        if res.ok and res.data.get("is_binary"):
            p.target_type = "binary"
            p.add_surface("binary")
            p.attributes["format"] = res.data.get("format")
        else:
            p.target_type = "file"
            p.add_surface("file")

    # -- optional LLM interpretation ---------------------------------------------------

    async def _interpret_with_llm(self) -> None:
        p = self.state.profile
        excerpt = str(p.attributes.get("root_excerpt", ""))
        if not self.llm.available or not excerpt:
            return
        data = await self.llm.ask_json(
            "You identify web technologies from an HTTP response excerpt.",
            f"Headers/server: {p.attributes.get('server', '')}\nKnown: {p.technologies}\nBody excerpt:\n{excerpt}\n"
            'Return {"technologies": ["short names"]} listing only technologies clearly evidenced.')
        for tech in (data or {}).get("technologies", [])[:8]:
            canon = canonical_technology(tech) if isinstance(tech, str) else ""
            if canon:                       # free-text LLM output never enters the profile
                p.add_technology(canon)

    @staticmethod
    def _obs(kind: str, surface: str, summary: str):
        from core.models import Observation
        return Observation(kind=kind, surface=surface, summary=summary, source_task="analysis")
