"""
core/profile.py
---------------
TargetProfile: the structured answer to "what exactly am I looking at?".

The schema is deliberately open: well-known fields for the common cases plus
free-form ``attributes`` so new analyzers/agents can record facts without a
core change.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class TargetProfile(BaseModel):
    target: str = ""
    # web_application | network_service | source_repository | binary | host | file | unknown
    target_type: str = "unknown"
    reachable: bool = False
    # http, web_application, rest_api, graphql, tcp:22, source_code ...
    surfaces: List[str] = Field(default_factory=list)
    technologies: List[str] = Field(default_factory=list)
    languages: List[str] = Field(default_factory=list)
    authentication: Optional[bool] = None  # None = unknown
    api: bool = False
    source_available: bool = False
    services: List[Dict[str, Any]] = Field(default_factory=list)  # {"port":22,"protocol":"ssh"}
    endpoints: List[str] = Field(default_factory=list)
    attributes: Dict[str, Any] = Field(default_factory=dict)

    def add_surface(self, surface: str) -> bool:
        if surface and surface not in self.surfaces:
            self.surfaces.append(surface)
            return True
        return False

    def add_technology(self, tech: str) -> bool:
        if tech and tech.lower() not in {t.lower() for t in self.technologies}:
            self.technologies.append(tech)
            return True
        return False

    def add_endpoint(self, endpoint: str) -> bool:
        if endpoint and endpoint not in self.endpoints:
            self.endpoints.append(endpoint)
            return True
        return False

    def add_service(self, service: Dict[str, Any]) -> bool:
        key = (service.get("port"), service.get("protocol"))
        if any((s.get("port"), s.get("protocol")) == key for s in self.services):
            return False
        self.services.append(service)
        return True

    def has_surface(self, surface: str) -> bool:
        return surface in self.surfaces

    def signature(self) -> str:
        """Cheap change detector: differs whenever new knowledge was added."""
        ports = sorted(str(s.get("port")) for s in self.services)
        injection_surface = self.attributes.get("injection_surface") or {}
        return "|".join([
            self.target_type,
            ",".join(sorted(self.surfaces)),
            ",".join(sorted(t.lower() for t in self.technologies)),
            ",".join(sorted(self.endpoints)),
            ",".join(ports),
            str(self.authentication),
            str(self.api),
            str(sum(len(v.get("params", [])) for v in injection_surface.values())),
        ])
