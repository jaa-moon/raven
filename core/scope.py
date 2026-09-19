"""
core/scope.py
-------------
Authorization boundary. Scope is *derived from the target*: anything the user
did not point Raven at is out of scope unless explicitly added. Nothing in
here depends on an LLM.
"""

from __future__ import annotations

import fnmatch
import ipaddress
from pathlib import Path
from typing import Dict, Iterable, List, Tuple
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from core.target import InputKind, TargetInput

RISK_ORDER: Dict[str, int] = {"passive": 0, "low": 1, "moderate": 2, "high": 3}
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}


class ScopeDecision(BaseModel):
    allowed: bool
    reason: str = ""
    kind: str = ""  # risk | host | port | path | ""


def _canon_host(host: str) -> str:
    h = (host or "").strip().lower().strip("[]")
    return "localhost" if h in _LOOPBACK else h


class Scope(BaseModel):
    """What Raven may touch, and how hard."""

    allowed_hosts: List[str] = Field(default_factory=list)      # exact, "*.example.com", or CIDR
    allowed_ports: List[int] = Field(default_factory=list)      # empty = any port on an allowed host
    allowed_paths: List[str] = Field(default_factory=list)      # filesystem roots
    excluded_url_patterns: List[str] = Field(default_factory=list)  # fnmatch on URL path
    max_risk: str = "low"                                       # passive | low | moderate | high

    @classmethod
    def from_target(cls, target: TargetInput, max_risk: str = "low") -> "Scope":
        if target.input_type in (InputKind.DIRECTORY, InputKind.FILE):
            root = target.path or ""
            return cls(allowed_paths=[root if target.input_type == InputKind.DIRECTORY
                                      else str(Path(root).parent)], max_risk=max_risk)
        ports = [target.port] if target.port else []
        return cls(allowed_hosts=[_canon_host(target.host or "")], allowed_ports=ports, max_risk=max_risk)

    def extended(self, hosts: Iterable[str] = (), paths: Iterable[str] = ()) -> "Scope":
        s = self.model_copy(deep=True)
        s.allowed_hosts += [_canon_host(h) for h in hosts]
        s.allowed_paths += list(paths)
        return s


class ScopeValidator:
    """Deterministic gate consulted by the gateway before every tool execution."""

    def __init__(self, scope: Scope) -> None:
        self.scope = scope

    # -- public -----------------------------------------------------------------

    def check(self, targets: List[Tuple[str, str]], risk: str) -> ScopeDecision:
        """targets: [(kind, value)] with kind in url|host|port|path."""
        if RISK_ORDER.get(risk, 99) > RISK_ORDER.get(self.scope.max_risk, 0):
            return ScopeDecision(
                allowed=False, kind="risk",
                reason=f"Risk level '{risk}' exceeds permitted maximum '{self.scope.max_risk}'.",
            )
        for kind, value in targets:
            if kind == "url":
                d = self._check_url(value)
            elif kind == "host":
                d = self._check_host(value)
            elif kind == "port":
                d = self._check_port(value)
            elif kind == "path":
                d = self._check_path(value)
            else:
                d = ScopeDecision(allowed=True)
            if not d.allowed:
                return d
        return ScopeDecision(allowed=True, reason="within scope")

    # -- internals --------------------------------------------------------------

    def _check_url(self, url: str) -> ScopeDecision:
        p = urlparse(str(url))
        if p.scheme not in ("http", "https") or not p.hostname:
            return ScopeDecision(allowed=False, kind="host", reason=f"Not an http(s) URL: {url}")
        d = self._check_host(p.hostname)
        if not d.allowed:
            return d
        port = p.port or (443 if p.scheme == "https" else 80)
        d = self._check_port(port)
        if not d.allowed:
            return d
        for pat in self.scope.excluded_url_patterns:
            if fnmatch.fnmatch(p.path or "/", pat):
                return ScopeDecision(allowed=False, kind="path", reason=f"URL path excluded by scope: {p.path}")
        return ScopeDecision(allowed=True)

    def _check_host(self, host: str) -> ScopeDecision:
        h = _canon_host(host)
        if not self.scope.allowed_hosts:
            return ScopeDecision(allowed=False, kind="host", reason="No hosts are in scope.")
        for allowed in self.scope.allowed_hosts:
            if self._host_matches(h, allowed):
                return ScopeDecision(allowed=True)
        return ScopeDecision(allowed=False, kind="host", reason=f"Host '{host}' is not in scope.")

    @staticmethod
    def _host_matches(host: str, allowed: str) -> bool:
        a = _canon_host(allowed)
        if host == a:
            return True
        if a.startswith("*."):
            return host.endswith(a[1:])
        try:
            net = ipaddress.ip_network(a, strict=False)
            return ipaddress.ip_address(host) in net
        except ValueError:
            return False

    def _check_port(self, port) -> ScopeDecision:
        try:
            n = int(port)
        except (TypeError, ValueError):
            return ScopeDecision(allowed=False, kind="port", reason=f"Invalid port: {port!r}")
        if self.scope.allowed_ports and n not in self.scope.allowed_ports:
            return ScopeDecision(allowed=False, kind="port", reason=f"Port {n} is not in scope.")
        return ScopeDecision(allowed=True)

    def _check_path(self, path: str) -> ScopeDecision:
        if not self.scope.allowed_paths:
            return ScopeDecision(allowed=False, kind="path", reason="No filesystem paths are in scope.")
        try:
            resolved = Path(path).resolve()
        except OSError:
            return ScopeDecision(allowed=False, kind="path", reason=f"Unresolvable path: {path}")
        for root in self.scope.allowed_paths:
            try:
                resolved.relative_to(Path(root).resolve())
                return ScopeDecision(allowed=True)
            except ValueError:
                continue
        return ScopeDecision(allowed=False, kind="path", reason=f"Path '{path}' is outside the permitted roots.")
