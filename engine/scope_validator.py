"""
engine/scope_validator.py
-------------------------
Universal scope validation engine for Raven adaptive security assessment.

Intercepts every AgentAction before tool execution to verify that:
1. Target and action parameters fall strictly within authorized scope boundaries
2. Operational and impact levels (passive, low, moderate, high, destructive) are permitted
3. Out-of-scope targets (domains, IPs, ports, paths, files, cloud resources) are blocked
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

from engine_models.actions import AgentAction
from engine_models.scope import Scope


@dataclass
class ScopeCheckResult:
    """Outcome of a scope check on an action or target."""

    allowed: bool
    reason: str
    action_id: Optional[str] = None
    violation_type: Optional[str] = None  # e.g., "impact_level", "domain", "ip", "port", "path", "file"

    def __bool__(self) -> bool:
        return self.allowed


class ScopeValidator:
    """
    Validates agent actions and assessment targets against defined Scope boundaries.
    Ensures safe, bounded autonomous operations.
    """

    def __init__(self, scope: Optional[Scope] = None) -> None:
        self.scope: Scope = scope or Scope()

    def validate_action(self, action: AgentAction) -> ScopeCheckResult:
        """
        Comprehensive pre-execution gate for an AgentAction.
        Inspects impact level, target string, operation parameters, and resource targets.
        """
        action_id = action.action_id

        # 1. Structural check
        if not action.is_valid():
            return ScopeCheckResult(
                allowed=False,
                reason=f"Action '{action_id}' is malformed: missing tool_name, purpose, or target.",
                action_id=action_id,
                violation_type="malformed_action",
            )

        # 2. Impact level check
        if not self.scope.is_impact_allowed(action.impact_level):
            return ScopeCheckResult(
                allowed=False,
                reason=(
                    f"Action impact '{action.impact_level}' exceeds permitted testing boundaries "
                    f"(active={self.scope.allow_active_testing}, "
                    f"auth={self.scope.allow_authenticated_testing}, "
                    f"destructive={self.scope.allow_destructive_testing})."
                ),
                action_id=action_id,
                violation_type="impact_level",
            )

        # 3. Validate target field
        target_str = action.target.strip()
        target_check = self.check_target_string(target_str)
        if not target_check.allowed:
            target_check.action_id = action_id
            return target_check

        # 4. Deep parameter validation for common target vectors
        params = action.parameters or {}

        # URL parameter checks
        for key in ("url", "target_url", "base_url", "endpoint"):
            if key in params and isinstance(params[key], str):
                url_check = self.validate_url(params[key])
                if not url_check.allowed:
                    url_check.action_id = action_id
                    return url_check

        # IP/Host parameter checks
        for key in ("ip", "host", "target_ip", "address"):
            if key in params and isinstance(params[key], str):
                host_val = params[key]
                if self._looks_like_ip(host_val):
                    ip_check = self.validate_ip(host_val)
                    if not ip_check.allowed:
                        ip_check.action_id = action_id
                        return ip_check
                elif self._looks_like_domain(host_val):
                    dom_check = self.validate_domain(host_val)
                    if not dom_check.allowed:
                        dom_check.action_id = action_id
                        return dom_check

        # Port parameter checks
        for key in ("port", "target_port"):
            if key in params:
                try:
                    port_num = int(params[key])
                    port_check = self.validate_port(port_num)
                    if not port_check.allowed:
                        port_check.action_id = action_id
                        return port_check
                except (ValueError, TypeError):
                    pass

        # File path parameter checks
        for key in ("file_path", "filepath", "path", "file"):
            if key in params and isinstance(params[key], str):
                val = params[key]
                # If it looks like a local file path
                if "/" in val or "\\" in val or os.path.exists(val):
                    file_check = self.validate_file_path(val)
                    if not file_check.allowed:
                        file_check.action_id = action_id
                        return file_check

        # 5. External interaction gate
        if not self.scope.allow_external_interactions:
            # Check if target refers to an external unexpected network call
            if self._is_external_target(target_str):
                return ScopeCheckResult(
                    allowed=False,
                    reason=f"External interactions are prohibited by scope: {target_str}",
                    action_id=action_id,
                    violation_type="external_interactions",
                )

        return ScopeCheckResult(
            allowed=True,
            reason="Action permitted within scope.",
            action_id=action_id,
        )

    def check_target_string(self, target: str) -> ScopeCheckResult:
        """Inspect a general target string (could be URL, IP, domain, path, etc.)."""
        target = target.strip()

        # Check explicit allowed/excluded targets list
        if target in self.scope.excluded_targets:
            return ScopeCheckResult(
                allowed=False,
                reason=f"Target '{target}' is explicitly listed in excluded_targets.",
                violation_type="target",
            )

        if self.scope.allowed_targets and target not in self.scope.allowed_targets:
            # If target does not directly match, check if it is part of allowed items
            matched = False
            for allowed in self.scope.allowed_targets:
                if target.startswith(allowed) or allowed.startswith(target):
                    matched = True
                    break
            if not matched and not self._is_url_or_ip(target):
                return ScopeCheckResult(
                    allowed=False,
                    reason=f"Target '{target}' is not in allowed_targets.",
                    violation_type="target",
                )

        # URL check
        if target.startswith("http://") or target.startswith("https://"):
            return self.validate_url(target)

        # IP check (e.g., 192.168.1.1 or 192.168.1.1:8080)
        clean_ip = target.split(":")[0] if ":" in target and not target.startswith("[") else target
        if self._looks_like_ip(clean_ip):
            ip_res = self.validate_ip(clean_ip)
            if not ip_res.allowed:
                return ip_res
            if ":" in target:
                try:
                    port_val = int(target.split(":")[1])
                    return self.validate_port(port_val)
                except ValueError:
                    pass
            return ip_res

        # Domain check
        if self._looks_like_domain(target):
            clean_dom = target.split(":")[0]
            dom_res = self.validate_domain(clean_dom)
            if not dom_res.allowed:
                return dom_res
            if ":" in target:
                try:
                    port_val = int(target.split(":")[1])
                    return self.validate_port(port_val)
                except ValueError:
                    pass
            return dom_res

        # Path / File check
        if "/" in target or "\\" in target or os.path.exists(target):
            return self.validate_file_path(target)

        # Default allow if no specific violation discovered
        return ScopeCheckResult(allowed=True, reason="Target passed general scope validation.")

    def validate_url(self, url: str) -> ScopeCheckResult:
        """Validate a full URL against domain and path scope boundaries."""
        try:
            parsed = urlparse(url)
        except Exception as e:
            return ScopeCheckResult(
                allowed=False,
                reason=f"Failed to parse URL '{url}': {e}",
                violation_type="malformed_url",
            )

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return ScopeCheckResult(
                allowed=False,
                reason=f"URL '{url}' lacks a valid hostname.",
                violation_type="domain",
            )

        # Domain check
        domain_check = self.validate_domain(hostname)
        if not domain_check.allowed:
            return domain_check

        # Port check if specified
        if parsed.port:
            port_check = self.validate_port(parsed.port)
            if not port_check.allowed:
                return port_check

        # Path check
        if parsed.path:
            path_check = self.validate_url_path(parsed.path)
            if not path_check.allowed:
                return path_check

        return ScopeCheckResult(allowed=True, reason=f"URL '{url}' is within scope.")

    def validate_domain(self, domain: str) -> ScopeCheckResult:
        """Validate domain name against allowed and excluded domains."""
        domain = domain.lower().strip()

        if not self.scope.is_domain_allowed(domain):
            return ScopeCheckResult(
                allowed=False,
                reason=f"Domain '{domain}' is excluded or not in allowed_domains scope.",
                violation_type="domain",
            )

        return ScopeCheckResult(allowed=True, reason=f"Domain '{domain}' is allowed.")

    def validate_ip(self, ip_str: str) -> ScopeCheckResult:
        """
        Validate IP address against allowed and excluded IPs or CIDR blocks.
        """
        ip_str = ip_str.strip()
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return ScopeCheckResult(
                allowed=False,
                reason=f"'{ip_str}' is not a valid IP address.",
                violation_type="ip",
            )

        # Check excluded IPs/subnets
        for exc in self.scope.excluded_ips:
            try:
                if "/" in exc:
                    if ip_obj in ipaddress.ip_network(exc, strict=False):
                        return ScopeCheckResult(
                            allowed=False,
                            reason=f"IP '{ip_str}' belongs to excluded subnet '{exc}'.",
                            violation_type="ip",
                        )
                else:
                    if ip_obj == ipaddress.ip_address(exc):
                        return ScopeCheckResult(
                            allowed=False,
                            reason=f"IP '{ip_str}' is explicitly excluded.",
                            violation_type="ip",
                        )
            except ValueError:
                continue

        # Check allowed IPs/subnets
        if self.scope.allowed_ips:
            allowed = False
            for allowable in self.scope.allowed_ips:
                try:
                    if "/" in allowable:
                        if ip_obj in ipaddress.ip_network(allowable, strict=False):
                            allowed = True
                            break
                    else:
                        if ip_obj == ipaddress.ip_address(allowable):
                            allowed = True
                            break
                except ValueError:
                    continue

            if not allowed:
                return ScopeCheckResult(
                    allowed=False,
                    reason=f"IP '{ip_str}' is not within any allowed_ips or subnets.",
                    violation_type="ip",
                )

        return ScopeCheckResult(allowed=True, reason=f"IP '{ip_str}' is allowed.")

    def validate_port(self, port: int) -> ScopeCheckResult:
        """Validate port against allowed and excluded ports."""
        if not self.scope.is_port_allowed(port):
            return ScopeCheckResult(
                allowed=False,
                reason=f"Port {port} is excluded or not permitted in scope.",
                violation_type="port",
            )
        return ScopeCheckResult(allowed=True, reason=f"Port {port} is permitted.")

    def validate_url_path(self, path: str) -> ScopeCheckResult:
        """Validate URL endpoint path."""
        if not self.scope.is_path_allowed(path):
            return ScopeCheckResult(
                allowed=False,
                reason=f"Path '{path}' is excluded or outside allowed paths.",
                violation_type="path",
            )
        return ScopeCheckResult(allowed=True, reason=f"Path '{path}' is allowed.")

    def validate_file_path(self, file_path: str) -> ScopeCheckResult:
        """Validate repository file path against scope."""
        norm_path = os.path.normpath(file_path).replace("\\", "/")

        if not self.scope.is_file_allowed(norm_path):
            return ScopeCheckResult(
                allowed=False,
                reason=f"File path '{file_path}' matches excluded files patterns.",
                violation_type="file",
            )

        if not self.scope.is_path_allowed(norm_path):
            return ScopeCheckResult(
                allowed=False,
                reason=f"File path '{file_path}' is outside allowed paths.",
                violation_type="path",
            )

        return ScopeCheckResult(allowed=True, reason=f"File path '{file_path}' is allowed.")

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def _looks_like_ip(self, val: str) -> bool:
        try:
            ipaddress.ip_address(val)
            return True
        except ValueError:
            return False

    def _looks_like_domain(self, val: str) -> bool:
        # Simple domain regex: e.g. example.com, api.internal.local
        return bool(re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$", val))

    def _is_url_or_ip(self, val: str) -> bool:
        return val.startswith("http://") or val.startswith("https://") or self._looks_like_ip(val) or self._looks_like_domain(val)

    def _is_external_target(self, target: str) -> bool:
        """Heuristic check for external addresses (non-localhost, non-private IP)."""
        if "localhost" in target or "127.0.0.1" in target or "::1" in target:
            return False
        # If target has an IP, check if it is private
        clean = target.split(":")[0].replace("http://", "").replace("https://", "").split("/")[0]
        try:
            ip = ipaddress.ip_address(clean)
            return not ip.is_private and not ip.is_loopback
        except ValueError:
            pass
        return False
