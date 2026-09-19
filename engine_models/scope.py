"""
engine_models/scope.py
----------------------
Universal scope boundaries for Raven adaptive security assessment.

Defines what assets, domains, paths, ports, cloud resources, and namespaces
are in-scope vs. excluded, and what categories of testing are permitted.
Works for all target types — not only URLs.
"""

from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field


class Scope(BaseModel):
    """
    Universal assessment scope definition.

    Every tool action is validated against this scope before execution.
    Different fields apply to different target types:
    - URL/web: allowed_domains, excluded_domains, allowed_paths, excluded_paths
    - Network: allowed_ips, excluded_ips, allowed_ports, excluded_ports
    - Repository: allowed_repositories, excluded_files
    - Cloud: allowed_cloud_accounts, allowed_cloud_regions, allowed_resources
    - Kubernetes: allowed_namespaces, excluded_namespaces
    """

    # Target-level scope
    allowed_targets: List[str] = Field(default_factory=list)
    excluded_targets: List[str] = Field(default_factory=list)

    # Domain scope (web, API)
    allowed_domains: List[str] = Field(default_factory=list)
    excluded_domains: List[str] = Field(default_factory=list)

    # Network scope
    allowed_ips: List[str] = Field(default_factory=list)
    excluded_ips: List[str] = Field(default_factory=list)
    allowed_ports: List[int] = Field(default_factory=list)
    excluded_ports: List[int] = Field(default_factory=list)

    # Path scope (web paths, file paths)
    allowed_paths: List[str] = Field(default_factory=list)
    excluded_paths: List[str] = Field(default_factory=list)

    # Repository scope
    allowed_repositories: List[str] = Field(default_factory=list)
    excluded_files: List[str] = Field(default_factory=list)

    # Cloud scope
    allowed_cloud_accounts: List[str] = Field(default_factory=list)
    allowed_cloud_regions: List[str] = Field(default_factory=list)
    allowed_resources: List[str] = Field(default_factory=list)

    # Kubernetes scope
    allowed_namespaces: List[str] = Field(default_factory=list)
    excluded_namespaces: List[str] = Field(default_factory=list)

    # Operational limits
    max_depth: int = 3
    max_requests: int = 500
    max_processes: int = 20

    # Assessment mode flags — default to safe passive-only mode
    allow_active_testing: bool = False
    allow_authenticated_testing: bool = False
    allow_destructive_testing: bool = False
    allow_external_interactions: bool = False

    def is_domain_allowed(self, domain: str) -> bool:
        """Check if a domain is within scope."""
        if domain in self.excluded_domains:
            return False
        if not self.allowed_domains:
            return True  # No domain restrictions configured
        return any(
            domain == allowed or domain.endswith("." + allowed)
            for allowed in self.allowed_domains
        )

    def is_ip_allowed(self, ip: str) -> bool:
        """Check if an IP address is within scope."""
        if ip in self.excluded_ips:
            return False
        if not self.allowed_ips:
            return True
        return ip in self.allowed_ips

    def is_port_allowed(self, port: int) -> bool:
        """Check if a port is within scope."""
        if port in self.excluded_ports:
            return False
        if not self.allowed_ports:
            return True
        return port in self.allowed_ports

    def is_path_allowed(self, path: str) -> bool:
        """Check if a file/URL path is within scope."""
        for excluded in self.excluded_paths:
            if path.startswith(excluded) or path == excluded:
                return False
        if not self.allowed_paths:
            return True
        return any(path.startswith(a) or path == a for a in self.allowed_paths)

    def is_file_allowed(self, filepath: str) -> bool:
        """Check if a file path is within scope for repository scanning."""
        for excluded in self.excluded_files:
            if filepath.endswith(excluded) or excluded in filepath:
                return False
        return True

    def is_namespace_allowed(self, namespace: str) -> bool:
        """Check if a Kubernetes namespace is within scope."""
        if namespace in self.excluded_namespaces:
            return False
        if not self.allowed_namespaces:
            return True
        return namespace in self.allowed_namespaces

    def is_impact_allowed(self, impact_level: str) -> bool:
        """
        Check if an action's impact level is permitted by scope.

        Impact levels (ascending severity):
            passive < low < moderate < high < destructive
        """
        if impact_level == "passive":
            return True
        if impact_level in ("low", "moderate"):
            return self.allow_active_testing
        if impact_level == "high":
            return self.allow_active_testing and self.allow_authenticated_testing
        if impact_level == "destructive":
            return self.allow_destructive_testing
        return False
