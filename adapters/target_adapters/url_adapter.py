"""
adapters/target_adapters/url_adapter.py
---------------------------------------
Target adapter for Web applications and REST/GraphQL APIs.
"""

from __future__ import annotations

from urllib.parse import urlparse

from engine_models.target import Target, TargetType


class UrlTargetAdapter:
    """Adapts HTTP/HTTPS URLs into Target models."""

    @classmethod
    def can_handle(cls, raw_input: str) -> bool:
        return raw_input.startswith("http://") or raw_input.startswith("https://")

    @classmethod
    def adapt(cls, raw_input: str) -> Target:
        raw_input = raw_input.strip()
        parsed = urlparse(raw_input)
        path = parsed.path.lower()

        if any(p in path for p in ("/api", "/v1", "/v2", "/v3", "/rest")):
            target_type = TargetType.REST_API
        elif "graphql" in path:
            target_type = TargetType.GRAPHQL_API
        else:
            target_type = TargetType.WEB_APPLICATION

        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        return Target(
            raw_input=raw_input,
            target_type=target_type,
            entrypoints=[raw_input],
            metadata={
                "scheme": parsed.scheme,
                "host": parsed.hostname,
                "port": port,
                "path": parsed.path or "/",
            },
        )
