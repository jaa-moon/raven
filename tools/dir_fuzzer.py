"""
tools/dir_fuzzer.py
-------------------
Asynchronous endpoint discovery and path fuzzing engine.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import List, Optional, Tuple
import httpx

from web.spa_fallback_detector import _normalize_body, _similarity_ratio, DEFAULT_SIMILARITY_THRESHOLD

_DEFAULT_WORDLIST = [
    "admin", "login", "api", "v1", "v2", "swagger", "docs", "health",
    "status", "user", "users", "dashboard", "config", "env", "git",
    "secret", "secrets", "debug", "console", "actuator", "metrics"
]


class DirFuzzer:
    """
    Fuzzes target sandbox web server to uncover hidden routes and endpoints.

    A response is only reported as "discovered" if it is not merely the
    same SPA-fallback shell the server returns for a guaranteed nonexistent
    path — status code alone (``status != 404``) is not sufficient evidence
    of a real route on an application with client-side (history-mode)
    routing.
    """

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")

    async def fuzz(self, wordlist: List[str] | None = None) -> List[Tuple[str, int]]:
        """
        Fuzz paths concurrently and return list of (discovered_path, http_status),
        excluding responses that match the SPA-fallback baseline.
        """
        paths_to_test = wordlist or _DEFAULT_WORDLIST
        discovered: List[Tuple[str, int]] = []

        async with httpx.AsyncClient(timeout=2.0, follow_redirects=False) as client:
            baseline = await self._establish_baseline(client)

            tasks = [self._check_path(client, path) for path in paths_to_test]
            results = await asyncio.gather(*tasks)

            for path, status, content_type, body in results:
                if status <= 0 or status == 404:
                    continue
                if baseline is not None and self._is_spa_fallback(status, content_type, body, baseline):
                    continue
                discovered.append((f"/{path}", status))

        return discovered

    async def _establish_baseline(self, client: httpx.AsyncClient) -> Optional[dict]:
        probe_path = f"raven-nonexistent-{uuid.uuid4().hex[:12]}"
        try:
            resp = await client.get(f"{self.base_url}/{probe_path}")
        except Exception:
            return None
        return {
            "status": resp.status_code,
            "content_type": resp.headers.get("content-type", ""),
            "normalized_body": _normalize_body(resp.text or ""),
        }

    @staticmethod
    def _is_spa_fallback(status: int, content_type: str, body: str, baseline: dict) -> bool:
        if status != baseline["status"]:
            return False
        if content_type != baseline["content_type"]:
            return False
        normalized = _normalize_body(body or "")
        similarity = _similarity_ratio(baseline["normalized_body"], normalized)
        return similarity >= DEFAULT_SIMILARITY_THRESHOLD

    async def _check_path(self, client: httpx.AsyncClient, path: str) -> Tuple[str, int, str, str]:
        url = f"{self.base_url}/{path.lstrip('/')}"
        try:
            resp = await client.get(url)
            return path, resp.status_code, resp.headers.get("content-type", ""), resp.text
        except Exception:
            return path, 0, "", ""


# ── Module-level wrapper for MCP gateway dispatch ────────────────────────────

async def fuzz(base_url: str, wordlist: list | None = None) -> list:
    """Gateway-callable wrapper for DirFuzzer.fuzz()."""
    fuzzer = DirFuzzer(base_url)
    return await fuzzer.fuzz(wordlist)

