"""
tools/dir_fuzzer.py
-------------------
Asynchronous endpoint discovery and path fuzzing engine.
"""

from __future__ import annotations

import asyncio
from typing import List, Tuple
import httpx

_DEFAULT_WORDLIST = [
    "admin", "login", "api", "v1", "v2", "swagger", "docs", "health",
    "status", "user", "users", "dashboard", "config", "env", "git",
    "secret", "secrets", "debug", "console", "actuator", "metrics"
]


class DirFuzzer:
    """
    Fuzzes target sandbox web server to uncover hidden routes and endpoints.
    """

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")

    async def fuzz(self, wordlist: List[str] | None = None) -> List[Tuple[str, int]]:
        """
        Fuzz paths concurrently and return list of (discovered_path, http_status).
        """
        paths_to_test = wordlist or _DEFAULT_WORDLIST
        discovered: List[Tuple[str, int]] = []

        async with httpx.AsyncClient(timeout=2.0, follow_redirects=False) as client:
            tasks = [self._check_path(client, path) for path in paths_to_test]
            results = await asyncio.gather(*tasks)

            for path, status in results:
                if status > 0 and status != 404:
                    discovered.append((f"/{path}", status))

        return discovered

    async def _check_path(self, client: httpx.AsyncClient, path: str) -> Tuple[str, int]:
        url = f"{self.base_url}/{path.lstrip('/')}"
        try:
            resp = await client.get(url)
            return path, resp.status_code
        except Exception:
            return path, 0
