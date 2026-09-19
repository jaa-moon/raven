"""
tools/http_prober.py
--------------------
Asynchronous HTTP payload probe engine for active web vulnerability testing.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional
import httpx


class HttpProber:
    """
    Sends customized HTTP payloads against targeted endpoints in the sandbox.
    """

    def __init__(self, base_url: str, timeout: float = 5.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    async def probe(
        self,
        endpoint: str,
        method: str = "GET",
        params: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        use_form: bool = False
    ) -> Dict[str, Any]:
        """
        Execute an HTTP probe request and return response metrics and body evidence.
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        method = method.upper()

        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
            try:
                start = time.monotonic()

                if method == "GET":
                    resp = await client.get(url, params=params, headers=headers)
                elif method == "POST":
                    if use_form and data:
                        resp = await client.post(url, params=params, data=data, headers=headers)
                    elif data:
                        resp = await client.post(url, params=params, json=data, headers=headers)
                    else:
                        resp = await client.post(url, params=params, headers=headers)
                elif method == "PUT":
                    if data:
                        resp = await client.put(url, params=params, json=data, headers=headers)
                    else:
                        resp = await client.put(url, params=params, headers=headers)
                elif method == "DELETE":
                    resp = await client.delete(url, params=params, headers=headers)
                else:
                    resp = await client.request(method, url, params=params, headers=headers)

                elapsed = (time.monotonic() - start) * 1000

                return {
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "body": resp.text[:3000],
                    "url": str(resp.url),
                    "elapsed_ms": round(elapsed, 2),
                    "error": None
                }
            except Exception as e:
                return {
                    "status_code": 0,
                    "headers": {},
                    "body": "",
                    "url": url,
                    "elapsed_ms": 0.0,
                    "error": str(e)
                }

    async def probe_batch(
        self,
        endpoint: str,
        payloads: List[str],
        param_name: str = "q",
        method: str = "GET"
    ) -> List[Dict[str, Any]]:
        """Probe an endpoint with multiple payloads and return all results."""
        results = []
        for payload in payloads:
            if method.upper() == "GET":
                res = await self.probe(endpoint, method="GET", params={param_name: payload})
            else:
                res = await self.probe(endpoint, method="POST", data={param_name: payload}, use_form=True)
            res["payload"] = payload
            res["param_name"] = param_name
            results.append(res)
        return results


# ── Module-level wrappers for MCP gateway dispatch ───────────────────────────
# These thin functions instantiate HttpProber and delegate to its methods.
# The gateway calls these by name; the existing class is untouched.

async def probe(
    base_url: str,
    endpoint: str,
    method: str = "GET",
    params: dict | None = None,
    data: dict | None = None,
    headers: dict | None = None,
    use_form: bool = False,
) -> dict:
    """Gateway-callable wrapper for HttpProber.probe()."""
    prober = HttpProber(base_url)
    return await prober.probe(endpoint, method, params, data, headers, use_form)


async def probe_batch(
    base_url: str,
    endpoint: str,
    payloads: list,
    param_name: str = "q",
    method: str = "GET",
) -> list:
    """Gateway-callable wrapper for HttpProber.probe_batch()."""
    prober = HttpProber(base_url)
    return await prober.probe_batch(endpoint, payloads, param_name, method)

