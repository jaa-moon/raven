"""
tools/http_client.py
--------------------
The single HTTP primitive. Agents obtain HTTP through the `http_request`
capability; validation re-uses it to independently reproduce observations.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

import httpx

from raven_mcp.models import ToolError

MAX_BODY_CHARS = 3_000_000


async def request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    data: Optional[Dict[str, Any]] = None,
    follow_redirects: bool = False,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    hdrs = {"User-Agent": "Raven/3 (authorized security assessment)"}
    hdrs.update(headers or {})
    started = time.monotonic()
    try:
        async with httpx.AsyncClient(
            verify=False, timeout=timeout, follow_redirects=follow_redirects
        ) as client:
            resp = await client.request(
                method.upper(), url, headers=hdrs, params=params, data=data)
    except (httpx.ConnectError, httpx.ConnectTimeout) as e:
        raise ToolError("target_unreachable", f"Could not connect to {url}: {e}") from e
    except httpx.TimeoutException as e:
        raise ToolError("timeout", f"Request to {url} timed out: {e}") from e
    except httpx.InvalidURL as e:
        raise ToolError("invalid_args", f"Invalid URL {url!r}: {e}") from e
    except httpx.HTTPError as e:
        raise ToolError("error", f"HTTP error for {url}: {e}") from e

    if resp.status_code == 429:
        raise ToolError("rate_limited", f"HTTP 429 from {url}")

    lowered: Dict[str, str] = {}
    for k in resp.headers.keys():
        lowered[k.lower()] = ", ".join(resp.headers.get_list(k))
    text = resp.text or ""
    return {
        "url": str(resp.url),
        "status_code": resp.status_code,
        "headers": lowered,
        "set_cookies": resp.headers.get_list("set-cookie"),
        "content_type": lowered.get("content-type", ""),
        "location": lowered.get("location", ""),
        "body": text[:MAX_BODY_CHARS],
        "body_truncated": len(text) > MAX_BODY_CHARS,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
    }
