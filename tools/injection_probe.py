"""
tools/injection_probe.py
-------------------------
Controlled, non-destructive HTTP-level probes for active injection testing.

Each function performs one bounded round of requests through httpx (the same
primitive `tools/http_client.py` uses elsewhere in Raven) and returns raw,
uninterpreted observations. Interpretation happens two places, independently:

    agents/injection.py            -- "is this worth raising as a candidate?"
    validation/checks_injection.py -- "does this re-reproduce under a fresh test?"

Nothing here reaches for `requests`/`subprocess`/`socket` outside of this
module's own httpx client and its own loopback canary listener; it is only
reachable through the Gateway-registered `injection.*` capabilities, same as
every other tool.

Payloads are deliberately non-destructive:
  * SQL:  a bare quote + two boolean (read-only) conditions. No UNION/stacked
          queries, no writes.
  * XSS:  a single reflected marker per test, not persisted anywhere.
  * SSRF: a URL pointing at a Raven-owned loopback canary, never at an
          arbitrary external host.
"""

from __future__ import annotations

import asyncio
import re
import secrets
import time
from typing import Any, Dict, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from raven_mcp.models import ToolError

# ── SQL injection ────────────────────────────────────────────────────────────

_SQLI_ERROR_RE = re.compile(
    r"sql syntax|unclosed quotation mark|quoted string not properly terminated|"
    r"pg_query\(\)|sqlite3\.OperationalError|ORA-\d{5}|SQLSTATE\[|"
    r"microsoft ole db provider|warning: mysqli|mysql_fetch|SQL command not properly ended",
    re.I,
)

BASELINE_VALUE = "raven1"
SQL_PAYLOADS = {
    "quote": BASELINE_VALUE + "'",
    "true": BASELINE_VALUE + "' OR '1'='1' -- ",
    "false": BASELINE_VALUE + "' AND '1'='2' -- ",
}

# ── XSS ──────────────────────────────────────────────────────────────────────

_XSS_MARKER_FMT = "ravenxss{}"
_XSS_PAYLOAD_FMT = "\"'><ravenxss{0}>"

# ── SSRF ─────────────────────────────────────────────────────────────────────

_SSRF_CALLBACK_FMT = "http://127.0.0.1:{port}/raven-canary/{token}"
_CANARY_TOKEN_RE = re.compile(r"raven-canary/([A-Za-z0-9]+)")


def _place(url: str, method: str, parameter: str, location: str, value: str) -> Dict[str, Any]:
    """Return request kwargs for *url* with *value* substituted at parameter/location."""
    if location == "query":
        parts = urlsplit(url)
        q = dict(parse_qsl(parts.query, keep_blank_values=True))
        q[parameter] = value
        new_url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))
        return {"url": new_url, "method": method, "data": None}
    if location == "body":
        return {"url": url, "method": method or "POST", "data": {parameter: value}}
    if location == "header":
        return {"url": url, "method": method, "headers": {parameter: value}}
    raise ToolError("invalid_args", f"Unsupported parameter location '{location}'.")


async def _fetch(url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None,
                 data: Optional[Dict[str, Any]] = None, timeout: float = 10.0) -> Dict[str, Any]:
    hdrs = {"User-Agent": "Raven/3 (authorized security assessment)"}
    hdrs.update(headers or {})
    started = time.monotonic()
    try:
        async with httpx.AsyncClient(verify=False, timeout=timeout, follow_redirects=False) as client:
            resp = await client.request(method.upper(), url, headers=hdrs, data=data)
    except (httpx.ConnectError, httpx.ConnectTimeout) as e:
        raise ToolError("target_unreachable", f"Could not connect to {url}: {e}") from e
    except httpx.TimeoutException as e:
        raise ToolError("timeout", f"Request to {url} timed out: {e}") from e
    except httpx.HTTPError as e:
        raise ToolError("error", f"HTTP error for {url}: {e}") from e
    if resp.status_code == 429:
        raise ToolError("rate_limited", f"HTTP 429 from {url}")
    text = resp.text or ""
    return {
        "status_code": resp.status_code,
        "headers": {k.lower(): v for k, v in resp.headers.items()},
        "body": text[:200_000],
        "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
    }


async def sql_probe(url: str, parameter: str, method: str = "GET", location: str = "query",
                    timeout: float = 10.0) -> Dict[str, Any]:
    """One controlled round: baseline (benign value) + quote + boolean-true + boolean-false."""
    tests: Dict[str, Any] = {}
    for name, value in {"baseline": BASELINE_VALUE, **SQL_PAYLOADS}.items():
        req = _place(url, method, parameter, location, value)
        try:
            data = await _fetch(timeout=timeout, **req)
            data["sql_error_signature"] = bool(_SQLI_ERROR_RE.search(data["body"]))
            tests[name] = data
        except ToolError as e:
            tests[name] = {"error": e.status, "message": e.message}
    return {"parameter": parameter, "location": location, "method": method, "tests": tests}


def _reflection_context(body: str, marker: str) -> str:
    i = body.find(marker)
    if i == -1:
        return "absent"
    window = body[max(0, i - 60):i]
    if re.search(r"<script[^>]*>(?:(?!</script>).)*$", window, re.I | re.S):
        return "javascript"
    if re.search(r'=["\']?[^"\'>]*$', window):
        return "html_attribute"
    return "html_body"


async def xss_probe(url: str, parameter: str, method: str = "GET", location: str = "query",
                    timeout: float = 10.0) -> Dict[str, Any]:
    """One controlled round: a single unique-canary payload, never persisted."""
    token = secrets.token_hex(4)
    marker = _XSS_MARKER_FMT.format(token)
    payload = _XSS_PAYLOAD_FMT.format(token)
    req = _place(url, method, parameter, location, payload)
    data = await _fetch(timeout=timeout, **req)
    body = data.get("body", "") or ""
    raw_reflected = payload in body
    marker_reflected = marker in body
    escaped = marker_reflected and not raw_reflected and (
        f"&lt;{marker}" in body or f"\\u003c{marker}" in body.lower())
    return {
        "parameter": parameter, "location": location, "token": token, "payload": payload,
        "status_code": data.get("status_code"),
        "raw_reflected": raw_reflected, "marker_reflected": marker_reflected, "escaped": escaped,
        "context": _reflection_context(body, marker) if marker_reflected else "absent",
        "elapsed_ms": data.get("elapsed_ms"),
    }


async def _run_canary(token: str) -> asyncio.base_events.Server:
    """
    Start a fresh, Raven-owned loopback HTTP listener for exactly one probe
    round. It never initiates outbound connections; it only records whether
    *this* round's unique token was hit, so a server-side fetch performed by
    the target is the only thing that can register a hit.

    A fresh listener per call (rather than a cached singleton) is deliberate:
    it is bound to the event loop of the caller's own probe round and is torn
    down immediately after, so it can never be left listening on a stale
    loop across independent calls.
    """
    hits: list = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=2)
        except asyncio.TimeoutError:
            data = b""
        text = data.decode("latin-1", errors="ignore")
        m = _CANARY_TOKEN_RE.search(text)
        if m and m.group(1) == token:
            hits.append(time.time())
        try:
            writer.write(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
        except (ConnectionError, OSError):
            pass
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    server.hits = hits  # type: ignore[attr-defined]
    return server


async def ssrf_probe(url: str, parameter: str, method: str = "GET", location: str = "query",
                     timeout: float = 10.0, settle: float = 1.0) -> Dict[str, Any]:
    """
    One controlled round using a fresh Raven-hosted callback canary rather
    than an arbitrary external destination: distinguishes "the application
    accepted the URL" from "the server actually performed the request".

    Limitation (honest, by design): the canary is bound to Raven's own
    loopback interface, so this only detects SSRF when the target can reach
    that address (true for the same host / same network namespace; not true
    across most real network boundaries for a remote target).
    """
    token = secrets.token_hex(8)
    server = await _run_canary(token)
    port = server.sockets[0].getsockname()[1]
    try:
        callback = _SSRF_CALLBACK_FMT.format(port=port, token=token)
        req = _place(url, method, parameter, location, callback)
        data = await _fetch(timeout=timeout, **req)
        await asyncio.sleep(settle)
        return {
            "parameter": parameter, "location": location, "callback": callback, "token": token,
            "application_status_code": data.get("status_code"),
            "application_accepted": bool(data.get("status_code")) and data["status_code"] < 500,
            "callback_received": bool(server.hits),  # type: ignore[attr-defined]
            "elapsed_ms": data.get("elapsed_ms"),
        }
    finally:
        server.close()
        await server.wait_closed()
