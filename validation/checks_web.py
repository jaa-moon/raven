"""
validation/checks_web.py
------------------------
Header / cookie / CORS validators. Each re-fetches the URL itself.
"""

from __future__ import annotations

from typing import Any, Dict, List

from core.models import Confidence, Finding, FindingStatus
from validation.evidence import http_evidence
from validation.outcome import conclude


def _cookie_flags(raw: str) -> Dict[str, Any]:
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0]
    attrs = [p.lower() for p in parts[1:]]
    return {
        "name": name,
        "httponly": "httponly" in attrs,
        "secure": "secure" in attrs,
        "samesite": any(a.startswith("samesite") for a in attrs),
    }


class WebChecks:
    async def _v_missing_header(self, f: Finding) -> Finding:  # type: ignore[misc]
        url, header = f.signal["url"], f.signal["header"].lower()
        data = await self._fetch(url, f"Re-check for missing {header}")
        if data is None:
            return conclude(f, FindingStatus.INCONCLUSIVE, Confidence.LOW,
                            "Could not re-fetch the URL.", "missing_header")
        ev = [http_evidence(url, data, note=f"Header '{header}' absent from response headers.")]
        headers = data["headers"]
        if header in headers:
            return conclude(f, FindingStatus.REJECTED, Confidence.NONE,
                            f"'{header}' is present on re-fetch.", "missing_header", ev)
        csp = headers.get("content-security-policy", "")
        if header == "x-frame-options" and "frame-ancestors" in csp:
            return conclude(f, FindingStatus.REJECTED, Confidence.NONE,
                            "Clickjacking is prevented by CSP frame-ancestors.", "missing_header", ev)
        if data["status_code"] >= 500:
            return conclude(f, FindingStatus.INCONCLUSIVE, Confidence.LOW,
                            f"Server error (HTTP {data['status_code']}) makes header state unreliable.",
                            "missing_header", ev)
        return conclude(f, FindingStatus.CONFIRMED, Confidence.HIGH,
                        f"'{header}' is absent on an independent re-fetch (HTTP {data['status_code']}).",
                        "missing_header", ev)

    async def _v_cookie_flags(self, f: Finding) -> Finding:  # type: ignore[misc]
        url, name = f.signal["url"], f.signal["cookie"]
        missing: List[str] = f.signal.get("missing", [])
        data = await self._fetch(url, f"Re-check flags on cookie '{name}'")
        if data is None:
            return conclude(f, FindingStatus.INCONCLUSIVE, Confidence.LOW,
                            "Could not re-fetch the URL.", "cookie_flags")
        flags = [_cookie_flags(c) for c in data.get("set_cookies", [])]
        mine = next((c for c in flags if c["name"] == name), None)
        ev = [http_evidence(url, {**data, "headers": {}}, note=f"Cookie '{name}' attributes re-read.")]
        if mine is None:
            return conclude(f, FindingStatus.INCONCLUSIVE, Confidence.LOW,
                            f"Cookie '{name}' was not set on re-fetch.", "cookie_flags", ev)
        still = [m for m in missing if not mine.get(m)]
        if not still:
            return conclude(f, FindingStatus.REJECTED, Confidence.NONE,
                            "All reported flags are present on re-fetch.", "cookie_flags", ev)
        # A missing Secure flag over plain HTTP is inherent to the transport, not the cookie.
        if still == ["secure"] and url.startswith("http://"):
            return conclude(f, FindingStatus.INCONCLUSIVE, Confidence.LOW,
                            "Secure flag is missing but the site is served over HTTP; the root issue is the "
                            "absence of TLS.", "cookie_flags", ev)
        return conclude(f, FindingStatus.CONFIRMED, Confidence.HIGH,
                        f"Cookie '{name}' lacks: {', '.join(still)} (re-observed).", "cookie_flags", ev)

    async def _v_cors_reflection(self, f: Finding) -> Finding:  # type: ignore[misc]
        url, origin = f.signal["url"], f.signal.get("origin", "https://raven-probe.invalid")
        data = await self._fetch(url, "Re-test CORS origin handling", headers={"Origin": origin})
        if data is None:
            return conclude(f, FindingStatus.INCONCLUSIVE, Confidence.LOW,
                            "Could not re-fetch the URL.", "cors_reflection")
        acao = data["headers"].get("access-control-allow-origin", "")
        acac = data["headers"].get("access-control-allow-credentials", "").lower() == "true"
        ev = [http_evidence(url, data, note=f"ACAO={acao!r}, credentials={acac}")]
        if acao == origin and acac:
            return conclude(f, FindingStatus.CONFIRMED, Confidence.HIGH,
                            "Arbitrary origin is reflected with credentials allowed.", "cors_reflection", ev)
        if acao in ("*", origin):
            return conclude(f, FindingStatus.CONFIRMED, Confidence.MEDIUM,
                            "Arbitrary origin is allowed (credentials not permitted, limiting impact).",
                            "cors_reflection", ev)
        return conclude(f, FindingStatus.REJECTED, Confidence.NONE,
                        "The probe origin is not allowed on re-test.", "cors_reflection", ev)
