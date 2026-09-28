"""
validation/checks_binary.py
----------------------------
Binary-analysis validators. Each re-runs the same static-analysis capability
fresh, through the gateway (never trusting the agent's claim), and
re-derives the verdict from that new result -- the same pattern used
throughout validation/ (e.g. checks_static.py's `_v_file_permission`
re-invokes `permission_audit` and compares).
"""

from __future__ import annotations

from core.models import Confidence, Evidence, Finding, FindingStatus
from validation.outcome import conclude


class BinaryChecks:
    async def _v_binary_hardening_missing(self, f: Finding) -> Finding:  # type: ignore[misc]
        from tools.binary_scanner import missing_hardening_properties
        sig = f.signal
        path, prop = sig["path"], sig["property"]
        res = await self.ctx.call("binary_hardening", {"path": path}, f"Re-check hardening indicators of {path}")
        if not res.ok:
            return conclude(f, FindingStatus.INCONCLUSIVE, Confidence.LOW,
                            "Hardening indicators could not be re-checked.", "binary_hardening_missing")
        data = res.data
        if not data.get("supported", True) or data.get("parsed") is False:
            return conclude(f, FindingStatus.INCONCLUSIVE, Confidence.LOW,
                            "The binary header could not be re-parsed on revalidation.",
                            "binary_hardening_missing")
        hard = data.get("hardening", {})
        still_missing = {m["property"] for m in missing_hardening_properties(hard, data.get("format", ""))}
        ev = [Evidence(kind="tool_output", source_tool="binary_hardening",
                       summary=f"Re-checked hardening indicators of {path}", data={"hardening": hard})]
        if prop in still_missing:
            return conclude(f, FindingStatus.CONFIRMED, Confidence.HIGH,
                            f"'{prop}' re-observed as missing on independent re-analysis of the header.",
                            "binary_hardening_missing", ev)
        return conclude(f, FindingStatus.REJECTED, Confidence.NONE,
                        f"'{prop}' is present on re-analysis; the original observation did not reproduce.",
                        "binary_hardening_missing", ev)

    async def _v_binary_suspicious_string(self, f: Finding) -> Finding:  # type: ignore[misc]
        sig = f.signal
        path, kind, offset = sig["path"], sig["type"], sig["offset"]
        res = await self.ctx.call("binary_strings", {"path": path}, f"Re-scan embedded strings of {path}")
        if not res.ok:
            return conclude(f, FindingStatus.INCONCLUSIVE, Confidence.LOW,
                            "Embedded strings could not be re-scanned.", "binary_suspicious_string")
        matches = res.data.get("matches", [])
        hit = next((m for m in matches if m.get("type") == kind and m.get("offset") == offset), None)
        ev = [Evidence(kind="tool_output", source_tool="binary_strings",
                       summary=f"Re-scanned embedded strings of {path}",
                       data={"type": kind, "offset": offset, "reproduced": bool(hit)})]
        if hit:
            return conclude(f, FindingStatus.CONFIRMED, Confidence.HIGH,
                            f"The '{kind}' string was re-observed at the same offset on re-scan.",
                            "binary_suspicious_string", ev)
        return conclude(f, FindingStatus.REJECTED, Confidence.NONE,
                        f"The '{kind}' string was not reproduced at the cited offset on re-scan.",
                        "binary_suspicious_string", ev)
