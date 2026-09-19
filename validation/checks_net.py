"""
validation/checks_net.py
------------------------
Network-service validators: re-probe the port and re-derive the verdict.
"""

from __future__ import annotations

from core.models import Confidence, Evidence, Finding, FindingStatus
from validation.outcome import conclude


class NetChecks:
    async def _v_open_service(self, f: Finding) -> Finding:  # type: ignore[misc]
        host, port = f.signal["host"], int(f.signal["port"])
        banner = await self.ctx.call(
            "service_identification", {"host": host, "port": port}, f"Re-probe {host}:{port}")
        proto = await self.ctx.call(
            "protocol_analysis", {"host": host, "port": port}, f"Re-identify protocol on {host}:{port}")
        b = banner.data if banner.ok else {}
        p = proto.data if proto.ok else {}
        reachable = bool(b.get("success")) or bool(b.get("banner")) or bool(p.get("detected"))
        ev = [Evidence(
            kind="tool_output", source_tool="banner_grab/protocol_probe",
            summary=f"Re-probe of {host}:{port}",
            data={"reachable": reachable, "banner": str(b.get("banner", ""))[:120],
                  "protocol": p.get("protocol"), "auth_required": p.get("auth_required"),
                  "authenticated": p.get("authenticated")},
        )]
        if not banner.ok and not proto.ok:
            return conclude(f, FindingStatus.INCONCLUSIVE, Confidence.LOW,
                            "Re-probe failed; the service state could not be reproduced.", "open_service", ev)
        if not reachable:
            return conclude(f, FindingStatus.REJECTED, Confidence.NONE,
                            "The port is no longer reachable / did not respond on re-probe.", "open_service", ev)
        if f.signal.get("unauthenticated"):
            if p.get("detected") and p.get("auth_required") is False:
                return conclude(f, FindingStatus.CONFIRMED, Confidence.HIGH,
                                f"{p.get('protocol')} accepted a protocol request without authentication.",
                                "open_service", ev)
            return conclude(f, FindingStatus.REJECTED, Confidence.NONE,
                            "Service requires authentication on re-probe.", "open_service", ev)
        return conclude(f, FindingStatus.CONFIRMED, Confidence.MEDIUM,
                        f"Service is reachable on {host}:{port} (exposure confirmed; "
                        "whether exposure is intended requires operator review).", "open_service", ev)
