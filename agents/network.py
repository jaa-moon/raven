"""
agents/network.py
-----------------
Network discovery and service assessment. ServiceAssessmentAgent proposes one
task per *discovered* service, so new ports found by NetworkReconAgent create
new work automatically.
"""

from __future__ import annotations

from typing import List

from agents.base import Agent, AgentContext, AgentResult
from core.models import Severity, TestTask
from core.profile import TargetProfile
from core.state import AssessmentState

# port -> (label, severity if reachable, severity if unauthenticated)
RISKY = {
    21: ("FTP", Severity.LOW, Severity.HIGH), 23: ("Telnet", Severity.HIGH, Severity.HIGH),
    3306: ("MySQL", Severity.MEDIUM, Severity.HIGH), 5432: ("PostgreSQL", Severity.MEDIUM, Severity.HIGH),
    6379: ("Redis", Severity.MEDIUM, Severity.CRITICAL), 9200: ("Elasticsearch", Severity.MEDIUM, Severity.HIGH),
    11211: ("Memcached", Severity.MEDIUM, Severity.HIGH), 27017: ("MongoDB", Severity.MEDIUM, Severity.HIGH),
}


# identified protocol -> (label, severity if reachable, severity if unauthenticated)
RISKY_PROTOCOLS = {
    "redis": ("Redis", Severity.MEDIUM, Severity.CRITICAL), "memcached": ("Memcached", Severity.MEDIUM, Severity.HIGH),
    "mongodb": ("MongoDB", Severity.MEDIUM, Severity.HIGH), "mysql": ("MySQL", Severity.MEDIUM, Severity.HIGH),
    "postgres": ("PostgreSQL", Severity.MEDIUM, Severity.HIGH), "postgresql": ("PostgreSQL", Severity.MEDIUM, Severity.HIGH),
    "ftp": ("FTP", Severity.LOW, Severity.HIGH), "telnet": ("Telnet", Severity.HIGH, Severity.HIGH),
    "elasticsearch": ("Elasticsearch", Severity.MEDIUM, Severity.HIGH),
}


def _networky(profile: TargetProfile) -> bool:
    return profile.target_type in ("network_service", "host")


class NetworkReconAgent(Agent):
    name = "network_recon"
    description = "Discovers open TCP ports on the target host."
    capabilities = ["network_discovery"]

    def applies(self, profile: TargetProfile) -> bool:
        return _networky(profile) and bool(profile.attributes.get("host"))

    def propose_tasks(self, state: AssessmentState) -> List[TestTask]:
        port = state.profile.attributes.get("port")
        return [self.task("discover", "network_discovery", "Network services", "Discover open TCP ports",
                          priority=95, rationale="Enumerate reachable services.",
                          ports=[port] if port else None)]

    async def run(self, task: TestTask, ctx: AgentContext) -> AgentResult:
        host = ctx.profile.attributes["host"]
        args = {"host": host}
        if task.params.get("ports"):
            args["ports"] = task.params["ports"]
        res = await ctx.call("network_discovery", args, f"Scan {host}")
        if not res.ok:
            return AgentResult(success=False, blocked=res.status in ("out_of_scope", "tool_unavailable"),
                               error=res.error)
        ports = res.data.get("open_ports", [])
        for p in ports:
            if ctx.profile.add_service({"port": p, "protocol": None}):
                ctx.profile.add_surface(f"tcp:{p}")
        ctx.observe("port.scan", "Network services", f"{len(ports)} open port(s): {ports}", ports=ports)
        return AgentResult(summary=f"open ports: {ports}")


class ServiceAssessmentAgent(Agent):
    name = "service_assessment"
    description = "Identifies each discovered service and checks for risky exposure."
    capabilities = ["service_identification", "protocol_analysis"]

    def applies(self, profile: TargetProfile) -> bool:
        return _networky(profile) and bool(profile.services)

    def propose_tasks(self, state: AssessmentState) -> List[TestTask]:
        return [self.task(f"service::{s['port']}", "service_identification", "Network services",
                          f"Identify service on port {s['port']}", priority=70, cost=2, port=s["port"],
                          rationale="Port discovered during this assessment.")
                for s in state.profile.services]

    async def run(self, task: TestTask, ctx: AgentContext) -> AgentResult:
        host, port = ctx.profile.attributes["host"], int(task.params["port"])
        banner = await ctx.call("service_identification", {"host": host, "port": port}, f"Banner {host}:{port}")
        proto = await ctx.call("protocol_analysis", {"host": host, "port": port}, f"Protocol {host}:{port}")
        if not banner.ok and not proto.ok:
            return AgentResult(success=False, error=banner.error or proto.error)
        b, p = (banner.data if banner.ok else {}), (proto.data if proto.ok else {})
        protocol = p.get("protocol") if p.get("detected") else None
        for s in ctx.profile.services:
            if s["port"] == port:
                s.update({"protocol": protocol, "banner": str(b.get("banner", ""))[:100]})
        ctx.observe("service.identified", "Network services",
                    f"{host}:{port} -> {protocol or 'unidentified'}", port=port, protocol=protocol,
                    auth_required=p.get("auth_required"))
        if protocol in ("http", "https") and not ctx.profile.attributes.get("base_url"):
            scheme = "https" if protocol == "https" or port in (443, 8443) else "http"
            ctx.profile.attributes["base_url"] = f"{scheme}://{host}:{port}"
            ctx.profile.add_surface("web_application")
            ctx.observe("web.detected", "HTTP", f"HTTP service found at {host}:{port}.")
        risky = RISKY_PROTOCOLS.get(protocol or "") or RISKY.get(port)   # protocol first, port as fallback
        if risky and (b.get("success") or p.get("detected")):
            label, sev_reach, sev_unauth = risky
            unauth = p.get("auth_required") is False
            ctx.candidate(
                title=f"{'Unauthenticated ' if unauth else 'Exposed '}{label} service on {host}:{port}",
                category="ExposedService", severity=sev_unauth if unauth else sev_reach,
                surface="Network services", location=f"{host}:{port}",
                description=f"{label} is reachable on port {port}." + (" It accepted requests without authentication." if unauth else ""),
                remediation="Restrict the service to trusted networks and require authentication.",
                reproduction=[f"nc -vz {host} {port}"],
                signal={"validator": "open_service", "host": host, "port": port, "unauthenticated": unauth})
        return AgentResult(summary=f"port {port}: {protocol or 'unidentified'}")
