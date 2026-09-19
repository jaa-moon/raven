"""
agents/specialized/network_agent.py
-----------------------------------
Specialized agent for Network and Port Security Assessment.
"""

from __future__ import annotations

import logging
from typing import Optional

from agents.base_agent import BaseSpecializedAgent
from engine.assessment_context import AssessmentContext
from engine.hypothesis_manager import HypothesisManager
from engine_models.actions import AgentAction
from engine_models.findings import EvidenceItem, Finding, ValidationStatus

logger = logging.getLogger("raven.agents.network")


class NetworkAssessmentAgent(BaseSpecializedAgent):
    """
    Scans network targets for open ports, unexpected services, and transport risks.
    """

    def __init__(self, context: AssessmentContext) -> None:
        super().__init__(context)
        self.agent_name = "NetworkAssessmentAgent"
        self.capability_id = "network_assessment"

    async def execute(self, context: Optional[AssessmentContext] = None) -> None:
        ctx = context or self.context
        target_str = ctx.target.raw_input
        hyp_mgr = HypothesisManager(ctx.state)

        hypotheses = hyp_mgr.get_untested(self.capability_id)
        current_hyp = hypotheses[0] if hypotheses else None

        host = target_str.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

        action = AgentAction(
            agent_name=self.agent_name,
            capability_id=self.capability_id,
            tool_name="port_scan",
            target=host,
            operation_type="port_scan",
            parameters={"host": host, "ports": [21, 22, 23, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200]},
            purpose="Enumerate open TCP ports and exposed service banners",
            impact_level="moderate",
            hypothesis_id=current_hyp.hypothesis_id if current_hyp else None,
        )

        if current_hyp:
            hyp_mgr.start_testing(current_hyp.hypothesis_id, action.action_id)

        result = await self.execute_action(action)
        found_issues = []

        if result.is_success and result.data:
            open_ports = result.data if isinstance(result.data, list) else (result.data.get("open_ports") or result.data.get("ports") or [])
            risky_ports = {
                21: ("FTP", "Cleartext file transfer service exposed", "Low", "ftp"),
                23: ("Telnet", "Insecure unencrypted remote shell exposed", "High", "telnet"),
                25: ("SMTP", "Mail transfer service exposed", "Low", "smtp"),
                3306: ("MySQL", "Database service exposed to network", "Medium", "mysql"),
                5432: ("PostgreSQL", "Database service exposed to network", "Medium", "postgres"),
                6379: ("Redis", "In-memory datastore exposed without network isolation", "High", "redis"),
                9200: ("Elasticsearch", "Search index service potentially exposed", "Medium", "http"),
                11211: ("Memcached", "Distributed cache service exposed without auth", "High", "memcached"),
                27017: ("MongoDB", "NoSQL database service exposed", "Medium", "mongodb"),
            }

            for item in open_ports:
                if not self.can_start_hypothesis():
                    break
                port_num = item.get("port") if isinstance(item, dict) else int(item)

                # 1. Grab Banner
                bg_action = AgentAction(
                    agent_name=self.agent_name,
                    capability_id=self.capability_id,
                    tool_name="banner_grab",
                    target=f"{host}:{port_num}",
                    operation_type="banner_grab",
                    parameters={"host": host, "port": port_num},
                    purpose=f"Extract service banner for port {port_num}",
                    impact_level="passive",
                )
                bg_res = await self.execute_action(bg_action)
                banner = bg_res.data.get("banner", "") if bg_res.is_success else ""

                # 2. Protocol Probe
                proto_action = AgentAction(
                    agent_name=self.agent_name,
                    capability_id=self.capability_id,
                    tool_name="protocol_probe",
                    target=f"{host}:{port_num}",
                    operation_type="protocol_probe",
                    parameters={"host": host, "port": port_num, "protocol": "auto"},
                    purpose=f"Identify application protocol for port {port_num}",
                    impact_level="passive",
                )
                proto_res = await self.execute_action(proto_action)
                proto_data = proto_res.data if proto_res.is_success else {}

                # 3. Default Credentials / Unauthenticated Test
                creds_tested = False
                unauth_access = False
                if proto_data.get("authenticated") is True and proto_data.get("auth_required") is False:
                    unauth_access = True
                elif port_num in (21, 6379, 5432):
                    svc_type = risky_ports.get(port_num, ("", "", "", "http"))[3]
                    creds_action = AgentAction(
                        agent_name=self.agent_name,
                        capability_id=self.capability_id,
                        tool_name="default_creds_test",
                        target=f"{host}:{port_num}",
                        operation_type="default_creds_test",
                        parameters={"host": host, "port": port_num, "service": svc_type},
                        purpose=f"Audit default credentials on port {port_num}",
                        impact_level="moderate",
                    )
                    creds_res = await self.execute_action(creds_action)
                    if creds_res.is_success and creds_res.data.get("vulnerable"):
                        unauth_access = True
                        creds_tested = True

                if port_num in risky_ports or unauth_access:
                    svc, desc, sev, _ = risky_ports.get(port_num, ("Service", f"Service exposed on port {port_num}", "Medium", "tcp"))
                    if unauth_access:
                        sev = "CRITICAL" if port_num in (6379, 11211, 3306, 5432) else "HIGH"
                        desc = f"Unauthenticated access permitted on {svc} (Port {port_num})"

                    cli_poc = f"redis-cli -h {host} -p {port_num} PING" if port_num == 6379 else f"nc -vz {host} {port_num}"

                    evidence = EvidenceItem(
                        evidence_type="network_packet",
                        raw_data=f"Port {port_num}/TCP open on {host}. Banner: {banner[:100]}",
                        sanitized_summary=f"Port {port_num} ({svc}) open. Unauthenticated: {unauth_access}",
                        confidence="High",
                    )
                    finding = Finding(
                        title=f"Unauthenticated or Exposed {svc} on Port {port_num}" if unauth_access else f"Exposed {svc} Service on Port {port_num}",
                        vulnerability_type="unauthenticated_service" if unauth_access else "exposed_service",
                        severity=sev,
                        cvss_score=9.8 if unauth_access and sev == "CRITICAL" else (7.5 if sev == "High" else 5.0),
                        cwe_id="CWE-306" if unauth_access else "CWE-200",
                        target_component=f"{host}:{port_num}",
                        asset_description=f"{host}:{port_num}",
                        cli_poc=cli_poc,
                        observation=f"{desc} - Banner: '{banner[:80]}'",
                        evidence=[evidence],
                        reproduction_steps=[f"Connect to {host}:{port_num} with standard client: `{cli_poc}`"],
                        validation_status=ValidationStatus.CONFIRMED,
                        remediation=f"Restrict access to port {port_num} with firewall rules, require strong authentication, and bind only to private interface.",
                        source_agent=self.agent_name,
                        capability_id=self.capability_id,
                        hypothesis_id=current_hyp.hypothesis_id if current_hyp else None,
                    )
                    self.publish_candidate_finding(finding)
                    found_issues.append(finding)

        if current_hyp:
            if found_issues:
                hyp_mgr.resolve(current_hyp.hypothesis_id, "confirmed", f"Discovered {len(found_issues)} exposed network services")
            else:
                hyp_mgr.resolve(current_hyp.hypothesis_id, "rejected", "No high-risk open ports identified")
