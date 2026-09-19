"""
agents/specialized/binary_agent.py
-----------------------------------
Specialized agent for Native Binary, CLI, and Process Security Assessment.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from agents.base_agent import BaseSpecializedAgent
from engine.assessment_context import AssessmentContext
from engine.hypothesis_manager import HypothesisManager
from engine_models.actions import AgentAction
from engine_models.findings import EvidenceItem, Finding, ValidationStatus

logger = logging.getLogger("raven.agents.binary")


class BinaryAssessmentAgent(BaseSpecializedAgent):
    """
    Assesses native compiled executables, local daemons, and CLI applications
    for command-line crashes, unhandled exceptions, and insecure permissions.
    """

    def __init__(self, context: AssessmentContext) -> None:
        super().__init__(context)
        self.agent_name = "BinaryAssessmentAgent"
        self.capability_id = "binary_assessment"

    async def execute(self, context: Optional[AssessmentContext] = None) -> None:
        ctx = context or self.context
        target_str = ctx.target.raw_input
        hyp_mgr = HypothesisManager(ctx.state)

        hypotheses = hyp_mgr.get_untested(self.capability_id)
        current_hyp = hypotheses[0] if hypotheses else None

        p = Path(target_str).resolve()
        bin_path = str(p)

        found_issues = []

        if current_hyp:
            hyp_mgr.start_testing(current_hyp.hypothesis_id, f"bin_audit_{p.name}")

        # 1. Process Inspection (if running or name matches)
        proc_action = AgentAction(
            agent_name=self.agent_name,
            capability_id=self.capability_id,
            tool_name="process_probe",
            target=p.name,
            operation_type="process_probe",
            parameters={"name": p.stem},
            purpose=f"Inspect running process instances for {p.name}",
            impact_level="passive",
            hypothesis_id=current_hyp.hypothesis_id if current_hyp else None,
        )
        proc_res = await self.execute_action(proc_action)
        if proc_res.is_success and proc_res.data and proc_res.data.get("found"):
            for proc in proc_res.data.get("processes", []):
                # Check for sensitive unmasked environment variables or insecure listening ports
                if proc.get("connections"):
                    for conn in proc["connections"]:
                        evidence = EvidenceItem(
                            evidence_type="process_output",
                            raw_data=str(conn),
                            sanitized_summary=f"Process listening on local socket: {conn.get('laddr')}",
                            confidence="High",
                        )
                        finding = Finding(
                            title=f"Binary Process Listening on Network Interface: {p.name}",
                            vulnerability_type="exposed_service",
                            severity="Medium",
                            cvss_score=5.0,
                            cwe_id="CWE-200",
                            target_component=p.name,
                            asset_description=p.name,
                            observation=f"Process {p.name} (PID {proc.get('pid')}) binds to network interface: {conn.get('laddr')}",
                            evidence=[evidence],
                            reproduction_steps=[f"Check listening port with netstat or lsof -p {proc.get('pid')}"],
                            validation_status=ValidationStatus.CONFIRMED,
                            remediation="Ensure debug or administration sockets bind only to loopback (127.0.0.1).",
                            source_agent=self.agent_name,
                            capability_id=self.capability_id,
                            hypothesis_id=current_hyp.hypothesis_id if current_hyp else None,
                        )
                        self.publish_candidate_finding(finding)
                        found_issues.append(finding)

        # 2. CLI Boundary & Crash Testing (Active only)
        if ctx.is_active_permitted and p.is_file() and self.can_start_hypothesis():
            fuzz_action = AgentAction(
                agent_name=self.agent_name,
                capability_id=self.capability_id,
                tool_name="cli_fuzz",
                target=bin_path,
                operation_type="cli_fuzz",
                parameters={"binary_path": bin_path, "timeout": 3.0},
                purpose=f"Boundary fuzz testing for binary {p.name}",
                impact_level="moderate",
                hypothesis_id=current_hyp.hypothesis_id if current_hyp else None,
            )
            fuzz_res = await self.execute_action(fuzz_action)
            if fuzz_res.is_success and fuzz_res.data and fuzz_res.data.get("crashes_detected", 0) > 0:
                for crash in fuzz_res.data.get("crashes", []):
                    cli_cmd = f"{bin_path} \"{crash.get('payload')}\""
                    evidence = EvidenceItem(
                        evidence_type="binary_output",
                        raw_data=str(crash),
                        sanitized_summary=f"Binary crash detected: {crash.get('reason')}",
                        confidence="High",
                    )
                    finding = Finding(
                        title=f"Unhandled Exception / Crash in Binary: {p.name}",
                        vulnerability_type="dos_or_memory_corruption",
                        severity="High" if crash.get("returncode") in (-11, 139) else "Medium",
                        cvss_score=7.5 if crash.get("returncode") in (-11, 139) else 5.5,
                        cwe_id="CWE-119" if crash.get("returncode") in (-11, 139) else "CWE-755",
                        target_component=p.name,
                        asset_description=bin_path,
                        cli_poc=cli_cmd,
                        observation=f"Binary exited abnormally: {crash.get('reason')} on input payload.",
                        evidence=[evidence],
                        reproduction_steps=[f"Run command: `{cli_cmd}`"],
                        validation_status=ValidationStatus.CONFIRMED,
                        remediation="Validate command-line arguments and handle exceptions gracefully without abnormal termination.",
                        source_agent=self.agent_name,
                        capability_id=self.capability_id,
                        hypothesis_id=current_hyp.hypothesis_id if current_hyp else None,
                    )
                    self.publish_candidate_finding(finding)
                    found_issues.append(finding)

        # 2.5 IPC Socket Probing
        if p.exists():
            ipc_action = AgentAction(
                agent_name=self.agent_name,
                capability_id=self.capability_id,
                tool_name="ipc_probe",
                target=bin_path,
                operation_type="ipc_probe",
                parameters={"binary_path": bin_path},
                purpose=f"Probe IPC sockets for binary {p.name}",
                impact_level="passive",
            )
            ipc_res = await self.execute_action(ipc_action)
            if ipc_res.is_success and ipc_res.data and ipc_res.data.get("unsecured_ipc"):
                for ipc in ipc_res.data.get("ipc_sockets", []):
                    evidence = EvidenceItem(
                        evidence_type="binary_output",
                        raw_data=str(ipc),
                        sanitized_summary="Unsecured IPC socket found",
                        confidence="High",
                    )
                    finding = Finding(
                        title=f"Unsecured IPC Socket in Binary: {p.name}",
                        vulnerability_type="exposed_service",
                        severity="Medium",
                        cvss_score=5.5,
                        cwe_id="CWE-1336",
                        target_component=p.name,
                        asset_description=bin_path,
                        observation=f"Binary exposes an insecure IPC socket: {ipc.get('path')}",
                        evidence=[evidence],
                        reproduction_steps=[f"Check socket permissions for {ipc.get('path')}"],
                        validation_status=ValidationStatus.CONFIRMED,
                        remediation="Apply strict permissions to IPC sockets (e.g., 0600).",
                        source_agent=self.agent_name,
                        capability_id=self.capability_id,
                        hypothesis_id=current_hyp.hypothesis_id if current_hyp else None,
                    )
                    self.publish_candidate_finding(finding)
                    found_issues.append(finding)

        # 3. File Permission Audit
        if p.exists():
            perm_action = AgentAction(
                agent_name=self.agent_name,
                capability_id=self.capability_id,
                tool_name="permission_scan",
                target=bin_path,
                operation_type="permission_scan",
                parameters={"path": bin_path},
                purpose=f"Audit binary file permissions for {p.name}",
                impact_level="passive",
            )
            perm_res = await self.execute_action(perm_action)
            if perm_res.is_success and perm_res.data and perm_res.data.get("issues_count", 0) > 0:
                for issue in perm_res.data.get("issues", []):
                    evidence = EvidenceItem(
                        evidence_type="file_content",
                        raw_data=str(issue),
                        sanitized_summary=f"Insecure file permission: {issue.get('issue')}",
                        confidence="High",
                    )
                    finding = Finding(
                        title=f"Insecure File Permission on Binary: {p.name}",
                        vulnerability_type="insecure_permissions",
                        severity=issue.get("severity", "Medium"),
                        cvss_score=7.0 if issue.get("severity") == "HIGH" else 4.0,
                        cwe_id="CWE-732",
                        target_component=p.name,
                        asset_description=bin_path,
                        observation=issue.get("details", "Insecure file permission detected."),
                        evidence=[evidence],
                        reproduction_steps=[f"Check file permissions of {bin_path}"],
                        validation_status=ValidationStatus.CONFIRMED,
                        remediation="Remove world-writable or SUID permissions from binary file.",
                        source_agent=self.agent_name,
                        capability_id=self.capability_id,
                        hypothesis_id=current_hyp.hypothesis_id if current_hyp else None,
                    )
                    self.publish_candidate_finding(finding)
                    found_issues.append(finding)

        if current_hyp:
            if found_issues:
                hyp_mgr.resolve(current_hyp.hypothesis_id, "confirmed", f"Identified {len(found_issues)} binary/process security findings")
            else:
                hyp_mgr.resolve(current_hyp.hypothesis_id, "rejected", "Binary executed without crashes; secure permissions verified")
