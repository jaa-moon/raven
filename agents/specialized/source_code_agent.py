"""
agents/specialized/source_code_agent.py
---------------------------------------
Specialized agent for Static Application Security Testing (SAST) and source code analysis.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from agents.base_agent import BaseSpecializedAgent
from engine.assessment_context import AssessmentContext
from engine.hypothesis_manager import HypothesisManager
from engine_models.actions import AgentAction
from engine_models.findings import EvidenceItem, Finding, ValidationStatus

logger = logging.getLogger("raven.agents.source_code")


class SourceCodeAssessmentAgent(BaseSpecializedAgent):
    """
    Performs AST and semantic security audits on application source code.
    """

    def __init__(self, context: AssessmentContext) -> None:
        super().__init__(context)
        self.agent_name = "SourceCodeAssessmentAgent"
        self.capability_id = "source_code_analysis"

    async def execute(self, context: Optional[AssessmentContext] = None) -> None:
        ctx = context or self.context
        target_path = ctx.target.raw_input
        hyp_mgr = HypothesisManager(ctx.state)

        hypotheses = hyp_mgr.get_untested(self.capability_id)
        current_hyp = hypotheses[0] if hypotheses else None

        p = Path(target_path)
        if not p.exists():
            return

        suspicious_patterns = [
            ("eval(", "code_injection", "Direct eval() execution on untrusted input", "CWE-95", "High", 8.0),
            ("exec(", "code_injection", "Direct exec() execution on dynamic input", "CWE-95", "High", 8.0),
            ("shell=True", "command_injection", "Subprocess executed with shell=True enabled", "CWE-78", "High", 8.5),
            ("os.system(", "command_injection", "os.system() call may allow command injection", "CWE-78", "High", 8.5),
            ("open(", "path_traversal", "File open operation without explicit path validation", "CWE-22", "Medium", 6.5),
        ]

        found_issues = []
        action = AgentAction(
            agent_name=self.agent_name,
            capability_id=self.capability_id,
            tool_name="file_analyzer",
            target=target_path,
            operation_type="file_analysis",
            purpose="Analyze source files for unsafe sinks and injection vectors",
            impact_level="passive",
            hypothesis_id=current_hyp.hypothesis_id if current_hyp else None,
        )

        if current_hyp:
            hyp_mgr.start_testing(current_hyp.hypothesis_id, action.action_id)

        # 0. Rule Engine Scan
        rule_action = AgentAction(
            agent_name=self.agent_name,
            capability_id=self.capability_id,
            tool_name="rule_engine_scan",
            target=target_path,
            operation_type="rule_engine_scan",
            parameters={"path": target_path},
            purpose="Scan source code using external rule engine (e.g. semgrep)",
            impact_level="passive",
            hypothesis_id=current_hyp.hypothesis_id if current_hyp else None,
        )
        rule_res = await self.execute_action(rule_action)
        if rule_res.is_success and rule_res.data and rule_res.data.get("findings"):
            for rf in rule_res.data.get("findings", []):
                ev = EvidenceItem(
                    evidence_type="code_snippet",
                    raw_data=str(rf),
                    sanitized_summary=f"Rule engine finding: {rf.get('rule_id')}",
                    confidence="High",
                )
                finding = Finding(
                    title=f"SAST Finding: {rf.get('rule_id')}",
                    vulnerability_type="code_flaw",
                    severity=rf.get("severity", "Medium"),
                    cvss_score=5.0,
                    cwe_id="CWE-1000",
                    target_component=rf.get("file", target_path),
                    endpoint=rf.get("file", target_path),
                    observation=rf.get("message", "Rule engine flagged a potential flaw."),
                    evidence=[ev],
                    reproduction_steps=[f"Review finding {rf.get('rule_id')} in {rf.get('file')}"],
                    validation_status=ValidationStatus.CONFIRMED,
                    remediation="Remediate according to SAST rule guidelines.",
                    source_agent=self.agent_name,
                    capability_id=self.capability_id,
                    hypothesis_id=current_hyp.hypothesis_id if current_hyp else None,
                )
                self.publish_candidate_finding(finding)
                found_issues.append(finding)

        # 1. Initialize AST compressor if available
        ast_compressor = None
        try:
            from core.ast_compressor import ASTCompressor
            ast_compressor = ASTCompressor()
        except Exception as e:
            logger.debug(f"ASTCompressor unavailable: {e}")

        # Walk target source files
        files_analyzed = 0
        for root, dirs, files in os.walk(p):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules", "venv", "__pycache__", "dist", "build")]
            for f in files:
                if not f.endswith((".py", ".js", ".ts", ".php", ".go", ".java")):
                    continue
                if not self.can_start_hypothesis() or files_analyzed >= 100:
                    break

                file_path = Path(root) / f
                rel_path = str(file_path.relative_to(p)).replace("\\", "/")
                files_analyzed += 1

                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")

                    # AST Compression & High-Risk Unit Detection
                    if ast_compressor:
                        comp_res = ast_compressor.compress(content, str(file_path))
                        for chunk in comp_res.chunks:
                            if chunk.risk_score >= 0.40:
                                # High-risk AST chunk identified
                                chunk_reasons = ", ".join(chunk.risk_reasons)
                                ev = EvidenceItem(
                                    evidence_type="code_snippet",
                                    raw_data=chunk.source[:300],
                                    sanitized_summary=f"High-risk AST unit '{chunk.name}' (lines {chunk.line_start}-{chunk.line_end}): {chunk_reasons}",
                                    file_path=rel_path,
                                    line_number=chunk.line_start,
                                    confidence="High",
                                )
                                # Check if chunk contains critical unsafe sinks
                                for pattern, vtype, desc, cwe, sev, cvss in suspicious_patterns:
                                    if pattern in chunk.source:
                                        finding = Finding(
                                            title=f"Unsafe Sink ({pattern}) in {rel_path}:{chunk.line_start}",
                                            vulnerability_type=vtype,
                                            severity=sev,
                                            cvss_score=cvss,
                                            cwe_id=cwe,
                                            target_component=rel_path,
                                            endpoint=rel_path,
                                            observation=f"{desc} inside AST unit '{chunk.name}' (lines {chunk.line_start}-{chunk.line_end}). Signals: {chunk_reasons}",
                                            evidence=[ev],
                                            reproduction_steps=[f"Inspect {rel_path}:{chunk.line_start} in function '{chunk.name}'"],
                                            validation_status=ValidationStatus.CONFIRMED,
                                            remediation="Sanitize input parameters and replace dynamic execution with safe APIs.",
                                            source_agent=self.agent_name,
                                            capability_id=self.capability_id,
                                            hypothesis_id=current_hyp.hypothesis_id if current_hyp else None,
                                        )
                                        self.publish_candidate_finding(finding)
                                        found_issues.append(finding)
                                        break
                    else:
                        # Fallback line-by-line pattern scan
                        lines = content.splitlines()
                        for idx, line in enumerate(lines, 1):
                            for pattern, vtype, desc, cwe, sev, cvss in suspicious_patterns:
                                if pattern in line and not line.strip().startswith("#"):
                                    evidence = EvidenceItem(
                                        evidence_type="code_snippet",
                                        raw_data=line.strip(),
                                        sanitized_summary=f"{pattern} call detected at line {idx}",
                                        file_path=rel_path,
                                        line_number=idx,
                                        confidence="High",
                                    )
                                    finding = Finding(
                                        title=f"Potential {vtype.replace('_', ' ').title()} in {rel_path}:{idx}",
                                        vulnerability_type=vtype,
                                        severity=sev,
                                        cvss_score=cvss,
                                        cwe_id=cwe,
                                        target_component=rel_path,
                                        endpoint=rel_path,
                                        observation=f"{desc} ({pattern}) in {rel_path}:{idx}",
                                        evidence=[evidence],
                                        reproduction_steps=[f"Inspect {rel_path} at line {idx}: '{line.strip()}'"],
                                        validation_status=ValidationStatus.CONFIRMED,
                                        remediation="Sanitize user inputs and replace dangerous dynamic calls with safe parameterized alternatives.",
                                        source_agent=self.agent_name,
                                        capability_id=self.capability_id,
                                        hypothesis_id=current_hyp.hypothesis_id if current_hyp else None,
                                    )
                                    self.publish_candidate_finding(finding)
                                    found_issues.append(finding)
                except Exception as e:
                    logger.debug(f"Failed to analyze file {file_path}: {e}")

        # Log action execution in state
        ctx.budget_manager.consume(tool_calls=1)
        ctx.state.tested_actions.append(
            {
                "action_id": action.action_id,
                "agent": self.agent_name,
                "tool": action.tool_name,
                "target": target_path,
                "status": "success",
            }
        )

        if current_hyp:
            if found_issues:
                hyp_mgr.resolve(current_hyp.hypothesis_id, "confirmed", f"Identified {len(found_issues)} source code risks")
            else:
                hyp_mgr.resolve(current_hyp.hypothesis_id, "rejected", "No unsafe sink patterns identified")
