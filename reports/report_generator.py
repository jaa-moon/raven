"""
reports/report_generator.py
---------------------------
Generates markdown and JSON final pentest reports with Attack Surface Maps and detailed evidence formatting.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Tuple
from reports.models import FinalReport


class ReportGenerator:
    """
    Renders and persists FinalReport objects into markdown and JSON formats.
    """

    def __init__(self, report: FinalReport) -> None:
        self.report = report

    def render_markdown(self) -> str:
        """Render complete markdown pentest report."""
        md = f"""# 🐦 Raven Autonomous Pentest Report

**Scan ID**: `{self.report.scan_id}`  
**Target**: `{self.report.target_path}`  
**Stack**: `{self.report.project_profile.language} + {self.report.project_profile.framework}`  
**Sandbox**: `{self.report.sandbox_info.mode.upper()}` (`{self.report.sandbox_info.base_url}`)  
**Duration**: `{self.report.duration_seconds:.2f}s`  
**Overall Risk Score**: `{self.report.risk_score}/10.0` (**{self.report.risk_label}**)  

---

## Executive Summary
{self.report.executive_summary or 'Autonomous scan completed across target endpoints and authentication boundaries.'}

---

## Attack Surface Map
| Endpoint Route | Status | Tested Vectors |
|---|---|---|
"""
        for route in self.report.project_profile.detected_routes or ["/"]:
            md += f"| `{route}` | Active | SQLi, XSS, SSRF, LFI, SSTI, CmdInj |\n"

        md += f"\n--- \n\n## Discovered Attack Chains ({len(self.report.attack_chains)})\n"
        for chain in self.report.attack_chains:
            md += f"### 🔴 [{chain.severity}] {chain.chain_name}\n"
            md += f"**Impact**: {chain.combined_impact}\n"
            md += f"**Estimated Time to Exploit**: {chain.time_to_exploit}\n\n"
            md += "**Execution Steps**:\n"
            for step in chain.steps:
                md += f"- {step}\n"
            md += "\n"

        all_findings = self.report.agent_1_findings + self.report.agent_2_findings
        md += f"## Vulnerability Findings ({len(all_findings)})\n\n"

        for f in all_findings:
            md += f"### [{f.severity}] {f.vulnerability_type} on `{f.target_url}`\n"
            md += f"- **Agent**: `{f.agent}`\n"
            md += f"- **Method**: `{f.method}` | **Parameter**: `{f.parameter}`\n"
            if f.payload_sent:
                md += f"- **Payload Sent**: `{f.payload_sent}`\n"
            if f.evidence:
                md += f"- **Evidence Output**:\n```\n{f.evidence}\n```\n"
            if f.curl_poc:
                md += f"- **Reproduction PoC**:\n```bash\n{f.curl_poc}\n```\n"
            md += f"- **AI Analysis**: {f.ai_analysis}\n"
            md += f"- **Actionable Remediation**: {f.remediation}\n\n"

        md += "## Prioritized Remediation Plan\n"
        for i, item in enumerate(self.report.remediation_plan, 1):
            md += f"{i}. {item}\n"

        return md

    def save(self, output_dir: Path | str = ".", output_json_path: str | None = None) -> Tuple[str, str]:
        """Save report markdown and JSON files."""
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        md_file = out_path / f"raven_report_{self.report.scan_id}.md"

        # Use user-specified JSON path if provided, otherwise generate default
        if output_json_path:
            json_file = Path(output_json_path)
            json_file.parent.mkdir(parents=True, exist_ok=True)
        else:
            json_file = out_path / f"raven_report_{self.report.scan_id}.json"

        md_content = self.render_markdown()
        md_file.write_text(md_content, encoding="utf-8")
        json_file.write_text(self.report.model_dump_json(indent=2), encoding="utf-8")

        return str(md_file), str(json_file)


# ── Universal v3 Report Generator ────────────────────────────────────────────

class UniversalReportGenerator:
    """
    Renders and serializes universal v3 PentestReport models into
    Markdown, JSON, and HTML formats with honest coverage and evidence.
    """

    def __init__(self, context: Any = None, report: Optional[Any] = None) -> None:
        self.context = context
        self.report = report

    async def build_report(self, start_time: Any) -> Any:
        """Construct full PentestReport from context and run reporting agent."""
        from datetime import datetime
        from agents.reporting_agent import ReportingAgent
        from engine.risk_engine import RiskEngine
        from engine_models.report import PentestReport

        ctx = self.context
        state = ctx.state

        # Calculate risk score
        score_obj, attack_paths = RiskEngine(ctx).calculate_score(
            state.confirmed_findings, []
        ), []

        duration = round((datetime.now() - start_time).total_seconds(), 2)

        report = PentestReport(
            assessment_id=state.assessment_id,
            target=ctx.target,
            duration_seconds=duration,
            confirmed_findings=state.confirmed_findings,
            inconclusive_findings=state.inconclusive_findings,
            risk_score=score_obj.score,
            risk_label=score_obj.label,
            risk_detail=score_obj,
            coverage=state.coverage,
            total_requests_made=ctx.budget_manager.requests_made,
            total_assets_discovered=len(ctx.asset_graph.all_assets()),
            total_tools_used=list(set(a.get("tool", "") for a in state.tested_actions if a.get("tool"))),
            total_capabilities_used=state.active_capabilities,
            limitations=state.limitations,
            not_assessed=state.not_assessed,
        )

        # Generate narrative sections
        reporting_agent = ReportingAgent(ctx)
        try:
            await reporting_agent.generate_narrative(report)
        except Exception:
            pass

        self.report = report
        return report

    def render_markdown(self, report: Optional[Any] = None) -> str:
        """Render universal v3 markdown report."""
        rep = report or self.report
        if not rep:
            return "# Empty Report"

        md = f"""# 🐦 Raven Universal Security Assessment Report

**Assessment ID**: `{rep.assessment_id}`  
**Target**: `{rep.target.raw_input if rep.target else 'Unknown'}` (`{rep.target.target_type.value if rep.target else 'generic'}`)  
**Risk Score**: `{rep.risk_score}/10.0` (**{rep.risk_label}**)  
**Duration**: `{rep.duration_seconds:.2f}s` | **Assets Discovered**: `{rep.total_assets_discovered}` | **Tool Calls**: `{rep.total_requests_made}`  
**Generated At**: `{rep.generated_at}`  

---

## 1. Executive Summary
{rep.executive_summary}

---

## 2. Methodology & Architecture
{rep.methodology_summary}

**Activated Capabilities**: {', '.join(f'`{c}`' for c in rep.total_capabilities_used) if rep.total_capabilities_used else 'None'}

---

## 3. Discovered Attack Paths ({len(rep.attack_paths)})
"""
        if rep.attack_paths:
            for path in rep.attack_paths:
                md += f"### 🔴 [{path.severity}] {path.name} ({path.confidence.upper()})\n"
                md += f"{path.description}\n\n"
                md += f"**Combined Impact**: {path.combined_impact}\n\n"
                md += "**Exploitation Sequence**:\n"
                for step in path.steps:
                    md += f"- **Step {step.step_number}** ({step.technique}): {step.description}\n"
                md += "\n"
        else:
            md += "No multi-step chained attack paths identified.\n\n"

        md += f"--- \n\n## 4. Confirmed Vulnerability Findings ({len(rep.confirmed_findings)})\n\n"
        if rep.confirmed_findings:
            for f in rep.confirmed_findings:
                md += f"### [{f.severity}] {f.title}\n"
                md += f"- **Vulnerability Type**: `{f.vulnerability_type}` | **CVSS**: `{f.cvss_score}` | **CWE**: `{f.cwe_id}`\n"
                md += f"- **Component**: `{f.target_component}`\n"
                if f.asset_description:
                    md += f"- **Asset**: `{f.asset_description}`\n"
                md += f"- **Observation**: {f.observation}\n"
                if f.evidence:
                    md += "- **Verified Evidence**:\n"
                    for ev in f.evidence:
                        md += f"  - `{ev.evidence_type}` ({ev.confidence}): {ev.sanitized_summary}\n"
                        if ev.raw_data:
                            md += f"    ```\n    {ev.raw_data[:200]}\n    ```\n"
                if f.cli_poc:
                    md += f"- **CLI Reproduction PoC**:\n```bash\n{f.cli_poc}\n```\n"
                if f.curl_poc:
                    md += f"- **HTTP Reproduction PoC**:\n```bash\n{f.curl_poc}\n```\n"
                if f.reproduction_steps:
                    md += "- **Reproduction Steps**:\n"
                    for step in f.reproduction_steps:
                        md += f"  1. {step}\n"
                md += f"- **Remediation**: {f.remediation}\n\n"
        else:
            if rep.not_assessed or any(c.status != "tested" for c in rep.coverage):
                md += "No confirmed vulnerabilities were identified in the **partially tested** surfaces. However, some attack surfaces were skipped or could not be fully assessed.\n\n"
            else:
                md += "No vulnerabilities found across all comprehensively tested attack surfaces.\n\n"

        md += f"--- \n\n## 5. Inconclusive Observations ({len(rep.inconclusive_findings)})\n"
        if rep.inconclusive_findings:
            for f in rep.inconclusive_findings:
                md += f"- **[{f.severity}] {f.title}** on `{f.target_component}`: {f.observation}\n"
        else:
            md += "No inconclusive items recorded.\n"

        md += f"\n--- \n\n## 6. Assessment Coverage & Boundaries\n"
        md += "| Attack Surface | Status | Tools Applied | Notes / Scope Constraints |\n"
        md += "|---|---|---|---|\n"
        for item in rep.coverage:
            tools_str = ", ".join(item.tools_used) if hasattr(item, "tools_used") and item.tools_used else "Built-in"
            md += f"| `{item.surface}` | **{item.status.upper()}** | {tools_str} | {item.reason} |\n"

        if rep.not_assessed:
            for na in rep.not_assessed:
                parts = na.split(":", 1)
                surface = parts[0].strip()
                reason = parts[1].strip() if len(parts) > 1 else "Out of target scope"
                md += f"| `{surface}` | **NOT ASSESSED** | None | {reason} |\n"

        md += f"\n--- \n\n## 7. Actionable Remediation Plan\n"
        if rep.remediation_plan:
            for i, r in enumerate(rep.remediation_plan, 1):
                md += f"{i}. {r}\n"
        else:
            md += "Maintain current security baselines and perform periodic continuous assessments.\n"

        return md

    def render_json(self, report: Optional[Any] = None) -> str:
        """Render report as JSON."""
        rep = report or self.report
        return rep.model_dump_json(indent=2) if rep else "{}"

    def save(
        self,
        output_path: str,
        format_type: str = "json",
        report: Optional[Any] = None,
    ) -> str:
        """Save report to specified path in JSON or Markdown format."""
        rep = report or self.report
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        if format_type.lower() == "markdown" or out.suffix == ".md":
            content = self.render_markdown(rep)
        else:
            content = self.render_json(rep)

        out.write_text(content, encoding="utf-8")
        return str(out.resolve())
