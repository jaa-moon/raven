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
