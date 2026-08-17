"""
web/web_report_generator.py
---------------------------
Raven Phase 8: Markdown report generator for web vulnerability scans.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.models import WebScanReport

def generate_web_report(report: WebScanReport, output_json: Path | None = None) -> str:
    """Writes the markdown report and optionally exports JSON. Returns the report path."""
    
    # 1. Generate Markdown
    md = [
        "# 🌐 Raven Web Security Assessment",
        f"**Target**: `{report.target}`",
        f"**Scan Type**: `{report.scan_type}`",
        f"**Date**: {report.timestamp}",
        f"**Duration**: {report.scan_duration_seconds:.1f}s",
        "",
        "---",
        "",
        "## 🔍 Site Fingerprint",
        f"**Detected Technologies**: {', '.join(report.fingerprint.get('detected_technologies', [])) or 'None detected'}",
        f"**Server**: `{report.fingerprint.get('server_header', 'Unknown')}`",
        ""
    ]

    # Security Headers Table
    if "security_headers" in report.fingerprint:
        md.extend([
            "### Security Headers",
            "| Header | Status | Value |",
            "|--------|--------|-------|"
        ])
        for header, status in report.fingerprint["security_headers"].items():
            icon = "✅" if status["present"] else "❌"
            val = status["value"] or "*(missing)*"
            md.append(f"| {header} | {icon} | `{val}` |")
        md.append("")

    # Cookie Security
    if "cookies" in report.fingerprint and report.fingerprint["cookies"]:
        md.append("### Cookie Security")
        for cookie in report.fingerprint["cookies"]:
            flags = []
            flags.append(f"HttpOnly {'✅' if cookie['has_httponly'] else '❌'}")
            flags.append(f"Secure {'✅' if cookie['has_secure'] else '❌'}")
            flags.append(f"SameSite {'✅' if cookie['has_samesite'] else '❌'}")
            md.append(f"- **`{cookie['name']}`**: {', '.join(flags)}")
        md.append("")

    # Interesting Paths
    if "interesting_paths" in report.fingerprint and report.fingerprint["interesting_paths"]:
        md.append("### Interesting Paths Found")
        for path in report.fingerprint["interesting_paths"]:
            md.append(f"- `{path}`")
        md.append("")

    md.extend([
        "---",
        "",
        "## 🎯 Findings Summary",
        "| Severity | Count |",
        "|----------|-------|"
    ])
    
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        count = report.findings_by_severity.get(sev, 0)
        md.append(f"| {sev} | {count} |")
        
    md.extend(["", "---", ""])
    
    # Detailed Findings
    critical_high = [f for f in report.findings if f.severity in ("Critical", "High")]
    if critical_high:
        md.append("## 🔴 Critical & High Findings\n")
        
        for f in critical_high:
            md.extend([
                f"### {f.finding_id} — {f.vulnerability_type}: {f.severity} Severity",
                f"**URL**: `{f.url}`",
                f"**Method**: {f.method} · **Parameter**: `{f.parameter}`",
                f"**Confirmed**: {'✅ Yes' if f.confirmed else '❌ No'}",
                "",
                "**AI Analysis**:",
                f"> {f.ai_analysis}",
                "",
                "**Remediation**:",
                f"{f.remediation}",
                "",
                "**Proof of Concept**:",
                "```bash",
                f.curl_poc,
                "```",
                ""
            ])
            if f.evidence:
                md.extend([
                    "**Evidence Snippet**:",
                    "```",
                    f.evidence.strip(),
                    "```",
                    ""
                ])

    report_content = "\n".join(md)
    
    # Save files
    timestamp_fs = report.timestamp.replace(" ", "_").replace(":", "-")
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    
    md_path = reports_dir / f"raven_web_{timestamp_fs}.md"
    md_path.write_text(report_content, encoding="utf-8")
    report.report_path = str(md_path.absolute())
    
    if output_json:
        output_json.write_text(
            report.model_dump_json(indent=2),
            encoding="utf-8"
        )
        
    return str(md_path.absolute())
