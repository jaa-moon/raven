"""
tests/test_backward_compat.py
-----------------------------
Backward compatibility tests ensuring existing v2.1.0 modules and CLI commands function properly.
"""

from orchestrator.orchestrator import run_scan
from reports.models import AgentFinding, AttackChain, FinalReport, ProjectProfile, SandboxInfo
from reports.report_generator import ReportGenerator
from reports.risk_classifier import RiskClassifier


def test_legacy_models_import_and_instantiate():
    profile = ProjectProfile(path="./mock_project", language="Python", framework="Flask")
    sandbox = SandboxInfo(mode="process", base_url="http://localhost:5000")

    finding = AgentFinding(
        agent="web_api",
        vulnerability_type="SQL Injection",
        severity="High",
        target_url="http://localhost:5000/login",
        evidence="sqlite3.OperationalError",
    )

    score, label = RiskClassifier.calculate_score([finding], [])
    assert score > 0.0
    assert label in ("High", "Medium", "Low", "Critical")

    report = FinalReport(
        scan_id="SCAN-COMPAT",
        target_path="./mock_project",
        project_profile=profile,
        sandbox_info=sandbox,
        agent_1_findings=[finding],
        risk_score=score,
        risk_label=label,
    )

    gen = ReportGenerator(report)
    md = gen.render_markdown()
    assert "# 🐦 Raven Autonomous Pentest Report" in md
