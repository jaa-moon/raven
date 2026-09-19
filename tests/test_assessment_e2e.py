"""
tests/test_assessment_e2e.py
----------------------------
End-to-end assessment integration tests.
"""

import asyncio
from engine.assessment_controller import run_assessment
from engine_models.target import TargetType


def test_repository_assessment_e2e():
    """Verify that assessing a source repository activates only relevant capabilities."""
    report = asyncio.run(run_assessment("./mock_project", depth="quick", mode="passive"))

    assert report.assessment_id.startswith("ASM-")
    assert report.target.target_type == TargetType.SOURCE_REPOSITORY
    assert report.total_assets_discovered > 0

    # Ensure web capabilities were NOT activated on a pure repository
    assert "web_api_assessment" not in report.total_capabilities_used
    assert "network_assessment" not in report.total_capabilities_used

    # Ensure source capabilities were activated
    assert "source_code_analysis" in report.total_capabilities_used
    assert "secrets_detection" in report.total_capabilities_used

    # Ensure coverage items were tracked
    assert len(report.coverage) > 0

    # Ensure report metrics are consistent
    assert report.duration_seconds >= 0.0


def test_web_assessment_e2e():
    """Verify that assessing a web URL activates web capabilities."""
    report = asyncio.run(run_assessment("https://httpbin.org", depth="quick", mode="passive"))

    assert report.target.target_type in (TargetType.WEB_APPLICATION, TargetType.REST_API)
    assert "web_api_assessment" in report.total_capabilities_used
    # Source code analysis should not run against remote web target without source
    assert "source_code_analysis" not in report.total_capabilities_used
