"""
End-to-end assessments through the real pipeline (intake -> analysis -> plan -> agents ->
gateway -> validation -> coverage -> report) against local fixtures. No mocks of Raven itself.
"""

import asyncio
import os

import pytest

from core.budget import BudgetLimits
from core.models import CoverageStatus, FindingStatus
from reporting.generator import render_markdown

FAST = dict(authorized=True, learn_lessons=False)


def _paths(state):
    return {o.data["path"]: o.data for o in state.observations if o.kind == "path.candidate"}


# ── web: the original false-positive scenario ──────────────────────────────────────

async def test_spa_target_produces_no_sensitive_file_findings(spa_server):
    from core.assessment import run_assessment
    state = await run_assessment(spa_server.url, **FAST)
    paths = _paths(state)
    for p in ("/.env", "/.git/HEAD", "/admin", "/actuator/env", "/wp-config.php"):
        assert paths[p]["classification"] == "spa_fallback", p          # recognized as the app shell
    assert not [f for f in state.findings if f.category in ("SensitiveFileExposure", "AdminPanelExposed", "ActuatorExposure")]
    assert state.profile.attributes["spa"] is True and "Fixture Shop" in state.profile.attributes["baseline"]["body"]


async def test_leaky_target_confirms_real_env_and_ignores_protected_git(leaky_server):
    from core.assessment import run_assessment
    state = await run_assessment(leaky_server.url, **FAST)
    env = next(f for f in state.confirmed_findings if f.signal.get("path") == "/.env")
    assert env.severity.value == "critical" and env.confidence.value == "high"
    dumped = state.model_dump_json()
    assert "hunter2" not in dumped and "topsecretvalue" not in dumped     # redacted everywhere, incl. state
    assert not any(f.signal.get("path") == "/.git/HEAD" and f.status == FindingStatus.CONFIRMED for f in state.findings)
    assert _paths(state)["/.git/HEAD"]["classification"] == "protected"
    cors = [f for f in state.confirmed_findings if f.signal.get("validator") == "cors_reflection"]
    assert cors and cors[0].confidence.value in ("medium", "high")


async def test_admin_actuator_and_config_exposures_are_confirmed_and_siblings_are_not(admin_leaky_server):
    """End-to-end: agent -> gateway -> validation/content.py -> independent revalidator -> report,
    for the three content-validated categories that previously had no fixture-server coverage."""
    from core.assessment import run_assessment
    state = await run_assessment(admin_leaky_server.url, **FAST)

    admin = next(f for f in state.confirmed_findings if f.category == "AdminPanelExposed")
    assert admin.signal.get("path") == "/admin" and admin.severity.value == "high"
    assert admin.evidence or admin.validation_notes

    actuator = next(f for f in state.confirmed_findings if f.category == "ActuatorExposure")
    assert actuator.signal.get("path") == "/actuator/health" and actuator.severity.value == "high"
    assert actuator.evidence or actuator.validation_notes

    config = next(f for f in state.confirmed_findings if f.category == "SensitiveFileExposure"
                  and f.signal.get("path") == "/wp-config.php")
    assert config.severity.value == "critical"
    assert config.evidence or config.validation_notes

    # Sibling paths in the same probe groups genuinely 404 -- they must not be confirmed too.
    paths = _paths(state)
    for missing in ("/actuator", "/actuator/env", "/console", "/administrator", "/wp-admin",
                    "/config.php", "/configuration.php"):
        assert paths[missing]["classification"] == "generic_404", missing
    confirmed_paths = {f.signal.get("path") for f in state.confirmed_findings
                       if f.signal.get("validator") == "http_path_exposure"}
    assert confirmed_paths == {"/admin", "/actuator/health", "/wp-config.php"}

    cov = {c.surface: c for c in state.coverage}
    assert cov["Exposed paths & files"].status == CoverageStatus.ASSESSED


async def test_web_assessment_adapts_to_what_it_discovers(spa_server):
    """robots.txt + JS bundle reveal endpoints -> profile changes -> new tasks -> API surface found."""
    from core.assessment import run_assessment
    state = await run_assessment(spa_server.url, limits=BudgetLimits(max_tool_calls=300), **FAST)
    assert "/internal-api" in state.profile.endpoints and "/api/Items" in state.profile.endpoints
    assert state.profile.api is True and "rest_api" in state.profile.surfaces
    keys = {t.key for t in state.tasks}
    assert "web_recon.endpoint::/internal-api" in keys and "web_recon.endpoint::/api/Items" in keys
    assert sum("new knowledge" in n for n in state.notes) >= 1
    api = next(c for c in state.coverage if c.surface == "REST API")
    assert api.status == CoverageStatus.ASSESSED


async def test_report_is_honest_for_a_partially_assessed_target(spa_server):
    from core.assessment import run_assessment
    state = await run_assessment(spa_server.url, **FAST)
    md = render_markdown(state)
    assert state.overall_state == "PARTIAL"
    assert "Path Discovery Summary" in md and "spa_fallback" in md
    assert "Authorization" in md and "NOT_ASSESSED" in md
    # Active injection testing exists but is capped by default scope (max_risk=low): honestly NOT_ASSESSED.
    assert "SQL Injection" in md and "SSRF" in md
    assert "clean" not in md.lower()


async def test_unreachable_target_reports_limitation_not_clean():
    from core.assessment import run_assessment
    state = await run_assessment("http://127.0.0.1:1", **FAST, sleep=lambda d: asyncio.sleep(0))
    assert state.profile.reachable is False
    assert state.confirmed_findings == [] and state.overall_state in ("INCOMPLETE", "PARTIAL")
    assert any("unreachable" in l.lower() or "could not be reached" in l.lower() for l in state.limitations)
    assert all(c.status != CoverageStatus.ASSESSED for c in state.coverage)


async def test_budget_exhaustion_degrades_gracefully_and_is_reported(spa_server):
    from core.assessment import run_assessment
    state = await run_assessment(spa_server.url, limits=BudgetLimits(max_tool_calls=12), **FAST)
    assert state.phase == "complete"                                     # no abrupt failure
    assert any("budget" in l.lower() for l in state.limitations)
    assert any(t.status == "skipped" for t in state.tasks)
    assert state.overall_state != "COMPLETE" and state.budget["status"] in ("critical", "exhausted", "constrained")


async def test_scope_is_enforced_for_every_tool_call(spa_server):
    from core.assessment import run_assessment
    state = await run_assessment(spa_server.url, **FAST)
    assert all(c.status != "out_of_scope" for c in state.tool_calls)      # agents stayed inside
    assert state.scope.allowed_hosts == ["localhost"]                    # 127.0.0.1 canonicalized


# ── source repository ──────────────────────────────────────────────────────────────

@pytest.fixture
def repo(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==2.0.1\nrequests==2.31.0\n")
    (tmp_path / "app.py").write_text(
        'import subprocess, os\n'
        'DB_PASSWORD = "Xk29!fjs81"\n'
        'API_KEY = "your_api_key_here"\n'
        'token = os.environ["TOKEN"]\n'
        'def run(cmd):\n    return subprocess.run(cmd, shell=True)\n'
        'DEBUG = True\n')
    return tmp_path


async def test_source_repo_validation_separates_real_from_false_positives(repo):
    from core.assessment import run_assessment
    state = await run_assessment(str(repo), **FAST)
    assert state.profile.target_type == "source_repository" and "Flask" in state.profile.technologies
    secrets = {f.signal["line"]: f for f in state.findings if f.category == "HardcodedSecret"}
    assert secrets[2].status == FindingStatus.CONFIRMED                 # real literal
    assert all(f.status != FindingStatus.CONFIRMED for l, f in secrets.items() if l == 3)  # placeholder
    shell = next(f for f in state.findings if f.signal.get("rule") == "cmd-shell-true")
    assert shell.status == FindingStatus.INCONCLUSIVE                   # pattern seen, exploitability unproven
    debug = next(f for f in state.findings if f.signal.get("rule") == "debug-enabled")
    assert debug.status == FindingStatus.CONFIRMED
    dep = next(f for f in state.confirmed_findings if f.category == "VulnerableDependency")
    assert dep.signal["package"] == "flask" and "reachable was not tested" in dep.validation_notes[0]
    assert "Xk29" not in state.model_dump_json()                        # secret value never stored


@pytest.fixture
def repo_with_config_issue(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==2.0.1\n")
    (tmp_path / ".env").write_text("DATABASE_URL=postgres://app:hunter2@db/app\nDEBUG=True\n")
    return tmp_path


async def test_config_scanner_finding_is_raised_and_confirmed_on_revalidation(repo_with_config_issue):
    from core.assessment import run_assessment
    state = await run_assessment(str(repo_with_config_issue), **FAST)
    misconfig = next(f for f in state.findings if f.category == "SecurityMisconfiguration")
    assert misconfig.signal["validator"] == "config_setting"
    assert misconfig.signal["file"] == ".env" and misconfig.signal["line"] == 2
    assert misconfig.status == FindingStatus.CONFIRMED                 # verified in B.2: unchanged file re-reads identical
    cov = {c.surface: c for c in state.coverage}
    assert cov["Configuration"].status == CoverageStatus.ASSESSED


async def test_repo_coverage_marks_unavailable_capability_blocked(repo):
    from core.assessment import run_assessment
    state = await run_assessment(str(repo), **FAST)
    cov = {c.surface: c for c in state.coverage}
    assert cov["Secrets"].status == cov["Dependencies"].status == CoverageStatus.ASSESSED
    assert cov["HTTP"].status == CoverageStatus.NOT_APPLICABLE
    expected = CoverageStatus.BLOCKED if os.name != "posix" else CoverageStatus.ASSESSED
    assert cov["File permissions"].status == expected


async def test_state_is_persisted_and_resumable(repo, tmp_path):
    from core.assessment import run_assessment
    from core.state import AssessmentState
    root = tmp_path / "saved"
    state = await run_assessment(str(repo), state_root=root, **FAST)
    loaded = AssessmentState.load(state.assessment_id, root)
    assert loaded.phase == "complete" and len(loaded.findings) == len(state.findings)
    assert loaded.tool_calls and loaded.agent_activity and loaded.rag_contexts and loaded.budget


# ── network service (target-agnostic proof) ───────────────────────────────────────

async def test_network_target_finds_unauthenticated_redis():
    from core.assessment import run_assessment

    async def fake_redis(reader, writer):
        data = await reader.read(64)
        if b"PING" in data.upper():
            writer.write(b"+PONG\r\n")
        else:
            writer.write(b"-ERR unknown command\r\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(fake_redis, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        state = await run_assessment(f"127.0.0.1:{port}", **FAST, sleep=lambda d: asyncio.sleep(0))
    finally:
        server.close()
        await server.wait_closed()
    assert state.profile.target_type == "network_service"
    assert {sv["port"] for sv in state.profile.services} == {port}
    assert state.profile.services[0]["protocol"] == "redis"
    redis = next(f for f in state.findings if f.category == "ExposedService")
    assert redis.status == FindingStatus.CONFIRMED and redis.severity.value == "critical"
    assert redis.signal["unauthenticated"] is True and redis.validator == "open_service"
    net = next(c for c in state.coverage if c.surface == "Network services")
    assert net.status == CoverageStatus.ASSESSED
    assert next(c for c in state.coverage if c.surface == "HTTP").status == CoverageStatus.NOT_APPLICABLE


# ── resume after interruption ───────────────────────────────────────────────────────

async def test_interrupted_assessment_resumes_without_repeating_work(repo, tmp_path):
    from core.assessment import run_assessment
    from core.state import AssessmentState
    root = tmp_path / "saved"
    first = await run_assessment(str(repo), state_root=root, limits=BudgetLimits(max_iterations=2), **FAST)
    done_before = {t.key for t in first.completed_tasks}
    assert len(done_before) == 2 and any(t.status == "skipped" for t in first.tasks)
    assert first.overall_state != "COMPLETE"

    resumed = await run_assessment(resume_id=first.assessment_id, state_root=root, **FAST)
    assert resumed.assessment_id == first.assessment_id
    assert {t.key for t in resumed.completed_tasks} > done_before          # strictly more work done
    calls_for_done = [c for c in resumed.tool_calls if c.task_id in {t.task_id for t in first.completed_tasks}]
    assert len(calls_for_done) == len([c for c in first.tool_calls if c.task_id in {t.task_id for t in first.completed_tasks}])
    assert not any(l.startswith("Assessment stopped early") for l in resumed.limitations)
    assert any("resumed" in n.lower() for n in resumed.notes)
    assert AssessmentState.load(first.assessment_id, root).phase == "complete"


async def test_resume_of_unknown_assessment_fails_clearly(tmp_path):
    from core.assessment import run_assessment
    with pytest.raises(FileNotFoundError):
        await run_assessment(resume_id="ASM-missing", state_root=tmp_path, authorized=True)
