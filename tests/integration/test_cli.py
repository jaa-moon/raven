"""CLI surface: simple menu commands and the non-interactive assess path."""

import json

from typer.testing import CliRunner

from cli.app import app

runner = CliRunner()


def test_version_command():
    r = runner.invoke(app, ["version"])
    assert r.exit_code == 0 and "Raven" in r.output


def test_assess_requires_authorization_confirmation(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    r = runner.invoke(app, ["assess", str(tmp_path)], input="n\n")
    assert r.exit_code == 0 and "aborted" in r.output.lower()


def test_assess_writes_report_and_fail_on_gates_ci(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "app.py").write_text('DB_PASSWORD = "Xk29!fjs81"\nDEBUG = True\n')
    out = tmp_path / "out"
    r = runner.invoke(app, ["assess", str(proj), "--depth", "quick", "--fail-on", "high", "-o", str(out)], input="y\n")
    assert r.exit_code == 1, r.output                       # confirmed HIGH secret trips the gate
    md = next(out.glob("raven_*.md")).read_text(encoding="utf-8")
    assert "Confirmed Findings" in md and "Coverage" in md and "Xk29" not in md
    data = json.loads(next(out.glob("raven_*.json")).read_text(encoding="utf-8"))
    assert data["phase"] == "complete" and data["overall_state"] in ("PARTIAL", "COMPLETE")


def test_assess_passes_gate_when_nothing_meets_threshold(tmp_path):
    proj = tmp_path / "clean"
    proj.mkdir()
    (proj / "app.py").write_text("print('hello')\n")
    r = runner.invoke(app, ["scan", str(proj), "--fail-on", "high"], input="y\n")
    assert r.exit_code == 0 and "PASS" in r.output
    assert "NOT evidence" in r.output or "not evidence" in r.output.lower() or "PARTIAL" in r.output or "COMPLETE" in r.output


def test_invalid_target_is_reported_cleanly():
    r = runner.invoke(app, ["assess", "./no/such/place"], input="y\n")
    assert r.exit_code != 0


def test_report_command_missing_id():
    assert runner.invoke(app, ["report", "ASM-nope"]).exit_code == 1


# ── risk-level configuration: one source of truth, CLI flag and menu agree ─────

def _capture_run(monkeypatch):
    """Replace run_assessment with a stub that records the kwargs it was given."""
    captured: dict = {}

    async def fake_run(target=None, **kw):
        from core.state import AssessmentState
        captured["target"] = target
        captured.update(kw)
        return AssessmentState()

    monkeypatch.setattr("core.assessment.run_assessment", fake_run)
    return captured


def test_assess_default_risk_is_low(tmp_path, monkeypatch):
    cap = _capture_run(monkeypatch)
    r = runner.invoke(app, ["assess", "http://localhost:3000", "-y", "-o", str(tmp_path)])
    assert r.exit_code == 0, r.output
    assert cap["max_risk"] == "low"


def test_assess_max_risk_moderate_is_wired_through(tmp_path, monkeypatch):
    cap = _capture_run(monkeypatch)
    r = runner.invoke(app, ["assess", "http://localhost:3000", "--max-risk", "moderate", "-y", "-o", str(tmp_path)])
    assert r.exit_code == 0, r.output
    assert cap["max_risk"] == "moderate"


def test_assess_max_risk_high_is_wired_through(tmp_path, monkeypatch):
    cap = _capture_run(monkeypatch)
    r = runner.invoke(app, ["assess", "http://localhost:3000", "--max-risk", "high", "-y", "-o", str(tmp_path)])
    assert r.exit_code == 0, r.output
    assert cap["max_risk"] == "high"


def test_assess_invalid_risk_is_rejected(tmp_path, monkeypatch):
    _capture_run(monkeypatch)
    r = runner.invoke(app, ["assess", "http://localhost:3000", "--max-risk", "nuke", "-y", "-o", str(tmp_path)])
    assert r.exit_code == 2 and "invalid --max-risk" in r.output.lower()


async def test_menu_and_cli_flag_produce_the_same_risk_config(tmp_path, monkeypatch):
    """Selecting 'Moderate' in the menu yields the same max_risk the CLI flag does."""
    import cli.menu as menu

    captured: dict = {}

    async def fake_run(target=None, **kw):
        from core.state import AssessmentState
        captured.update(kw)
        return AssessmentState()

    monkeypatch.setattr("core.assessment.run_assessment", fake_run)
    monkeypatch.setattr(menu, "save", lambda s, d: (tmp_path / "r.md", tmp_path / "r.json"))
    monkeypatch.setattr(menu.ConfigManager, "is_configured", lambda self: False)
    monkeypatch.setattr(menu.Prompt, "ask", staticmethod(lambda *a, **k: "2"))   # 2 -> moderate
    monkeypatch.setattr(menu.Confirm, "ask", staticmethod(lambda *a, **k: True))

    await menu.run_test_flow("http://localhost:3000")
    assert captured["max_risk"] == "moderate"
    assert menu.RISK_CHOICES == {"1": "low", "2": "moderate", "3": "high"}


def test_menu_risk_mapping_is_the_canonical_strings():
    from cli.menu import RISK_CHOICES
    assert set(RISK_CHOICES.values()) == {"low", "moderate", "high"}
