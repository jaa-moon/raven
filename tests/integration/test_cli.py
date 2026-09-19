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
