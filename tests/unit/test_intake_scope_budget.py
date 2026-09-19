"""Target intake, scope validation and budget management."""

import pytest

from core.budget import BudgetLimits, BudgetManager
from core.scope import Scope, ScopeValidator
from core.target import InputKind, TargetError, parse_target


# ── target classification ─────────────────────────────────────────────────────

@pytest.mark.parametrize("raw,kind,normalized", [
    ("https://Example.com/", InputKind.URL, "https://example.com"),
    ("http://localhost:3000", InputKind.URL, "http://localhost:3000"),
    ("192.168.1.50", InputKind.IP, "192.168.1.50"),
    ("192.168.1.50:6379", InputKind.IP, "192.168.1.50:6379"),
    ("localhost:3000", InputKind.HOST, "localhost:3000"),
    ("example.com", InputKind.HOST, "example.com"),
])
def test_network_targets_are_classified(raw, kind, normalized):
    t = parse_target(raw)
    assert t.input_type == kind and t.normalized_target == normalized


def test_directory_and_file_targets(tmp_path):
    (tmp_path / "app.py").write_text("x=1")
    assert parse_target(str(tmp_path)).input_type == InputKind.DIRECTORY
    assert parse_target(str(tmp_path / "app.py")).input_type == InputKind.FILE


@pytest.mark.parametrize("bad", ["", "   ", "./definitely/not/here", "not a target!!", "host:99999", "ftp://x"])
def test_invalid_targets_are_rejected(bad):
    with pytest.raises(TargetError):
        parse_target(bad)


# ── scope ─────────────────────────────────────────────────────────────────────

def _v(target, risk="low"):
    return ScopeValidator(Scope.from_target(parse_target(target), max_risk=risk))


def test_scope_is_derived_from_the_target():
    v = _v("http://localhost:3000")
    assert v.check([("url", "http://localhost:3000/rest/x")], "passive").allowed
    assert v.check([("url", "http://127.0.0.1:3000/")], "passive").allowed      # loopback aliases
    assert not v.check([("url", "http://evil.example/")], "passive").allowed    # other host
    assert not v.check([("url", "http://localhost:3001/")], "passive").allowed  # other port


def test_risk_level_above_maximum_is_blocked():
    d = _v("http://localhost:3000", risk="low").check([("url", "http://localhost:3000/")], "high")
    assert not d.allowed and d.kind == "risk"


def test_scope_can_be_extended_explicitly_and_supports_wildcards_and_cidr():
    s = Scope.from_target(parse_target("http://app.test:8080")).extended(hosts=["*.cdn.test", "10.0.0.0/24"])
    v = ScopeValidator(s)
    assert v.check([("host", "img.cdn.test")], "passive").allowed
    assert v.check([("host", "10.0.0.9")], "passive").allowed
    assert not v.check([("host", "10.0.1.9")], "passive").allowed


def test_filesystem_scope_blocks_traversal(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    v = _v(str(root))
    assert v.check([("path", str(root / "src" / "a.py"))], "passive").allowed
    assert not v.check([("path", str(root / ".." / "secrets.txt"))], "passive").allowed
    assert not v.check([("path", str(tmp_path))], "passive").allowed


# ── budget ────────────────────────────────────────────────────────────────────

def test_budget_status_degrades_before_it_exhausts():
    b = BudgetManager(BudgetLimits(max_tool_calls=100))
    assert b.status() == "ok"
    b.consume(tool_calls=75)
    assert b.status() == "constrained" and b.can_afford()
    b.consume(tool_calls=15)
    assert b.status() == "critical" and b.can_afford()
    b.consume(tool_calls=10)
    assert b.status() == "exhausted" and not b.can_afford()
    assert b.exhausted_dimensions() == ["tool_calls"]


def test_time_and_expensive_and_llm_budgets():
    t = [0.0]
    b = BudgetManager(BudgetLimits(max_seconds=10, max_expensive_ops=1, max_llm_calls=1), clock=lambda: t[0])
    assert b.can_afford(expensive=True, llm=True)
    b.consume(expensive=1, llm_calls=1)
    assert not b.can_afford(expensive=True) and not b.can_afford(llm=True) and b.can_afford()
    t[0] = 10.0
    assert not b.can_afford() and b.status() == "exhausted"


def test_retry_accounting_and_depth_presets():
    b = BudgetManager(BudgetLimits(max_retries=2))
    assert b.record_retry("k") and b.record_retry("k") and not b.record_retry("k")
    assert BudgetLimits.for_depth("quick").max_tool_calls < BudgetLimits.for_depth("deep").max_tool_calls
