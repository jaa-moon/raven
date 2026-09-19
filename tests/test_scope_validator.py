"""
tests/test_scope_validator.py
-----------------------------
Unit tests for universal ScopeValidator boundaries.
"""

from engine.scope_validator import ScopeValidator
from engine_models.actions import AgentAction
from engine_models.scope import Scope


def test_scope_blocks_out_of_scope_domain():
    scope = Scope(allowed_domains=["myapp.internal"])
    validator = ScopeValidator(scope)

    action = AgentAction(
        tool_name="send_http_request",
        target="https://evil.external.com/api",
        purpose="Test external domain",
        impact_level="passive",
    )
    result = validator.validate_action(action)
    assert result.allowed is False
    assert "not in allowed_domains" in result.reason or "excluded" in result.reason


def test_scope_allows_in_scope_domain():
    scope = Scope(allowed_domains=["myapp.internal"])
    validator = ScopeValidator(scope)

    action = AgentAction(
        tool_name="send_http_request",
        target="https://api.myapp.internal/v1",
        purpose="Test internal api",
        impact_level="passive",
    )
    result = validator.validate_action(action)
    assert result.allowed is True


def test_scope_blocks_active_when_passive_only():
    scope = Scope(allow_active_testing=False)
    validator = ScopeValidator(scope)

    action = AgentAction(
        tool_name="fuzz_parameter",
        target="http://localhost:5000",
        purpose="Fuzz parameters actively",
        impact_level="moderate",
    )
    result = validator.validate_action(action)
    assert result.allowed is False
    assert "exceeds permitted testing boundaries" in result.reason


def test_scope_cidr_boundary_enforcement():
    scope = Scope(
        allowed_ips=["192.168.1.0/24"],
        excluded_ips=["192.168.1.10"],
    )
    validator = ScopeValidator(scope)

    ip_ok = validator.validate_ip("192.168.1.50")
    assert ip_ok.allowed is True

    ip_excluded = validator.validate_ip("192.168.1.10")
    assert ip_excluded.allowed is False

    ip_out = validator.validate_ip("10.0.0.1")
    assert ip_out.allowed is False
