"""
tests/test_engine_models.py
---------------------------
Unit tests for Raven v3 universal engine models.
"""

from engine_models.actions import AgentAction
from engine_models.assets import AssetRelationship, AssetType, DiscoveredAsset
from engine_models.authorization import Authorization
from engine_models.coverage import CoverageItem
from engine_models.findings import EvidenceItem, Finding, ValidationStatus
from engine_models.hypotheses import Hypothesis
from engine_models.report import PentestReport
from engine_models.results import NormalizedToolResult
from engine_models.risk import AttackPath, AttackPathStep, RiskScore
from engine_models.scope import Scope
from engine_models.target import Target, TargetComponent, TargetType


def test_target_model_instantiation():
    t = Target(raw_input="https://example.com", target_type=TargetType.WEB_APPLICATION)
    assert t.target_type == TargetType.WEB_APPLICATION
    assert t.target_id.startswith("TGT-")
    assert t.is_web_like() is True


def test_scope_validation_helpers():
    s = Scope(
        allowed_domains=["example.com"],
        excluded_domains=["sub.example.com"],
        allowed_ports=[80, 443],
        allow_active_testing=False,
    )
    assert s.is_domain_allowed("example.com") is True
    assert s.is_domain_allowed("api.example.com") is True
    assert s.is_domain_allowed("sub.example.com") is False
    assert s.is_domain_allowed("google.com") is False
    assert s.is_port_allowed(80) is True
    assert s.is_port_allowed(8080) is False
    assert s.is_impact_allowed("passive") is True
    assert s.is_impact_allowed("moderate") is False


def test_authorization_redaction():
    auth = Authorization(
        confirmed=True,
        confirmed_by="Security Team",
        authorization_type="Bug Bounty",
        credentials={"admin": "supersecretpassword"},
    )
    assert auth.has_credentials() is True
    summary = auth.redacted_summary()
    assert "supersecretpassword" not in summary
    assert "1 username/password pair" in summary


def test_finding_is_reportable_constraint():
    finding = Finding(
        title="Unconfirmed Test",
        vulnerability_type="test",
        validation_status=ValidationStatus.CONFIRMED,
        evidence=[],  # No evidence!
    )
    # Core honesty constraint: confirmed findings must carry reproducible evidence to be reportable
    assert finding.is_reportable() is False

    finding.evidence.append(
        EvidenceItem(
            evidence_type="code_snippet",
            raw_data="os.system('rm -rf /')",
            confidence="High",
        )
    )
    assert finding.is_reportable() is True


def test_hypothesis_lifecycle():
    h = Hypothesis(
        title="SQL Injection in login endpoint",
        vulnerability_type="sql_injection",
        priority=80,
    )
    assert h.status == "proposed"
    assert h.is_testable is True
    h.resolve("confirmed", reason="Time delay reproduction observed")
    assert h.status == "confirmed"
    assert h.is_terminal is True
