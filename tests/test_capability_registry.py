"""
tests/test_capability_registry.py
---------------------------------
Unit tests for CapabilityRegistry discovery, filtering, and prerequisites.
"""

from capabilities.registry import CapabilityRegistry
from engine_models.scope import Scope
from engine_models.target import Target, TargetType


def test_registry_loads_all_manifests():
    reg = CapabilityRegistry()
    caps = reg.list_capabilities()
    assert len(caps) >= 15


def test_registry_filters_by_target_type():
    reg = CapabilityRegistry()

    # Web application target
    web_target = Target(raw_input="https://example.com", target_type=TargetType.WEB_APPLICATION)
    web_caps = reg.find_applicable_capabilities(web_target)
    web_cap_ids = [c.capability_id for c in web_caps]
    assert "web_api_assessment" in web_cap_ids
    assert "binary_analysis" not in web_cap_ids

    # Source repository target
    repo_target = Target(raw_input="./repo", target_type=TargetType.SOURCE_REPOSITORY)
    repo_caps = reg.find_applicable_capabilities(repo_target)
    repo_cap_ids = [c.capability_id for c in repo_caps]
    assert "source_code_analysis" in repo_cap_ids
    assert "secrets_detection" in repo_cap_ids
    assert "dependency_analysis" in repo_cap_ids
    assert "web_api_assessment" not in repo_cap_ids


def test_registry_filters_active_only_when_passive():
    reg = CapabilityRegistry()
    net_target = Target(raw_input="192.168.1.1", target_type=TargetType.NETWORK_SERVICE)

    # Passive scope should exclude active-only capabilities
    passive_scope = Scope(allow_active_testing=False)
    caps_passive = reg.find_applicable_capabilities(net_target, scope=passive_scope)
    cap_ids = [c.capability_id for c in caps_passive]
    assert "network_assessment" not in cap_ids

    # Active scope should include network assessment
    active_scope = Scope(allow_active_testing=True)
    caps_active = reg.find_applicable_capabilities(net_target, scope=active_scope)
    active_ids = [c.capability_id for c in caps_active]
    assert "network_assessment" in active_ids
