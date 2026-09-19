"""
capabilities/policies/default_policies.py
-----------------------------------------
Default operational and scope policies per capability.
"""

from typing import Any, Dict

DEFAULT_CAPABILITY_POLICIES: Dict[str, Dict[str, Any]] = {
    "web_api_assessment": {
        "requires_active_for_full_tests": True,
        "default_impact_level": "moderate",
        "rate_limit_rps": 10,
        "respect_robots_txt": True,
    },
    "source_code_analysis": {
        "requires_active_for_full_tests": False,
        "default_impact_level": "passive",
        "rate_limit_rps": 0,
        "respect_robots_txt": False,
    },
    "auth_identity_assessment": {
        "requires_active_for_full_tests": True,
        "default_impact_level": "low",
        "rate_limit_rps": 5,
        "respect_robots_txt": True,
    },
    "secrets_detection": {
        "requires_active_for_full_tests": False,
        "default_impact_level": "passive",
        "rate_limit_rps": 0,
        "respect_robots_txt": False,
    },
    "dependency_analysis": {
        "requires_active_for_full_tests": False,
        "default_impact_level": "passive",
        "rate_limit_rps": 0,
        "respect_robots_txt": False,
    },
    "network_assessment": {
        "requires_active_for_full_tests": True,
        "default_impact_level": "moderate",
        "rate_limit_rps": 50,
        "respect_robots_txt": False,
    },
}
