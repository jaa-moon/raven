"""
capabilities/manifests/web_api_assessment.py
--------------------------------------------
Capability manifest for Web and REST API security assessment.
"""

from engine_models.assets import AssetType
from engine_models.capabilities import CapabilityManifest
from engine_models.target import TargetType

MANIFEST = CapabilityManifest(
    capability_id="web_api_assessment",
    name="Web & REST API Security Assessment",
    description=(
        "Performs dynamic black-box/gray-box security assessment of web applications "
        "and REST APIs. Assesses OWASP Top 10 vulnerabilities, injection flaws, SSRF, "
        "broken access control, XSS, and security misconfigurations."
    ),
    supported_target_types=[
        TargetType.WEB_APPLICATION,
        TargetType.REST_API,
        TargetType.GRAPHQL_API,
        TargetType.MOBILE_BACKEND,
        TargetType.HYBRID_SYSTEM,
    ],
    supported_asset_types=[
        AssetType.URL,
        AssetType.ENDPOINT,
        AssetType.PARAMETER,
        AssetType.FORM,
        AssetType.HEADER,
        AssetType.COOKIE,
    ],
    required_tools=["send_http_request"],
    optional_tools=["crawl_endpoints", "fuzz_parameter", "test_sql_injection", "test_xss"],
    agent_module="agents.specialized.web_api_agent",
    agent_class="WebApiAssessmentAgent",
    required_inputs=["target_url"],
    produces_assets=[AssetType.ENDPOINT, AssetType.PARAMETER, AssetType.HEADER],
    risk_level="moderate",
    supports_passive_mode=True,
    supports_active_mode=True,
    supports_authenticated_mode=True,
    prerequisites=[],
    exclusions=[],
)
