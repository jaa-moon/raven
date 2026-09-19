"""
capabilities/manifests/auth_identity_assessment.py
--------------------------------------------------
Capability manifest for Authentication & Identity Assessment.
"""

from engine_models.assets import AssetType
from engine_models.capabilities import CapabilityManifest
from engine_models.target import TargetType

MANIFEST = CapabilityManifest(
    capability_id="auth_identity_assessment",
    name="Authentication & Identity Security Assessment",
    description=(
        "Analyzes authentication mechanisms, JWT token security, cookie flags, "
        "session fixation, OAuth/OIDC flows, and CORS policy misconfigurations."
    ),
    supported_target_types=[
        TargetType.WEB_APPLICATION,
        TargetType.REST_API,
        TargetType.MOBILE_BACKEND,
        TargetType.HYBRID_SYSTEM,
    ],
    supported_asset_types=[
        AssetType.TOKEN,
        AssetType.COOKIE,
        AssetType.HEADER,
        AssetType.ENDPOINT,
    ],
    required_tools=["send_http_request"],
    optional_tools=["decode_jwt", "audit_jwt_security", "check_cors_headers"],
    agent_module="agents.specialized.auth_identity_agent",
    agent_class="AuthIdentityAssessmentAgent",
    required_inputs=["target_url"],
    produces_assets=[AssetType.TOKEN, AssetType.COOKIE],
    risk_level="low",
    supports_passive_mode=True,
    supports_active_mode=True,
    supports_authenticated_mode=True,
    prerequisites=[],
    exclusions=[],
)
