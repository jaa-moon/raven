"""
capabilities/manifests/configuration_assessment.py
--------------------------------------------------
Capability manifest for Configuration & Baseline Security Assessment.
"""

from engine_models.assets import AssetType
from engine_models.capabilities import CapabilityManifest
from engine_models.target import TargetType

MANIFEST = CapabilityManifest(
    capability_id="configuration_assessment",
    name="Configuration & Security Hardening Baseline Assessment",
    description=(
        "Audits web server configurations (Nginx, Apache), environment files, CI/CD pipelines, "
        "and security headers against CIS baselines and industry best practices."
    ),
    supported_target_types=[
        TargetType.SOURCE_REPOSITORY,
        TargetType.INFRASTRUCTURE_AS_CODE,
        TargetType.CI_CD_PIPELINE,
        TargetType.OPERATING_SYSTEM,
        TargetType.WEB_APPLICATION,
        TargetType.HYBRID_SYSTEM,
    ],
    supported_asset_types=[
        AssetType.CONFIGURATION,
        AssetType.FILE,
        AssetType.HEADER,
    ],
    required_tools=["read_file"],
    optional_tools=["check_security_headers"],
    agent_module="agents.specialized.configuration_agent",
    agent_class="ConfigurationAssessmentAgent",
    required_inputs=["config_path"],
    produces_assets=[AssetType.CONFIGURATION],
    risk_level="low",
    supports_passive_mode=True,
    supports_active_mode=False,
    supports_authenticated_mode=False,
    prerequisites=[],
    exclusions=[],
)
